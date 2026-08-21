//! TP-Link Tapo dimmer switches (S500D and the rest of the S5xxD line), driven locally over
//! KLAP — the protocol the switch speaks on port 80 to whatever is on the same network.
//! Nothing here reaches TP-Link's cloud, and the switch does not need to either.
//!
//! ```text
//!   POST /app/handshake1        seeds are exchanged and both sides prove the account
//!   POST /app/handshake2
//!   POST /app/request?seq=N     {"method":"get_device_info"}
//!                               {"method":"set_device_info","params":{"brightness":40}}
//! ```
//!
//! The crypto is in [`klap`] and the HTTP framing in [`http`], both with their own reasons
//! written down. What is left here is the state machine, and it exists because of one thing:
//!
//! # Every exchange is several round trips, and a driver cannot wait
//!
//! A driver returns [`HostCall`]s and is called again when something arrives; it has no way to
//! block on a reply. So "turn this light on" is not one call — it is a handshake, a second
//! handshake, the command, and a read-back, each one landing in [`DriverModule::on_event`]
//! with the next step to take. That state lives in `inst.scratch`, and `phase` is what says
//! which reply is expected next.
//!
//! Two consequences worth stating rather than discovering:
//!
//! - **One request in flight.** The sequence number is both the last four bytes of the AES IV
//!   and a query parameter, so two requests sent before the first reply lands leave every
//!   reply after them decrypting against the wrong sequence — silently, as unpadding noise.
//!   Anything asked for while one is out waits in `queue`.
//! - **A command reads back rather than assuming.** `set_device_info` answers `{"error_code":
//!   0}` and nothing else, so the state Juno reports comes from a `get_device_info` that
//!   follows it, not from what was asked for. It costs one LAN round trip and it is right
//!   even when the switch clamps or refuses what was sent.
//!
//! # Nothing is pushed, so the poll is not optional
//!
//! A Tapo has no local subscription and sends nothing unsolicited: turn it up at the wall and
//! it tells nobody. `Poll interval` is what makes the house eventually agree with the switch,
//! and it is also what recovers a stalled exchange — a reply that never came leaves `phase`
//! where it was, and the next bind resets it.

mod http;
mod klap;

use driver_sdk::Value;
use driver_sdk::*;

#[derive(Default)]
pub struct Tapo;

const LIGHT: LocalId = 1;

/// Where the exchange stands: `""` no session, `hs1`/`hs2` mid-handshake, `ready` usable.
const PHASE: &str = "phase";
/// Bytes of a reply that have arrived but do not yet make a whole one.
const BUFFER: &str = "buffer";
const LOCAL_SEED: &str = "local_seed";
const COOKIE: &str = "cookie";
const KEY: &str = "key";
const IV: &str = "iv";
const SIG: &str = "sig";
const SEQ: &str = "seq";
/// Requests waiting for the session, in order.
const QUEUE: &str = "queue";
/// Whether a request is out. See the module doc — the sequence number is why.
const INFLIGHT: &str = "inflight";
/// The request that is out, so a session the switch has forgotten can be retried rather than
/// lost. A dropped `off` is a light left on.
const LAST: &str = "last";
/// Last brightness and power the switch reported, for `toggle` and for not re-notifying.
const LEVEL: &str = "level";
const ON: &str = "on";
/// A `toggle` that arrived before anything knew which way to go. Cleared by the read it is
/// waiting for.
const AFTER_READ: &str = "after_read";

const GET: &str = r#"{"method":"get_device_info","requestTimeMils":0}"#;

export_driver!(Tapo);

impl DriverModule for Tapo {
    /// Ask where it stands — at adoption, at every reconnect, and at every poll.
    ///
    /// Also the reset: half an exchange that never finished is cleared here rather than left
    /// to wedge the queue, which is the only recovery a driver with no clock has.
    fn on_bind(&self, inst: &mut Instance) -> Vec<HostCall> {
        inst.scratch.remove(BUFFER);
        inst.scratch.remove(INFLIGHT);
        inst.scratch.remove(AFTER_READ);
        // Deliberately dropped rather than carried over. A poll is up to fifteen minutes after
        // the command that queued it, and a light that turns on by itself long after somebody
        // gave up on the switch is worse than one that did nothing.
        inst.scratch.remove(QUEUE);
        // The session is kept: it may well still be good, and if the switch has forgotten it
        // the reply says so and the handshake happens then.
        if matches!(Self::phase(inst).as_str(), "hs1" | "hs2") {
            inst.scratch.remove(PHASE);
        }
        Self::request(inst, GET.into())
    }

    fn on_command(
        &self,
        inst: &mut Instance,
        _proxy: LocalId,
        cmd: &str,
        args: &Args,
    ) -> Vec<HostCall> {
        match cmd {
            "on" => Self::request(inst, Self::set(json!({ "device_on": true }))),
            "off" => Self::request(inst, Self::set(json!({ "device_on": false }))),

            "toggle" => match inst.scratch.get(ON).and_then(Value::as_bool) {
                Some(on) => Self::request(inst, Self::set(json!({ "device_on": !on }))),
                // Nothing has been read back yet — adopted seconds ago, or the switch was
                // unreachable at the last poll. Ask, and act on the answer.
                None => {
                    inst.scratch.insert(AFTER_READ.into(), json!("toggle"));
                    Self::request(inst, GET.into())
                }
            },

            "set_level" => {
                let Some(level) = args.get("level").and_then(Value::as_u64) else {
                    return vec![HostCall::warn("tapo: set_level needs a level")];
                };
                // Zero is off, and has to be said that way: the switch refuses `brightness: 0`
                // and would leave the light at whatever it was, reporting success.
                let params = if level == 0 {
                    json!({ "device_on": false })
                } else {
                    json!({ "device_on": true, "brightness": level.min(100) })
                };
                Self::request(inst, Self::set(params))
            }

            // Declared by the contract for any dimmer, and there is no local command for it:
            // the switch fades on its own schedule and has no "start going up until I say
            // stop". Held-button dimming has to be Juno stepping `set_level`, which is not
            // this driver's decision to make — so this says so rather than doing nothing.
            "ramp_start" | "ramp_stop" => vec![HostCall::warn(
                "tapo: this dimmer has no continuous ramp — use set_level",
            )],

            other => vec![HostCall::warn(format!("tapo: unhandled `{other}`"))],
        }
    }

    fn unsupported(&self) -> Vec<String> {
        vec!["ramp_start/ramp_stop — the hardware has no continuous ramp".into()]
    }

    /// Bytes arrived. There may be part of a reply, a whole one, or several.
    fn on_event(
        &self,
        inst: &mut Instance,
        _control: LocalId,
        note: &str,
        args: &Args,
    ) -> Vec<HostCall> {
        if note != "rx" {
            return Vec::new();
        }
        // `bytes` rather than `data` because this transport declares `binary` — a KLAP reply
        // read down the text path loses most of itself to a lossy UTF-8 decode.
        let Some(chunk) = args.get("bytes").and_then(Value::as_array) else {
            return Vec::new();
        };
        let Some(host) = Self::host(inst) else {
            return Vec::new();
        };

        let mut buffer = inst
            .scratch
            .get(BUFFER)
            .and_then(Value::as_str)
            .and_then(unhex)
            .unwrap_or_default();
        buffer.extend(chunk.iter().filter_map(|v| v.as_u64().map(|n| n as u8)));

        let mut out = Vec::new();
        while let Some((reply, used)) = http::parse(&buffer) {
            buffer.drain(..used);
            out.extend(Self::on_reply(inst, &host, reply));
        }
        // Whatever is half-received waits for the next read.
        inst.scratch.insert(BUFFER.into(), json!(hex(&buffer)));
        out
    }

    fn discover(&self, _driver_id: &str, state: &Value, input: &Args) -> (SetupStep, Value) {
        self.flow(state, input)
    }

    fn setup(&self, _driver_id: &str, state: &Value, input: &Args) -> (SetupStep, Value) {
        self.flow(state, input)
    }
}

// ---------------------------------------------------------------------------------------
// Talking to the switch
// ---------------------------------------------------------------------------------------

impl Tapo {
    fn host(inst: &Instance) -> Option<String> {
        let addr = inst.property("Address").as_str()?.trim().to_string();
        (!addr.is_empty()).then_some(addr)
    }

    fn auth(inst: &Instance) -> Option<[u8; 32]> {
        let email = inst.property("Email").as_str()?.trim();
        let password = inst.property("Password").as_str()?;
        (!email.is_empty() && !password.is_empty()).then(|| klap::auth_hash(email, password))
    }

    fn set(params: Value) -> String {
        json!({ "method": "set_device_info", "params": params, "requestTimeMils": 0 }).to_string()
    }

    /// Put one request on the wire, or hold it until there is a session to put it on.
    fn request(inst: &mut Instance, body: String) -> Vec<HostCall> {
        let Some(host) = Self::host(inst) else {
            return vec![HostCall::warn("tapo: set the Address on this dimmer first")];
        };
        if Self::auth(inst).is_none() {
            return vec![HostCall::warn(
                "tapo: set the Email and Password on this dimmer first — local control is \
                 checked against the TP-Link account it was set up with",
            )];
        }
        let phase = Self::phase(inst);
        let busy = inst.scratch.get(INFLIGHT).and_then(Value::as_bool) == Some(true);
        if phase != "ready" || busy {
            Self::push(inst, body);
            // No session and nothing on its way to getting one: this is the request that
            // starts the handshake. Mid-handshake, the queue is enough.
            return if phase.is_empty() {
                Self::handshake(inst, &host)
            } else {
                Vec::new()
            };
        }
        Self::wire(inst, &host, body)
    }

    /// Encrypt and send. The session is re-read from scratch each time because a reply may
    /// have replaced it since the last one.
    fn wire(inst: &mut Instance, host: &str, body: String) -> Vec<HostCall> {
        let Some(mut session) = Self::session(inst) else {
            // `ready` without a session is not a state that should happen; treating it as "no
            // session" rather than dropping the request is the recovery.
            Self::push(inst, body);
            return Self::handshake(inst, host);
        };
        let (seq, framed) = session.encrypt(body.as_bytes());
        Self::save_session(inst, &session);
        inst.scratch.insert(INFLIGHT.into(), json!(true));
        inst.scratch.insert(LAST.into(), json!(body));
        let cookie = inst.scratch.get(COOKIE).and_then(Value::as_str).map(str::to_string);
        vec![HostCall::Tx {
            control: 0,
            data: http::post(
                &format!("/app/request?seq={seq}"),
                host,
                cookie.as_deref(),
                &framed,
            ),
        }]
    }

    fn handshake(inst: &mut Instance, host: &str) -> Vec<HostCall> {
        let seed = klap::local_seed();
        inst.scratch.insert(LOCAL_SEED.into(), json!(hex(&seed)));
        inst.scratch.insert(PHASE.into(), json!("hs1"));
        inst.scratch.insert(INFLIGHT.into(), json!(true));
        inst.scratch.remove(COOKIE);
        vec![HostCall::Tx {
            control: 0,
            data: http::post("/app/handshake1", host, None, &seed),
        }]
    }

    /// One whole reply, read according to what was expected.
    fn on_reply(inst: &mut Instance, host: &str, reply: http::Reply) -> Vec<HostCall> {
        match Self::phase(inst).as_str() {
            "hs1" => Self::on_handshake1(inst, host, reply),
            "hs2" => Self::on_handshake2(inst, host, reply),
            "ready" => Self::on_result(inst, host, reply),
            // A reply to a request from before a reset. Nothing to do with it.
            _ => Vec::new(),
        }
    }

    fn on_handshake1(inst: &mut Instance, host: &str, reply: http::Reply) -> Vec<HostCall> {
        inst.scratch.insert(INFLIGHT.into(), json!(false));
        let (Some(seed), Some(auth)) = (
            inst.scratch.get(LOCAL_SEED).and_then(Value::as_str).and_then(unhex),
            Self::auth(inst),
        ) else {
            return Self::give_up(inst, "tapo: no local seed to check the handshake against");
        };
        let Ok(seed) = <[u8; 16]>::try_from(seed) else {
            return Self::give_up(inst, "tapo: the stored local seed is the wrong size");
        };
        if reply.status != 200 {
            return Self::give_up(inst, format!("tapo: the dimmer refused the handshake ({})", reply.status));
        }
        let Some(remote) = klap::accept_handshake1(&seed, &auth, &reply.body) else {
            // The device computed its half from the credentials it was set up with and got a
            // different answer. Nothing about retrying helps.
            return Self::give_up(
                inst,
                "tapo: the dimmer did not accept this TP-Link account — check the Email and \
                 Password, which are the account's, not the Wi-Fi's",
            );
        };
        if let Some(id) = reply.session {
            inst.scratch.insert(COOKIE.into(), json!(id));
        }
        Self::save_session(inst, &klap::Session::derive(&seed, &remote, &auth));
        inst.scratch.insert(PHASE.into(), json!("hs2"));
        inst.scratch.insert(INFLIGHT.into(), json!(true));
        let cookie = inst.scratch.get(COOKIE).and_then(Value::as_str).map(str::to_string);
        vec![HostCall::Tx {
            control: 0,
            data: http::post(
                "/app/handshake2",
                host,
                cookie.as_deref(),
                &klap::handshake2(&seed, &remote, &auth),
            ),
        }]
    }

    fn on_handshake2(inst: &mut Instance, host: &str, reply: http::Reply) -> Vec<HostCall> {
        inst.scratch.insert(INFLIGHT.into(), json!(false));
        if reply.status != 200 {
            return Self::give_up(
                inst,
                format!("tapo: the dimmer rejected the login ({})", reply.status),
            );
        }
        inst.scratch.insert(PHASE.into(), json!("ready"));
        Self::flush(inst, host)
    }

    fn on_result(inst: &mut Instance, host: &str, reply: http::Reply) -> Vec<HostCall> {
        inst.scratch.insert(INFLIGHT.into(), json!(false));
        let sent = inst.scratch.get(LAST).and_then(Value::as_str).unwrap_or("").to_string();

        // 403 is what a Tapo says when it has forgotten the session — a reboot, or a long
        // enough silence. Handshake again and send the same thing, rather than losing it.
        if reply.status != 200 {
            Self::clear_session(inst);
            if !sent.is_empty() {
                Self::push(inst, sent);
            }
            return Self::handshake(inst, host);
        }

        let Some(session) = Self::session(inst) else {
            return Self::give_up(inst, "tapo: a reply arrived with no session to open it");
        };
        // The JSON parse is the integrity check, not the decryption — see `klap::Session::
        // decrypt`. A reply matched to the wrong sequence unpads happily and comes back as
        // noise, so this is where a session that has slipped out of step is actually caught,
        // and every reply after it would slip too. Start over rather than retry.
        let message = session
            .decrypt(session.seq, &reply.body)
            .and_then(|plain| serde_json::from_slice::<Value>(&plain).ok());
        let Some(message) = message else {
            Self::clear_session(inst);
            if !sent.is_empty() {
                Self::push(inst, sent);
            }
            let mut out = vec![HostCall::warn("tapo: could not read the reply; reconnecting")];
            out.extend(Self::handshake(inst, host));
            return out;
        };

        let mut out = Vec::new();
        match message.get("error_code").and_then(Value::as_i64).unwrap_or(0) {
            0 => out.extend(Self::apply(inst, &message, &sent)),
            // The session expired between the handshake and now. Same recovery as a 403.
            9999 => {
                Self::clear_session(inst);
                if !sent.is_empty() {
                    Self::push(inst, sent);
                }
                out.extend(Self::handshake(inst, host));
                return out;
            }
            code => out.push(HostCall::warn(format!("tapo: the dimmer refused that ({code})"))),
        }
        out.extend(Self::flush(inst, host));
        out
    }

    /// What a `get_device_info` said, turned into notifications — or, for the bare
    /// acknowledgement a `set_device_info` gives, a read-back queued behind it.
    fn apply(inst: &mut Instance, message: &Value, sent: &str) -> Vec<HostCall> {
        let result = message.get("result");
        let on = result.and_then(|r| r.get("device_on")).and_then(Value::as_bool);
        let level = result
            .and_then(|r| r.get("brightness"))
            .and_then(Value::as_u64)
            .map(|b| b.min(100));

        let Some(on) = on else {
            // A write's acknowledgement carries no state. Ask, rather than assume the switch
            // did exactly what it was told — see the module doc.
            if sent.contains("set_device_info") {
                Self::push(inst, GET.into());
            }
            return Vec::new();
        };

        let mut out = Vec::new();
        let mut online = Args::new();
        online.insert("online".into(), json!(true));
        // ponytail: only ever `true`. A driver has no clock and no timeout, so "stopped
        // answering" is not something this can see — core's own reachability is what reports
        // that. Say so when it plainly is reachable, and leave the other half alone.
        out.push(HostCall::notify(LIGHT, "online_changed", online));

        // Both, because this hardware genuinely keeps them apart: a Tapo remembers the
        // brightness it will return to while it is off, so "brightness 40, off" is a real
        // state and core's derivation of `on` from `level` cannot express it. Sending
        // `power_changed` is what tells core to stop deriving it — see the light contract.
        if inst.scratch.get(ON).and_then(Value::as_bool) != Some(on) {
            let mut a = Args::new();
            a.insert("on".into(), json!(on));
            out.push(HostCall::notify(LIGHT, "power_changed", a));
        }
        if let Some(level) = level
            && inst.scratch.get(LEVEL).and_then(Value::as_u64) != Some(level)
        {
            let mut a = Args::new();
            a.insert("level".into(), json!(level));
            out.push(HostCall::notify(LIGHT, "level_changed", a));
            inst.scratch.insert(LEVEL.into(), json!(level));
        }
        inst.scratch.insert(ON.into(), json!(on));

        // A `toggle` that had nothing to go on when it arrived. Now it does.
        if inst.scratch.remove(AFTER_READ).and_then(|v| v.as_str().map(str::to_string))
            == Some("toggle".into())
        {
            Self::push(inst, Self::set(json!({ "device_on": !on })));
        }
        out
    }

    /// Send the next queued request, if the session is idle.
    fn flush(inst: &mut Instance, host: &str) -> Vec<HostCall> {
        if Self::phase(inst) != "ready"
            || inst.scratch.get(INFLIGHT).and_then(Value::as_bool) == Some(true)
        {
            return Vec::new();
        }
        match Self::pop(inst) {
            Some(body) => Self::wire(inst, host, body),
            None => Vec::new(),
        }
    }

    /// Stop, say why, and leave nothing half-open. The next poll starts clean.
    fn give_up(inst: &mut Instance, why: impl Into<String>) -> Vec<HostCall> {
        Self::clear_session(inst);
        inst.scratch.remove(QUEUE);
        vec![HostCall::warn(why)]
    }

    // -- scratch -----------------------------------------------------------------------

    fn phase(inst: &Instance) -> String {
        inst.scratch.get(PHASE).and_then(Value::as_str).unwrap_or("").to_string()
    }

    fn push(inst: &mut Instance, body: String) {
        let mut queue = inst
            .scratch
            .get(QUEUE)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        // A poll behind a command behind a poll is three round trips to say one thing. The
        // same request twice in the queue is the same answer twice.
        if !queue.iter().any(|v| v.as_str() == Some(body.as_str())) {
            queue.push(json!(body));
        }
        inst.scratch.insert(QUEUE.into(), json!(queue));
    }

    fn pop(inst: &mut Instance) -> Option<String> {
        let mut queue = inst.scratch.get(QUEUE).and_then(Value::as_array).cloned()?;
        if queue.is_empty() {
            return None;
        }
        let head = queue.remove(0);
        inst.scratch.insert(QUEUE.into(), json!(queue));
        head.as_str().map(str::to_string)
    }

    fn session(inst: &Instance) -> Option<klap::Session> {
        let get = |k: &str| inst.scratch.get(k).and_then(Value::as_str).and_then(unhex);
        Some(klap::Session::restore(
            get(KEY)?.try_into().ok()?,
            get(IV)?.try_into().ok()?,
            get(SIG)?.try_into().ok()?,
            inst.scratch.get(SEQ).and_then(Value::as_i64)? as i32,
        ))
    }

    fn save_session(inst: &mut Instance, session: &klap::Session) {
        let (key, iv, sig) = session.parts();
        inst.scratch.insert(KEY.into(), json!(hex(&key)));
        inst.scratch.insert(IV.into(), json!(hex(&iv)));
        inst.scratch.insert(SIG.into(), json!(hex(&sig)));
        inst.scratch.insert(SEQ.into(), json!(session.seq));
    }

    fn clear_session(inst: &mut Instance) {
        for key in [PHASE, KEY, IV, SIG, SEQ, COOKIE, LOCAL_SEED, BUFFER, LAST] {
            inst.scratch.remove(key);
        }
        inst.scratch.insert(INFLIGHT.into(), json!(false));
    }
}

// ---------------------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------------------

impl Tapo {
    /// The same flow whether it was reached from a survey or from Add device.
    ///
    /// It ends by actually logging in, not by confirming the address answers: the one thing
    /// that goes wrong here is the TP-Link account, and a dimmer adopted with the wrong
    /// password looks identical to a working one until somebody presses a button.
    fn flow(&self, state: &Value, input: &Args) -> (SetupStep, Value) {
        // Carried here rather than in each arm that opens a step: an arm may also need to
        // *listen again* on the same connection, and the id for it arrives in `input` on the
        // entry before that one. Reading it once at the top is what makes every arm's `state`
        // enough on its own.
        let state = &Self::keep_session(state.clone(), input);
        let phase = state.get("phase").and_then(Value::as_str).unwrap_or("start");
        // Empty is absent. A form prefilled with an address nobody had yet writes `""` into the
        // state, and a lookup that took it would shadow what the person then typed.
        let s = |key: &str| {
            let text = |v: Option<&Value>| {
                v.and_then(Value::as_str).map(str::to_string).filter(|t| !t.is_empty())
            };
            text(state.get(key)).or_else(|| text(input.get(key)))
        };

        match phase {
            "start" => {
                // What the survey already found, if this was reached by pressing Add on a row.
                let found: Vec<String> = state
                    .get("ssdp_candidates")
                    .and_then(Value::as_array)
                    .map(|rows| {
                        rows.iter()
                            .filter_map(|r| r.get("address").and_then(Value::as_str))
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let chosen = s("chosen_address").or_else(|| {
                    // One find is not a choice worth putting in front of anybody.
                    (found.len() == 1).then(|| found[0].clone())
                });

                match chosen {
                    Some(address) => Self::ask_credentials(&address),
                    None if found.len() > 1 => (
                        SetupStep::Pick {
                            title: "Which dimmer?".into(),
                            body: "These answered a Tapo handshake on this network.".into(),
                            columns: vec!["Address".into()],
                            rows: found
                                .iter()
                                .map(|a| PickRow {
                                    value: a.clone(),
                                    cells: vec![a.clone()],
                                    note: String::new(),
                                })
                                .collect(),
                            field: "address".into(),
                            manual: Some(Field {
                                name: "address".into(),
                                label: "Address".into(),
                                kind: "string".into(),
                                help: "if the dimmer is not listed".into(),
                                default: None,
                                options: Vec::new(),
                                required: true,
                            }),
                        },
                        json!({ "phase": "picked" }),
                    ),
                    // Nothing found, which is ordinary: a survey only sweeps the controller's
                    // own /24, and plenty of houses put lighting on another one.
                    None => Self::ask_credentials(""),
                }
            }

            "picked" => match s("address") {
                Some(address) => Self::ask_credentials(&address),
                None => Self::ask_credentials(""),
            },

            // Address and account in hand. Prove them.
            "credentials" => {
                let (Some(address), Some(email), Some(password)) =
                    (s("address"), s("email"), s("password"))
                else {
                    return Self::ask_credentials(&s("address").unwrap_or_default());
                };
                let address = address.trim().to_string();
                if address.is_empty() {
                    return Self::ask_credentials("");
                }
                let seed = klap::local_seed();
                (
                    SetupStep::Session {
                        session: None,
                        open: Some(Connect {
                            host: address.clone(),
                            port: 80,
                            tls: false,
                            client_cert: None,
                            client_key: None,
                        }),
                        accept: None,
                        send: String::new(),
                        send_bytes: http::post("/app/handshake1", &address, None, &seed),
                        read_ms: 3000,
                        close: false,
                        note: "saying hello to the dimmer".into(),
                    },
                    json!({
                        "phase": "hs1", "address": address, "email": email,
                        "password": password, "local_seed": hex(&seed), "buffer": "",
                    }),
                )
            }

            "hs1" => {
                let mut next = state.clone();
                let Some(reply) = Self::heard(&mut next, input) else {
                    return Self::listen_again(next, "hs1", "waiting for the dimmer");
                };
                let (Some(seed), Some(email), Some(password)) =
                    (s("local_seed").and_then(|h| unhex(&h)), s("email"), s("password"))
                else {
                    return (SetupStep::Failed { reason: "lost the handshake state".into() }, Value::Null);
                };
                let Ok(seed) = <[u8; 16]>::try_from(seed) else {
                    return (SetupStep::Failed { reason: "lost the handshake state".into() }, Value::Null);
                };
                if reply.status != 200 {
                    return (
                        SetupStep::Failed {
                            reason: format!(
                                "{} answered {} to a Tapo handshake. Check the address — it is \
                                 under Device Info in the Tapo app.",
                                s("address").unwrap_or_default(),
                                reply.status
                            ),
                        },
                        Value::Null,
                    );
                }
                let auth = klap::auth_hash(email.trim(), &password);
                let Some(remote) = klap::accept_handshake1(&seed, &auth, &reply.body) else {
                    return (
                        SetupStep::Failed {
                            reason: "The dimmer did not accept that TP-Link account. It wants \
                                     the email and password you sign in to the Tapo app with — \
                                     the same account the dimmer is paired to."
                                .into(),
                        },
                        Value::Null,
                    );
                };
                next["phase"] = json!("hs2");
                next["remote_seed"] = json!(hex(&remote));
                next["cookie"] = json!(reply.session.unwrap_or_default());
                next["tries"] = json!(0);
                let address = s("address").unwrap_or_default();
                let cookie = next["cookie"].as_str().unwrap_or("").to_string();
                (
                    SetupStep::Session {
                        session: state.get("session").and_then(Value::as_u64).map(|s| s as u32),
                        open: None,
                        accept: None,
                        send: String::new(),
                        send_bytes: http::post(
                            "/app/handshake2",
                            &address,
                            (!cookie.is_empty()).then_some(cookie.as_str()),
                            &klap::handshake2(&seed, &remote, &auth),
                        ),
                        read_ms: 3000,
                        close: false,
                        note: "signing in".into(),
                    },
                    next,
                )
            }

            "hs2" => {
                let mut next = state.clone();
                let Some(reply) = Self::heard(&mut next, input) else {
                    return Self::listen_again(next, "hs2", "signing in");
                };
                if reply.status != 200 {
                    return (
                        SetupStep::Failed {
                            reason: format!("The dimmer rejected the login ({}).", reply.status),
                        },
                        Value::Null,
                    );
                }
                let (Some(local), Some(remote), Some(email), Some(password)) = (
                    s("local_seed").and_then(|h| unhex(&h)),
                    s("remote_seed").and_then(|h| unhex(&h)),
                    s("email"),
                    s("password"),
                ) else {
                    return (SetupStep::Failed { reason: "lost the handshake state".into() }, Value::Null);
                };
                let (Ok(local), Ok(remote)) =
                    (<[u8; 16]>::try_from(local), <[u8; 16]>::try_from(remote))
                else {
                    return (SetupStep::Failed { reason: "lost the handshake state".into() }, Value::Null);
                };
                let auth = klap::auth_hash(email.trim(), &password);
                let mut session = klap::Session::derive(&local, &remote, &auth);
                let (seq, framed) = session.encrypt(GET.as_bytes());
                let (key, iv, sig) = session.parts();
                next["phase"] = json!("info");
                next["key"] = json!(hex(&key));
                next["iv"] = json!(hex(&iv));
                next["sig"] = json!(hex(&sig));
                next["seq"] = json!(seq);
                next["tries"] = json!(0);
                let cookie = s("cookie").unwrap_or_default();
                (
                    SetupStep::Session {
                        session: state.get("session").and_then(Value::as_u64).map(|s| s as u32),
                        open: None,
                        accept: None,
                        send: String::new(),
                        send_bytes: http::post(
                            &format!("/app/request?seq={seq}"),
                            &s("address").unwrap_or_default(),
                            (!cookie.is_empty()).then_some(cookie.as_str()),
                            &framed,
                        ),
                        read_ms: 3000,
                        close: true,
                        note: "asking the dimmer what it is".into(),
                    },
                    next,
                )
            }

            "info" => {
                let mut next = state.clone();
                let Some(reply) = Self::heard(&mut next, input) else {
                    return Self::listen_again(next, "info", "asking the dimmer what it is");
                };
                let address = s("address").unwrap_or_default();
                let (Some(key), Some(iv), Some(sig), Some(seq)) = (
                    s("key").and_then(|h| unhex(&h)),
                    s("iv").and_then(|h| unhex(&h)),
                    s("sig").and_then(|h| unhex(&h)),
                    state.get("seq").and_then(Value::as_i64),
                ) else {
                    return (SetupStep::Failed { reason: "lost the session state".into() }, Value::Null);
                };
                let (Ok(key), Ok(iv), Ok(sig)) = (
                    <[u8; 16]>::try_from(key),
                    <[u8; 12]>::try_from(iv),
                    <[u8; 28]>::try_from(sig),
                ) else {
                    return (SetupStep::Failed { reason: "lost the session state".into() }, Value::Null);
                };
                let session = klap::Session::restore(key, iv, sig, seq as i32);
                let info = session
                    .decrypt(seq as i32, &reply.body)
                    .and_then(|plain| serde_json::from_slice::<Value>(&plain).ok())
                    .unwrap_or(Value::Null);
                let result = info.get("result").cloned().unwrap_or(Value::Null);

                // The name somebody gave it in the Tapo app, which is the only thing that
                // tells eight identical dimmers apart. Base64 in the reply, always.
                let nickname = result
                    .get("nickname")
                    .and_then(Value::as_str)
                    .and_then(from_base64)
                    .filter(|n| !n.trim().is_empty());
                let model = result
                    .get("model")
                    .and_then(Value::as_str)
                    .unwrap_or("Tapo dimmer")
                    .to_string();

                let mut properties = std::collections::BTreeMap::new();
                properties.insert("Address".into(), json!(address));
                properties.insert("Email".into(), json!(s("email").unwrap_or_default()));
                properties.insert("Password".into(), json!(s("password").unwrap_or_default()));

                (
                    SetupStep::done(vec![Candidate {
                        label: nickname.clone().unwrap_or_else(|| format!("{model} at {address}")),
                        driver_id: "tapo.dimmer".into(),
                        properties,
                        verified: match result.get("device_on").and_then(Value::as_bool) {
                            Some(true) => format!("{model}, on"),
                            Some(false) => format!("{model}, off"),
                            // The login worked — that is what was being proved — even if the
                            // reply after it was not readable.
                            None => format!("{model}, signed in"),
                        },
                        ..Default::default()
                    }]),
                    Value::Null,
                )
            }

            other => (
                SetupStep::Failed { reason: format!("unknown setup phase `{other}`") },
                Value::Null,
            ),
        }
    }

    fn ask_credentials(address: &str) -> (SetupStep, Value) {
        (
            SetupStep::Form {
                title: "Sign in to the dimmer".into(),
                body: "Tapo checks local control against the TP-Link account the switch is \
                       paired to. This is that account — the one you sign in to the Tapo app \
                       with — and it is checked here rather than taken on trust."
                    .into(),
                fields: vec![
                    Field {
                        name: "address".into(),
                        label: "Address".into(),
                        kind: "string".into(),
                        help: "Tapo app → the dimmer → Settings → Device Info".into(),
                        default: (!address.is_empty()).then(|| json!(address)),
                        options: Vec::new(),
                        required: true,
                    },
                    Field {
                        name: "email".into(),
                        label: "Email".into(),
                        kind: "string".into(),
                        help: "the TP-Link account".into(),
                        default: None,
                        options: Vec::new(),
                        required: true,
                    },
                    Field {
                        name: "password".into(),
                        label: "Password".into(),
                        kind: "password".into(),
                        help: "that account's password".into(),
                        default: None,
                        options: Vec::new(),
                        required: true,
                    },
                ],
            },
            json!({ "phase": "credentials", "address": address }),
        )
    }

    /// The reply built out of however many reads it took.
    ///
    /// Core returns whatever arrived in the window, which for a 48-byte handshake is normally
    /// all of it and occasionally is not. The tail is kept in the flow state, exactly as the
    /// runtime path keeps it in scratch.
    fn heard(state: &mut Value, input: &Args) -> Option<http::Reply> {
        let mut buffer = state
            .get("buffer")
            .and_then(Value::as_str)
            .and_then(unhex)
            .unwrap_or_default();
        buffer.extend(
            input
                .get("received_bytes")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect::<Vec<u8>>())
                .unwrap_or_default(),
        );
        match http::parse(&buffer) {
            Some((reply, used)) => {
                state["buffer"] = json!(hex(&buffer[used..]));
                Some(reply)
            }
            None => {
                state["buffer"] = json!(hex(&buffer));
                None
            }
        }
    }

    /// Listen again on the same connection, sending nothing.
    fn listen_again(mut state: Value, phase: &str, note: &str) -> (SetupStep, Value) {
        let tries = state.get("tries").and_then(Value::as_u64).unwrap_or(0);
        if tries >= 4 {
            return (
                SetupStep::Failed {
                    reason: "The dimmer stopped part-way through answering. Try again — if it \
                             keeps happening, something else on the network is holding its one \
                             connection."
                        .into(),
                },
                Value::Null,
            );
        }
        state["tries"] = json!(tries + 1);
        state["phase"] = json!(phase);
        let session = state.get("session").and_then(Value::as_u64).map(|s| s as u32);
        (
            SetupStep::Session {
                session,
                open: None,
                accept: None,
                send: String::new(),
                send_bytes: Vec::new(),
                read_ms: 2000,
                close: false,
                note: note.into(),
            },
            state,
        )
    }

    /// Carry the open connection's id into the next step.
    fn keep_session(mut state: Value, input: &Args) -> Value {
        if let Some(id) = input.get("session") {
            state["session"] = id.clone();
        }
        state
    }
}

// ---------------------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Tapo sends every human-set name base64-encoded. Sixteen lines rather than a dependency,
/// because this is the only thing in the driver that needs it.
fn from_base64(s: &str) -> Option<String> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in s.bytes().filter(|c| *c != b'=') {
        acc = (acc << 6) | u32::from(value(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMAIL: &str = "someone@example.com";
    const PASSWORD: &str = "hunter2";

    fn dimmer() -> Instance {
        let mut inst = Instance::default();
        inst.properties.insert("Address".into(), json!("10.0.0.4"));
        inst.properties.insert("Email".into(), json!(EMAIL));
        inst.properties.insert("Password".into(), json!(PASSWORD));
        inst
    }

    /// The body of the one request the driver just made, and the path it went to.
    fn sent(calls: &[HostCall]) -> (String, Vec<u8>) {
        let data = calls
            .iter()
            .find_map(|c| match c {
                HostCall::Tx { data, .. } => Some(data.clone()),
                _ => None,
            })
            .expect("a request");
        let end = data.windows(4).position(|w| w == b"\r\n\r\n").expect("headers") + 4;
        let head = String::from_utf8_lossy(&data[..end]).to_string();
        let path = head.split_whitespace().nth(1).expect("a path").to_string();
        (path, data[end..].to_vec())
    }

    /// What core delivers when bytes come back.
    fn rx(bytes: &[u8]) -> Args {
        let mut args = Args::new();
        args.insert("bytes".into(), json!(bytes));
        args
    }

    fn reply(body: &[u8], cookie: bool) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 200 OK\r\n{}Content-Length: {}\r\n\r\n",
            if cookie { "Set-Cookie: TP_SESSIONID=SID;TIMEOUT=1440\r\n" } else { "" },
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// The switch's answer to the request at `seq` — encrypted the same way, at the same
    /// sequence, which is what the device does. `encrypt` always advances, so it is wound back
    /// one first rather than given a second entry point that only a test would use.
    fn answer(device: &mut klap::Session, seq: i32, plain: &[u8]) -> Vec<u8> {
        device.seq = seq - 1;
        let (used, body) = device.encrypt(plain);
        assert_eq!(used, seq);
        body
    }

    fn notified(calls: &[HostCall], name: &str) -> Option<Args> {
        calls.iter().find_map(|c| match c {
            HostCall::Notify { name: n, args, .. } if n == name => Some(args.clone()),
            _ => None,
        })
    }

    /// The whole exchange, with the test playing the switch: handshake, the read the bind
    /// asked for, a command, and the read-back that command triggers.
    ///
    /// It is one test rather than four because the states only mean anything in sequence —
    /// the sequence number, the queue and the phase are all carried between them, and every
    /// bug this has found so far was a step being right on its own and wrong after the last
    /// one.
    #[test]
    fn a_bind_a_command_and_a_read_back() {
        let tapo = Tapo;
        let mut inst = dimmer();
        let auth = klap::auth_hash(EMAIL, PASSWORD);

        // -- bind: nothing is known, so this has to start with a handshake ------------------
        let calls = tapo.on_bind(&mut inst);
        let (path, body) = sent(&calls);
        assert_eq!(path, "/app/handshake1");
        let local: [u8; 16] = body.try_into().expect("a 16-byte seed");

        // The switch answers with its own seed and proof it holds the account.
        let remote = [3u8; 16];
        let mut hs1 = remote.to_vec();
        hs1.extend_from_slice(&{
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(local);
            h.update(remote);
            h.update(auth);
            h.finalize()
        });
        let calls = tapo.on_event(&mut inst, 0, "rx", &rx(&reply(&hs1, true)));
        let (path, body) = sent(&calls);
        assert_eq!(path, "/app/handshake2");
        assert_eq!(body, klap::handshake2(&local, &remote, &auth));

        // -- the session is up, so the bind's own question goes out ------------------------
        let mut device = klap::Session::derive(&local, &remote, &auth);
        let mut seq = device.seq + 1;
        let calls = tapo.on_event(&mut inst, 0, "rx", &rx(&reply(b"", false)));
        let (path, body) = sent(&calls);
        assert_eq!(path, format!("/app/request?seq={seq}"));
        assert_eq!(
            device.decrypt(seq, &body).as_deref(),
            Some(GET.as_bytes()),
            "the bind asks where it stands"
        );

        // 40% and on. Both are reported, because a Tapo keeps power and brightness apart.
        let info = br#"{"error_code":0,"result":{"device_on":true,"brightness":40}}"#;
        let framed = answer(&mut device, seq, info);
        let calls = tapo.on_event(&mut inst, 0, "rx", &rx(&reply(&framed, false)));
        assert_eq!(notified(&calls, "power_changed").unwrap().get("on"), Some(&json!(true)));
        assert_eq!(notified(&calls, "level_changed").unwrap().get("level"), Some(&json!(40)));

        // -- a command, and the read-back it is required to do afterwards ------------------
        let mut args = Args::new();
        args.insert("level".into(), json!(0));
        let calls = tapo.on_command(&mut inst, LIGHT, "set_level", &args);
        let (_, body) = sent(&calls);
        seq += 1;
        let plain = device.decrypt(seq, &body).expect("the command");
        // Zero is off, not brightness zero — the switch refuses that and would report success.
        let plain: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(plain["params"], json!({ "device_on": false }));

        // A write is acknowledged with nothing to read, so the driver asks again rather than
        // reporting what it hoped for.
        let framed = answer(&mut device, seq, br#"{"error_code":0}"#);
        let calls = tapo.on_event(&mut inst, 0, "rx", &rx(&reply(&framed, false)));
        assert!(notified(&calls, "power_changed").is_none(), "nothing was read back yet");
        let (path, body) = sent(&calls);
        seq += 1;
        assert_eq!(path, format!("/app/request?seq={seq}"));
        assert_eq!(device.decrypt(seq, &body).as_deref(), Some(GET.as_bytes()));

        let framed = answer(
            &mut device,
            seq,
            br#"{"error_code":0,"result":{"device_on":false,"brightness":40}}"#,
        );
        let calls = tapo.on_event(&mut inst, 0, "rx", &rx(&reply(&framed, false)));
        assert_eq!(notified(&calls, "power_changed").unwrap().get("on"), Some(&json!(false)));
        // The brightness did not move, so nothing claims it did.
        assert!(notified(&calls, "level_changed").is_none());
    }

    /// Setup end to end, with the test playing the switch again: credentials in, a name out.
    ///
    /// Worth its own test because setup speaks the same protocol over a different mechanism —
    /// `SetupStep::Session` rather than `HostCall::Tx` — and the state it carries between steps
    /// is a flow value rather than scratch. Nothing is shared but `klap` and `http`, so the two
    /// halves can be wrong independently.
    #[test]
    fn setup_signs_in_and_names_the_dimmer() {
        let tapo = Tapo;
        let auth = klap::auth_hash(EMAIL, PASSWORD);

        // The form comes back with what somebody typed.
        let mut input = Args::new();
        input.insert("address".into(), json!("10.0.0.4"));
        input.insert("email".into(), json!(EMAIL));
        input.insert("password".into(), json!(PASSWORD));
        let (step, state) = tapo.setup("tapo.dimmer", &json!({ "phase": "credentials" }), &input);
        let SetupStep::Session { send_bytes, open, .. } = step else {
            panic!("expected a connection, got {step:?}");
        };
        assert_eq!(open.expect("an address").host, "10.0.0.4");
        let local: [u8; 16] = send_bytes[send_bytes.len() - 16..].try_into().unwrap();

        // Core answers with the id of the connection it opened, and the switch's reply.
        let remote = [11u8; 16];
        let mut hs1 = remote.to_vec();
        hs1.extend_from_slice(&{
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(local);
            h.update(remote);
            h.update(auth);
            h.finalize()
        });
        let heard = |bytes: &[u8], session: u32| {
            let mut a = Args::new();
            a.insert("received_bytes".into(), json!(bytes));
            a.insert("session".into(), json!(session));
            a
        };
        let (step, state) = tapo.setup("tapo.dimmer", &state, &heard(&reply(&hs1, true), 7));
        let SetupStep::Session { send_bytes, session, .. } = step else {
            panic!("expected handshake2, got {step:?}");
        };
        // The connection core opened is the one being continued, not a second one.
        assert_eq!(session, Some(7));
        assert_eq!(send_bytes[send_bytes.len() - 32..], klap::handshake2(&local, &remote, &auth));

        // Signed in. Now it asks what it is talking to.
        let (step, state) = tapo.setup("tapo.dimmer", &state, &heard(&reply(b"", false), 7));
        let SetupStep::Session { send_bytes, .. } = step else {
            panic!("expected get_device_info, got {step:?}");
        };
        let mut device = klap::Session::derive(&local, &remote, &auth);
        let seq = device.seq + 1;
        let end = send_bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(device.decrypt(seq, &send_bytes[end..]).as_deref(), Some(GET.as_bytes()));

        // "Hall" in base64, which is how a Tapo sends every name a person set.
        let info = br#"{"error_code":0,"result":{"device_on":true,"brightness":60,"nickname":"SGFsbA==","model":"S500D"}}"#;
        let framed = answer(&mut device, seq, info);
        let (step, _) = tapo.setup("tapo.dimmer", &state, &heard(&reply(&framed, false), 7));
        let SetupStep::Done { devices, .. } = step else {
            panic!("expected a device, got {step:?}");
        };
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].label, "Hall");
        assert_eq!(devices[0].verified, "S500D, on");
        assert_eq!(devices[0].properties["Address"], json!("10.0.0.4"));
        assert_eq!(devices[0].properties["Password"], json!(PASSWORD));
    }

    /// A reply that arrives in pieces, which is what a 250 ms read window does to one.
    #[test]
    fn a_reply_split_across_reads_is_not_acted_on_early() {
        let tapo = Tapo;
        let mut inst = dimmer();
        let calls = tapo.on_bind(&mut inst);
        let (_, body) = sent(&calls);
        let local: [u8; 16] = body.try_into().unwrap();
        let auth = klap::auth_hash(EMAIL, PASSWORD);
        let remote = [5u8; 16];
        let mut hs1 = remote.to_vec();
        hs1.extend_from_slice(&{
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(local);
            h.update(remote);
            h.update(auth);
            h.finalize()
        });
        let whole = reply(&hs1, true);

        // Half a reply is not a reply. Nothing goes out, and nothing is lost.
        let calls = tapo.on_event(&mut inst, 0, "rx", &rx(&whole[..30]));
        assert!(calls.is_empty());
        let calls = tapo.on_event(&mut inst, 0, "rx", &rx(&whole[30..]));
        assert_eq!(sent(&calls).0, "/app/handshake2");
    }

    /// The password is the thing that goes wrong here, and it has to be said so.
    #[test]
    fn a_wrong_account_is_named_rather_than_retried() {
        let tapo = Tapo;
        let mut inst = dimmer();
        let calls = tapo.on_bind(&mut inst);
        let (_, body) = sent(&calls);
        let local: [u8; 16] = body.try_into().unwrap();

        // The switch computed its half from a different password.
        let other = klap::auth_hash(EMAIL, "not this one");
        let remote = [1u8; 16];
        let mut hs1 = remote.to_vec();
        hs1.extend_from_slice(&{
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(local);
            h.update(remote);
            h.update(other);
            h.finalize()
        });
        let calls = tapo.on_event(&mut inst, 0, "rx", &rx(&reply(&hs1, true)));
        let warned = calls.iter().any(|c| matches!(c, HostCall::Log { level, msg } if level == "warn" && msg.contains("TP-Link account")));
        assert!(warned, "got {calls:?}");
        // And it stops: no second handshake, and the queue is not left holding the question.
        assert!(!calls.iter().any(|c| matches!(c, HostCall::Tx { .. })));
    }
}

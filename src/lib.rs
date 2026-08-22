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
//! The crypto is in [`klap`], with its reasons written down there. What is left here is the
//! state machine, and it exists because of one thing:
//!
//! # Every exchange is several round trips, and a driver cannot wait
//!
//! A driver returns [`HostCall`]s and is called again when something arrives; it has no way to
//! block on a reply. So "turn this light on" is not one call — it is a handshake, a second
//! handshake, the command, and a read-back, each one landing in [`DriverModule::on_event`]
//! with the next step to take. That state lives in `inst.scratch`.
//!
//! Which reply is which is read off the **URL core echoes back**, not off a phase this driver
//! remembers. Core returns `url` and `method` beside every response for exactly this, and it
//! is the more honest of the two: a phase says what this driver last *expected*, and an answer
//! that arrives after a restart, out of order, or late says what actually happened.
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
//! and it is also what recovers a stalled exchange — a reply that never came leaves the queue
//! where it was, and the next bind resets it.

mod klap;

use driver_sdk::Value;
use driver_sdk::*;

#[derive(Default)]
pub struct Tapo;

const LIGHT: LocalId = 1;

/// The session is up and requests can go out.
const READY: &str = "ready";
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

const HANDSHAKE1: &str = "/app/handshake1";
const HANDSHAKE2: &str = "/app/handshake2";
const REQUEST: &str = "/app/request";

export_driver!(Tapo);

impl DriverModule for Tapo {
    /// Ask where it stands — at adoption, at every reconnect, and at every poll.
    ///
    /// Also the reset: half an exchange that never finished is cleared here rather than left
    /// to wedge the queue, which is the only recovery a driver with no clock has.
    fn on_bind(&self, inst: &mut Instance) -> Vec<HostCall> {
        inst.scratch.remove(INFLIGHT);
        inst.scratch.remove(AFTER_READ);
        // Deliberately dropped rather than carried over. A poll is up to fifteen minutes after
        // the command that queued it, and a light that turns on by itself long after somebody
        // gave up on the switch is worse than one that did nothing.
        inst.scratch.remove(QUEUE);
        // The session is kept: it may well still be good, and if the switch has forgotten it
        // the reply says so and the handshake happens then.
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

    /// A reply came back. Which one it answers is read off the URL core echoed with it.
    fn on_event(
        &self,
        inst: &mut Instance,
        _control: LocalId,
        note: &str,
        args: &Args,
    ) -> Vec<HostCall> {
        if note != "http_response" {
            return Vec::new();
        }
        let Some(host) = Self::host(inst) else {
            return Vec::new();
        };
        let url = args.get("url").and_then(Value::as_str).unwrap_or("").to_string();
        let status = args.get("status").and_then(Value::as_u64).unwrap_or(0) as u16;
        // `bytes` rather than `body` because the request declared itself binary — see
        // `HttpRequest::bytes`. A KLAP reply read down the text path loses most of itself to a
        // lossy UTF-8 decode.
        let body: Vec<u8> = args
            .get("bytes")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect())
            .unwrap_or_default();

        if url.contains(HANDSHAKE1) {
            Self::on_handshake1(inst, &host, status, &body, args)
        } else if url.contains(HANDSHAKE2) {
            Self::on_handshake2(inst, &host, status)
        } else if url.contains(REQUEST) {
            Self::on_result(inst, &host, status, &body)
        } else {
            Vec::new()
        }
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

    /// One POST, with the session cookie if there is one yet.
    fn post(host: &str, path: &str, cookie: Option<&str>, body: Vec<u8>) -> HostCall {
        let mut request = HttpRequest::new("POST", format!("http://{host}{path}")).bytes(body);
        if let Some(id) = cookie {
            request = request.header("cookie", format!("TP_SESSIONID={id}"));
        }
        HostCall::Http(request)
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
        let ready = inst.scratch.get(READY).and_then(Value::as_bool) == Some(true);
        let busy = inst.scratch.get(INFLIGHT).and_then(Value::as_bool) == Some(true);
        if !ready || busy {
            Self::push(inst, body);
            // No session and nothing on its way to getting one: this is the request that
            // starts the handshake. Mid-handshake, the queue is enough.
            return if !ready && !busy {
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
        vec![Self::post(
            host,
            &format!("{REQUEST}?seq={seq}"),
            cookie.as_deref(),
            framed,
        )]
    }

    fn handshake(inst: &mut Instance, host: &str) -> Vec<HostCall> {
        let seed = klap::local_seed();
        inst.scratch.insert(LOCAL_SEED.into(), json!(hex(&seed)));
        inst.scratch.insert(INFLIGHT.into(), json!(true));
        inst.scratch.insert(READY.into(), json!(false));
        inst.scratch.remove(COOKIE);
        vec![Self::post(host, HANDSHAKE1, None, seed.to_vec())]
    }

    fn on_handshake1(
        inst: &mut Instance,
        host: &str,
        status: u16,
        body: &[u8],
        args: &Args,
    ) -> Vec<HostCall> {
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
        if status != 200 {
            return Self::give_up(
                inst,
                format!("tapo: the dimmer refused the handshake ({status})"),
            );
        }
        let Some(remote) = klap::accept_handshake1(&seed, &auth, body) else {
            // The device computed its half from the credentials it was set up with and got a
            // different answer. Nothing about retrying helps.
            return Self::give_up(
                inst,
                "tapo: the dimmer did not accept this TP-Link account — check the Email and \
                 Password, which are the account's, not the Wi-Fi's",
            );
        };
        if let Some(id) = session_cookie(args) {
            inst.scratch.insert(COOKIE.into(), json!(id));
        }
        Self::save_session(inst, &klap::Session::derive(&seed, &remote, &auth));
        inst.scratch.insert(INFLIGHT.into(), json!(true));
        let cookie = inst.scratch.get(COOKIE).and_then(Value::as_str).map(str::to_string);
        vec![Self::post(
            host,
            HANDSHAKE2,
            cookie.as_deref(),
            klap::handshake2(&seed, &remote, &auth).to_vec(),
        )]
    }

    fn on_handshake2(inst: &mut Instance, host: &str, status: u16) -> Vec<HostCall> {
        inst.scratch.insert(INFLIGHT.into(), json!(false));
        if status != 200 {
            return Self::give_up(inst, format!("tapo: the dimmer rejected the login ({status})"));
        }
        inst.scratch.insert(READY.into(), json!(true));
        Self::flush(inst, host)
    }

    fn on_result(inst: &mut Instance, host: &str, status: u16, body: &[u8]) -> Vec<HostCall> {
        inst.scratch.insert(INFLIGHT.into(), json!(false));
        let sent = inst.scratch.get(LAST).and_then(Value::as_str).unwrap_or("").to_string();

        // 403 is what a Tapo says when it has forgotten the session — a reboot, or a long
        // enough silence. Handshake again and send the same thing, rather than losing it.
        if status != 200 {
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
            .decrypt(session.seq, body)
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
        if inst.scratch.get(READY).and_then(Value::as_bool) != Some(true)
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
        for key in [READY, KEY, IV, SIG, SEQ, COOKIE, LOCAL_SEED, LAST] {
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
        let phase = state.get("phase").and_then(Value::as_str).unwrap_or("start");
        // Empty is absent. A form prefilled with an address nobody had yet writes `""` into the
        // state, and a lookup that took it would shadow what the person then typed.
        let s = |key: &str| {
            let text = |v: Option<&Value>| {
                v.and_then(Value::as_str).map(str::to_string).filter(|t| !t.is_empty())
            };
            text(state.get(key)).or_else(|| text(input.get(key)))
        };
        let status = || input.get("status").and_then(Value::as_u64).unwrap_or(0) as u16;
        let received = || {
            input
                .get("response_bytes")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u8))
                        .collect::<Vec<u8>>()
                })
                .unwrap_or_default()
        };

        match phase {
            "start" => {
                // What the broadcast already found, if this was reached by pressing Add on a
                // row. A Tapo announces nothing over mDNS or SSDP — see the manifest — so this
                // is the only kind of candidate that ever arrives here.
                let found = state.get("udp_candidates").and_then(Value::as_array);
                let chosen = s("chosen_address").or_else(|| {
                    found
                        .filter(|rows| rows.len() == 1)
                        .and_then(|rows| rows.first())
                        .and_then(|row| row.get("address"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                });

                // What the device said about itself in that reply. Only ever a nicety for the
                // address — except `encrypt_type`, which is the one thing a driver otherwise
                // has to guess at, and guessing wrong looks like a dimmer that refuses a
                // password somebody typed correctly.
                let broadcast = chosen
                    .as_deref()
                    .and_then(|address| Self::from_broadcast(state, address));
                if let Some(scheme) = broadcast
                    .as_ref()
                    .and_then(|info| info.get("mgt_encrypt_schm"))
                    .and_then(|s| s.get("encrypt_type"))
                    .and_then(Value::as_str)
                    && !scheme.eq_ignore_ascii_case("KLAP")
                {
                    return (
                        SetupStep::Failed {
                            reason: format!(
                                "This device says it speaks `{scheme}`, and this driver speaks \
                                 KLAP. That is the protocol current Tapo firmware uses — a unit \
                                 old enough to want something else needs a firmware update from \
                                 the Tapo app, or a driver that has been tested against it."
                            ),
                        },
                        Value::Null,
                    );
                }

                match chosen {
                    Some(address) => Self::ask_credentials(&address, broadcast),
                    None if found.is_some_and(|rows| rows.len() > 1) => (
                        SetupStep::Pick {
                            title: "Which dimmer?".into(),
                            body: "These answered TP-Link's discovery broadcast.".into(),
                            columns: vec!["Address".into(), "Model".into()],
                            rows: found
                                .into_iter()
                                .flatten()
                                .filter_map(|row| {
                                    let address =
                                        row.get("address").and_then(Value::as_str)?.to_string();
                                    let model = Self::from_broadcast(state, &address)
                                        .and_then(|i| {
                                            i.get("device_model")
                                                .and_then(Value::as_str)
                                                .map(str::to_string)
                                        })
                                        .unwrap_or_default();
                                    Some(PickRow {
                                        value: address.clone(),
                                        cells: vec![address, model],
                                        note: String::new(),
                                    })
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
                        json!({ "phase": "picked", "udp_candidates": state.get("udp_candidates") }),
                    ),
                    // Nothing found, which is ordinary: a broadcast does not cross a subnet,
                    // and plenty of houses put lighting on its own.
                    None => Self::ask_credentials("", None),
                }
            }

            "picked" => {
                let address = s("address").unwrap_or_default();
                let broadcast = Self::from_broadcast(state, &address);
                Self::ask_credentials(&address, broadcast)
            }

            // Address and account in hand. Prove them.
            "credentials" => {
                let (Some(address), Some(email), Some(password)) =
                    (s("address"), s("email"), s("password"))
                else {
                    return Self::ask_credentials(&s("address").unwrap_or_default(), None);
                };
                let address = address.trim().to_string();
                let seed = klap::local_seed();
                (
                    SetupStep::Fetch {
                        request: HttpRequest::new(
                            "POST",
                            format!("http://{address}{HANDSHAKE1}"),
                        )
                        .bytes(seed.to_vec()),
                        note: "saying hello to the dimmer".into(),
                    },
                    json!({
                        "phase": "hs1", "address": address, "email": email,
                        "password": password, "local_seed": hex(&seed),
                        "model": s("model"),
                    }),
                )
            }

            "hs1" => {
                let address = s("address").unwrap_or_default();
                let (Some(seed), Some(email), Some(password)) = (
                    s("local_seed").and_then(|h| unhex(&h)),
                    s("email"),
                    s("password"),
                ) else {
                    return Self::lost();
                };
                let Ok(seed) = <[u8; 16]>::try_from(seed) else {
                    return Self::lost();
                };
                if status() != 200 {
                    return (
                        SetupStep::Failed {
                            reason: format!(
                                "{address} answered {} to a Tapo handshake. Check the address — \
                                 it is under Device Info in the Tapo app.",
                                status()
                            ),
                        },
                        Value::Null,
                    );
                }
                let auth = klap::auth_hash(email.trim(), &password);
                let Some(remote) = klap::accept_handshake1(&seed, &auth, &received()) else {
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
                let cookie = setup_cookie(input).unwrap_or_default();
                let mut request = HttpRequest::new("POST", format!("http://{address}{HANDSHAKE2}"))
                    .bytes(klap::handshake2(&seed, &remote, &auth).to_vec());
                if !cookie.is_empty() {
                    request = request.header("cookie", format!("TP_SESSIONID={cookie}"));
                }
                let mut next = state.clone();
                next["phase"] = json!("hs2");
                next["remote_seed"] = json!(hex(&remote));
                next["cookie"] = json!(cookie);
                (
                    SetupStep::Fetch {
                        request,
                        note: "signing in".into(),
                    },
                    next,
                )
            }

            "hs2" => {
                if status() != 200 {
                    return (
                        SetupStep::Failed {
                            reason: format!("The dimmer rejected the login ({}).", status()),
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
                    return Self::lost();
                };
                let (Ok(local), Ok(remote)) =
                    (<[u8; 16]>::try_from(local), <[u8; 16]>::try_from(remote))
                else {
                    return Self::lost();
                };
                let auth = klap::auth_hash(email.trim(), &password);
                let mut session = klap::Session::derive(&local, &remote, &auth);
                let (seq, framed) = session.encrypt(GET.as_bytes());
                let (key, iv, sig) = session.parts();
                let address = s("address").unwrap_or_default();
                let cookie = s("cookie").unwrap_or_default();
                let mut request = HttpRequest::new(
                    "POST",
                    format!("http://{address}{REQUEST}?seq={seq}"),
                )
                .bytes(framed);
                if !cookie.is_empty() {
                    request = request.header("cookie", format!("TP_SESSIONID={cookie}"));
                }
                let mut next = state.clone();
                next["phase"] = json!("info");
                next["key"] = json!(hex(&key));
                next["iv"] = json!(hex(&iv));
                next["sig"] = json!(hex(&sig));
                next["seq"] = json!(seq);
                (
                    SetupStep::Fetch {
                        request,
                        note: "asking the dimmer what it is".into(),
                    },
                    next,
                )
            }

            "info" => {
                let address = s("address").unwrap_or_default();
                let (Some(key), Some(iv), Some(sig), Some(seq)) = (
                    s("key").and_then(|h| unhex(&h)),
                    s("iv").and_then(|h| unhex(&h)),
                    s("sig").and_then(|h| unhex(&h)),
                    state.get("seq").and_then(Value::as_i64),
                ) else {
                    return Self::lost();
                };
                let (Ok(key), Ok(iv), Ok(sig)) = (
                    <[u8; 16]>::try_from(key),
                    <[u8; 12]>::try_from(iv),
                    <[u8; 28]>::try_from(sig),
                ) else {
                    return Self::lost();
                };
                let session = klap::Session::restore(key, iv, sig, seq as i32);
                let info = session
                    .decrypt(seq as i32, &received())
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
                // The broadcast named the model too, and agrees; this is the authenticated
                // answer, so it wins where both exist.
                let model = result
                    .get("model")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| s("model"))
                    .unwrap_or_else(|| "Tapo dimmer".into());

                let mut properties = std::collections::BTreeMap::new();
                properties.insert("Address".into(), json!(address));
                properties.insert("Email".into(), json!(s("email").unwrap_or_default()));
                properties.insert("Password".into(), json!(s("password").unwrap_or_default()));

                (
                    SetupStep::done(vec![Candidate {
                        label: nickname.unwrap_or_else(|| format!("{model} at {address}")),
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
                SetupStep::Failed {
                    reason: format!("unknown setup phase `{other}`"),
                },
                Value::Null,
            ),
        }
    }

    /// What the device said when it answered the discovery broadcast, for one address.
    ///
    /// TP-Link's reply is a sixteen-byte header and then JSON, so the JSON is found rather
    /// than assumed to start at zero — the header's length and contents are the vendor's and
    /// have changed before.
    fn from_broadcast(state: &Value, address: &str) -> Option<Value> {
        let row = state
            .get("udp_candidates")?
            .as_array()?
            .iter()
            .find(|row| row.get("address").and_then(Value::as_str) == Some(address))?;
        let bytes: Vec<u8> = row
            .get("reply")?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u8))
            .collect();
        let text = String::from_utf8_lossy(&bytes);
        let json = &text[text.find('{')?..];
        let parsed: Value = serde_json::from_str(json).ok()?;
        // Everything useful is under `result`; a reply that is shaped differently is one this
        // driver should not be reading fields out of.
        parsed.get("result").cloned()
    }

    fn ask_credentials(address: &str, broadcast: Option<Value>) -> (SetupStep, Value) {
        let model = broadcast
            .as_ref()
            .and_then(|i| i.get("device_model"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let body = if model.is_empty() {
            "Tapo checks local control against the TP-Link account the switch is paired to. \
             This is that account — the one you sign in to the Tapo app with — and it is \
             checked here rather than taken on trust."
                .to_string()
        } else {
            format!(
                "This is a {model}. Tapo checks local control against the TP-Link account the \
                 switch is paired to — the one you sign in to the Tapo app with — and it is \
                 checked here rather than taken on trust."
            )
        };
        (
            SetupStep::Form {
                title: "Sign in to the dimmer".into(),
                body,
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
            json!({ "phase": "credentials", "address": address, "model": model }),
        )
    }

    /// The flow state did not survive, which is a bug here rather than anything about the
    /// hardware — so it says so rather than blaming the dimmer.
    fn lost() -> (SetupStep, Value) {
        (
            SetupStep::Failed {
                reason: "Lost track of the handshake part-way through. Start setup again.".into(),
            },
            Value::Null,
        )
    }
}

// ---------------------------------------------------------------------------------------

/// `TP_SESSIONID` out of a response's headers, which is where a Tapo issues it.
fn session_cookie(args: &Args) -> Option<String> {
    cookie_in(args.get("headers"))
}

/// The same, from a `SetupStep::Fetch` reply.
fn setup_cookie(input: &Args) -> Option<String> {
    cookie_in(input.get("response_headers"))
}

fn cookie_in(headers: Option<&Value>) -> Option<String> {
    headers?.as_array()?.iter().find_map(|entry| {
        let pair = entry.as_array()?;
        let name = pair.first()?.as_str()?;
        let value = pair.get(1)?.as_str()?;
        if !name.eq_ignore_ascii_case("set-cookie") {
            return None;
        }
        // `TP_SESSIONID=ABC;TIMEOUT=1440` — the id is up to the first attribute.
        let rest = value.trim().strip_prefix("TP_SESSIONID=")?;
        Some(rest.split(';').next().unwrap_or(rest).to_string())
    })
}

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

    /// The one request the driver just made: where it went and what it carried.
    fn sent(calls: &[HostCall]) -> (String, Vec<u8>) {
        calls
            .iter()
            .find_map(|c| match c {
                HostCall::Http(r) => Some((r.url.clone(), r.body_bytes.clone())),
                _ => None,
            })
            .expect("a request")
    }

    /// What core delivers when a reply comes back.
    fn answered(url: &str, status: u16, body: &[u8], cookie: bool) -> Args {
        let mut args = Args::new();
        args.insert("url".into(), json!(url));
        args.insert("method".into(), json!("POST"));
        args.insert("status".into(), json!(status));
        args.insert("bytes".into(), json!(body));
        let headers = if cookie {
            json!([["set-cookie", "TP_SESSIONID=SID;TIMEOUT=1440"], ["content-length", "48"]])
        } else {
            json!([["content-length", "16"]])
        };
        args.insert("headers".into(), headers);
        args
    }

    /// The switch's half of handshake1, computed the way the device computes it.
    fn hs1_reply(local: &[u8; 16], remote: &[u8; 16], auth: &[u8; 32]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(local);
        h.update(remote);
        h.update(auth);
        let mut out = remote.to_vec();
        out.extend_from_slice(&h.finalize());
        out
    }

    /// The switch's answer to the request at `seq`. `encrypt` always advances, so the
    /// stand-in is wound back one rather than given a second entry point only a test would use.
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
    /// One test rather than four because the states only mean anything in sequence — the
    /// sequence number, the queue and the session are carried between them, and every bug this
    /// has found was a step being right on its own and wrong after the last one.
    #[test]
    fn a_bind_a_command_and_a_read_back() {
        let tapo = Tapo;
        let mut inst = dimmer();
        let auth = klap::auth_hash(EMAIL, PASSWORD);

        // -- bind: nothing is known, so this has to start with a handshake ------------------
        let calls = tapo.on_bind(&mut inst);
        let (url, body) = sent(&calls);
        assert_eq!(url, "http://10.0.0.4/app/handshake1");
        let local: [u8; 16] = body.try_into().expect("a 16-byte seed");

        let remote = [3u8; 16];
        let calls = tapo.on_event(
            &mut inst,
            0,
            "http_response",
            &answered(&url, 200, &hs1_reply(&local, &remote, &auth), true),
        );
        let (url, body) = sent(&calls);
        assert_eq!(url, "http://10.0.0.4/app/handshake2");
        assert_eq!(body, klap::handshake2(&local, &remote, &auth));

        // -- the session is up, so the bind's own question goes out ------------------------
        let mut device = klap::Session::derive(&local, &remote, &auth);
        let mut seq = device.seq + 1;
        let calls = tapo.on_event(&mut inst, 0, "http_response", &answered(&url, 200, b"", false));
        let (url, body) = sent(&calls);
        assert_eq!(url, format!("http://10.0.0.4/app/request?seq={seq}"));
        assert_eq!(
            device.decrypt(seq, &body).as_deref(),
            Some(GET.as_bytes()),
            "the bind asks where it stands"
        );

        // 40% and on. Both are reported, because a Tapo keeps power and brightness apart.
        let framed = answer(
            &mut device,
            seq,
            br#"{"error_code":0,"result":{"device_on":true,"brightness":40}}"#,
        );
        let calls = tapo.on_event(&mut inst, 0, "http_response", &answered(&url, 200, &framed, false));
        assert_eq!(notified(&calls, "power_changed").unwrap().get("on"), Some(&json!(true)));
        assert_eq!(notified(&calls, "level_changed").unwrap().get("level"), Some(&json!(40)));

        // -- a command, and the read-back it is required to do afterwards ------------------
        let mut args = Args::new();
        args.insert("level".into(), json!(0));
        let calls = tapo.on_command(&mut inst, LIGHT, "set_level", &args);
        let (url, body) = sent(&calls);
        seq += 1;
        let plain = device.decrypt(seq, &body).expect("the command");
        // Zero is off, not brightness zero — the switch refuses that and would report success.
        let plain: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(plain["params"], json!({ "device_on": false }));

        // A write is acknowledged with nothing to read, so the driver asks again rather than
        // reporting what it hoped for.
        let framed = answer(&mut device, seq, br#"{"error_code":0}"#);
        let calls = tapo.on_event(&mut inst, 0, "http_response", &answered(&url, 200, &framed, false));
        assert!(notified(&calls, "power_changed").is_none(), "nothing was read back yet");
        let (url, body) = sent(&calls);
        seq += 1;
        assert_eq!(url, format!("http://10.0.0.4/app/request?seq={seq}"));
        assert_eq!(device.decrypt(seq, &body).as_deref(), Some(GET.as_bytes()));

        let framed = answer(
            &mut device,
            seq,
            br#"{"error_code":0,"result":{"device_on":false,"brightness":40}}"#,
        );
        let calls = tapo.on_event(&mut inst, 0, "http_response", &answered(&url, 200, &framed, false));
        assert_eq!(notified(&calls, "power_changed").unwrap().get("on"), Some(&json!(false)));
        // The brightness did not move, so nothing claims it did.
        assert!(notified(&calls, "level_changed").is_none());
    }

    /// A session the switch has forgotten is rebuilt, and the command that found out is not
    /// lost on the way. A dropped `off` is a light left on.
    #[test]
    fn a_forgotten_session_is_rebuilt_and_the_command_retried() {
        let tapo = Tapo;
        let mut inst = dimmer();
        let auth = klap::auth_hash(EMAIL, PASSWORD);

        let calls = tapo.on_bind(&mut inst);
        let (url, body) = sent(&calls);
        let local: [u8; 16] = body.try_into().unwrap();
        let remote = [4u8; 16];
        let calls = tapo.on_event(
            &mut inst,
            0,
            "http_response",
            &answered(&url, 200, &hs1_reply(&local, &remote, &auth), true),
        );
        let (url, _) = sent(&calls);
        let calls = tapo.on_event(&mut inst, 0, "http_response", &answered(&url, 200, b"", false));
        let (url, _) = sent(&calls);

        // The switch rebooted between the handshake and now.
        let calls = tapo.on_event(&mut inst, 0, "http_response", &answered(&url, 403, b"", false));
        let (url, _) = sent(&calls);
        assert_eq!(url, "http://10.0.0.4/app/handshake1", "a 403 means handshake again");

        // And after the new handshake the question that was refused goes out again.
        let (_, body) = sent(&calls);
        let local: [u8; 16] = body.try_into().unwrap();
        let remote = [5u8; 16];
        let calls = tapo.on_event(
            &mut inst,
            0,
            "http_response",
            &answered(&url, 200, &hs1_reply(&local, &remote, &auth), true),
        );
        let (url, _) = sent(&calls);
        let calls = tapo.on_event(&mut inst, 0, "http_response", &answered(&url, 200, b"", false));
        let (url, body) = sent(&calls);
        let device = klap::Session::derive(&local, &remote, &auth);
        assert!(url.contains("/app/request?seq="));
        assert_eq!(
            device.decrypt(device.seq + 1, &body).as_deref(),
            Some(GET.as_bytes()),
            "the request the 403 refused has to be retried, not dropped"
        );
    }

    /// The password is the thing that goes wrong here, and it has to be said so.
    #[test]
    fn a_wrong_account_is_named_rather_than_retried() {
        let tapo = Tapo;
        let mut inst = dimmer();
        let calls = tapo.on_bind(&mut inst);
        let (url, body) = sent(&calls);
        let local: [u8; 16] = body.try_into().unwrap();

        // The switch computed its half from a different password.
        let other = klap::auth_hash(EMAIL, "not this one");
        let calls = tapo.on_event(
            &mut inst,
            0,
            "http_response",
            &answered(&url, 200, &hs1_reply(&local, &[1u8; 16], &other), true),
        );
        let warned = calls.iter().any(|c| {
            matches!(c, HostCall::Log { level, msg } if level == "warn" && msg.contains("TP-Link account"))
        });
        assert!(warned, "got {calls:?}");
        // And it stops: no second handshake, and the queue is not left holding the question.
        assert!(!calls.iter().any(|c| matches!(c, HostCall::Http(_))));
    }

    /// Setup end to end, with the test playing the switch again: a broadcast reply and
    /// credentials in, a named device out.
    #[test]
    fn setup_signs_in_and_names_the_dimmer() {
        let tapo = Tapo;
        let auth = klap::auth_hash(EMAIL, PASSWORD);

        // What core hands the flow after a discovery broadcast: sixteen bytes of vendor header
        // and then JSON, exactly as it arrived.
        let mut reply = vec![0x02, 0x00, 0x00, 0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 0x46, 0x3c, 0xb5, 0xd3];
        reply.extend_from_slice(
            br#"{"result":{"device_model":"S500D","mgt_encrypt_schm":{"encrypt_type":"KLAP"}}}"#,
        );
        let seed_state = json!({
            "chosen_address": "10.0.0.4",
            "udp_candidates": [{ "address": "10.0.0.4", "port": 20002, "reply": reply }],
        });

        // The broadcast names the model, so the form says which device it is asking about.
        let (step, state) = tapo.discover("tapo.dimmer", &seed_state, &Args::new());
        let SetupStep::Form { body, .. } = &step else {
            panic!("expected a form, got {step:?}");
        };
        assert!(body.contains("S500D"), "the broadcast's model should reach the screen: {body}");

        let mut input = Args::new();
        input.insert("address".into(), json!("10.0.0.4"));
        input.insert("email".into(), json!(EMAIL));
        input.insert("password".into(), json!(PASSWORD));
        let (step, state) = tapo.setup("tapo.dimmer", &state, &input);
        let SetupStep::Fetch { request, .. } = step else {
            panic!("expected a handshake, got {step:?}");
        };
        assert_eq!(request.url, "http://10.0.0.4/app/handshake1");
        assert!(request.binary, "the handshake is not text");
        let local: [u8; 16] = request.body_bytes.try_into().unwrap();

        let remote = [11u8; 16];
        let fetched = |bytes: &[u8], cookie: bool| {
            let mut a = Args::new();
            a.insert("status".into(), json!(200));
            a.insert("response_bytes".into(), json!(bytes));
            a.insert(
                "response_headers".into(),
                if cookie {
                    json!([["set-cookie", "TP_SESSIONID=SID;TIMEOUT=1440"]])
                } else {
                    json!([])
                },
            );
            a
        };

        let (step, state) = tapo.setup(
            "tapo.dimmer",
            &state,
            &fetched(&hs1_reply(&local, &remote, &auth), true),
        );
        let SetupStep::Fetch { request, .. } = step else {
            panic!("expected handshake2, got {step:?}");
        };
        assert_eq!(request.body_bytes, klap::handshake2(&local, &remote, &auth));
        // The session id is issued in a header and presented on every request after it.
        assert!(
            request
                .headers
                .iter()
                .any(|(k, v)| k == "cookie" && v == "TP_SESSIONID=SID"),
            "the cookie has to be carried forward: {:?}",
            request.headers
        );

        let (step, state) = tapo.setup("tapo.dimmer", &state, &fetched(b"", false));
        let SetupStep::Fetch { request, .. } = step else {
            panic!("expected get_device_info, got {step:?}");
        };
        let mut device = klap::Session::derive(&local, &remote, &auth);
        let seq = device.seq + 1;
        assert_eq!(
            device.decrypt(seq, &request.body_bytes).as_deref(),
            Some(GET.as_bytes())
        );

        // "Hall" in base64, which is how a Tapo sends every name a person set.
        let info = br#"{"error_code":0,"result":{"device_on":true,"brightness":60,"nickname":"SGFsbA==","model":"S500D"}}"#;
        let framed = answer(&mut device, seq, info);
        let (step, _) = tapo.setup("tapo.dimmer", &state, &fetched(&framed, false));
        let SetupStep::Done { devices, .. } = step else {
            panic!("expected a device, got {step:?}");
        };
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].label, "Hall");
        assert_eq!(devices[0].verified, "S500D, on");
        assert_eq!(devices[0].properties["Address"], json!("10.0.0.4"));
        assert_eq!(devices[0].properties["Password"], json!(PASSWORD));
    }

    /// A unit that says it speaks something else is refused with the reason, rather than
    /// adopted and then failing to log in forever.
    #[test]
    fn a_device_on_the_old_protocol_is_told_why_not() {
        let mut reply = vec![0u8; 16];
        reply.extend_from_slice(
            br#"{"result":{"device_model":"HS100","mgt_encrypt_schm":{"encrypt_type":"AES"}}}"#,
        );
        let (step, _) = Tapo.discover(
            "tapo.dimmer",
            &json!({
                "chosen_address": "10.0.0.9",
                "udp_candidates": [{ "address": "10.0.0.9", "port": 20002, "reply": reply }],
            }),
            &Args::new(),
        );
        let SetupStep::Failed { reason } = step else {
            panic!("expected a refusal, got {step:?}");
        };
        assert!(reason.contains("AES") && reason.contains("KLAP"), "{reason}");
    }
}

# Tapo Dimmer

TP-Link Tapo dimmer switches (S500D and the rest of the S5xxD line), driven locally over KLAP —
the protocol the switch speaks on port 80 to anything on the same network. Nothing here reaches
TP-Link's cloud, and the switch does not need to either.

One `light` proxy, dimmable 1–100. No continuous ramp: the switch fades on a schedule stored in
the device and has no "go up until I say stop", so `ramp_start`/`ramp_stop` say so rather than
doing nothing. No button events either — the paddle works, and nothing local reports a press.

## Setup

Discovery is a probe, not an announcement: a Tapo advertises nothing over mDNS or SSDP, so a
controller with this driver installed sweeps its own network for port 80 and knocks with a KLAP
handshake1. That knock needs no credentials and grants nothing, and a Tapo answers it by opening
a session — which is what puts `TP_SESSIONID` in the reply headers and identifies one. Nothing
else on port 80 in a house sends that cookie name.

Setup then asks for the **TP-Link account** the dimmer is paired to: the email and password you
sign in to the Tapo app with. That is not a per-device secret and there is no pairing flow to
issue a token — the switch stores a hash of those credentials when the app sets it up, and local
control is checked against it. There is nothing to revoke afterwards, which is worth knowing
before typing them in.

They are checked before anything is adopted. The handshake makes the switch prove it holds the
same account before Juno proves it does, so a wrong password fails here with a sentence saying
so, rather than adopting a dimmer that never answers a command.

## Polling is not optional

A Tapo has no local subscription and pushes nothing: turn it up at the wall and it tells nobody.
`Poll interval` (30 s by default) is what makes the house eventually agree with the switch, and
it is also what recovers a stalled exchange.

## Why the HTTP is written by hand

KLAP is HTTP on port 80, and `HostCall::Http` cannot carry it: its body is a `String` in both
directions, so raw seeds and AES ciphertext arrive with every non-UTF-8 byte replaced, and the
reply's `Set-Cookie` — where the session id lives — never reaches a driver at all. So this goes
out over the device's own `binary` transport as `HostCall::Tx`, and `src/http.rs` owns the
framing a client would normally own. `src/klap.rs` is the crypto; both have their reasons in
their module docs.

## Not implemented

- **KLAP v1 and the older RSA `securePassthrough` protocol.** Every Tapo dimmer shipped with
  v2, and a fallback that cannot be tested against hardware is a second protocol to be wrong
  about.
- **Plugs, bulbs and strips.** They speak the same protocol and would be a manifest each; this
  ships the one it was written for.

Untested against real hardware. The protocol here follows
[python-kasa](https://github.com/python-kasa/python-kasa)'s KLAP implementation, which is the
field-tested reference; the tests play the switch's half with the same primitives, which catches
a handshake built in the wrong order but not a firmware that disagrees.

## Building

```bash
cargo build --release
```

Releases are built by [`junohouse/driver-ci`](https://github.com/junohouse/driver-ci): push to
`main` for a beta, tag `v1.2.0` for a release. To work on this against a local core checkout,
uncomment the `[patch]` block in `Cargo.toml`.

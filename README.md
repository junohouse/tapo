# Tapo Dimmer

TP-Link Tapo dimmer switches (S500D and the rest of the S5xxD line), driven locally over KLAP —
the protocol the switch speaks on port 80 to anything on the same network. Nothing here reaches
TP-Link's cloud, and the switch does not need to either.

One `light` proxy, dimmable 1–100. No continuous ramp: the switch fades on a schedule stored in
the device and has no "go up until I say stop", so `ramp_start`/`ramp_stop` say so rather than
doing nothing. No button events either — the paddle works, and nothing local reports a press.

## Setup

Discovery is a broadcast, not an announcement: a Tapo advertises nothing over mDNS, SSDP or
SDDP, and answers exactly one thing — TP-Link's own discovery query, on UDP 20002, in TP-Link's
own format. That query and the reply that identifies one are declared in the manifest as
`[[discovery.udp]]`, and core does the sending and the listening. It runs against the whole
registry index, so a controller with this driver *not* installed still lists the dimmer.

The reply is worth more than an address. It names the model — which is why the sign-in screen
knows what it is asking about — and it names the encryption scheme the device wants, so a unit
that is not on KLAP is refused with a sentence saying so rather than adopted and left failing to
log in forever.

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

## Session keys live in scratch

The handshake derives a key, an IV and a signing key, and they go in `inst.scratch` — which
core persists, so a restart resumes the session rather than re-handshaking. If the switch has
forgotten it in the meantime it answers 403, and this driver handshakes again and re-sends the
request that found out, rather than dropping it. A lost `off` is a light left on.

## Not implemented

- **KLAP v1 and the older RSA `securePassthrough` protocol.** Every Tapo dimmer shipped with
  v2, and a fallback that cannot be tested against hardware is a second protocol to be wrong
  about.
- **Plugs, bulbs and strips.** They speak the same protocol and would be a manifest each; this
  ships the one it was written for.

Untested against real hardware. The protocol here follows
[python-kasa](https://github.com/python-kasa/python-kasa)'s KLAP implementation, which is the
field-tested reference; the tests play the switch's half with the same primitives, end to end
through both the runtime path and the setup flow, which catches a handshake built in the wrong
order but not a firmware that disagrees. The discovery query is TP-Link's own — take the bytes
from `python-kasa`'s `discover.py` rather than from this file if you are checking them.

## Building

```bash
cargo build --release
```

Releases are built by [`junohouse/driver-ci`](https://github.com/junohouse/driver-ci): push to
`main` for a beta, tag `v1.2.0` for a release. To work on this against a local core checkout,
uncomment the `[patch]` block in `Cargo.toml`.

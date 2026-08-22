# Tapo Dimmer

TP-Link Tapo dimmer switches (S500D and the rest of the S5xxD line), driven locally over KLAP —
the protocol the switch speaks on port 80 to anything on the same network. Nothing here reaches
TP-Link's cloud, and the switch does not need to either.

One `light` proxy, dimmable 1–100. No continuous ramp: the switch fades on a schedule stored in
the device and has no "go up until I say stop", so `ramp_start`/`ramp_stop` say so rather than
doing nothing. No button events either — the paddle works, and nothing local reports a press.

## Two drivers: an account, and the dimmers behind it

The credentials a Tapo checks are a TP-Link **account**, not a per-device secret — the switch
stored a hash of it when the Tapo app set it up, and local control is checked against that. A
house with eight dimmers has one account, so it is its own device (`tapo.account`, a `bridge`)
and every dimmer inherits from it, exactly as a Hue bulb inherits its bridge's address and key.
Change the password once and all eight follow; without it, eight copies drift and one gets
missed.

It is not a hub — there is no box, and the dimmers talk to the controller directly. `bridge` is
the contract for "the thing children inherit from", which is precisely what this is.

**Adding them.** Set up the account once; it is checked against a real device on the network
before it is saved, because an account cannot be verified on its own and a typo would otherwise
surface later as every dimmer refusing to answer. Then browse the account: it broadcasts, logs
in to everything that answers, and adds each dimmer under the name you gave it in the Tapo app.
Nothing is typed — not a password per device, and not an address at all.

Addresses come from TP-Link's own discovery broadcast (`[[discovery.udp]]` on the account), the
same one the Tapo app and `python-kasa` send. An address field appears only when the broadcast
found nothing, which is real — a broadcast does not cross a router — and is then the only way
through.

A device that answers saying it speaks an older protocol, is unplugged, or is paired to a
different account is left out and named on screen rather than failing the run. One legacy plug
on the network must not be the reason seven dimmers cannot be added.

There is no OAuth here and there cannot be: the dimmer validates the login itself, offline,
against the hash it stored. No token from TP-Link's cloud is something it has any way to check.

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

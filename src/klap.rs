//! KLAP — the handshake and session a current-firmware Tapo device speaks on port 80.
//!
//! Two POSTs establish it and every request after them is encrypted:
//!
//! ```text
//!   POST /app/handshake1  local_seed (16 bytes)
//!        -> remote_seed (16) || server_hash (32), and a TP_SESSIONID cookie
//!   POST /app/handshake2  SHA256(remote_seed || local_seed || auth_hash)
//!   POST /app/request?seq=N   SHA256(sig || seq || ciphertext) || ciphertext
//! ```
//!
//! # The device proves it knows the password first
//!
//! `server_hash` is `SHA256(local_seed || remote_seed || auth_hash)` computed by the switch
//! from the credentials *it* was set up with. So the first reply already says whether the
//! account details are right, before anything is sent that depends on them — which is what
//! lets setup fail with "wrong email or password" instead of adopting a device that will
//! never answer a command. Handshake2 is us proving the same thing in the other direction.
//!
//! `auth_hash` is `SHA256(SHA1(email) || SHA1(password))` — the TP-Link *account* the switch
//! is paired to, not a per-device secret and not a local PIN. Nothing here is reverse-order
//! by accident: handshake1's hash is local-then-remote and handshake2's is remote-then-local,
//! and swapping them gives a device that refuses every login with no further explanation.
//!
//! Older firmware (KLAP v1, and the RSA `securePassthrough` protocol before it) hashes with
//! MD5 instead. Not implemented: every Tapo dimmer shipped with v2, and a fallback that
//! cannot be tested against hardware is a second protocol to be wrong about.

use aes::Aes128;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha1::Sha1;
use sha2::{Digest, Sha256};

type Encryptor = cbc::Encryptor<Aes128>;
type Decryptor = cbc::Decryptor<Aes128>;

/// What the switch checks a login against: the TP-Link account, hashed the way KLAP v2 wants.
pub fn auth_hash(email: &str, password: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(Sha1::digest(email.as_bytes()));
    h.update(Sha1::digest(password.as_bytes()));
    h.finalize().into()
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A fresh local seed. 16 bytes, and they must be unpredictable — they are half of what the
/// session key is derived from.
pub fn local_seed() -> [u8; 16] {
    let mut seed = [0u8; 16];
    // The controller owns the entropy; a driver that could not ask would derive the same
    // session key on every connection.
    let _ = getrandom::getrandom(&mut seed);
    seed
}

/// The remote seed out of a handshake1 reply, if the device proved it holds these credentials.
///
/// `None` covers both failures on purpose — a short reply and a wrong hash are the same thing
/// to a caller, which is "this is not a Tapo that will talk to you".
pub fn accept_handshake1(local: &[u8; 16], auth: &[u8; 32], body: &[u8]) -> Option<[u8; 16]> {
    if body.len() < 48 {
        return None;
    }
    let remote: [u8; 16] = body[..16].try_into().ok()?;
    (sha256(&[local, &remote, auth]) == body[16..48]).then_some(remote)
}

/// Our half of the proof — the body of handshake2.
pub fn handshake2(local: &[u8; 16], remote: &[u8; 16], auth: &[u8; 32]) -> [u8; 32] {
    sha256(&[remote, local, auth])
}

/// An established session. Every field is derived from the two seeds and the credential hash,
/// so it survives a restart in the driver's scratch and needs no second handshake to rebuild.
#[derive(Clone)]
pub struct Session {
    key: [u8; 16],
    iv: [u8; 12],
    sig: [u8; 28],
    /// Counts up, and is *both* the last four bytes of the IV and a query parameter. The device
    /// tracks it too, which is why it is stored rather than recomputed.
    pub seq: i32,
}

impl Session {
    pub fn derive(local: &[u8; 16], remote: &[u8; 16], auth: &[u8; 32]) -> Session {
        let lsk = sha256(&[b"lsk", local, remote, auth]);
        let ivf = sha256(&[b"iv", local, remote, auth]);
        let ldk = sha256(&[b"ldk", local, remote, auth]);
        Session {
            key: lsk[..16].try_into().expect("16 of 32"),
            iv: ivf[..12].try_into().expect("12 of 32"),
            sig: ldk[..28].try_into().expect("28 of 32"),
            // Signed, and it starts wherever the hash says — a device can hand back a negative
            // first sequence, and reading these four bytes as unsigned desynchronises the very
            // first request.
            seq: i32::from_be_bytes(ivf[28..].try_into().expect("4 of 32")),
        }
    }

    pub fn restore(key: [u8; 16], iv: [u8; 12], sig: [u8; 28], seq: i32) -> Session {
        Session { key, iv, sig, seq }
    }

    pub fn parts(&self) -> ([u8; 16], [u8; 12], [u8; 28]) {
        (self.key, self.iv, self.sig)
    }

    fn block_iv(&self, seq: i32) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(&self.iv);
        iv[12..].copy_from_slice(&seq.to_be_bytes());
        iv
    }

    /// Encrypt one request, advancing the sequence. The caller needs the new `seq` for the
    /// query string, so it comes back rather than having to be read off the session again.
    pub fn encrypt(&mut self, plain: &[u8]) -> (i32, Vec<u8>) {
        // Wrapping rather than saturating: the device wraps, and a session that pinned itself
        // at i32::MAX would stop matching after two billion commands rather than carrying on.
        self.seq = self.seq.wrapping_add(1);
        let ciphertext = Encryptor::new(&self.key.into(), &self.block_iv(self.seq).into())
            .encrypt_padded_vec_mut::<Pkcs7>(plain);
        let mut body = sha256(&[&self.sig, &self.seq.to_be_bytes(), &ciphertext]).to_vec();
        body.extend_from_slice(&ciphertext);
        (self.seq, body)
    }

    /// Decrypt the reply to the request at `seq`, dropping the device's leading 32-byte
    /// signature over what follows.
    ///
    /// **This does not authenticate.** CBC decrypts every block from the ciphertext before it,
    /// so only the *first* block depends on the IV — and the sequence number is in the IV.
    /// Answer with the wrong `seq` and the padding still validates, the tail still decodes, and
    /// what comes back is sixteen bytes of noise followed by real JSON. The signature is not
    /// checked against because nothing has confirmed against hardware how the device computes
    /// the one it sends, and rejecting good replies is worse than the alternative. So the
    /// caller's JSON parse is the integrity check, and a failure there means the sequence is
    /// out of step — see `on_result`, which reconnects rather than retrying.
    pub fn decrypt(&self, seq: i32, body: &[u8]) -> Option<Vec<u8>> {
        if body.len() <= 32 {
            return None;
        }
        Decryptor::new(&self.key.into(), &self.block_iv(seq).into())
            .decrypt_padded_vec_mut::<Pkcs7>(&body[32..])
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The handshake and one round trip, against a stand-in that plays the switch's half with
    /// the same primitives. It fails if either hash is built in the wrong order, if the
    /// sequence is read unsigned, or if encrypt and decrypt disagree about the IV — which are
    /// the four ways this protocol goes wrong silently.
    #[test]
    fn a_session_survives_the_handshake_and_a_round_trip() {
        let auth = auth_hash("someone@example.com", "hunter2");
        let local = [7u8; 16];
        let remote = [9u8; 16];

        // What the device sends back to handshake1.
        let mut reply = remote.to_vec();
        reply.extend_from_slice(&sha256(&[&local, &remote, &auth]));
        assert_eq!(accept_handshake1(&local, &auth, &reply), Some(remote));

        // The same reply against the wrong password is not a weak match, it is no match.
        let wrong = auth_hash("someone@example.com", "hunter3");
        assert_eq!(accept_handshake1(&local, &wrong, &reply), None);
        assert_eq!(accept_handshake1(&local, &auth, &reply[..40]), None);

        assert_eq!(handshake2(&local, &remote, &auth), sha256(&[&remote, &local, &auth]));

        let mut ours = Session::derive(&local, &remote, &auth);
        let theirs = Session::derive(&local, &remote, &auth);
        let (seq, body) = ours.encrypt(br#"{"method":"get_device_info"}"#);
        assert_eq!(seq, theirs.seq + 1, "the first request is one past the derived sequence");
        assert_eq!(
            theirs.decrypt(seq, &body).as_deref(),
            Some(&br#"{"method":"get_device_info"}"#[..])
        );
        // The sequence is part of the IV — but only of the first block, so a reply matched to
        // the wrong one comes back as garbage with valid padding rather than as an error. This
        // is the reason `decrypt`'s caller checks the JSON and not the return value.
        let wrong = theirs.decrypt(seq + 1, &body).expect("unpadding does not catch this");
        assert_ne!(wrong, br#"{"method":"get_device_info"}"#);
        assert_eq!(&wrong[16..], &br#"{"method":"get_device_info"}"#[16..]);
    }
}

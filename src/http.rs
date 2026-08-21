//! Just enough HTTP/1.1 to carry KLAP, written by hand because the bytes are binary.
//!
//! A driver's ordinary way to make a request is `HostCall::Http`, and it cannot be used here:
//! its body is a `String` in both directions, so a handshake made of raw seeds and a
//! ciphertext arrives with every byte that is not valid UTF-8 replaced — and the reply's
//! `Set-Cookie` never reaches the driver at all, which is where the session id lives. So this
//! goes out over the device's own `binary` transport as [`driver_sdk::HostCall::Tx`], and the
//! framing that a client would normally own is here instead.
//!
//! Core hands over whatever bytes arrived in a read window rather than whole replies — it
//! cannot know where one ends — so [`parse`] returns `None` for "not all here yet" and the
//! caller keeps the remainder for the next event.

/// One reply off the wire.
pub struct Reply {
    pub status: u16,
    /// `TP_SESSIONID`, when this reply set one. Handshake1 is the only one that does.
    pub session: Option<String>,
    pub body: Vec<u8>,
}

/// Build a request. `keep-alive` because core holds one connection per device and only
/// notices a closed one by failing to write down it — so a reply that closed the socket costs
/// the next command, and the poll after it is what recovers.
pub fn post(path: &str, host: &str, session: Option<&str>, body: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n",
        body.len()
    );
    if let Some(id) = session {
        head.push_str(&format!("Cookie: TP_SESSIONID={id}\r\n"));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// The first whole reply in `buf`, and how many bytes it used.
///
/// `None` means what has arrived so far is not a whole reply yet, which is ordinary rather
/// than an error — a 250 ms read window cuts wherever it lands.
///
/// ponytail: `Content-Length` only. Everything a Tapo sends is a short, counted body; a
/// `Transfer-Encoding: chunked` reply would be read as length zero and its body left in the
/// buffer to poison the next parse. Add a chunked branch if one ever turns up.
pub fn parse(buf: &[u8]) -> Option<(Reply, usize)> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&buf[..end]);
    let mut lines = head.lines();

    // `HTTP/1.1 200 OK` — the middle field, or this is not a reply we can act on.
    let status: u16 = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;

    let mut length = 0usize;
    let mut session = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().unwrap_or(0);
        } else if name.eq_ignore_ascii_case("set-cookie")
            && let Some(rest) = value.strip_prefix("TP_SESSIONID=")
        {
            // `TP_SESSIONID=ABC;TIMEOUT=1440` — the id is up to the first attribute.
            session = Some(rest.split(';').next().unwrap_or(rest).to_string());
        }
    }

    if buf.len() < end + length {
        return None;
    }
    Some((
        Reply {
            status,
            session,
            body: buf[end..end + length].to_vec(),
        },
        end + length,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_is_only_read_once_all_of_it_is_here() {
        let whole = b"HTTP/1.1 200 OK\r\nSet-Cookie: TP_SESSIONID=ABC123;TIMEOUT=1440\r\n\
                      Content-Length: 4\r\n\r\nseed";
        // Every prefix short of the last byte is "not yet", not a truncated read.
        for cut in 0..whole.len() {
            assert!(parse(&whole[..cut]).is_none(), "parsed at {cut} bytes");
        }
        let (reply, used) = parse(whole).expect("whole reply");
        assert_eq!((reply.status, used), (200, whole.len()));
        assert_eq!(reply.session.as_deref(), Some("ABC123"));
        assert_eq!(reply.body, b"seed");

        // Two replies in one window: the first is returned and the second left alone.
        let mut two = whole.to_vec();
        two.extend_from_slice(whole);
        let (_, used) = parse(&two).expect("first of two");
        assert_eq!(&two[used..], whole);
    }

    #[test]
    fn a_request_carries_the_session_only_once_there_is_one() {
        let out = post("/app/handshake1", "10.0.0.4", None, b"0123456789abcdef");
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("POST /app/handshake1 HTTP/1.1\r\n"));
        assert!(text.contains("Content-Length: 16\r\n"));
        assert!(!text.contains("Cookie:"));
        assert!(out.ends_with(b"\r\n\r\n0123456789abcdef"));

        let out = post("/app/handshake2", "10.0.0.4", Some("ABC"), b"");
        assert!(String::from_utf8_lossy(&out).contains("Cookie: TP_SESSIONID=ABC\r\n"));
    }
}

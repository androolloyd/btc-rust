//! Fixed-length HTTP/1.0/1.1 JSON-RPC on the ordinary RPC listener.
//! Ambiguous framing is rejected and closes the connection before dispatch.
use crate::{
    handler::RpcHandler,
    server::{read_line_limited, IO_TIMEOUT, MAX_REQUEST_BYTES},
    wire,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_KEEPALIVE_REQUESTS: usize = 100;

#[derive(Clone)]
pub struct HttpAuth {
    cookie: Vec<u8>,
}
impl std::fmt::Debug for HttpAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HttpAuth([REDACTED])")
    }
}
impl HttpAuth {
    pub fn from_cookie(cookie: &str) -> eyre::Result<Self> {
        let (user, password) = cookie
            .split_once(':')
            .ok_or_else(|| eyre::eyre!("invalid RPC credential"))?;
        eyre::ensure!(
            !user.is_empty()
                && !password.is_empty()
                && cookie.len() <= 256
                && cookie.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
            "invalid RPC credential"
        );
        Ok(Self {
            cookie: cookie.as_bytes().to_vec(),
        })
    }
    fn accepts(&self, value: &[u8]) -> bool {
        if value.len() < 6 || value.len() > 512 || !value[..6].eq_ignore_ascii_case(b"Basic ") {
            return false;
        }
        let Ok(decoded) = STANDARD.decode(value[6..].trim_ascii()) else {
            return false;
        };
        self.cookie.ct_eq(&decoded).into()
    }
}

struct RequestHead {
    length: usize,
    keep_alive: bool,
    expect_continue: bool,
}

fn parse_head(bytes: &[u8], auth: Option<&HttpAuth>) -> Result<RequestHead, u16> {
    if bytes.len() > MAX_HEADER_BYTES {
        return Err(431);
    }
    // Use a single strict framing interpretation. httparse validates tokens;
    // CRLF, duplicate framing/auth fields and transfer coding are explicit.
    if bytes.iter().enumerate().any(|(i, b)| {
        (*b == b'\n' && (i == 0 || bytes[i - 1] != b'\r'))
            || (*b == b'\r' && bytes.get(i + 1) != Some(&b'\n'))
    }) {
        return Err(400);
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    if request.parse(bytes).map_err(|_| 400u16)? != httparse::Status::Complete(bytes.len()) {
        return Err(400);
    }
    if request.path != Some("/") {
        return Err(404);
    }
    if request.method != Some("POST") {
        return Err(405);
    }
    let version = request.version.ok_or(400u16)?;
    let mut length = None;
    let mut authorization = None;
    let mut host = None;
    let mut keep_alive = version == 1;
    let mut expect_continue = false;
    for header in request.headers.iter() {
        let value = header.value.trim_ascii();
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err(400);
            }
            let text = std::str::from_utf8(value).map_err(|_| 400u16)?;
            let parsed: usize = text.parse().map_err(|_| 413u16)?;
            if parsed > MAX_REQUEST_BYTES {
                return Err(413);
            }
            length = Some(parsed);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(400);
        } else if header.name.eq_ignore_ascii_case("authorization") {
            if authorization.is_some() {
                return Err(400);
            }
            authorization = Some(value);
        } else if header.name.eq_ignore_ascii_case("host") {
            if host.is_some() || value.is_empty() {
                return Err(400);
            }
            host = Some(value);
        } else if header.name.eq_ignore_ascii_case("connection") {
            if value
                .split(|b| *b == b',')
                .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"close"))
            {
                keep_alive = false;
            }
        } else if header.name.eq_ignore_ascii_case("expect") {
            if expect_continue || !value.eq_ignore_ascii_case(b"100-continue") {
                return Err(417);
            }
            expect_continue = true;
        } else if header.name.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case(b"identity")
        {
            return Err(415);
        }
    }
    if version == 1 && host.is_none() {
        return Err(400);
    }
    let auth = auth.ok_or(503u16)?;
    if !authorization.is_some_and(|value| auth.accepts(value)) {
        return Err(401);
    }
    Ok(RequestHead {
        length: length.ok_or(411u16)?,
        keep_alive,
        expect_continue,
    })
}

async fn read_head<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut head = Vec::new();
    loop {
        let Some(line) = read_line_limited(reader, MAX_HEADER_BYTES - head.len()).await? else {
            if head.is_empty() {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated HTTP headers",
            ));
        };
        if !line.ends_with(b"\r\n") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HTTP requires CRLF",
            ));
        }
        if head.is_empty() {
            let mut headers = [];
            if httparse::Request::new(&mut headers).parse(&line).is_err() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid HTTP start line",
                ));
            }
        }
        let complete = line == b"\r\n";
        head.extend_from_slice(&line);
        if complete {
            return Ok(Some(head));
        }
    }
}

async fn respond<W: AsyncWrite + Unpin>(
    writer: &mut W,
    reply: wire::Reply,
    keep_alive: bool,
) -> std::io::Result<()> {
    let reason = match reply.status {
        100 => "Continue",
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Length: {}\r\nConnection: {}\r\n",
        reply.status,
        reply.body.len(),
        if keep_alive { "keep-alive" } else { "close" }
    );
    if !reply.body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    if reply.status == 401 {
        head.push_str("WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n");
    }
    if reply.status == 405 {
        head.push_str("Allow: POST\r\n");
    }
    head.push_str("\r\n");
    tokio::time::timeout(IO_TIMEOUT, async {
        writer.write_all(head.as_bytes()).await?;
        writer.write_all(&reply.body).await
    })
    .await?
}

async fn reject<W: AsyncWrite + Unpin>(writer: &mut W, status: u16) -> std::io::Result<()> {
    respond(
        writer,
        wire::Reply {
            status,
            body: Vec::new(),
        },
        false,
    )
    .await
}

pub(crate) async fn serve<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    handler: Arc<RpcHandler>,
    auth: Option<HttpAuth>,
) -> eyre::Result<()> {
    for round in 0..MAX_KEEPALIVE_REQUESTS {
        let head = tokio::select! {
            biased;
            _ = handler.wait_for_shutdown() => return Ok(()),
            result = tokio::time::timeout(IO_TIMEOUT, read_head(reader)) => result,
        };
        let bytes = match head {
            Ok(Ok(Some(bytes))) => bytes,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(error)) => {
                reject(
                    writer,
                    if error.kind() == std::io::ErrorKind::InvalidData {
                        431
                    } else {
                        400
                    },
                )
                .await?;
                return Ok(());
            }
            Err(_) => {
                reject(writer, 408).await?;
                return Ok(());
            }
        };
        let head = match parse_head(&bytes, auth.as_ref()) {
            Ok(head) => head,
            Err(status) => {
                reject(writer, status).await?;
                return Ok(());
            }
        };
        // Authenticate before allocating or waiting for the body, including
        // before acknowledging Expect. Rejections always close, never resync.
        if head.expect_continue {
            tokio::time::timeout(
                IO_TIMEOUT,
                writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n"),
            )
            .await??;
        }
        let mut body = vec![0; head.length];
        let read = tokio::select! {
            biased;
            _ = handler.wait_for_shutdown() => return Ok(()),
            result = tokio::time::timeout(IO_TIMEOUT, reader.read_exact(&mut body)) => result,
        };
        match read {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {
                reject(writer, 400).await?;
                return Ok(());
            }
            Err(_) => {
                reject(writer, 408).await?;
                return Ok(());
            }
        }
        let worker = handler.clone();
        let reply = tokio::task::spawn_blocking(move || wire::handle(&worker, &body)).await?;
        let keep_alive =
            head.keep_alive && round + 1 < MAX_KEEPALIVE_REQUESTS && !handler.should_shutdown();
        respond(writer, reply, keep_alive).await?;
        if !keep_alive {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_framing_and_credentials_are_rejected_before_dispatch() {
        let auth = HttpAuth::from_cookie("test:secret").unwrap();
        assert!(!format!("{auth:?}").contains("secret"));
        let base =
            "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dGVzdDpzZWNyZXQ=\r\n";
        for (fields, status) in [
            ("Content-Length: 2\r\nContent-Length: 2\r\n", 400),
            ("Content-Length: 2,2\r\n", 400),
            ("Content-Length: +2\r\n", 400),
            ("Content-Length: -2\r\n", 400),
            ("Transfer-Encoding: chunked\r\nContent-Length: 2\r\n", 400),
            ("Transfer-Encoding: identity\r\n", 400),
            (
                "Authorization: Basic dGVzdDpzZWNyZXQ=\r\nContent-Length: 2\r\n",
                400,
            ),
            ("Host: localhost\r\nContent-Length: 2\r\n", 400),
            ("Content-Length: 999999999999999999999999999999999\r\n", 413),
            ("Expect: nonsense\r\nContent-Length: 2\r\n", 417),
            ("Content-Encoding: gzip\r\nContent-Length: 2\r\n", 415),
            ("", 411),
            ("Content-Length: 2\n", 400),
            (" Content-Length: 2\r\n", 400),
        ] {
            assert_eq!(
                parse_head(format!("{base}{fields}\r\n").as_bytes(), Some(&auth)).err(),
                Some(status),
                "{fields}"
            );
        }
        let good = format!("{base}Content-Length: 2\r\n\r\n");
        assert_eq!(
            parse_head(
                good.replace("dGVzdDpzZWNyZXQ=", "dGVzdDp3cm9uZw==")
                    .as_bytes(),
                Some(&auth)
            )
            .err(),
            Some(401)
        );
        assert!(parse_head(good.as_bytes(), Some(&auth)).is_ok());
        assert_eq!(parse_head(good.as_bytes(), None).err(), Some(503));
        assert_eq!(
            parse_head(
                good.replace("POST /", "POST /wallet/a").as_bytes(),
                Some(&auth)
            )
            .err(),
            Some(404)
        );
        assert_eq!(
            parse_head(good.replace("POST /", "GET /").as_bytes(), Some(&auth)).err(),
            Some(405)
        );
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod transport_tests;

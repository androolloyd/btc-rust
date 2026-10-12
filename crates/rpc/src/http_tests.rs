use super::*;
use crate::server::RpcServer;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::{TcpListener, TcpStream},
};

fn request(body: &[u8], extra: &str) -> Vec<u8> {
    let mut bytes = format!("POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dGVzdDpzZWNyZXQ=\r\nContent-Length: {}\r\n{extra}\r\n",body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

async fn reply<R: AsyncBufRead + Unpin>(reader: &mut R) -> (u16, Vec<u8>) {
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let code = line
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut length = 0;
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
        if let Some(size) = line.strip_prefix("Content-Length: ") {
            length = size.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await.unwrap();
    (code, body)
}

async fn server(
    handler: Arc<RpcHandler>,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<eyre::Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(
        RpcServer::new(addr.port())
            .with_http_auth(HttpAuth::from_cookie("test:secret").unwrap())
            .run_listener(listener, handler),
    );
    (addr, task)
}

async fn shutdown(handler: &RpcHandler, task: tokio::task::JoinHandle<eyre::Result<()>>) {
    handler.handle_raw(r#"{"jsonrpc":"2.0","method":"stop","id":1}"#);
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn fragmented_pipelined_http_versions_notifications_and_legacy_share_dispatch() {
    let mut handler = RpcHandler::new();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = count.clone();
    handler.register("count", move |_| {
        json!(observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
    });
    let handler = Arc::new(handler);
    let (addr, task) = server(handler.clone()).await;
    let stream = TcpStream::connect(addr).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let mut bytes = request(br#"{"jsonrpc":"2.0","method":"count","id":"v2"}"#, "");
    bytes.extend(request(
        br#"{"jsonrpc":"1.0","method":"count","id":"legacy"}"#,
        "",
    ));
    for chunk in bytes.chunks(7) {
        write.write_all(chunk).await.unwrap();
    }
    let (code, body) = reply(&mut read).await;
    assert_eq!(code, 200);
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["result"], 0);
    assert_eq!(value["id"], "v2");
    assert!(value.get("error").is_none());
    let (code, body) = reply(&mut read).await;
    assert_eq!(code, 200);
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["result"], 1);
    assert_eq!(value["id"], "legacy");
    assert!(value["error"].is_null());
    assert!(value.get("jsonrpc").is_none());
    write
        .write_all(&request(br#"{"jsonrpc":"2.0","method":"count"}"#, ""))
        .await
        .unwrap();
    let (code, body) = reply(&mut read).await;
    assert_eq!(code, 204);
    assert!(body.is_empty());
    let mut raw = TcpStream::connect(addr).await.unwrap();
    raw.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"count\",\"id\":4}\n")
        .await
        .unwrap();
    let mut raw = BufReader::new(raw);
    let mut line = String::new();
    raw.read_line(&mut line).await.unwrap();
    let value: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["result"], 3);
    write
        .write_all(&request(br#"{"jsonrpc":"2.0","method":"stop","id":5}"#, ""))
        .await
        .unwrap();
    let (code, body) = reply(&mut read).await;
    assert_eq!(code, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["result"],
        "Bitcoin server stopping"
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(TcpStream::connect(addr).await.is_err());
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 4);
}

#[tokio::test]
async fn rejected_headers_cannot_smuggle_a_mutating_request_or_switch_modes() {
    let handler = Arc::new(RpcHandler::new());
    let (addr, task) = server(handler.clone()).await;
    let stop = br#"{"jsonrpc":"2.0","method":"stop","id":9}"#;
    for (headers,status) in [
        ("Authorization: Basic wrong\r\nContent-Length: 1\r\n",401),
        ("Authorization: Basic dGVzdDpzZWNyZXQ=\r\nContent-Length: 1\r\nContent-Length: 1\r\n",400),
        ("Authorization: Basic dGVzdDpzZWNyZXQ=\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n",400),
        ("Authorization: Basic dGVzdDpzZWNyZXQ=\r\nContent-Length: 9000000\r\n",413),
    ] {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut bytes = format!("POST / HTTP/1.1\r\nHost: localhost\r\n{headers}\r\nx\n").into_bytes();
        bytes.extend_from_slice(stop); bytes.push(b'\n'); bytes.extend(request(stop,""));
        stream.write_all(&bytes).await.unwrap(); let mut read = BufReader::new(stream);
        assert_eq!(reply(&mut read).await.0,status);
        assert!(read.read_u8().await.is_err()); assert!(!handler.should_shutdown());
    }
    // Once HTTP is selected, a raw JSON line on the next keepalive is rejected.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut bytes = request(br#"{"method":"getblockcount","id":1}"#, "");
    bytes.extend_from_slice(stop);
    bytes.push(b'\n');
    stream.write_all(&bytes).await.unwrap();
    let mut read = BufReader::new(stream);
    assert_eq!(reply(&mut read).await.0, 200);
    assert_eq!(reply(&mut read).await.0, 400);
    assert!(!handler.should_shutdown());
    drop(read);
    shutdown(&handler, task).await;
}

#[tokio::test]
async fn expect_is_authenticated_before_body_and_truncation_cannot_dispatch() {
    let handler = Arc::new(RpcHandler::new());
    let (addr, task) = server(handler.clone()).await;
    let body = br#"{"method":"getblockcount","id":1}"#;
    let bytes = request(body, "Expect: 100-continue\r\n");
    let split = bytes.len() - body.len();
    let stream = TcpStream::connect(addr).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    write.write_all(&bytes[..split]).await.unwrap();
    assert_eq!(reply(&mut read).await.0, 100);
    write.write_all(body).await.unwrap();
    assert_eq!(reply(&mut read).await.0, 200);
    drop(read);
    drop(write);
    let stream = TcpStream::connect(addr).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let wrong = String::from_utf8(bytes[..split].to_vec())
        .unwrap()
        .replace("dGVzdDpzZWNyZXQ=", "wrong");
    write.write_all(wrong.as_bytes()).await.unwrap();
    assert_eq!(reply(&mut read).await.0, 401);
    drop(read);
    drop(write);
    let stream = TcpStream::connect(addr).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    write
        .write_all(&request(br#"{"method":"stop","id":1}"#, "")[..split.min(50)])
        .await
        .unwrap();
    write.shutdown().await.unwrap();
    assert_eq!(reply(&mut read).await.0, 400);
    assert!(!handler.should_shutdown());
    drop(read);
    drop(write);
    let body = br#"{"method":"stop","id":1}"#;
    let stream = TcpStream::connect(addr).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let head=format!("POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dGVzdDpzZWNyZXQ=\r\nContent-Length: {}\r\n\r\n",body.len()+1);
    write.write_all(head.as_bytes()).await.unwrap();
    write.write_all(body).await.unwrap();
    write.shutdown().await.unwrap();
    assert_eq!(reply(&mut read).await.0, 400);
    assert!(!handler.should_shutdown());
    drop(read);
    drop(write);
    shutdown(&handler, task).await;
}

#[tokio::test]
async fn incomplete_body_deadline_returns_408_without_mutation() {
    let handler = Arc::new(RpcHandler::new());
    let observed = handler.clone();
    let (mut client, stream) = tokio::io::duplex(2048);
    let (read, mut write) = tokio::io::split(stream);
    let mut read = BufReader::new(read);
    let task = tokio::spawn(async move {
        serve(
            &mut read,
            &mut write,
            observed,
            Some(HttpAuth::from_cookie("test:secret").unwrap()),
        )
        .await
    });
    let body = br#"{"method":"stop","id":1}"#;
    let bytes = request(body, "Expect: 100-continue\r\n");
    client
        .write_all(&bytes[..bytes.len() - body.len()])
        .await
        .unwrap();
    let mut client = BufReader::new(client);
    assert_eq!(reply(&mut client).await.0, 100);
    tokio::time::pause();
    tokio::time::advance(IO_TIMEOUT + std::time::Duration::from_secs(1)).await;
    assert_eq!(reply(&mut client).await.0, 408);
    task.await.unwrap().unwrap();
    assert!(!handler.should_shutdown());
}

#[tokio::test]
async fn idle_connections_are_capped_and_stop_does_not_need_a_new_accept() {
    let handler = Arc::new(RpcHandler::new());
    let (addr, task) = server(handler.clone()).await;
    let body = br#"{"method":"stop","id":1}"#;
    let bytes = request(body, "Expect: 100-continue\r\n");
    let head = &bytes[..bytes.len() - body.len()];
    let mut held = Vec::new();
    for _ in 0..crate::server::MAX_CONNECTIONS {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(head).await.unwrap();
        let mut read = BufReader::new(stream);
        assert_eq!(reply(&mut read).await.0, 100);
        held.push(read);
    }
    let mut excess = TcpStream::connect(addr).await.unwrap();
    let _ = excess.write_all(head).await;
    assert!(excess.read_u8().await.is_err());
    assert!(!handler.should_shutdown());
    shutdown(&handler, task).await;
    drop(held);
    assert!(TcpStream::connect(addr).await.is_err());
}

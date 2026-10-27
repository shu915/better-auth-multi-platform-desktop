//! 通信のテストで使う道具(テストのときだけ)。決まった応答を返す、ローカルの偽のサーバー。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// 決まった応答を順に返す、ローカルの偽の Web。受け取った要求(ヘッダーと本文)を溜める。
pub struct Mock {
    pub base: String,
    pub requests: Arc<Mutex<Vec<String>>>,
}

pub fn serve(responses: Vec<(u16, &'static str)>) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    std::thread::spawn(move || {
        for (status, body) in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            let (head_end, content_length) = loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                buf.extend_from_slice(&chunk[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (i + 4, len);
                }
                if n == 0 {
                    break (buf.len(), 0);
                }
            };
            while buf.len() < head_end + content_length {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf).to_string());
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    Mock { base, requests }
}

/// 何も待ち受けていない接続先(接続が拒否される)。
pub fn dead_base() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", listener.local_addr().unwrap())
}

pub fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    tauri::async_runtime::block_on(future)
}

pub fn body_of(request: &str) -> serde_json::Value {
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(body).unwrap()
}

pub fn header_of(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

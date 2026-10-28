//! ブラウザの戻りを受ける、アプリの一時的な受け口(RFC 8252 の「ループバック」)。
//!
//! Google のログインと連携は、ブラウザで Google の画面を通ってから、アプリに戻る。独自スキームの
//! リンクで戻ると、ブラウザが「アプリを開きますか?」を出し、押しても押さなくても結果が変わらず、
//! 繰り返すと出なくなる。そこで、アプリが `127.0.0.1` の空きポートで受け口を開き、Web の戻り先を
//! `http://127.0.0.1:<ポート>/cb?…` にする。ブラウザがそこへ戻ると、アプリは `state` と `code`
//! (または `link`)を受け取り、ブラウザには完了のページを返す。
//!
//! 受け口は、ログインごとに 1 つ、1 回の戻りだけ受けて閉じる。10 分で閉じる(Web の `state` の有効期間)。
//! 受け取った内容を信用はしない: ここでは形だけ確かめ、`state` の突き合わせと PKCE は、リンクと同じ
//! 処理(`accept_sign_in_link`)が行う。標準ライブラリだけで書き、依存は増やさない。

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// 受け口を開いておく時間。
pub const LIFETIME: Duration = Duration::from_secs(10 * 60);

/// 要求の頭(リクエスト行とヘッダー)の最大バイト数。
const MAX_HEAD_BYTES: usize = 8 * 1024;

/// 1 つの接続を待つ時間(ブラウザは、すぐ送ってくる)。
const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// 受け口を見張る間隔(閉じる合図と期限を見る)。
const POLL: Duration = Duration::from_millis(50);

/// 受け取る道。戻り先の URL は、ちょうど `http://127.0.0.1:<ポート>/cb?…`。
pub const PATH: &str = "/cb";

/// 戻り先に載せる、ブラウザの戻りの URL(クエリは付けない)。
pub fn base_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}{PATH}")
}

/// ブラウザからの要求を、どう扱うか。
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// 戻り。`query` は `?` の後ろ(`state=…&code=…` など)。`refused` は、Web が断った(`error` 付き)戻り。
    Callback { query: String, refused: bool },
    /// 受け口の道ではない、形が違う、`Host` が違う(favicon の要求など)。何も受け取らない。
    Other,
}

/// 要求の頭を判断する。通すのは、`GET /cb?<クエリ>` で、次の 3 つを満たすものだけ。
///  - `Host` がちょうど `127.0.0.1:<自分のポート>`(DNS リバインディング=別の名前をこの受け口に向けた
///    Web ページを断る)
///  - クエリに、**自分が待っている目印**(`expect`。ログインなら `state`、連携なら `link` の値)がある。
///    ほかのページが、ポートを順に叩いて、形だけ合う要求を送っても、受け口は閉じない
///  - `Sec-Fetch-Mode` が付いているときは `navigate`(ページの遷移)。画像や `fetch` からの要求ではない。
///    付けないブラウザは、断らない
///
/// クエリのないもの、長すぎるものも断る。
pub fn parse_request(head: &str, port: u16, expect: &str) -> Request {
    let mut lines = head.split("\r\n");
    let Some(request_line) = lines.next() else {
        return Request::Other;
    };
    let mut parts = request_line.split(' ');
    let (Some("GET"), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Request::Other;
    };
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Request::Other;
    }
    let headers: Vec<(&str, &str)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name, value.trim()))
        .collect();
    let host = format!("127.0.0.1:{port}");
    let host_ok = headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("host") && *value == host);
    let navigation_ok = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("sec-fetch-mode"))
        .all(|(_, value)| value.eq_ignore_ascii_case("navigate"));
    if !host_ok || !navigation_ok {
        return Request::Other;
    }
    let Some((path, query)) = target.split_once('?') else {
        return Request::Other;
    };
    if path != PATH || query.is_empty() || query.len() > 4096 || query.contains(['\r', '\n', ' ']) {
        return Request::Other;
    }
    let ours = !expect.is_empty()
        && query.split('&').any(|pair| {
            matches!(pair.split_once('='), Some(("state" | "link", value)) if value == expect)
        });
    if !ours {
        return Request::Other;
    }
    let refused = query
        .split('&')
        .any(|pair| pair.split('=').next() == Some("error"));
    Request::Callback {
        query: query.to_string(),
        refused,
    }
}

const PAGE_DONE: &str =
    "Google の手続きが終わりました。このウィンドウを閉じて、アプリに戻ってください。";
const PAGE_REFUSED: &str = "Google でのログインは、完了しませんでした。このウィンドウを閉じて、アプリに戻り、もう一度お試しください。";

/// ブラウザに返す完了のページ。入力(クエリ)は、埋め込まない。
fn page(refused: bool) -> String {
    let message = if refused { PAGE_REFUSED } else { PAGE_DONE };
    let body = format!(
        "<!doctype html><html lang=\"ja\"><head><meta charset=\"utf-8\"><title>Auth Practice</title>\
         <style>body{{font-family:system-ui,sans-serif;margin:4rem auto;max-width:32rem;padding:0 1rem;line-height:1.7}}</style>\
         </head><body><h1>Auth Practice</h1><p>{message}</p></body></html>"
    );
    response("200 OK", &body)
}

fn response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// 開いている受け口。`cancel` で閉じる。
pub struct Receiver {
    pub port: u16,
    cancel: Arc<AtomicBool>,
}

impl Receiver {
    /// 受け口を閉じる(まだ戻りを受けていなくても)。
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}

/// `127.0.0.1` の空きポートで受け口を開き、**1 回の戻りだけ**受ける。戻り(`GET /cb?<クエリ>`で、
/// `expect` を含むもの)が来たら、ブラウザに完了のページを返してから、`on_query` にクエリを渡し、
/// 受け口を閉じる。ほかの要求(favicon や、目印の合わないもの)には 404 を返して、待ち続ける。
/// `lifetime` がたつか、`cancel` されたら、閉じる。
pub fn start(
    expect: String,
    on_query: impl FnOnce(String) + Send + 'static,
    lifetime: Duration,
) -> io::Result<Receiver> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancel);
    thread::spawn(move || {
        let deadline = Instant::now() + lifetime;
        let mut on_query = Some(on_query);
        while Instant::now() < deadline && !flag.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Request::Callback { query, .. } = serve_one(stream, port, &expect)
                        && let Some(done) = on_query.take()
                    {
                        done(query);
                        return;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
                Err(_) => thread::sleep(POLL),
            }
        }
    });
    Ok(Receiver { port, cancel })
}

/// 1 つの接続を読んで、答える。戻りなら、完了のページを返して `Callback` を返す。
fn serve_one(mut stream: TcpStream, port: u16, expect: &str) -> Request {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
    let started = Instant::now();
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        // 1 つの接続に使える時間は、全体で READ_TIMEOUT まで。1 バイトずつ送って受け口を占有されても、
        // 閉じる合図と期限を見に戻れる。
        let Some(left) = READ_TIMEOUT.checked_sub(started.elapsed()) else {
            return Request::Other;
        };
        let _ = stream.set_read_timeout(Some(left.max(Duration::from_millis(1))));
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Request::Other,
            Ok(n) => {
                head.extend_from_slice(&chunk[..n]);
                if head.len() > MAX_HEAD_BYTES {
                    let _ = stream
                        .write_all(response("431 Request Header Fields Too Large", "").as_bytes());
                    return Request::Other;
                }
            }
        }
    }
    let request = parse_request(&String::from_utf8_lossy(&head), port, expect);
    let answer = match &request {
        Request::Callback { refused, .. } => page(*refused),
        Request::Other => response("404 Not Found", ""),
    };
    let _ = stream.write_all(answer.as_bytes());
    request
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    const STATE: &str = "0123456789abcdef0123456789abcdef";

    fn head(target: &str, host: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n\r\n")
    }

    fn head_with(target: &str, host: &str, extra: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n\r\n")
    }

    fn ok_target() -> String {
        format!("/cb?state={STATE}&code=c")
    }

    #[test]
    fn a_callback_for_our_port_with_our_state_is_read() {
        assert_eq!(
            parse_request(&head(&ok_target(), "127.0.0.1:5000"), 5000, STATE),
            Request::Callback {
                query: format!("state={STATE}&code=c"),
                refused: false
            }
        );
    }

    #[test]
    fn a_linking_callback_is_read_by_its_mark() {
        assert_eq!(
            parse_request(
                &head(&format!("/cb?link={STATE}"), "127.0.0.1:5000"),
                5000,
                STATE
            ),
            Request::Callback {
                query: format!("link={STATE}"),
                refused: false
            }
        );
    }

    #[test]
    fn a_callback_the_web_app_refused_is_marked() {
        assert_eq!(
            parse_request(
                &head(
                    &format!("/cb?state={STATE}&error=signup_disabled"),
                    "127.0.0.1:5000"
                ),
                5000,
                STATE
            ),
            Request::Callback {
                query: format!("state={STATE}&error=signup_disabled"),
                refused: true
            }
        );
        // `error` が値の一部にあるだけでは、断りではない。
        assert!(matches!(
            parse_request(
                &head(&format!("/cb?state={STATE}&code=error"), "127.0.0.1:5000"),
                5000,
                STATE
            ),
            Request::Callback { refused: false, .. }
        ));
    }

    #[test]
    fn a_request_without_the_mark_we_wait_for_is_not_ours() {
        // 形だけ合う要求(ほかのページがポートを順に叩く)では、受け口は閉じない。
        let host = "127.0.0.1:5000";
        for target in [
            "/cb?x=1".to_string(),
            "/cb?state=other&code=c".to_string(),
            "/cb?link=other".to_string(),
            format!("/cb?code={STATE}"),
            format!("/cb?other={STATE}"),
            format!("/cb?state={STATE}x"),
            format!("/cb?state=x{STATE}"),
            "/cb?state=&code=c".to_string(),
        ] {
            assert_eq!(
                parse_request(&head(&target, host), 5000, STATE),
                Request::Other,
                "{target}"
            );
        }
        // 待っている目印がない(空)ときは、何も通さない。
        assert_eq!(
            parse_request(&head("/cb?state=&code=c", host), 5000, ""),
            Request::Other
        );
    }

    #[test]
    fn everything_else_is_not_a_callback() {
        let ok_host = "127.0.0.1:5000";
        for bad in [
            head("/favicon.ico", ok_host),
            head("/cb", ok_host),
            head("/cb?", ok_host),
            head(&format!("/other?state={STATE}"), ok_host),
            head(&format!("/cb/extra?state={STATE}"), ok_host),
            head(&format!("//cb?state={STATE}"), ok_host),
            head(
                &format!("/cb?state={STATE}&x={}", "x".repeat(5000)),
                ok_host,
            ),
            format!("POST /cb?state={STATE} HTTP/1.1\r\nHost: 127.0.0.1:5000\r\n\r\n"),
            format!("GET /cb?state={STATE} HTTP/2\r\nHost: 127.0.0.1:5000\r\n\r\n"),
            format!("GET /cb?state={STATE}\r\nHost: 127.0.0.1:5000\r\n\r\n"),
            format!("GET /cb?state={STATE} HTTP/1.1\r\n\r\n"),
            String::new(),
        ] {
            assert_eq!(parse_request(&bad, 5000, STATE), Request::Other, "{bad:?}");
        }
    }

    #[test]
    fn a_host_that_is_not_our_address_and_port_is_refused() {
        // DNS リバインディング: 別の名前をこの受け口に向けた Web ページからの要求。
        for host in [
            "evil.example:5000",
            "evil.example",
            "localhost:5000",
            "127.0.0.1",
            "127.0.0.1:5001",
            "127.0.0.1:5000.evil.example",
            "",
        ] {
            assert_eq!(
                parse_request(&head(&ok_target(), host), 5000, STATE),
                Request::Other,
                "{host}"
            );
        }
    }

    #[test]
    fn only_a_page_navigation_is_taken_when_the_browser_says_what_it_is() {
        let host = "127.0.0.1:5000";
        // 画像や fetch からの要求は断る。遷移(navigate)と、何も言わないブラウザは通す。
        for mode in ["no-cors", "cors", "same-origin", "websocket"] {
            let extra = format!("Sec-Fetch-Mode: {mode}");
            assert_eq!(
                parse_request(&head_with(&ok_target(), host, &extra), 5000, STATE),
                Request::Other,
                "{mode}"
            );
        }
        for extra in [
            "Sec-Fetch-Mode: navigate",
            "sec-fetch-mode: Navigate",
            "X-Other: 1",
        ] {
            assert!(
                matches!(
                    parse_request(&head_with(&ok_target(), host, extra), 5000, STATE),
                    Request::Callback { .. }
                ),
                "{extra}"
            );
        }
    }

    #[test]
    fn the_page_never_echoes_the_request() {
        let done = page(false);
        let refused = page(true);
        assert!(done.contains(PAGE_DONE) && !done.contains(PAGE_REFUSED));
        assert!(refused.contains(PAGE_REFUSED));
        assert!(done.contains("Content-Security-Policy"));
        assert!(done.contains("no-store"));
    }

    fn get(port: u16, target: &str, host: &str) -> String {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        stream
            .write_all(format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .unwrap();
        let mut out = String::new();
        let _ = stream.read_to_string(&mut out);
        out
    }

    fn open(lifetime: Duration) -> (Receiver, mpsc::Receiver<String>) {
        let (sender, received) = mpsc::channel();
        let receiver = start(
            STATE.to_string(),
            move |query| sender.send(query).unwrap(),
            lifetime,
        )
        .unwrap();
        (receiver, received)
    }

    #[test]
    fn the_receiver_takes_one_callback_shows_the_page_and_closes() {
        let (receiver, received) = open(Duration::from_secs(5));
        let host = format!("127.0.0.1:{}", receiver.port);

        // ほかの要求は、404 を返して、待ち続ける。目印の合わない要求でも、閉じない。
        assert!(get(receiver.port, "/favicon.ico", &host).starts_with("HTTP/1.1 404"));
        assert!(get(receiver.port, &ok_target(), "evil.example").starts_with("HTTP/1.1 404"));
        assert!(get(receiver.port, "/cb?x=1", &host).starts_with("HTTP/1.1 404"));
        assert!(get(receiver.port, "/cb?state=other&code=c", &host).starts_with("HTTP/1.1 404"));
        assert!(received.try_recv().is_err());

        let answer = get(receiver.port, &ok_target(), &host);
        assert!(answer.starts_with("HTTP/1.1 200 OK"));
        assert!(answer.contains(PAGE_DONE));
        assert_eq!(
            received.recv_timeout(Duration::from_secs(2)).unwrap(),
            format!("state={STATE}&code=c")
        );

        // 1 回だけ。閉じたので、2 回目はつながらない。
        thread::sleep(Duration::from_millis(200));
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, receiver.port)).is_err());
    }

    #[test]
    fn a_refused_callback_shows_the_refused_page() {
        let (receiver, received) = open(Duration::from_secs(5));
        let host = format!("127.0.0.1:{}", receiver.port);
        let target = format!("/cb?state={STATE}&error=x");
        let answer = get(receiver.port, &target, &host);
        assert!(answer.contains(PAGE_REFUSED));
        assert_eq!(
            received.recv_timeout(Duration::from_secs(2)).unwrap(),
            format!("state={STATE}&error=x")
        );
    }

    #[test]
    fn a_slow_connection_does_not_hold_the_receiver() {
        let (receiver, received) = open(Duration::from_secs(10));
        let port = receiver.port;
        let host = format!("127.0.0.1:{port}");

        // 1 バイトずつ、ゆっくり送る接続。READ_TIMEOUT をすぎたら、手放される。
        let slow = thread::spawn(move || {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            for byte in b"GET /cb?state=x HTTP/1.1\r\nHost: 127.0.0.1" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(300));
            }
        });
        thread::sleep(Duration::from_millis(100));
        // 本物の戻りは、占有が解けたあとで、受けられる。
        let started = Instant::now();
        let answer = get(port, &ok_target(), &host);
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
        assert!(started.elapsed() < Duration::from_secs(6));
        assert!(received.recv_timeout(Duration::from_secs(2)).is_ok());
        let _ = slow.join();
    }

    #[test]
    fn cancelling_closes_the_receiver_and_nothing_is_passed_on() {
        let (receiver, received) = open(Duration::from_secs(5));
        let port = receiver.port;
        receiver.cancel();
        thread::sleep(Duration::from_millis(300));
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
        assert!(received.try_recv().is_err());
    }

    #[test]
    fn the_receiver_closes_when_its_time_is_up() {
        let (receiver, _received) = open(Duration::from_millis(200));
        let port = receiver.port;
        thread::sleep(Duration::from_millis(500));
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
    }

    #[test]
    fn two_receivers_use_two_ports_and_listen_on_the_loopback_only() {
        let first = start(STATE.to_string(), |_| {}, Duration::from_secs(2)).unwrap();
        let second = start(STATE.to_string(), |_| {}, Duration::from_secs(2)).unwrap();
        assert_ne!(first.port, second.port);
        assert_eq!(
            base_url(first.port),
            format!("http://127.0.0.1:{}/cb", first.port)
        );
        first.cancel();
        second.cancel();
    }
}

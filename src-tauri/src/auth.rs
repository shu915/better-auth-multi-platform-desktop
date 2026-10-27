//! マジックリンクでのログイン、ログアウトの流れ(通信と保管)。
//!
//! 判断は `sign_in_rules.rs` と `session_cookie.rs` の純粋な関数に任せ、ここは「呼ぶ順番」と通信だけ。
//! モバイルの `sign-in-link.ts`、`exchange-code.ts`、ログアウトに当たる。
//!
//!  1. `request_sign_in_link`: state と verifier(PKCE)を作って pending に保存してから、Web に
//!     マジックリンクのメールを頼む。verifier そのものは、引き換えまで Mac の外に出ない。
//!  2. メールのリンクはブラウザで検証され、Web が `betterauthmulti:///?state=…&code=…` に戻す。
//!     セッションはリンクに載らない(同じスキームを他のアプリも登録できるため)。
//!  3. `accept_sign_in_link`: state が自分のものなら使い切り、`code` と verifier をセッションに引き換えて
//!     Keychain に保存する。(リンクを受け取る deep link の配線は、次の PR。)
//!
//! 秘密(verifier、code、セッション)は、戻り値にもログにも出さない。通信の失敗は理由の種類だけ返す。

use std::sync::Mutex as StdMutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::async_runtime::Mutex;

use crate::secret::{SecretError, Slot, Store};
use crate::session_cookie::{SessionCookie, parse_session_cookie};
use crate::sign_in_rules::{
    APP_SCHEME, Consumed, LinkVerdict, Pending, add_pending, callback_url, challenge_for,
    check_email, consume_pending, judge_link, link_state, parse_pending_list, remove_pending,
    state_from_bytes, verifier_from_bytes,
};

const TIMEOUT: Duration = Duration::from_secs(10);

/// 応答の本文の最大バイト数。大きな本文を読み込まない。
const MAX_BODY_BYTES: usize = 64 * 1024;

/// 同じリンクが 2 回届くことがある(OS が同じ URL を二重に渡す、など)。直近に処理した code と、
/// 拒否した state を覚えて、2 回目は何もしない。
const SEEN_MAX: usize = 5;

pub struct AuthState {
    /// pending の「読む → 変える → 書く」が、同時に走らないようにする。
    pending_lock: Mutex<()>,
    seen: StdMutex<Vec<String>>,
}

impl AuthState {
    pub fn new() -> Self {
        AuthState {
            pending_lock: Mutex::new(()),
            seen: StdMutex::new(Vec::new()),
        }
    }

    /// 初めて見るなら `true`(覚える)。2 回目以降は `false`。
    fn first_time(&self, key: String) -> bool {
        let Ok(mut seen) = self.seen.lock() else {
            return true;
        };
        if seen.contains(&key) {
            return false;
        }
        seen.push(key);
        if seen.len() > SEEN_MAX {
            seen.remove(0);
        }
        true
    }
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}

/// Web に `Origin` として見せる値。Web の `expo()` は `expo-origin` ヘッダーを Origin に置き換えるので、
/// これが `trustedOrigins`(`betterauthmulti://`)と一致して、Origin の検査を通る。
fn origin() -> String {
    format!("{APP_SCHEME}://")
}

fn client() -> Result<reqwest::Client, &'static str> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        // 応答がリダイレクトでも追わない(セッションを載せたまま別の場所へ行かない)。
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "http client failed")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn failure_reason(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "request timed out"
    } else {
        "request failed"
    }
}

/// 本文を、上限までだけ読む。上限を超えたり、途中で切れたりしたら `None`。
async fn read_limited(mut res: reqwest::Response) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        match res.chunk().await {
            Ok(Some(chunk)) => {
                if out.len() + chunk.len() > MAX_BODY_BYTES {
                    return None;
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => return Some(out),
            Err(_) => return None,
        }
    }
}

/// pending の一覧を、決まった順番で「読む → 変える → 書く」。
async fn update_pending(
    state: &AuthState,
    store: &dyn Store,
    change: impl FnOnce(Vec<Pending>) -> Vec<Pending>,
) -> Result<(), SecretError> {
    let _guard = state.pending_lock.lock().await;
    let list = parse_pending_list(store.load(Slot::Pending)?.as_deref());
    save_pending(store, &change(list))
}

fn save_pending(store: &dyn Store, list: &[Pending]) -> Result<(), SecretError> {
    if list.is_empty() {
        store.delete(Slot::Pending)
    } else {
        store.save(
            Slot::Pending,
            &serde_json::to_string(list).map_err(|_| SecretError::EmptyValue)?,
        )
    }
}

// --- 1. マジックリンクを頼む ---

#[derive(Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RequestOutcome {
    Sent,
    /// `status` は、Web が答えたときの HTTP ステータス(429 は「回数が多すぎる」)。
    Failed {
        reason: String,
        status: Option<u16>,
    },
}

fn request_failed(reason: &str, status: Option<u16>) -> RequestOutcome {
    RequestOutcome::Failed {
        reason: reason.to_string(),
        status,
    }
}

pub async fn request_sign_in_link(
    auth: &AuthState,
    store: &dyn Store,
    base: &str,
    email: &str,
) -> RequestOutcome {
    let Some(email) = check_email(email) else {
        return request_failed("invalid email", None);
    };
    let Ok(client) = client() else {
        return request_failed("http client failed", None);
    };

    // 32 バイトの verifier と、16 バイトの state。乱数が取れなければ、何も送らない。
    let (mut verifier_bytes, mut state_bytes) = ([0u8; 32], [0u8; 16]);
    if getrandom::fill(&mut verifier_bytes).is_err() || getrandom::fill(&mut state_bytes).is_err() {
        return request_failed("random failed", None);
    }
    let verifier = verifier_from_bytes(&verifier_bytes);
    let challenge = challenge_for(&verifier);
    let state = state_from_bytes(&state_bytes);

    // 送る前に覚える。リンクが先に戻ってきても、突き合わせられるようにする。
    let now = now_ms();
    if update_pending(auth, store, |list| {
        add_pending(&list, &state, &verifier, now)
    })
    .await
    .is_err()
    {
        return request_failed("storage failed", None);
    }

    let sent = client
        .post(format!("{base}/api/auth/sign-in/magic-link"))
        .header("expo-origin", origin())
        .json(&serde_json::json!({
            "email": email,
            "callbackURL": callback_url(&state, &challenge),
        }))
        .send()
        .await;
    match sent {
        Ok(res) if res.status().is_success() => RequestOutcome::Sent,
        Ok(res) => {
            let status = res.status().as_u16();
            // Web が答えて断った: この state のメールは存在しない。その 1 件だけ忘れる。
            if status >= 400 {
                let _ = update_pending(auth, store, |list| remove_pending(&list, &state)).await;
            }
            request_failed(&format!("request failed ({status})"), Some(status))
        }
        // 答えがない(タイムアウト、切断)ときは、メールが送られた可能性があるので、state は残す。
        Err(error) => request_failed(failure_reason(&error), None),
    }
}

// --- 2〜3. リンクを受け取って、セッションに引き換える ---

#[derive(Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum AcceptOutcome {
    /// ログインのリンクではない、または 2 回目に届いた同じリンク。何もしない。
    Ignored,
    /// ログインのリンクに見えるが、自分が頼んだものではない(または Web が断った)。
    Rejected {
        reason: String,
    },
    Stored,
    Failed {
        reason: String,
    },
}

fn accept_failed(reason: &str) -> AcceptOutcome {
    AcceptOutcome::Failed {
        reason: reason.to_string(),
    }
}

pub async fn accept_sign_in_link(
    auth: &AuthState,
    store: &dyn Store,
    base: &str,
    link: &str,
) -> AcceptOutcome {
    let (code, state) = match judge_link(link) {
        LinkVerdict::Ignored => return AcceptOutcome::Ignored,
        LinkVerdict::Rejected(reason) => {
            // 拒否も 2 回届くことがある。state ごとに 1 回だけ知らせる。
            if let Some(state) = link_state(link)
                && !auth.first_time(format!("refused:{state}"))
            {
                return AcceptOutcome::Ignored;
            }
            return AcceptOutcome::Rejected {
                reason: reason.to_string(),
            };
        }
        LinkVerdict::Code { code, state } => (code, state),
    };
    if !auth.first_time(code.clone()) {
        return AcceptOutcome::Ignored;
    }

    // 一致した state は、ここで使い切る(同じリンクを使い回せない)。引き換えが失敗しても戻らない。
    let consumed = {
        let _guard = auth.pending_lock.lock().await;
        let list = match store.load(Slot::Pending) {
            Ok(raw) => parse_pending_list(raw.as_deref()),
            Err(_) => return accept_failed("storage failed"),
        };
        let consumed = consume_pending(&list, &state, now_ms());
        let rest = match &consumed {
            Consumed::Accepted { rest, .. } | Consumed::Refused { rest, .. } => rest,
        };
        if save_pending(store, rest).is_err() {
            return accept_failed("storage failed");
        }
        consumed
    };
    let pending = match consumed {
        Consumed::Accepted { pending, .. } => pending,
        Consumed::Refused { reason, .. } => {
            return AcceptOutcome::Rejected {
                reason: reason.message().to_string(),
            };
        }
    };

    let Some(session) = exchange_code(base, &code, &pending.verifier).await else {
        return accept_failed("exchange refused");
    };
    match store.save(Slot::Session, &session.pair()) {
        Ok(()) => AcceptOutcome::Stored,
        Err(_) => accept_failed("storage failed"),
    }
}

/// 1 回限りの `code` と `verifier` を、セッションに引き換える。Web は、`SHA-256(verifier)` が、
/// リンクを頼んだときの challenge と合うかを調べる。失敗の理由は区別しない(Web も区別しない)。
async fn exchange_code(base: &str, code: &str, verifier: &str) -> Option<SessionCookie> {
    let res = client()
        .ok()?
        .post(format!("{base}/api/mobile/exchange"))
        .json(&serde_json::json!({ "code": code, "verifier": verifier }))
        .send()
        .await
        .ok()?;
    if !res.status().is_success() {
        return None;
    }
    let body: serde_json::Value = serde_json::from_slice(&read_limited(res).await?).ok()?;
    parse_session_cookie(body.get("cookie")?.as_str()?)
}

// --- ログイン状態、ログアウト ---

/// Keychain に、読めるセッションがあるか。Web に確かめてはいない(失効は、使ったときに分かる)。
pub fn is_signed_in(store: &dyn Store) -> bool {
    matches!(store.load(Slot::Session), Ok(Some(raw)) if parse_session_cookie(&raw).is_some())
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SignOutOutcome {
    /// この Mac のセッションは消えた。`server_notified` は、Web にも伝わったか(伝わらなくても、
    /// サーバー側のセッションは期限で切れる)。
    SignedOut { server_notified: bool },
    /// この Mac のセッションを消せなかった(まだログイン中)。
    Failed { reason: String },
}

pub async fn sign_out(store: &dyn Store, base: &str) -> SignOutOutcome {
    let session = match store.load(Slot::Session) {
        Ok(raw) => raw.as_deref().and_then(parse_session_cookie),
        Err(_) => {
            return SignOutOutcome::Failed {
                reason: "storage failed".to_string(),
            };
        }
    };
    // Web への通知は、うまくいかなくてもよい。ここで止まると、画面から出られなくなる。
    let server_notified = match &session {
        Some(session) => notify_sign_out(base, session).await,
        None => false,
    };
    match store.delete(Slot::Session) {
        Ok(()) => SignOutOutcome::SignedOut { server_notified },
        Err(_) => SignOutOutcome::Failed {
            reason: "storage failed".to_string(),
        },
    }
}

async fn notify_sign_out(base: &str, session: &SessionCookie) -> bool {
    let Ok(client) = client() else { return false };
    client
        .post(format!("{base}/api/auth/sign-out"))
        // Bearer は `/token` 以外では受け付けられない。ここは Cookie で送る。
        .header("cookie", session.pair())
        .header("expo-origin", origin())
        .json(&serde_json::json!({}))
        .send()
        .await
        .is_ok_and(|res| res.status().is_success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::testing::MemoryStore;
    use crate::sign_in_rules::PENDING_MAX_AGE_MS;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    const VERIFIER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 43 文字

    /// 決まった応答を順に返す、ローカルの偽の Web。受け取った要求(ヘッダーと本文)を溜める。
    struct Mock {
        base: String,
        requests: Arc<StdMutex<Vec<String>>>,
    }

    fn serve(responses: Vec<(u16, &'static str)>) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(StdMutex::new(Vec::new()));
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
    fn dead_base() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    }

    fn run<T>(future: impl std::future::Future<Output = T>) -> T {
        tauri::async_runtime::block_on(future)
    }

    fn pending_list(store: &MemoryStore) -> Vec<Pending> {
        parse_pending_list(store.load(Slot::Pending).unwrap().as_deref())
    }

    fn open_request(store: &MemoryStore, state: &str) {
        let list = vec![Pending {
            state: state.to_string(),
            verifier: VERIFIER.to_string(),
            created_at: now_ms(),
        }];
        store
            .save(Slot::Pending, &serde_json::to_string(&list).unwrap())
            .unwrap();
    }

    fn body_of(request: &str) -> serde_json::Value {
        let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
        serde_json::from_str(body).unwrap()
    }

    fn header_of(request: &str, name: &str) -> Option<String> {
        request.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }

    const SESSION_JSON: &str =
        r#"{"cookie":"better-auth.session_token=tok.sig%3D; Max-Age=604800; Path=/; HttpOnly"}"#;

    // --- マジックリンクを頼む ---

    #[test]
    fn requesting_a_link_remembers_the_request_and_sends_the_challenge_only() {
        let mock = serve(vec![(200, r#"{"status":true}"#)]);
        let (auth, store) = (AuthState::new(), MemoryStore::default());

        let outcome = run(request_sign_in_link(
            &auth,
            &store,
            &mock.base,
            " me@example.com ",
        ));
        assert_eq!(outcome, RequestOutcome::Sent);

        let requests = mock.requests.lock().unwrap();
        let request = &requests[0];
        assert!(request.starts_with("POST /api/auth/sign-in/magic-link "));
        assert_eq!(
            header_of(request, "expo-origin").as_deref(),
            Some("betterauthmulti://")
        );
        assert_eq!(header_of(request, "cookie"), None);
        let body = body_of(request);
        assert_eq!(body["email"], "me@example.com");
        let callback = body["callbackURL"].as_str().unwrap();

        let list = pending_list(&store);
        assert_eq!(list.len(), 1);
        let p = &list[0];
        // callbackURL には state と challenge が入り、verifier は入らない。
        assert_eq!(
            callback,
            callback_url(&p.state, &challenge_for(&p.verifier))
        );
        assert!(!request.contains(&p.verifier));
    }

    #[test]
    fn a_refused_request_forgets_only_that_state() {
        let mock = serve(vec![(429, r#"{"message":"too many"}"#)]);
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        open_request(&store, "older");

        let outcome = run(request_sign_in_link(
            &auth,
            &store,
            &mock.base,
            "me@example.com",
        ));
        assert_eq!(
            outcome,
            RequestOutcome::Failed {
                reason: "request failed (429)".to_string(),
                status: Some(429)
            }
        );
        let states: Vec<_> = pending_list(&store).into_iter().map(|p| p.state).collect();
        assert_eq!(states, ["older"]);
    }

    #[test]
    fn when_there_is_no_answer_the_request_is_kept() {
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        let outcome = run(request_sign_in_link(
            &auth,
            &store,
            &dead_base(),
            "me@example.com",
        ));
        assert!(matches!(
            outcome,
            RequestOutcome::Failed { status: None, .. }
        ));
        // メールが送られた可能性があるので、state は残す。
        assert_eq!(pending_list(&store).len(), 1);
    }

    #[test]
    fn a_bad_email_sends_nothing_and_remembers_nothing() {
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        let outcome = run(request_sign_in_link(&auth, &store, &dead_base(), "nope"));
        assert_eq!(outcome, request_failed("invalid email", None));
        assert!(pending_list(&store).is_empty());
    }

    // --- リンクを受け取る ---

    fn link(state: &str, code: &str) -> String {
        format!("betterauthmulti:///?state={state}&code={code}")
    }

    #[test]
    fn a_link_of_ours_is_traded_for_a_session_and_stored_once() {
        let mock = serve(vec![(200, SESSION_JSON)]);
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        open_request(&store, "st1");

        let outcome = run(accept_sign_in_link(
            &auth,
            &store,
            &mock.base,
            &link("st1", "code1"),
        ));
        assert_eq!(outcome, AcceptOutcome::Stored);

        // verifier と code が Web に渡り、保存されるのは session_token の「名前=値」だけ。
        let body = body_of(&mock.requests.lock().unwrap()[0]);
        assert_eq!(body["code"], "code1");
        assert_eq!(body["verifier"], VERIFIER);
        assert_eq!(
            store.load(Slot::Session).unwrap().as_deref(),
            Some("better-auth.session_token=tok.sig%3D")
        );
        assert!(is_signed_in(&store));
        // 使い切った。
        assert!(pending_list(&store).is_empty());

        // 同じリンクがもう一度届いても、何もしない(Web にも行かない)。
        let again = run(accept_sign_in_link(
            &auth,
            &store,
            &mock.base,
            &link("st1", "code1"),
        ));
        assert_eq!(again, AcceptOutcome::Ignored);
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_link_we_did_not_ask_for_is_refused_and_leaves_our_request_alone() {
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        open_request(&store, "mine");

        let outcome = run(accept_sign_in_link(
            &auth,
            &store,
            &dead_base(),
            &link("evil", "c"),
        ));
        assert_eq!(
            outcome,
            AcceptOutcome::Rejected {
                reason: "state does not match".to_string()
            }
        );
        assert_eq!(pending_list(&store).len(), 1);
        assert!(!is_signed_in(&store));
    }

    #[test]
    fn a_link_with_no_request_at_all_is_refused() {
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        let outcome = run(accept_sign_in_link(
            &auth,
            &store,
            &dead_base(),
            &link("x", "c"),
        ));
        assert_eq!(
            outcome,
            AcceptOutcome::Rejected {
                reason: "no sign-in was requested from this app".to_string()
            }
        );
    }

    #[test]
    fn an_expired_request_is_refused() {
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        let list = vec![Pending {
            state: "old".to_string(),
            verifier: VERIFIER.to_string(),
            created_at: now_ms().saturating_sub(PENDING_MAX_AGE_MS + 1000),
        }];
        store
            .save(Slot::Pending, &serde_json::to_string(&list).unwrap())
            .unwrap();
        let outcome = run(accept_sign_in_link(
            &auth,
            &store,
            &dead_base(),
            &link("old", "c"),
        ));
        assert_eq!(
            outcome,
            AcceptOutcome::Rejected {
                reason: "the request has expired".to_string()
            }
        );
    }

    #[test]
    fn a_failed_exchange_still_uses_up_the_request() {
        let mock = serve(vec![(400, r#"{"error":"invalid_code"}"#)]);
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        open_request(&store, "st1");

        let outcome = run(accept_sign_in_link(
            &auth,
            &store,
            &mock.base,
            &link("st1", "c"),
        ));
        assert_eq!(outcome, accept_failed("exchange refused"));
        assert!(pending_list(&store).is_empty());
        assert!(!is_signed_in(&store));
    }

    #[test]
    fn an_exchange_without_a_session_stores_nothing() {
        for body in [
            r#"{"cookie":"better-auth.session_token=; Max-Age=0"}"#,
            r#"{"cookie":1}"#,
            "{}",
            "junk",
        ] {
            let mock = serve(vec![(200, body)]);
            let (auth, store) = (AuthState::new(), MemoryStore::default());
            open_request(&store, "st1");
            let outcome = run(accept_sign_in_link(
                &auth,
                &store,
                &mock.base,
                &link("st1", "c"),
            ));
            assert_eq!(outcome, accept_failed("exchange refused"), "{body}");
            assert_eq!(store.load(Slot::Session).unwrap(), None);
        }
    }

    #[test]
    fn a_link_with_a_session_in_it_is_refused_once() {
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        let bad = "betterauthmulti:///?state=s&code=c&cookie=better-auth.session_token%3Dx";
        let first = run(accept_sign_in_link(&auth, &store, &dead_base(), bad));
        assert!(matches!(first, AcceptOutcome::Rejected { .. }));
        // 2 回届いても、知らせるのは 1 回。
        assert_eq!(
            run(accept_sign_in_link(&auth, &store, &dead_base(), bad)),
            AcceptOutcome::Ignored
        );
        assert!(!is_signed_in(&store));
    }

    #[test]
    fn links_that_are_not_sign_ins_are_ignored() {
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        for l in ["betterauthmulti:///", "betterauthmulti:///?x=1", "junk"] {
            assert_eq!(
                run(accept_sign_in_link(&auth, &store, &dead_base(), l)),
                AcceptOutcome::Ignored
            );
        }
    }

    // --- ログアウト ---

    fn sign_in(store: &MemoryStore) {
        store
            .save(Slot::Session, "better-auth.session_token=tok.sig%3D")
            .unwrap();
    }

    #[test]
    fn signing_out_tells_the_web_app_with_a_cookie_and_forgets_the_session() {
        let mock = serve(vec![(200, r#"{"success":true}"#)]);
        let store = MemoryStore::default();
        sign_in(&store);

        assert_eq!(
            run(sign_out(&store, &mock.base)),
            SignOutOutcome::SignedOut {
                server_notified: true
            }
        );
        assert!(!is_signed_in(&store));
        let requests = mock.requests.lock().unwrap();
        assert!(requests[0].starts_with("POST /api/auth/sign-out "));
        assert_eq!(
            header_of(&requests[0], "cookie").as_deref(),
            Some("better-auth.session_token=tok.sig%3D")
        );
        assert_eq!(header_of(&requests[0], "authorization"), None);
    }

    #[test]
    fn signing_out_forgets_the_session_even_when_the_web_app_cannot_be_reached() {
        let store = MemoryStore::default();
        sign_in(&store);
        assert_eq!(
            run(sign_out(&store, &dead_base())),
            SignOutOutcome::SignedOut {
                server_notified: false
            }
        );
        assert!(!is_signed_in(&store));
    }

    #[test]
    fn signing_out_when_not_signed_in_sends_nothing() {
        let store = MemoryStore::default();
        assert_eq!(
            run(sign_out(&store, &dead_base())),
            SignOutOutcome::SignedOut {
                server_notified: false
            }
        );
    }

    #[test]
    fn a_stored_value_that_is_not_a_session_does_not_count_as_signed_in() {
        let store = MemoryStore::default();
        store.save(Slot::Session, "garbage").unwrap();
        assert!(!is_signed_in(&store));
    }
}

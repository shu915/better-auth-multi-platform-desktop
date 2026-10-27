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
    pub(crate) pending_lock: Mutex<()>,
    /// セッションの「保存」と「消す」が、同時に走らないようにする。古いセッションの失敗で、新しく保存した
    /// セッションを消してしまわないよう、消すときは、この錠の中で「今あるのが、失敗した時に使ったものと
    /// 同じか」を確かめる(profile.rs の `end_session`)。
    pub(crate) session_lock: Mutex<()>,
    seen: StdMutex<Vec<String>>,
    /// 最後に処理したリンクの結果。画面は、これを Rust のコマンドで取りに行く(イベントは「何か起きた」
    /// という合図だけ)。起動時のリンクは、画面が準備できる前に処理が終わることがあるので、画面が
    /// 後から取れるように、ここに残す。
    last_outcome: StdMutex<Option<AcceptOutcome>>,
}

impl AuthState {
    pub fn new() -> Self {
        AuthState {
            pending_lock: Mutex::new(()),
            session_lock: Mutex::new(()),
            seen: StdMutex::new(Vec::new()),
            last_outcome: StdMutex::new(None),
        }
    }

    /// リンクの結果を残す(前のものは置き換える)。ただし、`Stored` と `Failed`(自分が頼んだリンクの
    /// 結果)は、`Rejected`(頼んでいないリンク)では置き換えない。画面が取る前に、第三者のリンクが
    /// 届いても、正規の結果の表示が消えないように。
    pub fn set_outcome(&self, outcome: AcceptOutcome) {
        if let Ok(mut last) = self.last_outcome.lock() {
            let keeps = matches!(outcome, AcceptOutcome::Rejected { .. })
                && matches!(
                    *last,
                    Some(AcceptOutcome::Stored | AcceptOutcome::Failed { .. })
                );
            if !keeps {
                *last = Some(outcome);
            }
        }
    }

    /// 残っている結果を渡して、空にする(同じ結果を 2 回表示しない)。
    pub fn take_outcome(&self) -> Option<AcceptOutcome> {
        self.last_outcome.lock().ok()?.take()
    }

    /// 初めて見るなら `true`(覚える)。2 回目以降は `false`。
    fn first_time(&self, key: String) -> bool {
        // 錠が壊れていたら、通さない側に倒す(同じリンクの二重処理より、取りこぼしのほうが安全)。
        let Ok(mut seen) = self.seen.lock() else {
            return false;
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

/// 拒否したリンクの state を覚えるときのキー。長い state で、覚えている件数を押し出されないよう、
/// 長さに上限を付ける。
fn refused_key(state: &str) -> String {
    format!("refused:{}", state.chars().take(64).collect::<String>())
}

/// Web に `Origin` として見せる値。Web の `expo()` は `expo-origin` ヘッダーを Origin に置き換えるので、
/// これが `trustedOrigins`(`betterauthmulti://`)と一致して、Origin の検査を通る。
fn origin() -> String {
    format!("{APP_SCHEME}://")
}

pub(crate) fn client() -> Result<reqwest::Client, &'static str> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        // 応答がリダイレクトでも追わない(セッションを載せたまま別の場所へ行かない)。
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "http client failed")
}

/// デバッグビルドだけ、原因の切り分けのために標準エラーに出す(リリースビルドでは何も出さない)。
/// 出してよいのは、固定の種類名、HTTP ステータス、Keychain のエラーの種類だけ。秘密(verifier、
/// code、セッションの値)は、決して渡さない。
pub(crate) fn debug_log(message: &str) {
    if cfg!(debug_assertions) {
        eprintln!("[auth] {message}");
    }
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
pub(crate) async fn read_limited(mut res: reqwest::Response) -> Option<Vec<u8>> {
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
                && !auth.first_time(refused_key(&state))
            {
                return AcceptOutcome::Ignored;
            }
            return AcceptOutcome::Rejected {
                reason: reason.to_string(),
            };
        }
        LinkVerdict::Code { code, state } => (code, state),
    };
    // code を、state の確認より先に記録する。同じリンクの二重配信で、引き換えを 2 回走らせないため。
    // 代わりに、適当な code で届いた他人のリンクの code も、記録に入る(件数は SEEN_MAX まで)。同じ
    // code の正規のリンクは存在しない(code は Web が作る)ので、実害はない。ただし、同じ URL を
    // 繰り返して試すときは、code を毎回変えること(2 回目からは `Ignored` で、何も出ない)。
    if !auth.first_time(code.clone()) {
        return AcceptOutcome::Ignored;
    }

    // 一致した state は、ここで使い切る(同じリンクを使い回せない)。引き換えが失敗しても戻らない。
    let consumed = {
        let _guard = auth.pending_lock.lock().await;
        let list = match store.load(Slot::Pending) {
            Ok(raw) => parse_pending_list(raw.as_deref()),
            Err(error) => {
                debug_log(&format!("loading pending failed: {error:?}"));
                return accept_failed("storage failed");
            }
        };
        let consumed = consume_pending(&list, &state, now_ms());
        let rest = match &consumed {
            Consumed::Accepted { rest, .. } | Consumed::Refused { rest, .. } => rest,
        };
        if let Err(error) = save_pending(store, rest) {
            debug_log(&format!("saving pending failed: {error:?}"));
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
    let saved = {
        let _guard = auth.session_lock.lock().await;
        store.save(Slot::Session, &session.pair())
    };
    match saved {
        Ok(()) => AcceptOutcome::Stored,
        Err(error) => {
            debug_log(&format!("saving the session failed: {error:?}"));
            accept_failed("storage failed")
        }
    }
}

/// 1 回限りの `code` と `verifier` を、セッションに引き換える。Web は、`SHA-256(verifier)` が、
/// リンクを頼んだときの challenge と合うかを調べる。失敗の理由は区別しない(Web も区別しない)。
async fn exchange_code(base: &str, code: &str, verifier: &str) -> Option<SessionCookie> {
    let sent = client()
        .ok()?
        .post(format!("{base}/api/mobile/exchange"))
        .json(&serde_json::json!({ "code": code, "verifier": verifier }))
        .send()
        .await;
    let res = match sent {
        Ok(res) => res,
        Err(error) => {
            debug_log(&format!("exchange: {}", failure_reason(&error)));
            return None;
        }
    };
    if !res.status().is_success() {
        debug_log(&format!(
            "exchange: refused with status {}",
            res.status().as_u16()
        ));
        return None;
    }
    let body: serde_json::Value = serde_json::from_slice(&read_limited(res).await?).ok()?;
    let session = body
        .get("cookie")
        .and_then(|c| c.as_str())
        .and_then(parse_session_cookie);
    if session.is_none() {
        debug_log("exchange: the answer held no session");
    }
    session
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

pub async fn sign_out(auth: &AuthState, store: &dyn Store, base: &str) -> SignOutOutcome {
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
    // 頼んだまま届いていないメールのリンクで、ログアウトのあとに再びログインされないよう、
    // pending も消す。消せなくても、セッションが消えれば、ログアウトとしては成功。
    {
        let _guard = auth.pending_lock.lock().await;
        if let Err(error) = store.delete(Slot::Pending) {
            debug_log(&format!("clearing pending failed: {error:?}"));
        }
    }
    let deleted = {
        let _guard = auth.session_lock.lock().await;
        store.delete(Slot::Session)
    };
    match deleted {
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
    use crate::test_support::{body_of, dead_base, header_of, run, serve};

    const VERIFIER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 43 文字

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
            run(sign_out(&AuthState::new(), &store, &mock.base)),
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
            run(sign_out(&AuthState::new(), &store, &dead_base())),
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
            run(sign_out(&AuthState::new(), &store, &dead_base())),
            SignOutOutcome::SignedOut {
                server_notified: false
            }
        );
    }

    #[test]
    fn signing_out_also_forgets_a_mail_link_that_was_asked_for_but_not_used() {
        let store = MemoryStore::default();
        sign_in(&store);
        open_request(&store, "st1");
        run(sign_out(&AuthState::new(), &store, &dead_base()));
        assert!(pending_list(&store).is_empty());
    }

    #[test]
    fn the_last_outcome_is_kept_until_taken_and_taken_once() {
        let auth = AuthState::new();
        assert_eq!(auth.take_outcome(), None);
        auth.set_outcome(AcceptOutcome::Rejected {
            reason: "x".to_string(),
        });
        auth.set_outcome(AcceptOutcome::Stored); // 新しい結果が、前のものを置き換える
        assert_eq!(auth.take_outcome(), Some(AcceptOutcome::Stored));
        assert_eq!(auth.take_outcome(), None);
    }

    #[test]
    fn a_link_we_did_not_ask_for_does_not_replace_the_result_of_one_we_did() {
        let rejected = || AcceptOutcome::Rejected {
            reason: "x".to_string(),
        };
        let failed = || AcceptOutcome::Failed {
            reason: "exchange refused".to_string(),
        };
        for ours in [AcceptOutcome::Stored, failed()] {
            let auth = AuthState::new();
            auth.set_outcome(ours);
            auth.set_outcome(rejected());
            assert_ne!(auth.take_outcome(), Some(rejected()));
        }
        // 頼んでいないリンクどうしは、新しいほうに置き換わる。
        let auth = AuthState::new();
        auth.set_outcome(AcceptOutcome::Rejected {
            reason: "first".to_string(),
        });
        auth.set_outcome(AcceptOutcome::Rejected {
            reason: "second".to_string(),
        });
        assert_eq!(
            auth.take_outcome(),
            Some(AcceptOutcome::Rejected {
                reason: "second".to_string()
            })
        );
    }

    #[test]
    fn the_key_for_a_refused_link_has_a_length_limit() {
        assert_eq!(refused_key("abc"), "refused:abc");
        assert_eq!(refused_key(&"x".repeat(1000)).len(), "refused:".len() + 64);
    }

    #[test]
    fn what_the_screen_is_told_holds_only_a_kind_and_a_fixed_reason() {
        let json = |outcome: &AcceptOutcome| serde_json::to_string(outcome).unwrap();
        assert_eq!(json(&AcceptOutcome::Stored), r#"{"kind":"stored"}"#);
        assert_eq!(json(&AcceptOutcome::Ignored), r#"{"kind":"ignored"}"#);
        assert_eq!(
            json(&AcceptOutcome::Rejected {
                reason: "state does not match".to_string()
            }),
            r#"{"kind":"rejected","reason":"state does not match"}"#
        );
        assert_eq!(
            serde_json::to_string(&SignOutOutcome::SignedOut {
                server_notified: true
            })
            .unwrap(),
            r#"{"kind":"signedOut","server_notified":true}"#
        );
    }

    #[test]
    fn a_stored_value_that_is_not_a_session_does_not_count_as_signed_in() {
        let store = MemoryStore::default();
        store.save(Slot::Session, "garbage").unwrap();
        assert!(!is_signed_in(&store));
    }
}

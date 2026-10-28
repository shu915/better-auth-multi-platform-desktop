//! Google の連携(一覧、紐づけ、解除)の通信。判断は `link_rules.rs` と `api_parse.rs` の純粋な関数に
//! 任せ、ここは「呼ぶ順番」と通信だけ。モバイルの `google-link.ts` に当たる。
//!
//! 呼び先は Better Auth の口(`/api/auth/list-accounts`、`/link-social`、`/unlink-account`)で、セッションを
//! `Cookie` ヘッダーで送る(Bearer は `/token` 以外では断られる)。紐づけと解除には、Web が「5 分以内の
//! ログイン」を求める(`SESSION_NOT_FRESH`)。
//!
//! 紐づけは、Google の認可 URL をもらい、**システムのブラウザ**で、Web のプロキシ経由で開く。ブラウザは
//! Google の画面を通ってから、`betterauthmulti:///?link=<目印>` でアプリに戻る(`link_rules.rs`)。
//! アプリは戻りを受けても、結果を決めない: 画面が、連携の一覧を読み直して決める(モバイルと同じ)。

use serde::Serialize;

use crate::api_parse::{LinkedAccount, parse_accounts, parse_authorization_url, parse_error_code};
use crate::auth::{AuthState, client};
use crate::link_rules::{
    AccountFailure, classify_account_failure, link_callback_url, link_return_token, proxy_url,
    token_from_bytes,
};
use crate::profile::{Reply, call, end_session, read_session};
use crate::secret::Store;
use crate::session_cookie::SessionCookie;
use crate::sign_in_rules::APP_SCHEME;

const GOOGLE: &str = "google";

/// システムのブラウザで URL を開く。テストでは、記録するだけのものに替える。
pub trait Opener: Sync {
    /// 開けたら `true`。
    fn open(&self, url: &str) -> bool;
}

/// macOS の `open`(既定のブラウザ)。シェルを通さず、URL は 1 つの引数として渡す。呼ぶ前に、URL は
/// `proxy_url` が作った、自分の Web のものであることが決まっている。
pub struct SystemOpener;

impl Opener for SystemOpener {
    fn open(&self, url: &str) -> bool {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return false;
        }
        // 終わりを待たずに起動する(待つと、LaunchServices が遅いとき、実行スレッドが止まる)。
        // 終了の回収(ゾンビを残さない)は、別のスレッドで行う。
        match std::process::Command::new("open").arg(url).spawn() {
            Ok(mut child) => {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                true
            }
            Err(_) => false,
        }
    }
}

/// Web に `Origin` として見せる値(`auth.rs` の `origin` と同じ)。
fn origin() -> String {
    format!("{APP_SCHEME}://")
}

// --- 一覧 ---

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum AccountsOutcome {
    /// 連携の一覧から、Google が紐づいているか。(アカウントの ID は、画面に出さない。)
    Loaded {
        google_linked: bool,
    },
    SessionEnded,
    Failed,
}

/// 失敗した呼び出しの、ステータスと、本文の `code`。
struct Failed {
    status: Option<u16>,
    code: Option<String>,
}

fn failed_reply(reply: Option<&Reply>) -> Failed {
    Failed {
        status: reply.map(|r| r.status),
        code: reply
            .and_then(|r| r.body.as_ref())
            .and_then(parse_error_code)
            .map(str::to_string),
    }
}

async fn fetch_accounts(web: &str, session: &SessionCookie) -> Result<Vec<LinkedAccount>, Failed> {
    let http = client().map_err(|_| failed_reply(None))?;
    let reply = call(
        http.get(format!("{web}/api/auth/list-accounts"))
            .header("cookie", session.pair()),
    )
    .await;
    match reply {
        Some(r) if r.status == 200 => r
            .body
            .as_ref()
            .and_then(parse_accounts)
            .ok_or_else(|| failed_reply(None)),
        other => Err(failed_reply(other.as_ref())),
    }
}

/// 失敗を、画面に渡す種類にする。401 なら、使ったセッションがまだ今のものであるときだけ消す。
async fn failure_kind(
    auth: &AuthState,
    store: &dyn Store,
    session: &SessionCookie,
    failed: &Failed,
) -> AccountFailure {
    let kind = classify_account_failure(failed.status, failed.code.as_deref());
    if kind == AccountFailure::SessionEnded && !end_session(auth, store, session).await {
        // もう新しいセッションに替わっている。古い答えで、ログアウトさせない。
        return AccountFailure::Failed;
    }
    kind
}

pub async fn load_accounts(auth: &AuthState, store: &dyn Store, web: &str) -> AccountsOutcome {
    let Some(session) = read_session(store) else {
        return AccountsOutcome::SessionEnded;
    };
    match fetch_accounts(web, &session).await {
        Ok(accounts) => AccountsOutcome::Loaded {
            google_linked: accounts.iter().any(|a| a.provider_id == GOOGLE),
        },
        Err(failed) => match failure_kind(auth, store, &session, &failed).await {
            AccountFailure::SessionEnded => AccountsOutcome::SessionEnded,
            _ => AccountsOutcome::Failed,
        },
    }
}

// --- 紐づけ ---

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum LinkOutcome {
    /// ブラウザを開いた。結果は、戻りのあとに、画面が一覧を読み直して決める。
    Started,
    /// 「5 分以内のログイン」が要る。入り直してから、すぐやり直す。
    NotFresh,
    SessionEnded,
    Failed,
}

pub async fn link_google(
    auth: &AuthState,
    store: &dyn Store,
    web: &str,
    opener: &dyn Opener,
) -> LinkOutcome {
    let Some(session) = read_session(store) else {
        return LinkOutcome::SessionEnded;
    };
    let Ok(http) = client() else {
        return LinkOutcome::Failed;
    };
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        return LinkOutcome::Failed;
    }
    let token = token_from_bytes(&bytes);
    let callback = link_callback_url(&token);

    let reply = call(
        http.post(format!("{web}/api/auth/link-social"))
            .header("cookie", session.pair())
            .header("expo-origin", origin())
            .json(&serde_json::json!({
                "provider": GOOGLE,
                "callbackURL": callback,
                "errorCallbackURL": callback,
                "disableRedirect": true,
            })),
    )
    .await;
    let reply = match reply {
        Some(reply) if reply.status == 200 => reply,
        other => {
            let failed = failed_reply(other.as_ref());
            return match failure_kind(auth, store, &session, &failed).await {
                AccountFailure::SessionEnded => LinkOutcome::SessionEnded,
                AccountFailure::NotFresh => LinkOutcome::NotFresh,
                AccountFailure::Failed => LinkOutcome::Failed,
            };
        }
    };
    let Some(proxy) = reply
        .body
        .as_ref()
        .and_then(parse_authorization_url)
        .and_then(|authorization| proxy_url(web, &authorization))
    else {
        return LinkOutcome::Failed;
    };

    // 開く前に覚える。戻りが先に着いても、突き合わせられるように。
    auth.remember_link(&token);
    if opener.open(&proxy) {
        LinkOutcome::Started
    } else {
        LinkOutcome::Failed
    }
}

/// アプリを開いたリンクが、**自分が頼んだ**Google の連携の戻りなら `true`(目印を使い切る)。
/// 頼んでいないもの、2 回目、古いものは `false`(画面に何も出さない)。
pub fn accept_link_return(auth: &AuthState, link: &str) -> bool {
    link_return_token(link).is_some_and(|token| auth.use_link(&token))
}

// --- 解除 ---

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum UnlinkOutcome {
    Unlinked,
    /// 解除する Google が、もうない(別の場所で解除済み)。
    NotLinked,
    NotFresh,
    SessionEnded,
    Failed,
}

/// Google を外す。アカウントの ID は、Rust が一覧から探す(画面には出さず、画面から受け取らない)。
pub async fn unlink_google(auth: &AuthState, store: &dyn Store, web: &str) -> UnlinkOutcome {
    let Some(session) = read_session(store) else {
        return UnlinkOutcome::SessionEnded;
    };
    let accounts = match fetch_accounts(web, &session).await {
        Ok(accounts) => accounts,
        Err(failed) => return unlink_failure(auth, store, &session, &failed).await,
    };
    let Some(google) = accounts.iter().find(|a| a.provider_id == GOOGLE) else {
        return UnlinkOutcome::NotLinked;
    };
    let Ok(http) = client() else {
        return UnlinkOutcome::Failed;
    };
    let reply = call(
        http.post(format!("{web}/api/auth/unlink-account"))
            .header("cookie", session.pair())
            .header("expo-origin", origin())
            .json(&serde_json::json!({ "providerId": GOOGLE, "accountId": google.id })),
    )
    .await;
    match reply {
        Some(reply) if reply.status == 200 => UnlinkOutcome::Unlinked,
        other => unlink_failure(auth, store, &session, &failed_reply(other.as_ref())).await,
    }
}

async fn unlink_failure(
    auth: &AuthState,
    store: &dyn Store,
    session: &SessionCookie,
    failed: &Failed,
) -> UnlinkOutcome {
    match failure_kind(auth, store, session, failed).await {
        AccountFailure::SessionEnded => UnlinkOutcome::SessionEnded,
        AccountFailure::NotFresh => UnlinkOutcome::NotFresh,
        AccountFailure::Failed => UnlinkOutcome::Failed,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::secret::Slot;
    use crate::secret::testing::MemoryStore;
    use crate::test_support::{body_of, dead_base, header_of, run, serve};

    const SESSION: &str = "better-auth.session_token=tok.sig%3D";
    const LINK_ANSWER: &str = r#"{"url":"https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=s","redirect":false}"#;
    const ACCOUNTS: &str =
        r#"[{"id":"a1","providerId":"credential"},{"id":"a2","providerId":"google"}]"#;

    fn signed_in() -> MemoryStore {
        let store = MemoryStore::default();
        store.save(Slot::Session, SESSION).unwrap();
        store
    }

    fn has_session(store: &MemoryStore) -> bool {
        store.load(Slot::Session).unwrap().is_some()
    }

    struct Recording {
        opened: Mutex<Vec<String>>,
        works: bool,
    }

    impl Recording {
        fn new(works: bool) -> Self {
            Recording {
                opened: Mutex::new(Vec::new()),
                works,
            }
        }
    }

    impl Opener for Recording {
        fn open(&self, url: &str) -> bool {
            self.opened.lock().unwrap().push(url.to_string());
            self.works
        }
    }

    // --- 一覧 ---

    #[test]
    fn the_list_says_whether_google_is_linked_and_sends_the_session_as_a_cookie() {
        let web = serve(vec![
            (200, ACCOUNTS),
            (200, r#"[{"id":"a1","providerId":"credential"}]"#),
        ]);
        let store = signed_in();

        assert_eq!(
            run(load_accounts(&AuthState::new(), &store, &web.base)),
            AccountsOutcome::Loaded {
                google_linked: true
            }
        );
        assert_eq!(
            run(load_accounts(&AuthState::new(), &store, &web.base)),
            AccountsOutcome::Loaded {
                google_linked: false
            }
        );
        let requests = web.requests.lock().unwrap();
        assert!(requests[0].starts_with("GET /api/auth/list-accounts "));
        assert_eq!(header_of(&requests[0], "cookie").as_deref(), Some(SESSION));
        assert_eq!(header_of(&requests[0], "authorization"), None);
    }

    #[test]
    fn a_401_ends_the_session_and_other_failures_keep_it() {
        let web = serve(vec![(401, "{}"), (500, "{}")]);
        let store = signed_in();
        assert_eq!(
            run(load_accounts(&AuthState::new(), &store, &web.base)),
            AccountsOutcome::SessionEnded
        );
        assert!(!has_session(&store));

        let store = signed_in();
        assert_eq!(
            run(load_accounts(&AuthState::new(), &store, &web.base)),
            AccountsOutcome::Failed
        );
        assert!(has_session(&store));
        assert_eq!(
            run(load_accounts(&AuthState::new(), &store, &dead_base())),
            AccountsOutcome::Failed
        );
        // セッションがなければ、誰にも聞かない。
        assert_eq!(
            run(load_accounts(
                &AuthState::new(),
                &MemoryStore::default(),
                &dead_base()
            )),
            AccountsOutcome::SessionEnded
        );
    }

    #[test]
    fn an_unreadable_list_is_a_failure_not_an_unlinked_google() {
        let web = serve(vec![
            (200, "<html>proxy</html>"),
            (200, r#"{"not":"a list"}"#),
        ]);
        let store = signed_in();
        for _ in 0..2 {
            assert_eq!(
                run(load_accounts(&AuthState::new(), &store, &web.base)),
                AccountsOutcome::Failed
            );
        }
    }

    // --- 紐づけ ---

    #[test]
    fn linking_opens_our_proxy_in_the_browser_and_remembers_the_return() {
        let web = serve(vec![(200, LINK_ANSWER)]);
        let store = signed_in();
        let opener = Recording::new(true);
        let auth = AuthState::new();

        assert_eq!(
            run(link_google(&auth, &store, &web.base, &opener)),
            LinkOutcome::Started
        );

        let requests = web.requests.lock().unwrap();
        assert!(requests[0].starts_with("POST /api/auth/link-social "));
        assert_eq!(header_of(&requests[0], "cookie").as_deref(), Some(SESSION));
        assert_eq!(
            header_of(&requests[0], "expo-origin").as_deref(),
            Some("betterauthmulti://")
        );
        let body = body_of(&requests[0]);
        assert_eq!(body["provider"], "google");
        assert_eq!(body["disableRedirect"], true);
        // 戻り先は、成功も断られたときも同じ(セッションも code も state も載せない)。
        let callback = body["callbackURL"].as_str().unwrap().to_string();
        assert_eq!(body["errorCallbackURL"], callback.as_str());
        assert!(callback.starts_with("betterauthmulti:///?link="));

        let opened = opener.opened.lock().unwrap();
        assert_eq!(opened.len(), 1);
        assert!(opened[0].starts_with(&format!(
            "{}/api/auth/expo-authorization-proxy?authorizationURL=",
            web.base
        )));
        assert!(opened[0].contains("accounts.google.com"));

        // 戻りは、頼んだものだけが 1 回通る。
        assert!(accept_link_return(&auth, &callback));
        assert!(!accept_link_return(&auth, &callback));
    }

    #[test]
    fn the_returns_of_a_user_who_left_are_forgotten() {
        let auth = AuthState::new();
        let token = "0123456789abcdef0123456789abcdef";
        auth.remember_link(token);
        auth.set_link_error(Some("state_mismatch".to_string()));
        auth.forget_links();
        assert!(!accept_link_return(
            &auth,
            &format!("betterauthmulti:///?link={token}")
        ));
        assert_eq!(auth.take_link_error(), None);
    }

    #[test]
    fn ending_a_session_forgets_the_returns() {
        let web = serve(vec![(401, "{}")]);
        let auth = AuthState::new();
        let token = "0123456789abcdef0123456789abcdef";
        auth.remember_link(token);
        assert_eq!(
            run(load_accounts(&auth, &signed_in(), &web.base)),
            AccountsOutcome::SessionEnded
        );
        assert!(!accept_link_return(
            &auth,
            &format!("betterauthmulti:///?link={token}")
        ));
    }

    #[test]
    fn a_return_nobody_asked_for_is_not_accepted() {
        let auth = AuthState::new();
        let other = "betterauthmulti:///?link=0123456789abcdef0123456789abcdef";
        assert!(!accept_link_return(&auth, other));
        assert!(!accept_link_return(
            &auth,
            "betterauthmulti:///?state=s&code=c"
        ));
        assert!(!accept_link_return(&auth, "not a url"));
    }

    #[test]
    fn a_link_that_needs_a_fresh_sign_in_opens_nothing() {
        let web = serve(vec![(
            403,
            r#"{"code":"SESSION_NOT_FRESH","message":"Session is not fresh"}"#,
        )]);
        let store = signed_in();
        let opener = Recording::new(true);

        assert_eq!(
            run(link_google(&AuthState::new(), &store, &web.base, &opener)),
            LinkOutcome::NotFresh
        );
        assert!(opener.opened.lock().unwrap().is_empty());
        assert!(has_session(&store));
    }

    #[test]
    fn linking_failures_open_nothing_and_a_401_ends_the_session() {
        let opener = Recording::new(true);
        let store = signed_in();
        let web = serve(vec![(401, "{}")]);
        assert_eq!(
            run(link_google(&AuthState::new(), &store, &web.base, &opener)),
            LinkOutcome::SessionEnded
        );
        assert!(!has_session(&store));

        let store = signed_in();
        for (status, body) in [
            (403, r#"{"code":"SERVER_ONLY"}"#),
            (500, "{}"),
            (200, r#"{"url":"https://evil.example/"}"#),
            (200, r#"{"redirect":false}"#),
            (200, "<html>proxy</html>"),
        ] {
            let web = serve(vec![(status, body)]);
            assert_eq!(
                run(link_google(&AuthState::new(), &store, &web.base, &opener)),
                LinkOutcome::Failed,
                "{status} {body}"
            );
        }
        assert_eq!(
            run(link_google(
                &AuthState::new(),
                &store,
                &dead_base(),
                &opener
            )),
            LinkOutcome::Failed
        );
        assert!(opener.opened.lock().unwrap().is_empty());
        assert!(has_session(&store));
    }

    #[test]
    fn a_browser_that_cannot_be_opened_is_a_failure() {
        let web = serve(vec![(200, LINK_ANSWER)]);
        assert_eq!(
            run(link_google(
                &AuthState::new(),
                &signed_in(),
                &web.base,
                &Recording::new(false)
            )),
            LinkOutcome::Failed
        );
    }

    #[test]
    fn the_system_opener_refuses_anything_but_a_web_address() {
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "-a Calculator",
            "",
        ] {
            assert!(!SystemOpener.open(url), "{url}");
        }
    }

    // --- 解除 ---

    #[test]
    fn unlinking_sends_the_id_of_the_google_row_that_rust_found() {
        let web = serve(vec![(200, ACCOUNTS), (200, r#"{"status":true}"#)]);
        let store = signed_in();

        assert_eq!(
            run(unlink_google(&AuthState::new(), &store, &web.base)),
            UnlinkOutcome::Unlinked
        );
        let requests = web.requests.lock().unwrap();
        assert!(requests[1].starts_with("POST /api/auth/unlink-account "));
        assert_eq!(header_of(&requests[1], "cookie").as_deref(), Some(SESSION));
        assert_eq!(
            header_of(&requests[1], "expo-origin").as_deref(),
            Some("betterauthmulti://")
        );
        assert_eq!(
            body_of(&requests[1]),
            serde_json::json!({"providerId": "google", "accountId": "a2"})
        );
    }

    #[test]
    fn unlinking_what_is_not_linked_asks_nothing_more() {
        let web = serve(vec![(200, r#"[{"id":"a1","providerId":"credential"}]"#)]);
        assert_eq!(
            run(unlink_google(&AuthState::new(), &signed_in(), &web.base)),
            UnlinkOutcome::NotLinked
        );
        assert_eq!(web.requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn unlinking_failures_are_told_apart() {
        let fresh = r#"{"code":"SESSION_NOT_FRESH"}"#;
        let cases: Vec<(Vec<(u16, &'static str)>, UnlinkOutcome)> = vec![
            (vec![(200, ACCOUNTS), (403, fresh)], UnlinkOutcome::NotFresh),
            (vec![(200, ACCOUNTS), (500, "{}")], UnlinkOutcome::Failed),
            (
                vec![(200, ACCOUNTS), (401, "{}")],
                UnlinkOutcome::SessionEnded,
            ),
            (vec![(401, "{}")], UnlinkOutcome::SessionEnded),
            (vec![(500, "{}")], UnlinkOutcome::Failed),
        ];
        for (answers, expected) in cases {
            let web = serve(answers);
            let store = signed_in();
            let outcome = run(unlink_google(&AuthState::new(), &store, &web.base));
            assert_eq!(outcome, expected);
            assert_eq!(has_session(&store), outcome != UnlinkOutcome::SessionEnded);
        }
        assert_eq!(
            run(unlink_google(
                &AuthState::new(),
                &MemoryStore::default(),
                &dead_base()
            )),
            UnlinkOutcome::SessionEnded
        );
    }

    #[test]
    fn what_the_screen_is_told_has_no_secret() {
        assert_eq!(
            serde_json::to_string(&AccountsOutcome::Loaded {
                google_linked: true
            })
            .unwrap(),
            r#"{"kind":"loaded","googleLinked":true}"#
        );
        assert_eq!(
            serde_json::to_string(&LinkOutcome::NotFresh).unwrap(),
            r#"{"kind":"notFresh"}"#
        );
    }
}

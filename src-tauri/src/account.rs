//! 退会(通信)。モバイルの `delete-account.ts` に当たる。
//!
//! 退会は Web が行う(`DELETE /api/mobile/account`): ユーザーは Web の DB に、データは Go にあり、
//! Web が、自分の「退会」画面と同じ規則で、順に消す。認証は `/api/auth/token` と同じで、セッションを
//! `Authorization: Bearer` で送り、Cookie は付けない。
//!
//! 確認のメールは、利用者が打つ。Web がセッションのメールと突き合わせる(クライアントは判断しない)。
//! 成功したら、この Mac のセッションを消す。消せなくても、退会は済んでいるので `Deleted` を返す。

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::auth::{AuthState, client};
use crate::profile::{Reply, call, end_session, read_session};
use crate::profile_rules::{FailureKind, classify_failure};
use crate::secret::{Slot, Store};

/// Web は、複数の段階(Go の呼び出しを含む)で消す。ふだんの通信より長く待つ。
const TIMEOUT: Duration = Duration::from_secs(20);

/// Web が受け付ける本文の上限(2 KB)に収まる、確認のメールの最大のバイト数。メールアドレスは 254 バイトまで。
const MAX_EMAIL_BYTES: usize = 320;

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum DeleteOutcome {
    /// 退会した。この Mac のセッションは消した(画面はログイン画面へ)。
    Deleted,
    /// 打ったメールが、このアカウントのものではない(空のときは、送らずにこれを返す)。
    EmailMismatch,
    /// ログインが古い。いったんログアウトし、メールのリンクで入り直してから、すぐ退会する。
    NotFresh,
    /// セッションが無効。この Mac のセッションは消した(画面はログイン画面へ)。
    SessionEnded,
    /// 退会できなかった(接続できない、タイムアウト、サーバーの失敗)。Web 側は、どの段階も繰り返して
    /// よい作りなので、もう一度試してよい。
    Failed,
}

pub async fn delete_account(
    auth: &AuthState,
    store: &dyn Store,
    web: &str,
    confirm_email: &str,
) -> DeleteOutcome {
    let email = confirm_email.trim();
    if email.is_empty() || email.len() > MAX_EMAIL_BYTES {
        return DeleteOutcome::EmailMismatch;
    }
    let Some(session) = read_session(store) else {
        return DeleteOutcome::SessionEnded;
    };
    let Ok(http) = client() else {
        return DeleteOutcome::Failed;
    };
    let reply = call(
        http.delete(format!("{web}/api/mobile/account"))
            .timeout(TIMEOUT)
            .bearer_auth(session.bearer())
            .json(&serde_json::json!({ "confirmEmail": email })),
    )
    .await;
    // 答えがない(接続できない、タイムアウト)ときは、Web が終えたかどうか分からない。繰り返してよい。
    let Some(reply) = reply else {
        return DeleteOutcome::Failed;
    };
    match reply.status {
        // 退会の印は、本文の `{"deleted":true}`。200 だけでは、プロキシやメンテナンス画面の 200 を
        // 退会と取り違える(データが残っているのに「退会しました」と出す)。本文が違えば `Failed`
        // (Web はどの段階も繰り返してよい。済んでいれば、次は 401 になる)。
        200 if is_deleted(&reply) => {
            // ユーザーとともに、セッションもなくなった。使ったセッションがまだ今のものなら消し、その
            // ときだけ、リンクの途中の記録(pending)も消す(入り直していたら、新しい側は消さない)。
            // Keychain の削除に失敗しても、退会は済んでいる(無効なセッションは、次の 401 で消える)。
            if end_session(auth, store, &session).await {
                let _guard = auth.pending_lock.lock().await;
                let _ = store.delete(Slot::Pending);
            }
            DeleteOutcome::Deleted
        }
        422 => DeleteOutcome::EmailMismatch,
        // Cookie は付けていないので、Web の 403 は `recent_sign_in_required`(ログインが古い)。
        // ただし、WAF やプロキシの 403 も 403 なので、本文の印まで見る。
        403 if error_of(&reply) == Some("recent_sign_in_required") => DeleteOutcome::NotFresh,
        status => match classify_failure(Some(status)) {
            FailureKind::SessionEnded if end_session(auth, store, &session).await => {
                DeleteOutcome::SessionEnded
            }
            _ => DeleteOutcome::Failed,
        },
    }
}

fn is_deleted(reply: &Reply) -> bool {
    reply.json().and_then(|body| body.get("deleted")) == Some(&Value::Bool(true))
}

fn error_of(reply: &Reply) -> Option<&str> {
    reply.json()?.get("error")?.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::testing::MemoryStore;
    use crate::test_support::{body_of, dead_base, header_of, run, serve};

    const SESSION: &str = "better-auth.session_token=tok.sig%3D";

    fn signed_in() -> MemoryStore {
        let store = MemoryStore::default();
        store.save(Slot::Session, SESSION).unwrap();
        store
    }

    fn has_session(store: &MemoryStore) -> bool {
        store.load(Slot::Session).unwrap().is_some()
    }

    fn delete(store: &dyn Store, web: &str, email: &str) -> DeleteOutcome {
        run(delete_account(&AuthState::new(), store, web, email))
    }

    #[test]
    fn deleting_sends_the_email_with_the_session_as_a_bearer_and_no_cookie() {
        let web = serve(vec![(200, r#"{"deleted":true}"#)]);
        let store = signed_in();

        assert_eq!(
            delete(&store, &web.base, "  a@example.com \n"),
            DeleteOutcome::Deleted
        );

        let requests = web.requests.lock().unwrap();
        assert!(requests[0].starts_with("DELETE /api/mobile/account "));
        assert_eq!(
            header_of(&requests[0], "authorization").as_deref(),
            Some("Bearer tok.sig%3D")
        );
        assert_eq!(header_of(&requests[0], "cookie"), None);
        assert_eq!(
            body_of(&requests[0]),
            serde_json::json!({ "confirmEmail": "a@example.com" })
        );
    }

    #[test]
    fn a_deleted_account_forgets_the_session_and_the_pending_sign_in() {
        let web = serve(vec![(200, r#"{"deleted":true}"#)]);
        let store = signed_in();
        store.save(Slot::Pending, "[]").unwrap();

        assert_eq!(
            delete(&store, &web.base, "a@example.com"),
            DeleteOutcome::Deleted
        );
        assert!(!has_session(&store));
        assert!(store.load(Slot::Pending).unwrap().is_none());
    }

    #[test]
    fn an_empty_or_too_long_email_sends_nothing() {
        let web = serve(vec![]);
        let store = signed_in();

        assert_eq!(
            delete(&store, &web.base, "  \n"),
            DeleteOutcome::EmailMismatch
        );
        let long = format!("{}@example.com", "a".repeat(400));
        assert_eq!(
            delete(&store, &web.base, &long),
            DeleteOutcome::EmailMismatch
        );
        assert!(web.requests.lock().unwrap().is_empty());
        assert!(has_session(&store));
    }

    #[test]
    fn without_a_session_nothing_is_sent() {
        let web = serve(vec![]);
        let store = MemoryStore::default();

        assert_eq!(
            delete(&store, &web.base, "a@example.com"),
            DeleteOutcome::SessionEnded
        );
        assert!(web.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn a_wrong_email_and_an_old_sign_in_keep_the_session() {
        let web = serve(vec![
            (422, r#"{"error":"email_mismatch"}"#),
            (403, r#"{"error":"recent_sign_in_required"}"#),
        ]);
        let store = signed_in();

        assert_eq!(
            delete(&store, &web.base, "b@example.com"),
            DeleteOutcome::EmailMismatch
        );
        assert_eq!(
            delete(&store, &web.base, "a@example.com"),
            DeleteOutcome::NotFresh
        );
        assert!(has_session(&store));
    }

    #[test]
    fn a_401_ends_the_session() {
        let web = serve(vec![(401, r#"{"error":"unauthorized"}"#)]);
        let store = signed_in();

        assert_eq!(
            delete(&store, &web.base, "a@example.com"),
            DeleteOutcome::SessionEnded
        );
        assert!(!has_session(&store));
    }

    #[test]
    fn a_failure_keeps_the_session_and_may_be_tried_again() {
        let web = serve(vec![(500, r#"{"error":"failed"}"#)]);
        let store = signed_in();

        assert_eq!(
            delete(&store, &web.base, "a@example.com"),
            DeleteOutcome::Failed
        );
        assert!(has_session(&store));
    }

    #[test]
    fn when_the_web_app_cannot_be_reached_the_session_is_kept() {
        let store = signed_in();

        assert_eq!(
            delete(&store, &dead_base(), "a@example.com"),
            DeleteOutcome::Failed
        );
        assert!(has_session(&store));
    }

    #[test]
    fn the_outcome_is_told_to_the_screen_by_kind_only() {
        let json = serde_json::to_string(&DeleteOutcome::NotFresh).unwrap();
        assert_eq!(json, r#"{"kind":"notFresh"}"#);
    }
}

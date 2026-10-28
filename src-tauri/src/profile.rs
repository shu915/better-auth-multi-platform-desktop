//! プロフィールの読み込みと保存(通信)。
//!
//! 判断は `profile_rules.rs`(検証、何を送るか、失敗の分類)と `api_parse.rs`(応答の検査)の純粋な
//! 関数に任せ、ここは「呼ぶ順番」と通信だけ。モバイルの `api.ts`、`token.ts`、`profile-name.ts` に当たる。
//!
//! - 名前とメール: Web の `GET /api/auth/get-session`(セッションを `Cookie` で送る)
//! - 名前の更新: Web の `PATCH /api/mobile/profile`(`Authorization: Bearer <session_token>`、Cookie なし)
//! - bio: Go の `GET` / `PUT /me/profile`(`Authorization: Bearer <JWT>`)
//! - JWT: Web の `GET /api/auth/token`(Bearer のみ)。5 分で切れるので、使うたびに取り直し、保存しない
//!
//! セッションが無効(401、または `get-session` が `null`)と分かったら、この Mac のセッションを消して
//! `SessionEnded` を返す(画面はログイン画面へ戻る)。秘密(セッション、JWT)は、戻り値にもログにも出さない。

use serde::Serialize;
use serde_json::Value;

use crate::api_parse::{
    SessionUser, parse_go_profile, parse_name_refusal, parse_saved_name, parse_session_user,
    parse_token,
};
use crate::auth::{AuthState, client, debug_log, read_limited};
use crate::profile_rules::{
    FailureKind, FieldProblem, ProfileValues, check_bio, check_name, classify_failure, plan_save,
};
use crate::secret::{Slot, Store};
use crate::session_cookie::{SessionCookie, parse_session_cookie};

/// サーバーの答え。`status` は HTTP ステータス、`body` は JSON。本文が読めなかったとき(上限を超えた、
/// 壊れている、途中で切れた)は `None`。JSON の `null`(`Some(Value::Null)`)とは、区別する。
/// 区別しないと、壊れた 200 の答え(プロキシの HTML など)を「セッションがない」と取り違えて、有効な
/// セッションを消してしまう。
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) body: Option<Value>,
}

impl Reply {
    /// 読めた JSON(`null` を除く)。
    pub(crate) fn json(&self) -> Option<&Value> {
        self.body.as_ref().filter(|body| !body.is_null())
    }
}

/// 要求を送って、答えを読む。答えがなければ(接続できない、タイムアウト)`None`。本文が読めなくても、
/// ステータスは使う。
pub(crate) async fn call(request: reqwest::RequestBuilder) -> Option<Reply> {
    let res = request.send().await.ok()?;
    let status = res.status().as_u16();
    let body = read_limited(res)
        .await
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    Some(Reply { status, body })
}

pub(crate) fn read_session(store: &dyn Store) -> Option<SessionCookie> {
    store
        .load(Slot::Session)
        .ok()
        .flatten()
        .as_deref()
        .and_then(parse_session_cookie)
}

/// サーバーが「このセッションは無効」と言った。この Mac のセッションを消す(使い続けても、毎回
/// 断られるだけで、画面から出られなくなる)。
///
/// 消すのは、**失敗したときに使ったセッション(`used`)と、今 Keychain にあるものが同じときだけ**。
/// 失敗の最中に、メールのリンクの引き換えが終わって、新しいセッションに替わっていたら、それを消さない
/// (ログインに成功した直後に、ログアウトされないように)。確認と削除は、錠の中でまとめて行う。
/// 消した(またはもともとなかった)ときは `true`、新しいセッションに替わっていて消さなかったときは `false`。
pub(crate) async fn end_session(auth: &AuthState, store: &dyn Store, used: &SessionCookie) -> bool {
    let _guard = auth.session_lock.lock().await;
    match read_session(store) {
        Some(current) if &current != used => false,
        Some(_) => {
            if let Err(error) = store.delete(Slot::Session) {
                debug_log(&format!("clearing the ended session failed: {error:?}"));
            }
            // 前のユーザーの連携の戻りは、次のユーザーに見せない。
            auth.forget_links();
            true
        }
        None => true,
    }
}

/// 呼び出しの失敗。`status` は、サーバーが答えたときのステータス。
struct CallFailure {
    status: Option<u16>,
    /// 名前が断られたとき(422)の、サーバーの理由。
    refusal: Option<String>,
}

fn failure(status: Option<u16>) -> CallFailure {
    CallFailure {
        status,
        refusal: None,
    }
}

/// JWT を取る。`Authorization: Bearer <session_token>` だけで、Cookie ヘッダーは付けない
/// (Web は、Cookie 付きの Bearer を断る)。
async fn fetch_jwt(web: &str, session: &SessionCookie) -> Result<String, CallFailure> {
    let http = client().map_err(|_| failure(None))?;
    let reply = call(
        http.get(format!("{web}/api/auth/token"))
            .bearer_auth(session.bearer()),
    )
    .await
    .ok_or_else(|| failure(None))?;
    if reply.status != 200 {
        return Err(failure(Some(reply.status)));
    }
    reply
        .json()
        .and_then(parse_token)
        .ok_or_else(|| failure(None))
}

enum UserLookup {
    User(SessionUser),
    /// セッションが無効(`get-session` が 401、または `null`)。
    Ended,
    Failed,
}

/// 名前とメールを取る。`get-session` は Cookie で呼ぶ。セッションがないとき、Web は `null` を返す。
async fn fetch_user(web: &str, session: &SessionCookie) -> UserLookup {
    let Ok(http) = client() else {
        return UserLookup::Failed;
    };
    let reply = call(
        http.get(format!("{web}/api/auth/get-session"))
            .header("cookie", session.pair()),
    )
    .await;
    match reply {
        None => UserLookup::Failed,
        Some(reply) if reply.status == 401 => UserLookup::Ended,
        // セッションがないとき、Web は JSON の `null` を返す。読めなかった答えは、これではない。
        Some(reply) if reply.status == 200 && reply.body == Some(Value::Null) => UserLookup::Ended,
        Some(reply) if reply.status == 200 => reply
            .json()
            .and_then(parse_session_user)
            .map_or(UserLookup::Failed, UserLookup::User),
        Some(_) => UserLookup::Failed,
    }
}

/// Go から bio を取る。
async fn fetch_bio(api: &str, jwt: &str) -> Result<String, CallFailure> {
    let http = client().map_err(|_| failure(None))?;
    let reply = call(http.get(format!("{api}/me/profile")).bearer_auth(jwt))
        .await
        .ok_or_else(|| failure(None))?;
    if reply.status != 200 {
        return Err(failure(Some(reply.status)));
    }
    reply
        .json()
        .and_then(parse_go_profile)
        .map(|profile| profile.bio)
        .ok_or_else(|| failure(None))
}

/// Go に bio を送る(置き換える)。保存された bio を返す。
async fn put_bio(api: &str, jwt: &str, bio: &str) -> Result<String, CallFailure> {
    let http = client().map_err(|_| failure(None))?;
    let reply = call(
        http.put(format!("{api}/me/profile"))
            .bearer_auth(jwt)
            .json(&serde_json::json!({ "bio": bio })),
    )
    .await
    .ok_or_else(|| failure(None))?;
    if reply.status != 200 {
        return Err(failure(Some(reply.status)));
    }
    reply
        .json()
        .and_then(parse_go_profile)
        .map(|profile| profile.bio)
        .ok_or_else(|| failure(None))
}

/// Web に名前を送る(`PATCH /api/mobile/profile`)。保存された名前を返す。
async fn patch_name(web: &str, session: &SessionCookie, name: &str) -> Result<String, CallFailure> {
    let http = client().map_err(|_| failure(None))?;
    let reply = call(
        http.patch(format!("{web}/api/mobile/profile"))
            .bearer_auth(session.bearer())
            .json(&serde_json::json!({ "name": name })),
    )
    .await
    .ok_or_else(|| failure(None))?;
    if reply.status == 200 {
        return reply
            .json()
            .and_then(parse_saved_name)
            .ok_or_else(|| failure(None));
    }
    Err(CallFailure {
        status: Some(reply.status),
        refusal: (reply.status == 422)
            .then(|| reply.json().and_then(parse_name_refusal))
            .flatten(),
    })
}

// --- 読み込み ---

#[derive(PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum LoadOutcome {
    /// `bio` は、Go から取れなかったとき(接続できない、5xx など)は `None`(名前とメールは見せる)。
    Loaded {
        name: String,
        email: String,
        bio: Option<String>,
    },
    /// セッションが無効。この Mac のセッションは消した(画面はログイン画面へ)。
    SessionEnded,
    /// 名前とメールが取れなかった(接続できない、予想外の答え)。
    Failed,
}

/// 読み込みの最中に「セッションが無効」と分かったときの答え。使ったセッションがまだ今のものなら、消して
/// `SessionEnded`。もう新しいセッションに替わっていたら、その古い答えでログアウトさせず、`Failed`
/// (画面は、新しいセッションで読み直す)。
async fn session_ended_for_load(
    auth: &AuthState,
    store: &dyn Store,
    used: &SessionCookie,
) -> LoadOutcome {
    if end_session(auth, store, used).await {
        LoadOutcome::SessionEnded
    } else {
        LoadOutcome::Failed
    }
}

pub async fn load_profile(
    auth: &AuthState,
    store: &dyn Store,
    web: &str,
    api: &str,
) -> LoadOutcome {
    let Some(session) = read_session(store) else {
        return LoadOutcome::SessionEnded;
    };
    let user = match fetch_user(web, &session).await {
        UserLookup::User(user) => user,
        UserLookup::Ended => return session_ended_for_load(auth, store, &session).await,
        UserLookup::Failed => return LoadOutcome::Failed,
    };

    // bio は Go にある。取れなくても、名前とメールは見せる(401 だけは、セッションの終わり)。
    let bio = match fetch_jwt(web, &session).await {
        Ok(jwt) => fetch_bio(api, &jwt).await,
        Err(failed) => Err(failed),
    };
    let bio = match bio {
        Ok(bio) => Some(bio),
        Err(failed) if classify_failure(failed.status) == FailureKind::SessionEnded => {
            return session_ended_for_load(auth, store, &session).await;
        }
        Err(_) => None,
    };
    LoadOutcome::Loaded {
        name: user.name,
        email: user.email,
        bio,
    }
}

// --- 保存 ---

/// `{:?}` でログに出ても、名前・メール・bio は出さない(種類だけ)。
impl std::fmt::Debug for LoadOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadOutcome::Loaded { bio, .. } => {
                write!(
                    f,
                    "Loaded {{ bio: {} }}",
                    if bio.is_some() { "read" } else { "unread" }
                )
            }
            LoadOutcome::SessionEnded => write!(f, "SessionEnded"),
            LoadOutcome::Failed => write!(f, "Failed"),
        }
    }
}

/// `{:?}` でログに出ても、名前・bio・サーバーの理由は出さない(種類だけ)。
impl std::fmt::Debug for SaveOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaveOutcome::NothingToSave => write!(f, "NothingToSave"),
            SaveOutcome::Invalid { name, bio } => {
                write!(f, "Invalid {{ name: {name:?}, bio: {bio:?} }}")
            }
            SaveOutcome::Saved { .. } => write!(f, "Saved"),
            SaveOutcome::SessionEnded => write!(f, "SessionEnded"),
            SaveOutcome::Failed { field, refused, .. } => {
                write!(f, "Failed {{ field: {field:?}, refused: {refused} }}")
            }
        }
    }
}

/// 画面が送ってくる、今保存されている値と、編集中の値。
pub struct SaveInput<'a> {
    pub saved_name: &'a str,
    pub name_draft: &'a str,
    pub saved_bio: &'a str,
    pub bio_draft: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Field {
    Name,
    Bio,
}

#[derive(PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SaveOutcome {
    /// 変わったものがない(何も送っていない)。
    NothingToSave,
    /// 入力が規則に合わない(何も送っていない)。送ろうとした項目だけに、理由がある。
    Invalid {
        name: Option<FieldProblem>,
        bio: Option<FieldProblem>,
    },
    /// 保存した。送った項目だけに、サーバーが保存した値がある。
    Saved {
        name: Option<String>,
        bio: Option<String>,
    },
    /// セッションが無効。この Mac のセッションは消した(画面はログイン画面へ)。
    SessionEnded,
    /// 保存できなかった。`refused` はサーバーが値を断ったとき(422)、`refusal` はその理由(名前のみ)。
    /// `name_saved` は、名前は保存できたあとで bio が失敗したとき、保存された名前。
    Failed {
        /// どの項目の保存が失敗したか。どの項目でもない失敗(接続先の設定の誤りなど)は `None`。
        field: Option<Field>,
        refused: bool,
        refusal: Option<String>,
        name_saved: Option<String>,
    },
}

/// 失敗を、画面に渡す形にする。401 なら、使ったセッションがまだ今のものであるときだけ、消す。
/// もう新しいセッションに替わっていたら、消さず、普通の失敗として返す。
async fn failed(
    auth: &AuthState,
    store: &dyn Store,
    used: &SessionCookie,
    failure: CallFailure,
    field: Field,
    name_saved: Option<String>,
) -> SaveOutcome {
    let kind = classify_failure(failure.status);
    if kind == FailureKind::SessionEnded && end_session(auth, store, used).await {
        return SaveOutcome::SessionEnded;
    }
    SaveOutcome::Failed {
        field: Some(field),
        refused: kind == FailureKind::Refused,
        refusal: failure.refusal,
        name_saved,
    }
}

/// 変わったものだけを保存する。先に両方の入力を確かめ、どちらかが規則に合わなければ、何も送らない。
/// 名前(Web)を先に、bio(Go)を後に送る。名前が通って bio が失敗したら、そのことを伝える。
pub async fn save_profile(
    auth: &AuthState,
    store: &dyn Store,
    web: &str,
    api: &str,
    input: &SaveInput<'_>,
) -> SaveOutcome {
    let plan = plan_save(&ProfileValues {
        name: input.saved_name,
        name_draft: input.name_draft,
        saved_bio: input.saved_bio,
        bio_draft: input.bio_draft,
    });
    if !plan.has_changes() {
        return SaveOutcome::NothingToSave;
    }

    let name = plan.send_name.then(|| check_name(input.name_draft));
    let bio = plan.send_bio.then(|| check_bio(input.bio_draft));
    let problem_of = |checked: &Option<Result<String, FieldProblem>>| {
        checked
            .as_ref()
            .and_then(|result| result.as_ref().err().copied())
    };
    let (name_problem, bio_problem) = (problem_of(&name), problem_of(&bio));
    if name_problem.is_some() || bio_problem.is_some() {
        return SaveOutcome::Invalid {
            name: name_problem,
            bio: bio_problem,
        };
    }
    let (name, bio) = (name.and_then(Result::ok), bio.and_then(Result::ok));

    let Some(session) = read_session(store) else {
        return SaveOutcome::SessionEnded;
    };

    let mut saved_name = None;
    if let Some(name) = name {
        match patch_name(web, &session, &name).await {
            Ok(saved) => saved_name = Some(saved),
            Err(error) => return failed(auth, store, &session, error, Field::Name, None).await,
        }
    }
    let mut saved_bio = None;
    if let Some(bio) = bio {
        let saved = match fetch_jwt(web, &session).await {
            Ok(jwt) => put_bio(api, &jwt, &bio).await,
            Err(error) => Err(error),
        };
        match saved {
            Ok(saved) => saved_bio = Some(saved),
            Err(error) => {
                return failed(auth, store, &session, error, Field::Bio, saved_name).await;
            }
        }
    }
    SaveOutcome::Saved {
        name: saved_name,
        bio: saved_bio,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::testing::MemoryStore;
    use crate::test_support::{body_of, dead_base, header_of, run, serve};

    const SESSION: &str = "better-auth.session_token=tok.sig%3D";
    const USER_JSON: &str =
        r#"{"session":{"id":"s"},"user":{"name":"Alice","email":"a@example.com"}}"#;
    const TOKEN_JSON: &str = r#"{"token":"jwt-value"}"#;
    const BIO_JSON: &str = r#"{"user_id":"u1","bio":"hello"}"#;

    fn signed_in() -> MemoryStore {
        let store = MemoryStore::default();
        store.save(Slot::Session, SESSION).unwrap();
        store
    }

    fn has_session(store: &MemoryStore) -> bool {
        store.load(Slot::Session).unwrap().is_some()
    }

    // --- 読み込み ---

    #[test]
    fn loading_reads_the_user_from_the_session_and_the_bio_from_go() {
        let web = serve(vec![(200, USER_JSON), (200, TOKEN_JSON)]);
        let api = serve(vec![(200, BIO_JSON)]);
        let store = signed_in();

        let outcome = run(load_profile(
            &AuthState::new(),
            &store,
            &web.base,
            &api.base,
        ));
        assert_eq!(
            outcome,
            LoadOutcome::Loaded {
                name: "Alice".to_string(),
                email: "a@example.com".to_string(),
                bio: Some("hello".to_string()),
            }
        );

        let web_requests = web.requests.lock().unwrap();
        // get-session は Cookie で、token は Bearer のみ(Cookie ヘッダーなし)。
        assert!(web_requests[0].starts_with("GET /api/auth/get-session "));
        assert_eq!(
            header_of(&web_requests[0], "cookie").as_deref(),
            Some(SESSION)
        );
        assert_eq!(header_of(&web_requests[0], "authorization"), None);
        assert!(web_requests[1].starts_with("GET /api/auth/token "));
        assert_eq!(
            header_of(&web_requests[1], "authorization").as_deref(),
            Some("Bearer tok.sig%3D")
        );
        assert_eq!(header_of(&web_requests[1], "cookie"), None);
        // Go には、JWT だけを Bearer で送る(セッションは送らない)。
        let api_requests = api.requests.lock().unwrap();
        assert!(api_requests[0].starts_with("GET /me/profile "));
        assert_eq!(
            header_of(&api_requests[0], "authorization").as_deref(),
            Some("Bearer jwt-value")
        );
        assert_eq!(header_of(&api_requests[0], "cookie"), None);
        assert!(!api_requests[0].contains("tok.sig"));
    }

    #[test]
    fn loading_without_a_session_ends_the_session_without_asking_anyone() {
        let store = MemoryStore::default();
        assert_eq!(
            run(load_profile(
                &AuthState::new(),
                &store,
                &dead_base(),
                &dead_base()
            )),
            LoadOutcome::SessionEnded
        );
    }

    #[test]
    fn a_session_the_web_app_no_longer_knows_is_forgotten() {
        for (status, body) in [(200, "null"), (401, r#"{"message":"x"}"#)] {
            let web = serve(vec![(status, body)]);
            let store = signed_in();
            assert_eq!(
                run(load_profile(
                    &AuthState::new(),
                    &store,
                    &web.base,
                    &dead_base()
                )),
                LoadOutcome::SessionEnded,
                "{status} {body}"
            );
            assert!(!has_session(&store));
        }
    }

    #[test]
    fn an_answer_that_could_not_be_read_is_not_taken_for_no_session() {
        // 200 でも、本文が JSON でない(プロキシの HTML、空、壊れた JSON)ものは、「セッションがない」
        // ではない。有効なセッションを消さない。
        for body in ["<html>captive portal</html>", "", "{\"user\":", "nul"] {
            let web = serve(vec![(200, body)]);
            let store = signed_in();
            assert_eq!(
                run(load_profile(
                    &AuthState::new(),
                    &store,
                    &web.base,
                    &dead_base()
                )),
                LoadOutcome::Failed,
                "{body:?}"
            );
            assert!(has_session(&store), "{body:?}");
        }
    }

    #[test]
    fn when_the_web_app_cannot_be_reached_the_session_is_kept() {
        let store = signed_in();
        assert_eq!(
            run(load_profile(
                &AuthState::new(),
                &store,
                &dead_base(),
                &dead_base()
            )),
            LoadOutcome::Failed
        );
        assert!(has_session(&store));
        let web = serve(vec![(500, "boom")]);
        assert_eq!(
            run(load_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base()
            )),
            LoadOutcome::Failed
        );
        assert!(has_session(&store));
    }

    #[test]
    fn the_name_and_email_are_shown_even_when_go_cannot_be_reached() {
        let web = serve(vec![(200, USER_JSON), (200, TOKEN_JSON)]);
        let store = signed_in();
        assert_eq!(
            run(load_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base()
            )),
            LoadOutcome::Loaded {
                name: "Alice".to_string(),
                email: "a@example.com".to_string(),
                bio: None,
            }
        );
        assert!(has_session(&store));
    }

    #[test]
    fn a_401_from_go_or_from_the_token_route_ends_the_session() {
        // JWT を取れない(Web が 401)
        let web = serve(vec![(200, USER_JSON), (401, "{}")]);
        let store = signed_in();
        assert_eq!(
            run(load_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base()
            )),
            LoadOutcome::SessionEnded
        );
        assert!(!has_session(&store));
        // Go が 401
        let web = serve(vec![(200, USER_JSON), (200, TOKEN_JSON)]);
        let api = serve(vec![(401, "{}")]);
        let store = signed_in();
        assert_eq!(
            run(load_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &api.base
            )),
            LoadOutcome::SessionEnded
        );
        assert!(!has_session(&store));
    }

    #[test]
    fn an_unexpected_answer_from_go_leaves_the_bio_out() {
        let web = serve(vec![(200, USER_JSON), (200, TOKEN_JSON)]);
        let api = serve(vec![(200, r#"{"unexpected":true}"#)]);
        let store = signed_in();
        assert!(matches!(
            run(load_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &api.base
            )),
            LoadOutcome::Loaded { bio: None, .. }
        ));
    }

    // --- 保存 ---

    fn input<'a>(name_draft: &'a str, bio_draft: &'a str) -> SaveInput<'a> {
        SaveInput {
            saved_name: "Alice",
            name_draft,
            saved_bio: "hello",
            bio_draft,
        }
    }

    #[test]
    fn nothing_is_sent_when_nothing_changed() {
        let store = signed_in();
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &dead_base(),
                &dead_base(),
                &input(" Alice ", "hello")
            )),
            SaveOutcome::NothingToSave
        );
    }

    #[test]
    fn input_that_breaks_the_rules_sends_nothing_at_all() {
        let store = signed_in();
        // 名前は空、bio は長すぎる: どちらの理由も返り、どこにも送らない(dead_base でも失敗しない)。
        let outcome = run(save_profile(
            &AuthState::new(),
            &store,
            &dead_base(),
            &dead_base(),
            &input("   ", &"a".repeat(1001)),
        ));
        assert_eq!(
            outcome,
            SaveOutcome::Invalid {
                name: Some(FieldProblem::Empty),
                bio: Some(FieldProblem::TooLong),
            }
        );
        // 片方だけ変えて、その片方が不正なら、もう片方は何も言わない。
        let outcome = run(save_profile(
            &AuthState::new(),
            &store,
            &dead_base(),
            &dead_base(),
            &input("Alice", "a\0"),
        ));
        assert_eq!(
            outcome,
            SaveOutcome::Invalid {
                name: None,
                bio: Some(FieldProblem::InvalidCharacter)
            }
        );
        assert!(has_session(&store));
    }

    #[test]
    fn only_the_name_is_sent_when_only_the_name_changed() {
        let web = serve(vec![(200, r#"{"name":"Alicia"}"#)]);
        let store = signed_in();
        let outcome = run(save_profile(
            &AuthState::new(),
            &store,
            &web.base,
            &dead_base(),
            &input("  Alicia ", "hello"),
        ));
        assert_eq!(
            outcome,
            SaveOutcome::Saved {
                name: Some("Alicia".to_string()),
                bio: None
            }
        );
        let requests = web.requests.lock().unwrap();
        assert!(requests[0].starts_with("PATCH /api/mobile/profile "));
        assert_eq!(body_of(&requests[0]), serde_json::json!({"name": "Alicia"}));
        assert_eq!(
            header_of(&requests[0], "authorization").as_deref(),
            Some("Bearer tok.sig%3D")
        );
        assert_eq!(header_of(&requests[0], "cookie"), None);
        assert_eq!(requests.len(), 1); // JWT は要らない
    }

    #[test]
    fn only_the_bio_is_sent_when_only_the_bio_changed() {
        let web = serve(vec![(200, TOKEN_JSON)]);
        let api = serve(vec![(200, r#"{"user_id":"u1","bio":"new"}"#)]);
        let store = signed_in();
        let outcome = run(save_profile(
            &AuthState::new(),
            &store,
            &web.base,
            &api.base,
            &input("Alice", "new\r\nline"),
        ));
        assert_eq!(
            outcome,
            SaveOutcome::Saved {
                name: None,
                bio: Some("new".to_string())
            }
        );
        let requests = api.requests.lock().unwrap();
        assert!(requests[0].starts_with("PUT /me/profile "));
        // 送る bio は、改行をそろえたもの。JWT を Bearer で送る。
        assert_eq!(
            body_of(&requests[0]),
            serde_json::json!({"bio": "new\nline"})
        );
        assert_eq!(
            header_of(&requests[0], "authorization").as_deref(),
            Some("Bearer jwt-value")
        );
        assert_eq!(web.requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn both_are_saved_name_first() {
        let web = serve(vec![(200, r#"{"name":"Bob"}"#), (200, TOKEN_JSON)]);
        let api = serve(vec![(200, r#"{"user_id":"u1","bio":"new"}"#)]);
        let store = signed_in();
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &api.base,
                &input("Bob", "new")
            )),
            SaveOutcome::Saved {
                name: Some("Bob".to_string()),
                bio: Some("new".to_string())
            }
        );
        let requests = web.requests.lock().unwrap();
        assert!(requests[0].starts_with("PATCH /api/mobile/profile "));
        assert!(requests[1].starts_with("GET /api/auth/token "));
    }

    #[test]
    fn a_refused_name_says_why_and_keeps_the_session() {
        let web = serve(vec![(
            422,
            r#"{"errors":{"name":"Use 50 characters or fewer."}}"#,
        )]);
        let store = signed_in();
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base(),
                &input("Bob", "hello")
            )),
            SaveOutcome::Failed {
                field: Some(Field::Name),
                refused: true,
                refusal: Some("Use 50 characters or fewer.".to_string()),
                name_saved: None,
            }
        );
        assert!(has_session(&store));
    }

    #[test]
    fn when_the_name_is_saved_but_the_bio_fails_the_saved_name_is_reported() {
        let web = serve(vec![(200, r#"{"name":"Bob"}"#), (200, TOKEN_JSON)]);
        let api = serve(vec![(422, "{}")]);
        let store = signed_in();
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &api.base,
                &input("Bob", "new")
            )),
            SaveOutcome::Failed {
                field: Some(Field::Bio),
                refused: true,
                refusal: None,
                name_saved: Some("Bob".to_string()),
            }
        );
    }

    #[test]
    fn a_failure_that_is_not_a_refusal_asks_to_try_again() {
        // Web が 500
        let web = serve(vec![(500, "boom")]);
        let store = signed_in();
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base(),
                &input("Bob", "hello")
            )),
            SaveOutcome::Failed {
                field: Some(Field::Name),
                refused: false,
                refusal: None,
                name_saved: None
            }
        );
        // Go に届かない
        let web = serve(vec![(200, TOKEN_JSON)]);
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base(),
                &input("Alice", "new")
            )),
            SaveOutcome::Failed {
                field: Some(Field::Bio),
                refused: false,
                refusal: None,
                name_saved: None
            }
        );
        // 退会直後の 410 も、同じ扱い
        let web = serve(vec![(200, TOKEN_JSON)]);
        let api = serve(vec![(410, "{}")]);
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &api.base,
                &input("Alice", "new")
            )),
            SaveOutcome::Failed {
                field: Some(Field::Bio),
                refused: false,
                refusal: None,
                name_saved: None
            }
        );
        assert!(has_session(&store));
    }

    #[test]
    fn a_401_while_saving_ends_the_session() {
        let web = serve(vec![(401, "{}")]);
        let store = signed_in();
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base(),
                &input("Bob", "hello")
            )),
            SaveOutcome::SessionEnded
        );
        assert!(!has_session(&store));

        let web = serve(vec![(200, TOKEN_JSON)]);
        let api = serve(vec![(401, "{}")]);
        let store = signed_in();
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &api.base,
                &input("Alice", "new")
            )),
            SaveOutcome::SessionEnded
        );
        assert!(!has_session(&store));
    }

    #[test]
    fn saving_without_a_session_ends_the_session() {
        let store = MemoryStore::default();
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &dead_base(),
                &dead_base(),
                &input("Bob", "hello")
            )),
            SaveOutcome::SessionEnded
        );
    }

    // --- 古いセッションの失敗で、新しいセッションを消さない(競合) ---

    fn cookie(value: &str) -> SessionCookie {
        parse_session_cookie(&format!("better-auth.session_token={value}")).unwrap()
    }

    #[test]
    fn ending_a_session_forgets_it_only_if_it_is_still_the_current_one() {
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        store
            .save(Slot::Session, "better-auth.session_token=new")
            .unwrap();
        // 失敗したのは古いセッション(old)。いまあるのは、引き換えで保存された新しいもの(new)。
        assert!(!run(end_session(&auth, &store, &cookie("old"))));
        assert!(has_session(&store));
        // 同じセッションなら、消す。
        assert!(run(end_session(&auth, &store, &cookie("new"))));
        assert!(!has_session(&store));
        // もともとなければ、消したことにする(何度やっても同じ結果)。
        assert!(run(end_session(&auth, &store, &cookie("new"))));
    }

    #[test]
    fn a_session_replaced_while_loading_is_not_forgotten_by_the_old_answer() {
        // get-session が 401 で返る前に、別のセッションに替わっていた状況を、組み立てる。
        let web = serve(vec![(401, "{}")]);
        let (auth, store) = (AuthState::new(), MemoryStore::default());
        store
            .save(Slot::Session, "better-auth.session_token=old")
            .unwrap();
        // 要求を送った後、答えが返る前に、新しいセッションが保存された、という順序を再現するため、
        // 古いセッションで要求を作り、保存を差し替えてから、答えの処理(end_session)を行う。
        let used = cookie("old");
        let reply = run(async {
            let http = client().unwrap();
            call(
                http.get(format!("{}/api/auth/get-session", web.base))
                    .header("cookie", used.pair()),
            )
            .await
        });
        assert_eq!(reply.map(|r| r.status), Some(401));
        store
            .save(Slot::Session, "better-auth.session_token=new")
            .unwrap();
        assert!(!run(end_session(&auth, &store, &used)));
        assert_eq!(
            store.load(Slot::Session).unwrap().as_deref(),
            Some("better-auth.session_token=new")
        );
    }

    /// 読むたびに答えが替わる置き場。最初に読むと古いセッション、2 回目から新しいセッション。
    /// 「失敗の最中に、別のセッションに替わった」状況を、配線ごと再現する(`load_profile` と
    /// `save_profile` が、**最初に読んだセッション**を `end_session` に渡しているかを守る)。
    #[derive(Default)]
    struct SwitchingStore {
        reads: std::sync::Mutex<u32>,
        deleted: std::sync::Mutex<bool>,
    }

    impl Store for SwitchingStore {
        fn load(&self, slot: Slot) -> Result<Option<String>, crate::secret::SecretError> {
            if slot != Slot::Session {
                return Ok(None);
            }
            let mut reads = self.reads.lock().unwrap();
            *reads += 1;
            let value = if *reads == 1 { "old" } else { "new" };
            Ok(Some(format!("better-auth.session_token={value}")))
        }
        fn save(&self, _slot: Slot, _value: &str) -> Result<(), crate::secret::SecretError> {
            Ok(())
        }
        fn delete(&self, slot: Slot) -> Result<(), crate::secret::SecretError> {
            if slot == Slot::Session {
                *self.deleted.lock().unwrap() = true;
            }
            Ok(())
        }
    }

    #[test]
    fn loading_does_not_forget_a_session_that_was_replaced_while_it_ran() {
        let web = serve(vec![(401, "{}")]);
        let store = SwitchingStore::default();
        // 古いセッションで 401 が返る間に、新しいセッションに替わっている。
        assert_eq!(
            run(load_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base()
            )),
            LoadOutcome::Failed
        );
        assert!(!*store.deleted.lock().unwrap());
    }

    #[test]
    fn loading_does_not_forget_a_session_replaced_while_the_token_was_asked_for() {
        // get-session は通り、/token が 401: そのあいだに、別のセッションに替わっていた。
        let web = serve(vec![(200, USER_JSON), (401, "{}")]);
        let store = SwitchingStore::default();
        assert_eq!(
            run(load_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base()
            )),
            LoadOutcome::Failed
        );
        assert!(!*store.deleted.lock().unwrap());
    }

    #[test]
    fn saving_does_not_forget_a_session_that_was_replaced_while_it_ran() {
        let failed_name = SaveOutcome::Failed {
            field: Some(Field::Name),
            refused: false,
            refusal: None,
            name_saved: None,
        };
        // 名前の保存が 401
        let web = serve(vec![(401, "{}")]);
        let store = SwitchingStore::default();
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base(),
                &input("Bob", "hello")
            )),
            failed_name
        );
        assert!(!*store.deleted.lock().unwrap());

        // bio の保存で、JWT の取得が 401
        let web = serve(vec![(401, "{}")]);
        let store = SwitchingStore::default();
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base(),
                &input("Alice", "new")
            )),
            SaveOutcome::Failed {
                field: Some(Field::Bio),
                refused: false,
                refusal: None,
                name_saved: None,
            }
        );
        assert!(!*store.deleted.lock().unwrap());
    }

    #[test]
    fn a_session_that_is_still_the_same_is_forgotten_on_a_401() {
        // 対照: 置き場が替わらなければ、同じ 401 で、セッションを消す。
        let web = serve(vec![(401, "{}")]);
        let store = signed_in();
        assert_eq!(
            run(save_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base(),
                &input("Bob", "hello")
            )),
            SaveOutcome::SessionEnded
        );
        assert!(!has_session(&store));
    }

    #[test]
    fn a_token_answer_that_could_not_be_read_does_not_end_the_session() {
        // /token が 200 でも本文が壊れている: bio は読めないが、セッションは消さない。
        let web = serve(vec![(200, USER_JSON), (200, "<html>captive portal</html>")]);
        let store = signed_in();
        assert!(matches!(
            run(load_profile(
                &AuthState::new(),
                &store,
                &web.base,
                &dead_base()
            )),
            LoadOutcome::Loaded { bio: None, .. }
        ));
        assert!(has_session(&store));
    }

    #[test]
    fn debug_output_hides_the_name_the_email_and_the_bio() {
        let loaded = LoadOutcome::Loaded {
            name: "secret-name".to_string(),
            email: "secret@example.com".to_string(),
            bio: Some("secret-bio".to_string()),
        };
        let saved = SaveOutcome::Saved {
            name: Some("secret-name".to_string()),
            bio: Some("secret-bio".to_string()),
        };
        let failed = SaveOutcome::Failed {
            field: Some(Field::Name),
            refused: true,
            refusal: Some("secret-reason".to_string()),
            name_saved: Some("secret-name".to_string()),
        };
        for text in [
            format!("{loaded:?}"),
            format!("{saved:?}"),
            format!("{failed:?}"),
        ] {
            assert!(!text.contains("secret"), "{text}");
        }
    }

    #[test]
    fn a_failure_that_belongs_to_no_field_has_no_field() {
        let failed = SaveOutcome::Failed {
            field: None,
            refused: false,
            refusal: None,
            name_saved: None,
        };
        assert_eq!(
            serde_json::to_string(&failed).unwrap(),
            r#"{"kind":"failed","field":null,"refused":false,"refusal":null,"nameSaved":null}"#
        );
    }

    #[test]
    fn what_the_screen_is_told_has_no_secret() {
        let json = |outcome: &SaveOutcome| serde_json::to_string(outcome).unwrap();
        assert_eq!(
            json(&SaveOutcome::NothingToSave),
            r#"{"kind":"nothingToSave"}"#
        );
        assert_eq!(
            json(&SaveOutcome::SessionEnded),
            r#"{"kind":"sessionEnded"}"#
        );
        assert_eq!(
            json(&SaveOutcome::Saved {
                name: Some("A".to_string()),
                bio: None
            }),
            r#"{"kind":"saved","name":"A","bio":null}"#
        );
        assert_eq!(
            json(&SaveOutcome::Failed {
                field: Some(Field::Bio),
                refused: false,
                refusal: None,
                name_saved: None
            }),
            r#"{"kind":"failed","field":"bio","refused":false,"refusal":null,"nameSaved":null}"#
        );
        assert_eq!(
            json(&SaveOutcome::Invalid {
                name: Some(FieldProblem::TooLong),
                bio: None
            }),
            r#"{"kind":"invalid","name":"tooLong","bio":null}"#
        );
        assert_eq!(
            serde_json::to_string(&LoadOutcome::Loaded {
                name: "A".to_string(),
                email: "e".to_string(),
                bio: None
            })
            .unwrap(),
            r#"{"kind":"loaded","name":"A","email":"e","bio":null}"#
        );
    }
}

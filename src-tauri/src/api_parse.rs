//! Web と Go の答え(JSON)を、信用する前に検査する。通信には触らない純粋な関数だけ。
//!
//! 答えは外から来るデータなので、形が違えば `None`(「予想外の答え」)にする。モバイルの `api.ts`
//! の `toProfile`、`token.ts`、`profile-name.ts` に当たる。秘密(JWT)は、`Debug` で値を出さない。

use serde_json::Value;

/// 画面に見せてよい、サーバーが断った理由の最大文字数(長すぎる文章を、そのまま出さない)。
const MAX_REFUSAL_CHARS: usize = 200;

/// Web の `GET /api/auth/token` の答え `{ "token": "…" }`。空でない文字列のときだけ。
pub fn parse_token(body: &Value) -> Option<String> {
    let token = body.get("token")?.as_str()?;
    (!token.is_empty()).then(|| token.to_string())
}

/// Go の `GET /me/profile` と `PUT /me/profile` の答え `{ "user_id": "…", "bio": "…" }`。
#[derive(Debug, PartialEq, Eq)]
pub struct GoProfile {
    pub user_id: String,
    pub bio: String,
}

pub fn parse_go_profile(body: &Value) -> Option<GoProfile> {
    Some(GoProfile {
        user_id: body.get("user_id")?.as_str()?.to_string(),
        bio: body.get("bio")?.as_str()?.to_string(),
    })
}

/// Web の `GET /api/auth/get-session` の答えにある、ユーザーの名前とメール。セッションがないとき、
/// Web は `null` を返すので、そのときは `None`。
#[derive(Debug, PartialEq, Eq)]
pub struct SessionUser {
    pub name: String,
    pub email: String,
}

pub fn parse_session_user(body: &Value) -> Option<SessionUser> {
    let user = body.get("user")?;
    Some(SessionUser {
        name: user.get("name")?.as_str()?.to_string(),
        email: user.get("email")?.as_str()?.to_string(),
    })
}

/// Web の `PATCH /api/mobile/profile` の成功の答え `{ "name": "…" }`(保存された名前)。
pub fn parse_saved_name(body: &Value) -> Option<String> {
    Some(body.get("name")?.as_str()?.to_string())
}

/// 名前が断られたとき(422)の理由 `{ "errors": { "name": "…" } }`。画面に見せるので、制御文字を
/// 取り除き、長さを切る。
pub fn parse_name_refusal(body: &Value) -> Option<String> {
    let reason = body.get("errors")?.get("name")?.as_str()?;
    let shown: String = reason
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REFUSAL_CHARS)
        .collect();
    (!shown.is_empty()).then_some(shown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_token_must_be_a_non_empty_string() {
        assert_eq!(
            parse_token(&json!({"token": "abc"})).as_deref(),
            Some("abc")
        );
        for body in [
            json!({"token": ""}),
            json!({"token": 1}),
            json!({}),
            json!(null),
            json!("abc"),
        ] {
            assert_eq!(parse_token(&body), None, "{body}");
        }
    }

    #[test]
    fn a_go_profile_needs_both_fields_as_strings() {
        assert_eq!(
            parse_go_profile(&json!({"user_id": "u1", "bio": ""})),
            Some(GoProfile {
                user_id: "u1".to_string(),
                bio: String::new()
            })
        );
        for body in [
            json!({"user_id": "u1"}),
            json!({"bio": "x"}),
            json!({"user_id": 1, "bio": "x"}),
            json!({"user_id": "u1", "bio": null}),
            json!([]),
            json!(null),
        ] {
            assert_eq!(parse_go_profile(&body), None, "{body}");
        }
    }

    #[test]
    fn a_session_user_has_a_name_and_an_email() {
        let body = json!({"session": {"id": "s"}, "user": {"name": "Alice", "email": "a@example.com", "x": 1}});
        assert_eq!(
            parse_session_user(&body),
            Some(SessionUser {
                name: "Alice".to_string(),
                email: "a@example.com".to_string()
            })
        );
    }

    #[test]
    fn no_session_means_no_user() {
        // セッションがないとき、Web は null を返す。
        assert_eq!(parse_session_user(&json!(null)), None);
        for body in [
            json!({}),
            json!({"user": null}),
            json!({"user": {"name": "A"}}),
            json!({"user": {"name": 1, "email": "e"}}),
        ] {
            assert_eq!(parse_session_user(&body), None, "{body}");
        }
    }

    #[test]
    fn a_saved_name_is_read_from_the_answer() {
        assert_eq!(
            parse_saved_name(&json!({"name": "Alice"})).as_deref(),
            Some("Alice")
        );
        for body in [json!({}), json!({"name": 1}), json!(null)] {
            assert_eq!(parse_saved_name(&body), None, "{body}");
        }
    }

    #[test]
    fn a_refusal_reason_is_read_and_cut_short() {
        assert_eq!(
            parse_name_refusal(&json!({"errors": {"name": "Enter a name."}})).as_deref(),
            Some("Enter a name.")
        );
        let long = parse_name_refusal(&json!({"errors": {"name": "x".repeat(1000)}})).unwrap();
        assert_eq!(long.chars().count(), 200);
        // 制御文字(改行、NUL、ESC など)は、画面に出さない。
        assert_eq!(
            parse_name_refusal(&json!({"errors": {"name": "a\nb\u{0}c\u{1b}[0m"}})).as_deref(),
            Some("abc[0m")
        );
        assert_eq!(
            parse_name_refusal(&json!({"errors": {"name": "\n\u{0}"}})),
            None
        );
        for body in [
            json!({"errors": {"name": ""}}),
            json!({"errors": {}}),
            json!({"errors": {"name": 1}}),
            json!({}),
            json!(null),
        ] {
            assert_eq!(parse_name_refusal(&body), None, "{body}");
        }
    }
}

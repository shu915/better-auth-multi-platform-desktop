//! Google の連携(紐づけ、解除)の判断。通信にも保存にも触れない純粋な関数だけ。
//! モバイルの `linked-accounts-rules.ts` に当たる。
//!
//! 連携は、ブラウザで Google の画面を通ってから、アプリに戻る。戻りは `betterauthmulti:///?link=<目印>`
//! で、セッションも `code` も載らない(連携ではセッションを作らない)。戻りが自分の頼んだものかは、
//! 頼んだときの目印をメモリに覚えておいて、突き合わせる。ログインのリンク(`state` と `code`)とは、
//! 別のパラメータにして、`judge_link` の判断とぶつからないようにしている。

use serde::Serialize;
use url::Url;

use crate::sign_in_rules::APP_SCHEME;

/// 連携の目印を覚えておく時間。Web の `state` の有効期間(10 分)に合わせる。
pub const LINK_MAX_AGE_MS: u64 = 10 * 60 * 1000;

/// 同時に覚えておく目印の数。
pub const MAX_LINK_TOKENS: usize = 3;

/// 目印は、16 バイトの乱数を 16 進にした 32 文字。
pub fn token_from_bytes(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_token(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Web に渡す戻り先。成功も、断られた(`errorCallbackURL`)ときも、これに戻る(Web が `error` を足す)。
pub fn link_callback_url(token: &str) -> String {
    format!("{APP_SCHEME}:///?link={token}")
}

/// アプリを開いたリンクが、連携の戻りなら、その目印。ちょうど `<スキーム>:///?link=…`(ホストなし、
/// パスなし)で、`link` が 1 つだけのときだけ。`state` や `code` や `cookie` が付いたものは、ログインの
/// リンクなので、ここでは扱わない。
pub fn link_return_token(link: &str) -> Option<String> {
    let url = Url::parse(link).ok()?;
    if url.scheme() != APP_SCHEME
        || url.host_str().is_some_and(|h| !h.is_empty())
        || !matches!(url.path(), "" | "/")
        || url.fragment().is_some()
    {
        return None;
    }
    let mut token = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "link" => {
                if token.is_some() {
                    return None;
                }
                token = Some(value.into_owned());
            }
            "state" | "code" | "cookie" => return None,
            _ => {}
        }
    }
    token.filter(|t| is_token(t))
}

/// 戻りのリンクに Web が付けた `error`(断られた理由のコード)。画面に見せるので、英数字と `_` `-` だけの
/// 短いものに限る(それ以外は、中身を出さず `unknown` にする)。付いていなければ `None`。
pub fn link_return_error(link: &str) -> Option<String> {
    let url = Url::parse(link).ok()?;
    let (_, value) = url.query_pairs().find(|(key, _)| key == "error")?;
    let plain = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    Some(if plain {
        value.into_owned()
    } else {
        "unknown".to_string()
    })
}

/// 覚えている目印(`(目印, 頼んだ時刻)`)に、`token` を足す。古いもの、多すぎるものは捨てる。
pub fn add_token(list: &[(String, u64)], token: &str, now: u64) -> Vec<(String, u64)> {
    let mut next: Vec<(String, u64)> = list
        .iter()
        .filter(|(_, at)| now.saturating_sub(*at) < LINK_MAX_AGE_MS)
        .cloned()
        .collect();
    next.push((token.to_string(), now));
    while next.len() > MAX_LINK_TOKENS {
        next.remove(0);
    }
    next
}

/// `token` が覚えている(有効な)ものなら、使い切って(消して)`true`。そうでなければ `false`。
pub fn use_token(list: &[(String, u64)], token: &str, now: u64) -> (bool, Vec<(String, u64)>) {
    let known = list
        .iter()
        .any(|(t, at)| t == token && now.saturating_sub(*at) < LINK_MAX_AGE_MS);
    let rest = list
        .iter()
        .filter(|(t, at)| t != token && now.saturating_sub(*at) < LINK_MAX_AGE_MS)
        .cloned()
        .collect();
    (known, rest)
}

/// Web に頼んだ連携の失敗の種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountFailure {
    /// セッションが無効(401)。
    SessionEnded,
    /// 「5 分以内のログイン」が要る(`SESSION_NOT_FRESH`)。入り直してから、すぐやり直す。
    NotFresh,
    Failed,
}

/// 連携と解除の失敗を分ける。`NotFresh` は、本文の `code` が `SESSION_NOT_FRESH` のときだけ
/// (別の理由の 403 を「入り直して」と案内しない)。
pub fn classify_account_failure(status: Option<u16>, code: Option<&str>) -> AccountFailure {
    match (status, code) {
        (Some(401), _) => AccountFailure::SessionEnded,
        (Some(403), Some("SESSION_NOT_FRESH")) => AccountFailure::NotFresh,
        _ => AccountFailure::Failed,
    }
}

/// ブラウザで開く URL。Web のプロキシに、Google の認可 URL を渡す(プロキシが、ブラウザに OAuth の
/// `state` の Cookie を置いてから、Google へ進める)。開くのは、**自分の Web のプロキシだけ**。
/// 認可 URL は、Google のもの(`https://accounts.google.com`)でなければ、開かない。
pub fn proxy_url(web: &str, authorization_url: &str) -> Option<String> {
    let google = Url::parse(authorization_url).ok()?;
    if google.origin().ascii_serialization() != "https://accounts.google.com" {
        return None;
    }
    let mut proxy = Url::parse(web).ok()?;
    proxy.set_path("/api/auth/expo-authorization-proxy");
    proxy.set_query(None);
    proxy
        .query_pairs_mut()
        .append_pair("authorizationURL", authorization_url);
    Some(proxy.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn a_token_is_32_lower_case_hex_characters() {
        assert_eq!(
            token_from_bytes(&[0xab; 16]),
            "abababababababababababababababab"
        );
        assert!(is_token(TOKEN));
        for bad in [
            "",
            "abc",
            &TOKEN.to_uppercase(),
            &format!("{TOKEN}0"),
            "g123456789abcdef0123456789abcdef",
        ] {
            assert!(!is_token(bad), "{bad}");
        }
    }

    #[test]
    fn the_callback_comes_back_as_the_link_the_app_reads() {
        assert_eq!(
            link_return_token(&link_callback_url(TOKEN)).as_deref(),
            Some(TOKEN)
        );
        // 断られたときは、Web が error を足して戻す。目印は読める。
        assert_eq!(
            link_return_token(&format!("{}&error=access_denied", link_callback_url(TOKEN)))
                .as_deref(),
            Some(TOKEN)
        );
    }

    #[test]
    fn the_reason_the_web_app_gave_is_read_and_made_safe() {
        let base = link_callback_url(TOKEN);
        assert_eq!(link_return_error(&base), None);
        assert_eq!(
            link_return_error(&format!("{base}&error=state_mismatch")).as_deref(),
            Some("state_mismatch")
        );
        for odd in ["a%20b", "%3Cscript%3E", "", &"x".repeat(65)] {
            assert_eq!(
                link_return_error(&format!("{base}&error={odd}")).as_deref(),
                Some("unknown"),
                "{odd}"
            );
        }
    }

    #[test]
    fn only_the_exact_shape_is_a_link_return() {
        for bad in [
            "https://example.com/?link=0123456789abcdef0123456789abcdef",
            "otherapp:///?link=0123456789abcdef0123456789abcdef",
            "betterauthmulti://host/?link=0123456789abcdef0123456789abcdef",
            "betterauthmulti:///path?link=0123456789abcdef0123456789abcdef",
            "betterauthmulti:///?link=0123456789abcdef0123456789abcdef#x",
            "betterauthmulti:///?link=short",
            "betterauthmulti:///",
            "betterauthmulti:///?other=1",
            "betterauthmulti:///?link=0123456789abcdef0123456789abcdef&link=0123456789abcdef0123456789abcdef",
            // ログインのリンク(state や code や cookie が付いたもの)は、ここでは扱わない。
            "betterauthmulti:///?link=0123456789abcdef0123456789abcdef&state=s",
            "betterauthmulti:///?link=0123456789abcdef0123456789abcdef&code=c",
            "betterauthmulti:///?link=0123456789abcdef0123456789abcdef&cookie=c",
            "not a url",
        ] {
            assert_eq!(link_return_token(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_token_is_used_once_and_expires() {
        let list = add_token(&[], TOKEN, 1_000);
        let (known, rest) = use_token(&list, TOKEN, 2_000);
        assert!(known);
        assert!(rest.is_empty());
        // 2 回目は知らない。
        assert!(!use_token(&rest, TOKEN, 3_000).0);
        // 古いものは使えない。
        let (known, rest) = use_token(&list, TOKEN, 1_000 + LINK_MAX_AGE_MS);
        assert!(!known);
        assert!(rest.is_empty());
        // 別の目印では使えず、覚えているものは残る。
        let (known, rest) = use_token(&list, "other", 2_000);
        assert!(!known);
        assert_eq!(rest.len(), 1);
    }

    #[test]
    fn only_a_few_tokens_are_kept() {
        let mut list = Vec::new();
        for i in 0..5u64 {
            list = add_token(&list, &format!("t{i}"), 1_000 + i);
        }
        assert_eq!(list.len(), MAX_LINK_TOKENS);
        assert_eq!(list[0].0, "t2");
    }

    #[test]
    fn failures_are_told_apart() {
        assert_eq!(
            classify_account_failure(Some(401), None),
            AccountFailure::SessionEnded
        );
        assert_eq!(
            classify_account_failure(Some(403), Some("SESSION_NOT_FRESH")),
            AccountFailure::NotFresh
        );
        for (status, code) in [
            (Some(403), None),
            (Some(403), Some("SERVER_ONLY")),
            (Some(500), Some("SESSION_NOT_FRESH")),
            (Some(429), None),
            (None, None),
        ] {
            assert_eq!(
                classify_account_failure(status, code),
                AccountFailure::Failed
            );
        }
    }

    #[test]
    fn only_our_proxy_is_opened_and_only_with_a_google_address() {
        let google = "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=s";
        let opened = proxy_url("http://localhost:3000", google).unwrap();
        assert!(opened.starts_with(
            "http://localhost:3000/api/auth/expo-authorization-proxy?authorizationURL="
        ));
        let parsed = Url::parse(&opened).unwrap();
        let (_, value) = parsed
            .query_pairs()
            .find(|(k, _)| k == "authorizationURL")
            .unwrap();
        assert_eq!(value, google);
        for bad in [
            "https://evil.example/",
            "https://accounts.google.com.evil.example/",
            "http://accounts.google.com/",
            "javascript:alert(1)",
            "",
        ] {
            assert_eq!(proxy_url("http://localhost:3000", bad), None, "{bad}");
        }
    }
}

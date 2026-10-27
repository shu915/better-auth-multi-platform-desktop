//! Web が返したセッションの cookie(Set-Cookie の文字列)から、session_token を取り出す。
//!
//! 引き換えで返る `cookie` は、Better Auth が付けた Set-Cookie の文字列で、複数の cookie がカンマで
//! つながることがある(`session_token` のほかに `session_data` など)。必要なのは session_token の
//! 「名前=値」だけ。値は署名付きで、Web の `/token` に Bearer で渡し、ログアウトには Cookie として送る。
//! モバイルの `token.ts` の `SESSION_TOKEN` と、Web の `mobile-code.ts` の `SESSION_COOKIE` に当たる。

#[derive(Clone, PartialEq, Eq)]
pub struct SessionCookie {
    /// `better-auth.session_token`、または https の Web では `__Secure-better-auth.session_token`。
    pub name: String,
    /// 署名付きのトークン(cookie の値のまま。URL エンコードされている)。
    pub value: String,
}

/// `{:?}` でログに出ても、値(セッションの秘密)は出さない。
impl std::fmt::Debug for SessionCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCookie")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

const NAMES: [&str; 2] = [
    "__Secure-better-auth.session_token",
    "better-auth.session_token",
];

impl SessionCookie {
    /// `Cookie` ヘッダーに載せる形(`名前=値`)。ログアウトで送る。Keychain にも、この形で保存する。
    pub fn pair(&self) -> String {
        format!("{}={}", self.name, self.value)
    }

    /// `Authorization: Bearer …` に載せる値。`/token` だけが受け付ける(Cookie ヘッダーは付けない)。
    pub fn bearer(&self) -> &str {
        &self.value
    }
}

/// Set-Cookie の文字列(または保存した `名前=値`)から、空でない session_token を取り出す。
/// 値が空の cookie(セッションを消す指示)は、セッションではないので `None`。
pub fn parse_session_cookie(text: &str) -> Option<SessionCookie> {
    // 値には `;` `,` 空白が入らない。属性(`Max-Age=…` など)や、次の cookie の前の区切りで切れる。
    text.split(|c: char| c == ';' || c == ',' || c.is_whitespace())
        .find_map(|token| {
            let (name, value) = token.split_once('=')?;
            (NAMES.contains(&name) && !value.is_empty()).then(|| SessionCookie {
                name: name.to_string(),
                value: value.to_string(),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie(name: &str, value: &str) -> Option<SessionCookie> {
        Some(SessionCookie {
            name: name.to_string(),
            value: value.to_string(),
        })
    }

    #[test]
    fn takes_the_token_from_a_set_cookie_string() {
        let text =
            "better-auth.session_token=abc.def%3D; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax";
        assert_eq!(
            parse_session_cookie(text),
            cookie("better-auth.session_token", "abc.def%3D")
        );
    }

    #[test]
    fn takes_the_secure_prefixed_name() {
        let text = "__Secure-better-auth.session_token=xyz; Max-Age=1; Secure";
        assert_eq!(
            parse_session_cookie(text),
            cookie("__Secure-better-auth.session_token", "xyz")
        );
    }

    #[test]
    fn finds_the_token_after_other_cookies_joined_by_commas() {
        let text = "better-auth.session_data=zzz; Max-Age=300; Path=/, better-auth.session_token=tok; Max-Age=9; Path=/";
        assert_eq!(
            parse_session_cookie(text),
            cookie("better-auth.session_token", "tok")
        );
    }

    #[test]
    fn an_expires_attribute_with_a_comma_does_not_confuse_it() {
        let text = "better-auth.session_token=tok; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/";
        assert_eq!(
            parse_session_cookie(text),
            cookie("better-auth.session_token", "tok")
        );
    }

    #[test]
    fn a_cookie_that_deletes_the_session_is_not_a_session() {
        assert_eq!(
            parse_session_cookie("better-auth.session_token=; Max-Age=0; Path=/"),
            None
        );
    }

    #[test]
    fn other_cookies_and_garbage_are_not_sessions() {
        for text in [
            "",
            "better-auth.session_data=zzz; Path=/",
            "evil.better-auth.session_token=x",
            "better-auth.session_token_extra=x",
            "no equals sign",
        ] {
            assert_eq!(parse_session_cookie(text), None, "{text}");
        }
    }

    #[test]
    fn debug_output_hides_the_value() {
        let c = cookie("better-auth.session_token", "very-secret").unwrap();
        assert!(!format!("{c:?}").contains("very-secret"));
    }

    #[test]
    fn the_stored_pair_reads_back_the_same() {
        let c = cookie("better-auth.session_token", "a.b%3D").unwrap();
        assert_eq!(parse_session_cookie(&c.pair()), Some(c.clone()));
        assert_eq!(c.bearer(), "a.b%3D");
    }
}

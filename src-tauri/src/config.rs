//! 接続先の URL。ビルド時に環境変数で埋め込む(`AUTH_WEB_URL` と `AUTH_API_URL`。例:
//! `AUTH_WEB_URL=https://… AUTH_API_URL=https://… npm run tauri build`)。
//!
//! 実行時の環境変数は読まない(アプリの外から接続先を差し替えられないようにする)。値は Rust にだけ
//! あり、WebView には渡らない。判断は純粋な関数に分けて、`cargo test` で試す。

/// 開発(デバッグビルド)の Web と Go の既定の接続先。
const DEV_WEB_URL: &str = "http://localhost:3000";
const DEV_API_URL: &str = "http://localhost:8080";

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// リリースビルドなのに、接続先が埋め込まれていない。
    Missing,
    /// リリースビルドなのに、`https://` でない。
    NotHttps,
    /// URL として読めない、またはホストがない。
    Invalid,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // どの変数かは、呼び出し側が知っている。ここでは、種類だけを言う(Web と Go で使い回す)。
            ConfigError::Missing => write!(f, "the URL must be set in a release build"),
            ConfigError::NotHttps => write!(f, "the URL must be https in a release build"),
            ConfigError::Invalid => write!(f, "the URL is not valid"),
        }
    }
}

/// 埋め込まれた値(あれば)と、デバッグビルドかどうかから、接続先を決める。`dev_default` は、
/// デバッグビルドで値がないときの既定。末尾の `/` は取る。リリースビルドでは `https://` を必須にする
/// (平文の通信にセッションや JWT を載せない)。
pub fn resolve_url(
    value: Option<&str>,
    debug: bool,
    dev_default: &str,
) -> Result<String, ConfigError> {
    let value = match value.map(str::trim) {
        None | Some("") => {
            return if debug {
                Ok(dev_default.to_string())
            } else {
                Err(ConfigError::Missing)
            };
        }
        Some(v) => v,
    };
    let url = url::Url::parse(value).map_err(|_| ConfigError::Invalid)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ConfigError::Invalid);
    }
    if !debug && url.scheme() != "https" {
        return Err(ConfigError::NotHttps);
    }
    // `https://user:pw@host` のような、ユーザー情報つきの URL は受け付けない(秘密を URL に書かない)。
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::Invalid);
    }
    // 接続先にパスや問い合わせがあると、`{base}/api/...` の組み立てが崩れる。
    if url.query().is_some() || url.fragment().is_some() || !url.path().chars().all(|c| c == '/') {
        return Err(ConfigError::Invalid);
    }
    Ok(value.trim_end_matches('/').to_string())
}

/// この実行ファイルの Web の接続先。
pub fn web_url() -> Result<String, ConfigError> {
    resolve_url(
        option_env!("AUTH_WEB_URL"),
        cfg!(debug_assertions),
        DEV_WEB_URL,
    )
}

/// この実行ファイルの Go API の接続先。
pub fn api_url() -> Result<String, ConfigError> {
    resolve_url(
        option_env!("AUTH_API_URL"),
        cfg!(debug_assertions),
        DEV_API_URL,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_build_defaults_to_localhost() {
        assert_eq!(
            resolve_url(None, true, DEV_WEB_URL).as_deref(),
            Ok("http://localhost:3000")
        );
        assert_eq!(
            resolve_url(Some("  "), true, DEV_WEB_URL).as_deref(),
            Ok("http://localhost:3000")
        );
    }

    #[test]
    fn release_build_needs_a_value() {
        assert_eq!(
            resolve_url(None, false, DEV_WEB_URL),
            Err(ConfigError::Missing)
        );
        assert_eq!(
            resolve_url(Some(""), false, DEV_WEB_URL),
            Err(ConfigError::Missing)
        );
    }

    #[test]
    fn release_build_needs_https() {
        assert_eq!(
            resolve_url(Some("http://example.com"), false, DEV_WEB_URL),
            Err(ConfigError::NotHttps)
        );
        assert_eq!(
            resolve_url(Some("https://example.com"), false, DEV_WEB_URL).as_deref(),
            Ok("https://example.com")
        );
    }

    #[test]
    fn debug_build_accepts_http() {
        assert_eq!(
            resolve_url(Some("http://192.168.0.5:3000"), true, DEV_WEB_URL).as_deref(),
            Ok("http://192.168.0.5:3000")
        );
    }

    #[test]
    fn trailing_slashes_are_removed() {
        assert_eq!(
            resolve_url(Some("https://example.com///"), false, DEV_WEB_URL).as_deref(),
            Ok("https://example.com")
        );
    }

    #[test]
    fn other_schemes_and_junk_are_invalid() {
        for value in [
            "ftp://example.com",
            "betterauthmulti://x",
            "not a url",
            "https://",
            "https://example.com/app",
            "https://example.com/?a=b",
            "https://example.com/#x",
            "https://user@example.com",
            "https://user:pw@example.com",
        ] {
            assert_eq!(
                resolve_url(Some(value), true, DEV_WEB_URL),
                Err(ConfigError::Invalid),
                "{value}"
            );
        }
    }
}

//! 接続先の URL。ビルド時に環境変数で埋め込む(`AUTH_WEB_URL=https://… npm run tauri build`)。
//!
//! 実行時の環境変数は読まない(アプリの外から接続先を差し替えられないようにする)。値は Rust にだけ
//! あり、WebView には渡らない。判断は純粋な関数に分けて、`cargo test` で試す。

/// 開発(デバッグビルド)の Web の既定の接続先。
const DEV_WEB_URL: &str = "http://localhost:3000";

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
            ConfigError::Missing => write!(f, "AUTH_WEB_URL must be set in a release build"),
            ConfigError::NotHttps => {
                write!(f, "AUTH_WEB_URL must be an https URL in a release build")
            }
            ConfigError::Invalid => write!(f, "AUTH_WEB_URL is not a valid URL"),
        }
    }
}

/// 埋め込まれた値(あれば)と、デバッグビルドかどうかから、Web の接続先を決める。
/// 末尾の `/` は取る。リリースビルドでは `https://` を必須にする(平文の通信にセッションを載せない)。
pub fn resolve_web_url(value: Option<&str>, debug: bool) -> Result<String, ConfigError> {
    let value = match value.map(str::trim) {
        None | Some("") => {
            return if debug {
                Ok(DEV_WEB_URL.to_string())
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
    // 接続先にパスや問い合わせがあると、`{base}/api/...` の組み立てが崩れる。
    if url.query().is_some() || url.fragment().is_some() || !url.path().chars().all(|c| c == '/') {
        return Err(ConfigError::Invalid);
    }
    Ok(value.trim_end_matches('/').to_string())
}

/// この実行ファイルの Web の接続先。
pub fn web_url() -> Result<String, ConfigError> {
    resolve_web_url(option_env!("AUTH_WEB_URL"), cfg!(debug_assertions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_build_defaults_to_localhost() {
        assert_eq!(
            resolve_web_url(None, true).as_deref(),
            Ok("http://localhost:3000")
        );
        assert_eq!(
            resolve_web_url(Some("  "), true).as_deref(),
            Ok("http://localhost:3000")
        );
    }

    #[test]
    fn release_build_needs_a_value() {
        assert_eq!(resolve_web_url(None, false), Err(ConfigError::Missing));
        assert_eq!(resolve_web_url(Some(""), false), Err(ConfigError::Missing));
    }

    #[test]
    fn release_build_needs_https() {
        assert_eq!(
            resolve_web_url(Some("http://example.com"), false),
            Err(ConfigError::NotHttps)
        );
        assert_eq!(
            resolve_web_url(Some("https://example.com"), false).as_deref(),
            Ok("https://example.com")
        );
    }

    #[test]
    fn debug_build_accepts_http() {
        assert_eq!(
            resolve_web_url(Some("http://192.168.0.5:3000"), true).as_deref(),
            Ok("http://192.168.0.5:3000")
        );
    }

    #[test]
    fn trailing_slashes_are_removed() {
        assert_eq!(
            resolve_web_url(Some("https://example.com///"), false).as_deref(),
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
        ] {
            assert_eq!(
                resolve_web_url(Some(value), true),
                Err(ConfigError::Invalid),
                "{value}"
            );
        }
    }
}

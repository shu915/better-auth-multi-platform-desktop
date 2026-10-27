//! Keychain への保存。秘密は Rust の中だけに置き、読み出しの結果を JS には返さない。
//!
//! 判断(名前と値の検証)は純粋な関数に分けて、`cargo test` で試す。Keychain 本体を触る部分は
//! OS に依存するので、テストでは触らない。

use keyring::Entry;

/// Keychain の「サービス名」。アプリの識別子と同じにして、他のアプリの項目と混ざらないようにする。
const SERVICE: &str = "com.shu915.authpractice.desktop";

/// 値の最大バイト数。大きすぎる値を Keychain に入れさせない。
const MAX_VALUE_BYTES: usize = 4096;

/// JS から指定できる項目名。ここにない名前は拒否する(任意の名前で Keychain を読み書きさせない)。
const ALLOWED_NAMES: &[&str] = &["practice"];

#[derive(Debug, PartialEq)]
pub enum SecretError {
    UnknownName,
    EmptyValue,
    ValueTooLarge,
    Keychain(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::UnknownName => write!(f, "unknown secret name"),
            SecretError::EmptyValue => write!(f, "value is empty"),
            SecretError::ValueTooLarge => write!(f, "value is too large"),
            // Keychain のエラーの詳細は、JS には渡さない(ログにも値は含まれない)。
            SecretError::Keychain(_) => write!(f, "keychain error"),
        }
    }
}

/// 項目名が許可リストにあるか。
pub fn check_name(name: &str) -> Result<(), SecretError> {
    if ALLOWED_NAMES.contains(&name) {
        Ok(())
    } else {
        Err(SecretError::UnknownName)
    }
}

/// 保存する値が空でなく、大きすぎないか。
pub fn check_value(value: &str) -> Result<(), SecretError> {
    if value.is_empty() {
        return Err(SecretError::EmptyValue);
    }
    if value.len() > MAX_VALUE_BYTES {
        return Err(SecretError::ValueTooLarge);
    }
    Ok(())
}

fn entry(name: &str) -> Result<Entry, SecretError> {
    check_name(name)?;
    Entry::new(SERVICE, name).map_err(|e| SecretError::Keychain(e.to_string()))
}

pub fn save(name: &str, value: &str) -> Result<(), SecretError> {
    check_value(value)?;
    entry(name)?
        .set_password(value)
        .map_err(|e| SecretError::Keychain(e.to_string()))
}

/// 値があるかどうかだけを返す。値そのものは返さない。
pub fn exists(name: &str) -> Result<bool, SecretError> {
    match entry(name)?.get_password() {
        Ok(_) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(SecretError::Keychain(e.to_string())),
    }
}

/// 消す。もともとなくても成功にする(何度やっても同じ結果になる)。
pub fn delete(name: &str) -> Result<(), SecretError> {
    match entry(name)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(SecretError::Keychain(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_name_is_accepted() {
        assert_eq!(check_name("practice"), Ok(()));
    }

    #[test]
    fn unknown_name_is_rejected() {
        assert_eq!(check_name("session"), Err(SecretError::UnknownName));
        assert_eq!(check_name(""), Err(SecretError::UnknownName));
        assert_eq!(check_name("practice "), Err(SecretError::UnknownName));
        assert_eq!(check_name("../practice"), Err(SecretError::UnknownName));
    }

    #[test]
    fn empty_value_is_rejected() {
        assert_eq!(check_value(""), Err(SecretError::EmptyValue));
    }

    #[test]
    fn value_up_to_the_limit_is_accepted() {
        assert_eq!(check_value(&"a".repeat(MAX_VALUE_BYTES)), Ok(()));
    }

    #[test]
    fn value_over_the_limit_is_rejected() {
        assert_eq!(
            check_value(&"a".repeat(MAX_VALUE_BYTES + 1)),
            Err(SecretError::ValueTooLarge)
        );
    }

    #[test]
    fn limit_counts_bytes_not_characters() {
        // 「あ」は 3 バイト。1366 文字で 4098 バイトになり、上限を超える。
        assert_eq!(
            check_value(&"あ".repeat(1366)),
            Err(SecretError::ValueTooLarge)
        );
    }

    #[test]
    fn keychain_error_message_hides_details() {
        let e = SecretError::Keychain("secret-detail".to_string());
        assert_eq!(e.to_string(), "keychain error");
    }
}

//! Keychain への保存。秘密は Rust の中だけに置き、JS には値を返さない。
//!
//! 保存先は `Slot`(決まった名前だけ)。Keychain に触れるのは Rust の内部だけで、JS には、保存・
//! 読み出しのコマンドを一切公開しない。判断(値の検証)は純粋な関数に分けて、`cargo test` で試す。Keychain 本体を触る部分は OS に依存するので、テストでは触らない
//! (テストでは `Store` を、メモリ上の偽物に差し替える)。

use keyring::Entry;

/// Keychain の「サービス名」。アプリの識別子と同じにして、他のアプリの項目と混ざらないようにする。
const SERVICE: &str = "com.shu915.authpractice.desktop";

/// 値の最大バイト数。大きすぎる値を Keychain に入れさせない。
const MAX_VALUE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// ログイン中のセッション(`名前=値`)。Rust の内部だけ。
    Session,
    /// 自分が始めたログインの一覧(JSON)。Rust の内部だけ。
    Pending,
}

impl Slot {
    /// Keychain の「アカウント名」。
    fn account(self) -> &'static str {
        match self {
            Slot::Session => "session",
            Slot::Pending => "pending_sign_in",
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SecretError {
    EmptyValue,
    ValueTooLarge,
    Keychain(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::EmptyValue => write!(f, "value is empty"),
            SecretError::ValueTooLarge => write!(f, "value is too large"),
            // Keychain のエラーの詳細は、JS には渡さない(ログにも値は含まれない)。
            SecretError::Keychain(_) => write!(f, "keychain error"),
        }
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

/// 秘密の置き場。本物は Keychain、テストではメモリ上の偽物。
pub trait Store: Send + Sync {
    fn load(&self, slot: Slot) -> Result<Option<String>, SecretError>;
    fn save(&self, slot: Slot, value: &str) -> Result<(), SecretError>;
    /// 消す。もともとなくても成功にする(何度やっても同じ結果になる)。
    fn delete(&self, slot: Slot) -> Result<(), SecretError>;
}

pub struct KeychainStore;

fn entry(slot: Slot) -> Result<Entry, SecretError> {
    Entry::new(SERVICE, slot.account()).map_err(|e| SecretError::Keychain(e.to_string()))
}

impl Store for KeychainStore {
    fn load(&self, slot: Slot) -> Result<Option<String>, SecretError> {
        match entry(slot)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(SecretError::Keychain(e.to_string())),
        }
    }

    fn save(&self, slot: Slot, value: &str) -> Result<(), SecretError> {
        check_value(value)?;
        entry(slot)?
            .set_password(value)
            .map_err(|e| SecretError::Keychain(e.to_string()))
    }

    fn delete(&self, slot: Slot) -> Result<(), SecretError> {
        match entry(slot)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretError::Keychain(e.to_string())),
        }
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// メモリ上の偽の置き場。
    #[derive(Default)]
    pub struct MemoryStore(Mutex<HashMap<&'static str, String>>);

    impl Store for MemoryStore {
        fn load(&self, slot: Slot) -> Result<Option<String>, SecretError> {
            Ok(self.0.lock().unwrap().get(slot.account()).cloned())
        }
        fn save(&self, slot: Slot, value: &str) -> Result<(), SecretError> {
            check_value(value)?;
            self.0
                .lock()
                .unwrap()
                .insert(slot.account(), value.to_string());
            Ok(())
        }
        fn delete(&self, slot: Slot) -> Result<(), SecretError> {
            self.0.lock().unwrap().remove(slot.account());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::MemoryStore;
    use super::*;

    #[test]
    fn slots_use_different_accounts() {
        let accounts = [Slot::Session, Slot::Pending].map(Slot::account);
        assert_eq!(accounts, ["session", "pending_sign_in"]);
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

    #[test]
    fn the_memory_store_saves_loads_and_deletes() {
        let store = MemoryStore::default();
        assert_eq!(store.load(Slot::Session), Ok(None));
        store.save(Slot::Session, "v").unwrap();
        assert_eq!(store.load(Slot::Session), Ok(Some("v".to_string())));
        assert_eq!(store.load(Slot::Pending), Ok(None));
        store.delete(Slot::Session).unwrap();
        store.delete(Slot::Session).unwrap(); // 2 回目も成功(何度やっても同じ)
        assert_eq!(store.load(Slot::Session), Ok(None));
    }
}

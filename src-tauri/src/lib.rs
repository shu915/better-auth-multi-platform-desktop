pub mod auth;
pub mod config;
mod secret;
pub mod session_cookie;
pub mod sign_in_rules;

use auth::{AuthState, RequestOutcome, SignOutOutcome};
use secret::{KeychainStore, Slot, Store};

// Tauri のコマンドは薄く保つ。判断は純粋な関数(sign_in_rules.rs など)に置き、流れは auth.rs に置く。
// 値を読み出して JS に返すコマンドは作らない(秘密を JS に出さない)。
// エラーは JS には種類だけを文字列で返す(Keychain の詳細は返さない)。

// 練習用(段階 1)。JS が開けるのは `practice` だけで、セッションなどには触れない。
#[tauri::command]
fn secret_save(name: &str, value: &str) -> Result<(), String> {
    let slot = Slot::from_js(name).map_err(|e| e.to_string())?;
    KeychainStore.save(slot, value).map_err(|e| e.to_string())
}

#[tauri::command]
fn secret_exists(name: &str) -> Result<bool, String> {
    let slot = Slot::from_js(name).map_err(|e| e.to_string())?;
    KeychainStore
        .load(slot)
        .map(|value| value.is_some())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn secret_delete(name: &str) -> Result<(), String> {
    let slot = Slot::from_js(name).map_err(|e| e.to_string())?;
    KeychainStore.delete(slot).map_err(|e| e.to_string())
}

/// マジックリンクのメールを頼む。
#[tauri::command]
async fn request_sign_in_link(
    email: String,
    state: tauri::State<'_, AuthState>,
) -> Result<RequestOutcome, String> {
    let outcome = match config::web_url() {
        Ok(base) => auth::request_sign_in_link(&state, &KeychainStore, &base, &email).await,
        Err(error) => RequestOutcome::Failed {
            reason: error.to_string(),
            status: None,
        },
    };
    Ok(outcome)
}

/// ログイン中か(Keychain にセッションがあるか)。
#[tauri::command]
fn session_status() -> bool {
    auth::is_signed_in(&KeychainStore)
}

/// ログアウト。この Mac のセッションは必ず消す。
#[tauri::command]
async fn sign_out() -> Result<SignOutOutcome, String> {
    let outcome = match config::web_url() {
        Ok(base) => auth::sign_out(&KeychainStore, &base).await,
        // 接続先が決まらなくても、この Mac のセッションは消せる。
        Err(_) => auth::sign_out(&KeychainStore, "").await,
    };
    Ok(outcome)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AuthState::new())
        .invoke_handler(tauri::generate_handler![
            secret_save,
            secret_exists,
            secret_delete,
            request_sign_in_link,
            session_status,
            sign_out
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

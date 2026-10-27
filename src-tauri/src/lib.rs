pub mod auth;
pub mod config;
mod secret;
pub mod session_cookie;
pub mod sign_in_rules;

use auth::{AcceptOutcome, AuthState, RequestOutcome, SignOutOutcome};
use secret::{KeychainStore, Slot, Store};
use tauri::{Emitter, Manager};
use tauri_plugin_deep_link::DeepLinkExt;

/// 画面に、ログインのリンクの結果を伝えるイベント。中身は `AcceptOutcome`(秘密は入らない)。
const AUTH_EVENT: &str = "auth-changed";

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

/// OS から渡されたリンク(`betterauthmulti://…`)を、ログインの処理に回す。
/// リンクの中身は、ログにも画面にも出さない。ログインのリンクでないもの(`Ignored`)は黙って捨てる。
fn handle_link(app: tauri::AppHandle, link: String) {
    tauri::async_runtime::spawn(async move {
        let outcome = match config::web_url() {
            Ok(base) => {
                let state = app.state::<AuthState>();
                auth::accept_sign_in_link(&state, &KeychainStore, &base, &link).await
            }
            Err(error) => AcceptOutcome::Failed {
                reason: error.to_string(),
            },
        };
        if outcome == AcceptOutcome::Ignored {
            return;
        }
        // デバッグビルドだけ、結果の種類を出す(`reason` は固定の文字列で、秘密は入らない)。
        if cfg!(debug_assertions) {
            eprintln!("[auth] link outcome: {outcome:?}");
        }
        // メールのリンクはブラウザで開くので、結果が出たらアプリを前に出す。
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
        let _ = app.emit(AUTH_EVENT, &outcome);
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init())
        .manage(AuthState::new())
        .setup(|app| {
            let handle = app.handle().clone();
            // リンクを押してアプリが起動したとき(まだ動いていなかったとき)のリンク。
            if let Some(urls) = app.deep_link().get_current()? {
                for url in urls {
                    handle_link(handle.clone(), url.to_string());
                }
            }
            // アプリが動いているときに届くリンク。
            app.deep_link().on_open_url(move |event| {
                for url in event.urls() {
                    handle_link(handle.clone(), url.to_string());
                }
            });
            Ok(())
        })
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

pub mod account;
pub mod api_parse;
pub mod auth;
pub mod config;
pub mod google;
pub mod link_rules;
pub mod profile;
pub mod profile_rules;
mod secret;
pub mod session_cookie;
pub mod sign_in_rules;
#[cfg(test)]
mod test_support;

use account::DeleteOutcome;
use auth::{AcceptOutcome, AuthState, RequestOutcome, SignOutOutcome};
use google::{AccountsOutcome, LinkOutcome, SystemOpener, UnlinkOutcome};
use profile::{LoadOutcome, SaveInput, SaveOutcome};
use secret::KeychainStore;
use sign_in_rules::{LinkVerdict, judge_link};
use tauri::{Emitter, Manager};
use tauri_plugin_deep_link::DeepLinkExt;

/// 画面への合図。「リンクの結果が出た」というだけで、中身は運ばない。結果は、画面が
/// `take_auth_outcome` で Rust から取る(画面が、イベントの中身を信じなくて済む。起動時のリンクの
/// 結果を、画面の準備が間に合わなくても、取りこぼさない)。
const AUTH_EVENT: &str = "auth-changed";

/// 画面への合図。「Google の連携のブラウザから戻った」というだけ。画面は、連携の一覧を読み直して、
/// 結果を決める。
const ACCOUNTS_EVENT: &str = "accounts-changed";

// Tauri のコマンドは薄く保つ。判断は純粋な関数(sign_in_rules.rs など)に置き、流れは auth.rs に置く。
// Keychain の保存・読み出しを JS に公開するコマンドは作らない(秘密を JS に出さない)。
// エラーは JS には種類だけを返す(Keychain の詳細は返さない)。

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

/// 最後に処理したリンクの結果を渡す(1 回だけ。なければ `null`)。
#[tauri::command]
fn take_auth_outcome(state: tauri::State<'_, AuthState>) -> Option<AcceptOutcome> {
    state.take_outcome()
}

/// プロフィール(名前、メール、bio)を読む。セッションが無効なら、この Mac のセッションを消す。
#[tauri::command]
async fn load_profile(state: tauri::State<'_, AuthState>) -> Result<LoadOutcome, String> {
    let outcome = match (config::web_url(), config::api_url()) {
        (Ok(web), Ok(api)) => profile::load_profile(&state, &KeychainStore, &web, &api).await,
        _ => LoadOutcome::Failed,
    };
    Ok(outcome)
}

/// 変わったものだけを保存する。画面は、今保存されている値と、編集中の値を渡す。
#[tauri::command]
async fn save_profile(
    saved_name: String,
    name_draft: String,
    saved_bio: String,
    bio_draft: String,
    state: tauri::State<'_, AuthState>,
) -> Result<SaveOutcome, String> {
    let input = SaveInput {
        saved_name: &saved_name,
        name_draft: &name_draft,
        saved_bio: &saved_bio,
        bio_draft: &bio_draft,
    };
    let outcome = match (config::web_url(), config::api_url()) {
        (Ok(web), Ok(api)) => {
            profile::save_profile(&state, &KeychainStore, &web, &api, &input).await
        }
        // 接続先の設定の誤りは、どの項目の失敗でもない。
        _ => SaveOutcome::Failed {
            field: None,
            refused: false,
            refusal: None,
            name_saved: None,
        },
    };
    Ok(outcome)
}

/// 連携の一覧から、Google が紐づいているか。
#[tauri::command]
async fn load_accounts(state: tauri::State<'_, AuthState>) -> Result<AccountsOutcome, String> {
    let outcome = match config::web_url() {
        Ok(web) => google::load_accounts(&state, &KeychainStore, &web).await,
        Err(_) => AccountsOutcome::Failed,
    };
    Ok(outcome)
}

/// Google の連携を始める(システムのブラウザを開く)。結果は、戻りのあとに、画面が一覧を読み直して決める。
#[tauri::command]
async fn link_google(state: tauri::State<'_, AuthState>) -> Result<LinkOutcome, String> {
    let outcome = match config::web_url() {
        Ok(web) => google::link_google(&state, &KeychainStore, &web, &SystemOpener).await,
        Err(_) => LinkOutcome::Failed,
    };
    Ok(outcome)
}

/// 最後の連携の戻りに付いていた、Web が断った理由のコード(1 回だけ。なければ `null`)。
#[tauri::command]
fn take_link_error(state: tauri::State<'_, AuthState>) -> Option<String> {
    state.take_link_error()
}

/// Google の連携を外す。
#[tauri::command]
async fn unlink_google(state: tauri::State<'_, AuthState>) -> Result<UnlinkOutcome, String> {
    let outcome = match config::web_url() {
        Ok(web) => google::unlink_google(&state, &KeychainStore, &web).await,
        Err(_) => UnlinkOutcome::Failed,
    };
    Ok(outcome)
}

/// 退会する。確認のメールは、利用者が打ったもの(Web がセッションのメールと突き合わせる)。
#[tauri::command]
async fn delete_account(
    confirm_email: String,
    state: tauri::State<'_, AuthState>,
) -> Result<DeleteOutcome, String> {
    let outcome = match config::web_url() {
        Ok(web) => account::delete_account(&state, &KeychainStore, &web, &confirm_email).await,
        Err(_) => DeleteOutcome::Failed,
    };
    Ok(outcome)
}

/// ログアウト。この Mac のセッションは必ず消す。
#[tauri::command]
async fn sign_out(state: tauri::State<'_, AuthState>) -> Result<SignOutOutcome, String> {
    let outcome = match config::web_url() {
        Ok(base) => auth::sign_out(&state, &KeychainStore, &base).await,
        // 接続先が決まらなくても、この Mac のセッションは消せる。
        Err(_) => auth::sign_out(&state, &KeychainStore, "").await,
    };
    Ok(outcome)
}

/// OS から渡されたリンク(`betterauthmulti://…`)を、ログインの処理に回す。
/// リンクの中身は、ログにも画面にも出さない。ログインのリンクでないもの(`Ignored`)は黙って捨てる。
fn handle_link(app: tauri::AppHandle, link: String) {
    // Google の連携から戻るリンク(`?link=<目印>`)。自分が頼んだものだけ、画面に合図する。
    if link_rules::link_return_token(&link).is_some() {
        tauri::async_runtime::spawn(async move {
            let state = app.state::<AuthState>();
            if !google::accept_link_return(&state, &link) {
                return;
            }
            let error = link_rules::link_return_error(&link);
            // デバッグビルドだけ、理由のコード(英数字だけに整えたもの)を出す。
            auth::debug_log(&format!("link return: error={error:?}"));
            state.set_link_error(error);
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
            let _ = app.emit_to("main", ACCOUNTS_EVENT, ());
        });
        return;
    }
    // ログインのリンクでないもの(`state` や `code` のない `betterauthmulti://…`)は、接続先の設定の
    // 確認より前に捨てる。設定が欠けているときに、無関係なリンクで、アプリを前に出させない。
    if judge_link(&link) == LinkVerdict::Ignored {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AuthState>();
        let outcome = match config::web_url() {
            Ok(base) => auth::accept_sign_in_link(&state, &KeychainStore, &base, &link).await,
            Err(error) => AcceptOutcome::Failed {
                reason: error.to_string(),
            },
        };
        if outcome == AcceptOutcome::Ignored {
            return;
        }
        // デバッグビルドだけ、結果の種類を出す(`reason` は固定の文字列で、秘密は入らない)。
        auth::debug_log(&format!("link outcome: {outcome:?}"));
        // アプリを前に出すのは、ログインできたときと、自分が頼んだリンクの処理が失敗したときだけ。
        // 自分が頼んでいないリンク(`Rejected`)で、誰でも前面を奪ったり、表示を出させたりできないように。
        let bring_front = matches!(
            outcome,
            AcceptOutcome::Stored | AcceptOutcome::Failed { .. }
        );
        state.set_outcome(outcome);
        if bring_front && let Some(window) = app.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
        let _ = app.emit_to("main", AUTH_EVENT, ());
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .manage(AuthState::new())
        .setup(|app| {
            let handle = app.handle().clone();
            // リンクを押してアプリが起動したとき(まだ動いていなかったとき)のリンク。取れなくても、
            // アプリの起動は続ける(ログイン画面まで使えなくならないように)。
            match app.deep_link().get_current() {
                Ok(Some(urls)) => {
                    for url in urls {
                        handle_link(handle.clone(), url.to_string());
                    }
                }
                Ok(None) => {}
                Err(error) => auth::debug_log(&format!("reading the launch link failed: {error}")),
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
            request_sign_in_link,
            session_status,
            take_auth_outcome,
            load_profile,
            save_profile,
            load_accounts,
            link_google,
            unlink_google,
            take_link_error,
            delete_account,
            sign_out
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

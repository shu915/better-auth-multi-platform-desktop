mod secret;
pub mod sign_in_rules;

// Tauri のコマンドは薄く保つ。判断は secret.rs の純粋な関数に置く。
// 値を読み出して JS に返すコマンドは作らない(秘密を JS に出さない)。
// エラーは JS には種類だけを文字列で返す(Keychain の詳細は返さない)。

#[tauri::command]
fn secret_save(name: &str, value: &str) -> Result<(), String> {
    secret::save(name, value).map_err(|e| e.to_string())
}

#[tauri::command]
fn secret_exists(name: &str) -> Result<bool, String> {
    secret::exists(name).map_err(|e| e.to_string())
}

#[tauri::command]
fn secret_delete(name: &str) -> Result<(), String> {
    secret::delete(name).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            secret_save,
            secret_exists,
            secret_delete
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

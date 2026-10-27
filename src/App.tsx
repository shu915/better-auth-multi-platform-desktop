import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

// 段階 1 の練習用の画面。Rust のコマンドを呼んで Keychain に保存・確認・削除する。
// 保存した値は読み出さない(Rust は「あるか」だけを返す)。
const NAME = "practice";

function App() {
  const [value, setValue] = useState("");
  const [message, setMessage] = useState("");

  async function run(action: () => Promise<string>) {
    try {
      setMessage(await action());
    } catch (e) {
      setMessage(`失敗: ${String(e)}`);
    }
  }

  const save = () =>
    run(async () => {
      await invoke("secret_save", { name: NAME, value });
      setValue("");
      return "Keychain に保存しました";
    });

  const check = () =>
    run(async () => {
      const exists = await invoke<boolean>("secret_exists", { name: NAME });
      return exists ? "値があります" : "値はありません";
    });

  const remove = () =>
    run(async () => {
      await invoke("secret_delete", { name: NAME });
      return "削除しました";
    });

  return (
    <main className="container">
      <h1>Keychain の練習</h1>
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <input
          value={value}
          onChange={(e) => setValue(e.currentTarget.value)}
          placeholder="保存する値"
        />
        <button type="submit">保存</button>
      </form>
      <div className="row">
        <button type="button" onClick={() => void check()}>
          あるか確認
        </button>
        <button type="button" onClick={() => void remove()}>
          削除
        </button>
      </div>
      <p>{message}</p>
    </main>
  );
}

export default App;

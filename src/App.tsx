import { useEffect, useRef, useState } from "react";
import "./App.css";
import { listen } from "@tauri-apps/api/event";
import { isSignedIn, requestSignInLink, signOut } from "./lib/auth";
import {
  linkMessage,
  parseLinkResult,
  requestMessage,
  signOutFailedMessage,
} from "./lib/auth-outcomes";

type Status = "loading" | "signed-out" | "signed-in";

function App() {
  const [status, setStatus] = useState<Status>("loading");
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  // State is not updated until the next render, so a double click would slip past `busy`.
  const running = useRef(false);

  useEffect(() => {
    let cancelled = false;
    void isSignedIn().then((signedIn) => {
      if (!cancelled) setStatus(signedIn ? "signed-in" : "signed-out");
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // The mail link is opened in the browser, which hands it to the app; Rust trades it for a session
  // and tells the screen how it went (src-tauri/src/lib.rs).
  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    void listen<unknown>("auth-changed", (event) => {
      const result = parseLinkResult(event.payload);
      if (result === null) return;
      if (result.kind === "stored") {
        setMessage("");
        setStatus("signed-in");
      } else {
        setMessage(linkMessage(result));
      }
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  async function guarded(action: () => Promise<void>) {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    try {
      await action();
    } finally {
      running.current = false;
      setBusy(false);
    }
  }

  const sendLink = () =>
    guarded(async () => {
      setMessage("");
      const result = await requestSignInLink(email);
      setMessage(requestMessage(result));
    });

  const logout = () =>
    guarded(async () => {
      setMessage("");
      const result = await signOut();
      if (result.kind === "signed-out") setStatus("signed-out");
      else setMessage(signOutFailedMessage);
    });

  if (status === "loading") {
    return <main className="container" />;
  }

  if (status === "signed-in") {
    return (
      <main className="container">
        <h1>ログイン中</h1>
        <div className="row">
          <button type="button" disabled={busy} onClick={() => void logout()}>
            ログアウト
          </button>
        </div>
        <p>{message}</p>
      </main>
    );
  }

  return (
    <main className="container">
      <h1>ログイン</h1>
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          void sendLink();
        }}
      >
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.currentTarget.value)}
          placeholder="メールアドレス"
          autoComplete="email"
        />
        <button type="submit" disabled={busy || email.trim() === ""}>
          ログインのリンクを送る
        </button>
      </form>
      <p>{message}</p>
    </main>
  );
}

export default App;

import { useEffect, useRef, useState } from "react";
import "./App.css";
import { listen } from "@tauri-apps/api/event";
import { isSignedIn, requestSignInLink, signOut, takeLinkResult } from "./lib/auth";
import {
  requestMessage,
  screenAfterRefresh,
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
  // Which refresh is the latest. Two can be in flight (the first on start, one per nudge), and the
  // answers of an older one must not overwrite the sign-in state set by a newer one.
  const latestRefresh = useRef(0);

  // Rust trades the mail link for a session, remembers how it went, and nudges the screen with an
  // event. The screen asks Rust (the session, and the result of the link) instead of trusting what
  // the event carries; and it asks once when it starts, because a link that launched the app can be
  // handled before the screen is listening (src-tauri/src/lib.rs).
  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;

    async function refresh() {
      const run = ++latestRefresh.current;
      // The result first, then the session: a link that was traded in between is then seen in the
      // session, not missed (and `screenAfterRefresh` covers the other order).
      const result = await takeLinkResult();
      const signedIn = await isSignedIn();
      // No check for an unmounted screen here: in development React mounts, unmounts and mounts
      // again, and the first run may have taken the result (it is given out once). Setting state
      // on a screen that has gone is harmless.
      const screen = screenAfterRefresh(signedIn, result);
      // The message of a result is shown whichever run took it (it is given out once); the sign-in
      // state only from the latest run.
      if (screen.message !== null) setMessage(screen.message);
      if (run === latestRefresh.current) {
        setStatus(screen.signedIn ? "signed-in" : "signed-out");
      }
    }

    // Listen first, then ask: a result that arrives in between is not lost.
    void listen("auth-changed", () => void refresh())
      .then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      })
      .finally(() => void refresh());

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

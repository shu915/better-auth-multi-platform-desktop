import { useEffect, useRef, useState } from "react";
import "./App.css";
import { listen } from "@tauri-apps/api/event";
import { isSignedIn, loadProfile, requestSignInLink, signOut, takeLinkResult } from "./lib/auth";
import {
  requestMessage,
  screenAfterRefresh,
  signOutFailedMessage,
} from "./lib/auth-outcomes";
import {
  bioFailedMessage,
  profileFailedMessage,
  sessionEndedMessage,
} from "./lib/profile-outcomes";

type Profile = { name: string; email: string; bio: string | null };

type Status = "loading" | "signed-out" | "signed-in";

function App() {
  const [status, setStatus] = useState<Status>("loading");
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [profileMessage, setProfileMessage] = useState("");
  // Bumped to read the profile again (a new sign-in while signed in, or the retry button).
  const [reloadKey, setReloadKey] = useState(0);
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
        if (!screen.signedIn) {
          // Whoever was shown is no longer signed in: their profile must not stay on the screen.
          setProfile(null);
          setProfileMessage("");
        }
        setStatus(screen.signedIn ? "signed-in" : "signed-out");
      }
      // A new sign-in while already signed in may be another user's: drop what is shown and read the
      // profile again (the effect below runs for `status` changes only, and `status` has not changed).
      if (result?.kind === "stored") {
        setProfile(null);
        setProfileMessage("");
        setReloadKey((key) => key + 1);
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

  // Once signed in, read the profile through Rust. If the web app says the session is no longer
  // valid, Rust has already forgotten it, and the screen goes back to the sign-in form.
  useEffect(() => {
    if (status !== "signed-in") return;
    let cancelled = false;
    void loadProfile().then((result) => {
      if (cancelled) return;
      if (result.kind === "loaded") {
        setProfile({ name: result.name, email: result.email, bio: result.bio });
        setProfileMessage(result.bio === null ? bioFailedMessage : "");
      } else if (result.kind === "session-ended") {
        setProfile(null);
        setProfileMessage("");
        setStatus("signed-out");
        setMessage(sessionEndedMessage);
      } else {
        setProfileMessage(profileFailedMessage);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [status, reloadKey]);

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
      if (result.kind === "signed-out") {
        setProfile(null);
        setProfileMessage("");
        setStatus("signed-out");
      } else setMessage(signOutFailedMessage);
    });

  if (status === "loading") {
    return <main className="container" />;
  }

  if (status === "signed-in") {
    return (
      <main className="container">
        <h1>ログイン中</h1>
        {profile && (
          <dl>
            <dt>名前</dt>
            <dd>{profile.name === "" ? "(未設定)" : profile.name}</dd>
            <dt>メール</dt>
            <dd>{profile.email}</dd>
            <dt>bio</dt>
            <dd>
              {profile.bio === null
                ? "(読み込めませんでした)"
                : profile.bio === ""
                  ? "(未設定)"
                  : profile.bio}
            </dd>
          </dl>
        )}
        <p>{profileMessage}</p>
        <div className="row">
          {profile === null && profileMessage !== "" && (
            <button
              type="button"
              onClick={() => {
                setProfileMessage("");
                setReloadKey((key) => key + 1);
              }}
            >
              再読み込み
            </button>
          )}
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

import { useEffect, useRef, useState } from "react";
import "./App.css";
import { listen } from "@tauri-apps/api/event";
import {
  isSignedIn,
  loadProfile,
  requestSignInLink,
  saveProfile,
  signOut,
  takeLinkResult,
} from "./lib/auth";
import {
  requestMessage,
  screenAfterRefresh,
  signOutFailedMessage,
} from "./lib/auth-outcomes";
import {
  draftsAfterLoad,
  hasChanges,
  isSameGeneration,
  mergeSaved,
  saveMessage as saveMessageFor,
  savedFrom,
} from "./lib/profile-edit";
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
  // What is being edited. `profile` holds what is saved now; a save compares the two.
  const [nameDraft, setNameDraft] = useState("");
  const [bioDraft, setBioDraft] = useState("");
  const [saveNotice, setSaveNotice] = useState("");
  // The profile is shown first; the edit form opens only after the "編集" button.
  const [editing, setEditing] = useState(false);
  // Bumped to read the profile again (a new sign-in while signed in, or the retry button).
  const [reloadKey, setReloadKey] = useState(0);
  // State is not updated until the next render, so a double click would slip past `busy`.
  const running = useRef(false);
  // The latest profile and drafts, for the callback of a profile read that finishes later: it must
  // not overwrite what the user is typing (see the effect that reads the profile).
  const latest = useRef({ profile: null as Profile | null, nameDraft: "", bioDraft: "" });
  // Changes whenever the screen forgets whoever it showed. A save that was started before the change
  // belongs to the previous user: its answer is dropped (see `save`).
  const generation = useRef(0);
  useEffect(() => {
    latest.current = { profile, nameDraft, bioDraft };
  });
  // Which refresh is the latest. Two can be in flight (the first on start, one per nudge), and the
  // answers of an older one must not overwrite the sign-in state set by a newer one.
  const latestRefresh = useRef(0);

  // Forget whoever was shown: the profile and what was being edited must not stay in memory for the
  // next user. (All setters are stable, so this is safe to call from effects.)
  function clearProfileState() {
    generation.current += 1;
    setProfile(null);
    setProfileMessage("");
    setSaveNotice("");
    setNameDraft("");
    setBioDraft("");
    setEditing(false);
  }

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
          clearProfileState();
        }
        setStatus(screen.signedIn ? "signed-in" : "signed-out");
      }
      // A new sign-in while already signed in may be another user's: drop what is shown and read the
      // profile again (the effect below runs for `status` changes only, and `status` has not changed).
      if (result?.kind === "stored") {
        clearProfileState();
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
        // A read that finishes later (the retry button, a new sign-in) must not overwrite what the
        // user is typing (see `draftsAfterLoad`).
        const { profile: shown, nameDraft: nameNow, bioDraft: bioNow } = latest.current;
        const drafts = draftsAfterLoad(
          shown,
          { nameDraft: nameNow, bioDraft: bioNow },
          { name: result.name, bio: result.bio },
        );
        setProfile({ name: result.name, email: result.email, bio: result.bio });
        setNameDraft(drafts.nameDraft);
        setBioDraft(drafts.bioDraft);
        setProfileMessage(result.bio === null ? bioFailedMessage : "");
      } else if (result.kind === "session-ended") {
        clearProfileState();
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

  // While the bio could not be read (null) it is not edited, and not sent: both sides pass empty,
  // which `planSave` takes for "no change". Saving the name then cannot wipe a bio that is not shown.
  const editedValues = () =>
    profile === null
      ? null
      : {
          name: profile.name,
          nameDraft,
          savedBio: profile.bio ?? "",
          bioDraft: profile.bio === null ? "" : bioDraft,
        };
  const values = editedValues();
  const changed = values !== null && hasChanges(values);

  // Opening the form starts from what is saved now; cancelling throws the edits away.
  function startEditing() {
    if (profile === null) return;
    setNameDraft(profile.name);
    setBioDraft(profile.bio ?? "");
    setSaveNotice("");
    setEditing(true);
  }

  function cancelEditing() {
    if (profile !== null) {
      setNameDraft(profile.name);
      setBioDraft(profile.bio ?? "");
    }
    setSaveNotice("");
    setEditing(false);
  }

  const save = () =>
    guarded(async () => {
      const toSave = editedValues();
      if (toSave === null) return;
      const started = generation.current;
      setSaveNotice("");
      const result = await saveProfile({
        savedName: toSave.name,
        nameDraft: toSave.nameDraft,
        savedBio: toSave.savedBio,
        bioDraft: toSave.bioDraft,
      });
      // The screen may belong to someone else by now (another account signed in while this ran):
      // the answer is for the previous user, so it is dropped.
      if (!isSameGeneration(started, generation.current)) return;
      if (result.kind === "session-ended") {
        // Rust has forgotten the session: back to the sign-in form.
        clearProfileState();
        setStatus("signed-out");
        setMessage(sessionEndedMessage);
        return;
      }
      // What the servers saved becomes what is saved now (a name saved before the bio failed counts
      // too, or the next save would send it again).
      const saved = savedFrom(result);
      if (saved.name !== null || saved.bio !== null) {
        setProfile((current) => (current === null ? current : mergeSaved(current, saved)));
        if (saved.name !== null) setNameDraft(saved.name);
        if (saved.bio !== null) setBioDraft(saved.bio);
      }
      setSaveNotice(saveMessageFor(result));
      // Saved: back to the read view (the notice stays). A refusal or a failure keeps the form open
      // with what was typed.
      if (result.kind === "saved" || result.kind === "nothing-to-save") setEditing(false);
    });

  const logout = () =>
    guarded(async () => {
      setMessage("");
      const result = await signOut();
      if (result.kind === "signed-out") {
        clearProfileState();
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
        {profile && !editing && (
          <div className="column">
            <dl className="profile">
              <dt>メール</dt>
              <dd>{profile.email}</dd>
              <dt>名前</dt>
              <dd className="value">{profile.name === "" ? "(未設定)" : profile.name}</dd>
              <dt>bio</dt>
              <dd className="value">
                {profile.bio === null
                  ? "(読み込めませんでした)"
                  : profile.bio === ""
                    ? "(未設定)"
                    : profile.bio}
              </dd>
            </dl>
            <button type="button" disabled={busy} onClick={startEditing}>
              編集
            </button>
          </div>
        )}
        {profile && editing && (
          <form
            className="column"
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            <p>メール: {profile.email}</p>
            <label>
              名前
              <input
                value={nameDraft}
                onChange={(e) => setNameDraft(e.currentTarget.value)}
                placeholder="(未設定)"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                disabled={busy}
              />
            </label>
            {profile.bio !== null ? (
              <label>
                bio
                <textarea
                  value={bioDraft}
                  onChange={(e) => setBioDraft(e.currentTarget.value)}
                  placeholder="(未設定)"
                  rows={5}
                  disabled={busy}
                />
              </label>
            ) : (
              <p>bio は、読み込めるまで編集できません(名前は編集できます)。</p>
            )}
            <div className="row">
              <button type="submit" disabled={busy || !changed}>
                {busy ? "保存中…" : "保存"}
              </button>
              <button type="button" disabled={busy} onClick={cancelEditing}>
                キャンセル
              </button>
            </div>
          </form>
        )}
        <p>{saveNotice}</p>
        <p>{profileMessage}</p>
        <div className="row">
          {((profile === null && profileMessage !== "") || profile?.bio === null) && (
            <button
              type="button"
              disabled={busy}
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
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
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

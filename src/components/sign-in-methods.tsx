import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { linkGoogle, loadAccounts, takeLinkReason, unlinkGoogle } from "../lib/auth";
import {
  accountsFailedMessage,
  LINK_POLL_INTERVAL_MS,
  linkWaitingMessage,
  linkedMessage,
  messageAfterLinkAttempt,
  shouldKeepPolling,
  startFailedMessage,
  unlinkConfirmBody,
  unlinkDoneMessage,
} from "../lib/google-outcomes";

type Google = "unknown" | "linked" | "unlinked";

// How the accounts are read: at the start; after the browser came back (or the user asked), which
// says how it went; or while waiting for the browser, which only notices that Google got linked.
type Mode = "initial" | "return" | "poll";

type Props = {
  /** Something else is in flight (a save, a withdrawal): do not start anything here. */
  disabled: boolean;
  /** Tells the parent while a call here is in flight, so it can switch off what must not run meanwhile. */
  onWorkingChange: (working: boolean) => void;
  /** The session is gone: the parent goes back to the sign-in screen. */
  onSessionEnded: () => void;
};

// The ways to sign in: the email link (always), and Google, which a signed-in user adds or removes.
// Linking opens the system browser; the app is told when the browser comes back, and then reads the
// accounts again: the browser comes back the same way whether Google was linked, cancelled or
// refused, so the answer is read from the accounts, never from the way back.
export function SignInMethods({ disabled, onWorkingChange, onSessionEnded }: Props) {
  const [google, setGoogle] = useState<Google>("unknown");
  const [message, setMessage] = useState("");
  const [working, setWorking] = useState(false);
  const [confirming, setConfirming] = useState(false);
  // Linking was started and the browser has not come back yet.
  const [waiting, setWaiting] = useState(false);

  // Latest values for callbacks that outlive a render (the event listener, calls that finish later).
  const mounted = useRef(true);
  const waitingRef = useRef(false);
  const running = useRef(false);
  const parent = useRef({ onWorkingChange, onSessionEnded });
  useEffect(() => {
    parent.current = { onWorkingChange, onSessionEnded };
  });

  function setWaitingBoth(value: boolean) {
    waitingRef.current = value;
    setWaiting(value);
  }

  // Reads the accounts. `afterLink`: the browser came back (or the user asked): say how it went.
  // Defined in the effect (it uses only refs and stable setters) and kept in a ref for the buttons.
  const refreshRef = useRef<(mode: Mode) => Promise<void>>(async () => {});

  useEffect(() => {
    mounted.current = true;
    let cancelled = false;
    let unlisten: (() => void) | undefined;

    async function refresh(mode: Mode) {
      const result = await loadAccounts();
      if (!mounted.current) return;
      if (mode === "poll") {
        // Quiet: only a finished linking is shown (a failure or "not yet" says nothing). But the
        // session being gone is not quiet: Rust has forgotten it, so the screen must leave too.
        if (result.kind === "session-ended") {
          parent.current.onSessionEnded();
          return;
        }
        if (result.kind === "loaded" && result.googleLinked && waitingRef.current) {
          waitingRef.current = false;
          setWaiting(false);
          setGoogle("linked");
          setMessage(linkedMessage);
        }
        return;
      }
      if (result.kind === "session-ended") {
        parent.current.onSessionEnded();
        return;
      }
      if (result.kind === "failed") {
        setMessage(accountsFailedMessage);
        return;
      }
      setGoogle(result.googleLinked ? "linked" : "unlinked");
      if (mode === "return") {
        waitingRef.current = false;
        setWaiting(false);
        const reason = result.googleLinked ? null : await takeLinkReason();
        if (!mounted.current) return;
        setMessage(messageAfterLinkAttempt(result.googleLinked, reason));
      }
    }
    refreshRef.current = refresh;

    // Listen first, then ask: a return that arrives in between is not lost.
    void listen("accounts-changed", () => void refresh(waitingRef.current ? "return" : "initial"))
      .then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      })
      .finally(() => {
        if (!cancelled) void refresh("initial");
      });
    return () => {
      cancelled = true;
      mounted.current = false;
      unlisten?.();
    };
  }, []);

  // While the browser is open: read the accounts again now and then (see LINK_POLL_INTERVAL_MS).
  useEffect(() => {
    if (!waiting) return;
    const startedAt = Date.now();
    let reading = false;
    const timer = setInterval(() => {
      if (!shouldKeepPolling(startedAt, Date.now())) {
        clearInterval(timer);
        return;
      }
      if (reading) return;
      reading = true;
      void refreshRef.current("poll").finally(() => {
        reading = false;
      });
    }, LINK_POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [waiting]);

  async function run(action: () => Promise<void>) {
    if (running.current) return;
    running.current = true;
    setWorking(true);
    parent.current.onWorkingChange(true);
    try {
      await action();
    } finally {
      running.current = false;
      if (mounted.current) setWorking(false);
      parent.current.onWorkingChange(false);
    }
  }

  const link = () =>
    run(async () => {
      setMessage("");
      const result = await linkGoogle();
      if (!mounted.current) return;
      if (result.kind === "session-ended") {
        parent.current.onSessionEnded();
      } else if (result.kind === "started") {
        setWaitingBoth(true);
        setMessage(linkWaitingMessage);
      } else {
        setMessage(startFailedMessage(result));
      }
    });

  const unlink = () =>
    run(async () => {
      setConfirming(false);
      setMessage("");
      const result = await unlinkGoogle();
      if (!mounted.current) return;
      if (result.kind === "session-ended") {
        parent.current.onSessionEnded();
        return;
      }
      if (result.kind === "unlinked" || result.kind === "not-linked") setGoogle("unlinked");
      setMessage(unlinkDoneMessage(result));
    });

  const locked = disabled || working;

  return (
    <section className="column methods">
      <h2>ログイン方法</h2>
      <p>メールのリンク: 利用できます</p>
      <p>
        Google:{" "}
        {google === "unknown" ? "確認中…" : google === "linked" ? "連携済み" : "未連携"}
      </p>
      {google === "unlinked" && (
        <div className="row">
          <button type="button" disabled={locked} onClick={() => void link()}>
            {working ? "処理中…" : "Google を連携する"}
          </button>
          {waiting && (
            <button type="button" disabled={locked} onClick={() => void refreshRef.current("return")}>
              確認する
            </button>
          )}
        </div>
      )}
      {google === "linked" && !confirming && (
        <div className="row">
          <button type="button" disabled={locked} onClick={() => setConfirming(true)}>
            Google の連携を解除する
          </button>
        </div>
      )}
      {google === "linked" && confirming && (
        <div className="column">
          <p>{unlinkConfirmBody}</p>
          <div className="row">
            <button type="button" className="danger" disabled={locked} onClick={() => void unlink()}>
              {working ? "解除中…" : "解除する"}
            </button>
            <button type="button" disabled={locked} onClick={() => setConfirming(false)}>
              キャンセル
            </button>
          </div>
        </div>
      )}
      {google === "unknown" && message !== "" && (
        <div className="row">
          <button type="button" disabled={locked} onClick={() => void refreshRef.current("initial")}>
            再読み込み
          </button>
        </div>
      )}
      <p>{message}</p>
    </section>
  );
}

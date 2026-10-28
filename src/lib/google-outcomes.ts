// What the Google commands answer, checked before they are trusted (the answers cross the invoke
// boundary as unknown), and the messages the screen shows. Pure, so it is tested on its own. The
// wording follows the mobile app's (linked-accounts-rules.ts there). Nothing here holds a secret:
// the account id stays in Rust.

export type AccountsResult =
  | { kind: 'loaded'; googleLinked: boolean }
  | { kind: 'session-ended' }
  | { kind: 'failed' };

export type GoogleLinkResult =
  // The browser was opened. Whether Google got linked is decided after the browser comes back.
  | { kind: 'started' }
  // Linking needs a sign-in within the last five minutes.
  | { kind: 'not-fresh' }
  | { kind: 'session-ended' }
  | { kind: 'failed' };

export type GoogleUnlinkResult =
  | { kind: 'unlinked' }
  // Google is already gone (unlinked somewhere else).
  | { kind: 'not-linked' }
  | { kind: 'not-fresh' }
  | { kind: 'session-ended' }
  | { kind: 'failed' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

// Anything unexpected is a failure: "linked" must not be shown, or hidden, on a guess.
export function parseAccountsResult(value: unknown): AccountsResult {
  if (!isRecord(value)) return { kind: 'failed' };
  if (value.kind === 'sessionEnded') return { kind: 'session-ended' };
  if (value.kind === 'loaded' && typeof value.googleLinked === 'boolean') {
    return { kind: 'loaded', googleLinked: value.googleLinked };
  }
  return { kind: 'failed' };
}

export function parseGoogleLinkResult(value: unknown): GoogleLinkResult {
  if (!isRecord(value)) return { kind: 'failed' };
  switch (value.kind) {
    case 'started':
      return { kind: 'started' };
    case 'notFresh':
      return { kind: 'not-fresh' };
    case 'sessionEnded':
      return { kind: 'session-ended' };
    default:
      return { kind: 'failed' };
  }
}

export function parseGoogleUnlinkResult(value: unknown): GoogleUnlinkResult {
  if (!isRecord(value)) return { kind: 'failed' };
  switch (value.kind) {
    case 'unlinked':
      return { kind: 'unlinked' };
    case 'notLinked':
      return { kind: 'not-linked' };
    case 'notFresh':
      return { kind: 'not-fresh' };
    case 'sessionEnded':
      return { kind: 'session-ended' };
    default:
      return { kind: 'failed' };
  }
}

// Linking and unlinking need a recent sign-in. Say how to fix that instead of showing an API message.
const signInAgain = (doing: string) =>
  `セキュリティのため、いったんログアウトし、メールのリンクでもう一度ログインしてから、すぐに${doing}をやり直してください。`;

export const linkNotFreshMessage = signInAgain('連携');
export const unlinkNotFreshMessage = signInAgain('解除');
export const accountsFailedMessage = 'ログイン方法を読み込めませんでした。接続を確かめて、もう一度お試しください。';
export const linkFailedMessage = 'Google の連携を始められませんでした。接続を確かめて、もう一度お試しください。';
export const unlinkFailedMessage = 'Google の連携を解除できませんでした。接続を確かめて、もう一度お試しください。';
export const linkWaitingMessage =
  'ブラウザで Google の画面を開きました。連携が終わると、この画面に反映されます(数秒かかることがあります)。反映されないときは「確認する」を押してください。';
export const linkedMessage = 'Google を連携しました。';
export const unlinkedMessage = 'Google の連携を解除しました。メールのリンクでは、これまでどおりログインできます。';
export const notLinkedAnymoreMessage = 'Google は、すでに連携されていません。';
// Linking comes back the same way whether it worked, was cancelled, or Google refused: the answer
// is read from the accounts, so the wording does not claim to know which.
export const notLinkedMessage = 'Google は連携されていません(やめたか、断られたか、まだ反映されていません)。もう一度お試しください。';

export const unlinkConfirmBody = 'Google の連携を解除しますか? メールのリンクでは、これまでどおりログインできます。';

// What to say once the accounts were read again after the browser came back (or after "確認する").
// The codes the web app (Better Auth) gives when it turns an OAuth sign-in or linking down, in words
// the user can act on. Any other code is shown as it is (it is a short plain word: see parseLinkReason).
const REASONS: Record<string, string> = {
  account_already_linked_to_different_user:
    'この Google アカウントは、別のユーザーにすでに連携されています。別の Google アカウントを使うか、もとのユーザーで連携を解除してください。',
  access_denied: 'Google の画面で、許可されませんでした。',
  state_mismatch: '連携の途中でやり直しが必要になりました。もう一度「Google を連携する」を押してください(古いブラウザのタブは閉じてください)。',
  please_restart_the_process: '連携の途中でやり直しが必要になりました。もう一度お試しください。',
  state_not_found: '連携の途中でやり直しが必要になりました。もう一度お試しください。',
};

// `reason` is the code the web app gave when it turned the linking down.
export function messageAfterLinkAttempt(googleLinked: boolean, reason: string | null = null): string {
  if (googleLinked) return linkedMessage;
  if (reason === null) return notLinkedMessage;
  return `${REASONS[reason] ?? notLinkedMessage} (理由のコード: ${reason})`;
}

// The reason comes through Rust, which has made it plain; anything else is not shown.
export function parseLinkReason(value: unknown): string | null {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value) ? value : null;
}

export function startFailedMessage(result: GoogleLinkResult): string {
  switch (result.kind) {
    case 'not-fresh':
      return linkNotFreshMessage;
    case 'failed':
      return linkFailedMessage;
    default:
      return '';
  }
}

export function unlinkDoneMessage(result: GoogleUnlinkResult): string {
  switch (result.kind) {
    case 'unlinked':
      return unlinkedMessage;
    case 'not-linked':
      return notLinkedAnymoreMessage;
    case 'not-fresh':
      return unlinkNotFreshMessage;
    case 'failed':
      return unlinkFailedMessage;
    default:
      return '';
  }
}

// While the browser is open, the accounts are read again now and then: the way back to the app (a
// link the browser opens) may not arrive, for example when the browser stops asking to open the
// app after it has been asked a few times. The linking itself is done by the web app either way.
export const LINK_POLL_INTERVAL_MS = 2000;
export const LINK_POLL_MAX_MS = 2 * 60 * 1000;

// Whether to keep reading the accounts: from the start of the wait, for at most LINK_POLL_MAX_MS.
export function shouldKeepPolling(startedAt: number, now: number): boolean {
  return now - startedAt < LINK_POLL_MAX_MS;
}

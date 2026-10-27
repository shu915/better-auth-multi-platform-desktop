// What `load_profile` answers, checked before it is trusted (the answer crosses the invoke boundary
// as unknown), and the messages the screen shows for it. Pure, so it is tested on its own. The
// answer holds no secret: the name, the email and the bio are what the screen shows anyway.

export type LoadResult =
  // `bio` is null when the Go API could not be reached: the name and the email are still shown.
  | { kind: 'loaded'; name: string; email: string; bio: string | null }
  | { kind: 'session-ended' }
  | { kind: 'failed' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

// Anything unexpected is a failure: the screen must not show a half-read profile as the user's.
export function parseLoadResult(value: unknown): LoadResult {
  if (!isRecord(value)) return { kind: 'failed' };
  if (value.kind === 'sessionEnded') return { kind: 'session-ended' };
  if (value.kind !== 'loaded') return { kind: 'failed' };
  const { name, email, bio } = value;
  if (typeof name !== 'string' || typeof email !== 'string') return { kind: 'failed' };
  if (bio !== null && typeof bio !== 'string') return { kind: 'failed' };
  return { kind: 'loaded', name, email, bio };
}

export const sessionEndedMessage = 'セッションが切れました。もう一度ログインしてください。';
export const profileFailedMessage =
  'プロフィールを読み込めませんでした。接続を確かめて、しばらくしてからもう一度お試しください。';
export const bioFailedMessage = 'bio を読み込めませんでした(名前とメールは表示しています)。';

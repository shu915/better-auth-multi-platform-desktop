// What the Rust commands answer, checked before it is trusted (the answer crosses the invoke
// boundary as unknown), and the messages the screen shows for it. Pure, so it is tested on its own.
// The commands never return a secret: only a kind, and for a refused request the HTTP status.

export type RequestResult =
  | { kind: 'sent' }
  | { kind: 'failed'; status: number | null };

export type SignOutResult = { kind: 'signed-out' } | { kind: 'failed' };

function kindOf(value: unknown): { kind: string; fields: Record<string, unknown> } | null {
  if (typeof value !== 'object' || value === null) return null;
  const fields = value as Record<string, unknown>;
  return typeof fields.kind === 'string' ? { kind: fields.kind, fields } : null;
}

// Anything unexpected counts as a failure: the screen must not claim a mail was sent unless Rust
// said so.
export function parseRequestResult(value: unknown): RequestResult {
  const parsed = kindOf(value);
  if (parsed?.kind === 'sent') return { kind: 'sent' };
  const status = parsed?.fields.status;
  return { kind: 'failed', status: typeof status === 'number' ? status : null };
}

export function parseSignOutResult(value: unknown): SignOutResult {
  return kindOf(value)?.kind === 'signedOut' ? { kind: 'signed-out' } : { kind: 'failed' };
}

// `session_status` answers true or false; anything else is treated as signed out.
export const parseSignedIn = (value: unknown): boolean => value === true;

export function requestMessage(result: RequestResult): string {
  if (result.kind === 'sent') {
    return 'メールを送りました。届いたリンクを開いてください(宛先が登録済みでなくても、同じ表示になります)。';
  }
  if (result.status === 429) return '送信の回数が多すぎます。しばらくしてからもう一度お試しください。';
  return '送れませんでした。メールアドレスを確かめて、もう一度お試しください。';
}

export const signOutFailedMessage = 'ログアウトできませんでした。もう一度お試しください。';

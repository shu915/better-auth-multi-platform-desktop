// What `delete_account` answers, checked before it is trusted (the answer crosses the invoke
// boundary as unknown), and the messages the screen shows for it. Pure, so it is tested on its own.
// The web app compares the typed email with the account's; the screen does not decide.

export type DeleteResult =
  | { kind: 'deleted' }
  | { kind: 'email-mismatch' }
  // The sign-in is too old: the user signs out, signs in again with a mail link, and deletes at once.
  | { kind: 'not-fresh' }
  | { kind: 'session-ended' }
  // Nothing is lost, and trying again is safe.
  | { kind: 'failed' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

// Anything unexpected is a failure, never a success: "deleted" must not be shown on a guess.
export function parseDeleteResult(value: unknown): DeleteResult {
  if (!isRecord(value)) return { kind: 'failed' };
  switch (value.kind) {
    case 'deleted':
      return { kind: 'deleted' };
    case 'emailMismatch':
      return { kind: 'email-mismatch' };
    case 'notFresh':
      return { kind: 'not-fresh' };
    case 'sessionEnded':
      return { kind: 'session-ended' };
    default:
      return { kind: 'failed' };
  }
}

export const deletedMessage = '退会しました。ご利用ありがとうございました。';

// Shown under the form for the answers that leave the form open.
export function deleteFailedMessage(result: DeleteResult): string {
  switch (result.kind) {
    case 'email-mismatch':
      return 'このアカウントのメールアドレスではありません。';
    case 'not-fresh':
      return 'セキュリティのため、いったんログアウトし、メールのリンクでもう一度ログインしてから、数分以内に退会してください。';
    case 'failed':
      return '退会できませんでした。接続を確かめて、もう一度お試しください(繰り返しても安全です)。';
    default:
      return '';
  }
}

// The form sends nothing when the field is empty (the button is off).
export const canDelete = (email: string, busy: boolean): boolean => !busy && email.trim() !== '';

// A deletion that failed (a timeout, say) may still have finished on the web app. If the next try is
// answered "no session", the account is probably gone: say so, not just "the session ended".
export const probablyDeletedMessage =
  '前回の退会が完了していた可能性があります(アカウントはすでに削除されているようです)。';

// Whether the last answer that left the form open was a failure that may have finished anyway. A
// wrong email or an old sign-in changes nothing about that (the earlier failure still counts).
export function failedBeforeAfter(previous: boolean, result: DeleteResult): boolean {
  switch (result.kind) {
    case 'failed':
      return true;
    case 'email-mismatch':
    case 'not-fresh':
      return previous;
    default:
      return false;
  }
}

// What the sign-in screen says when the session is gone. After a failed try, the account is probably
// deleted already.
export function sessionEndedMessageFor(failedBefore: boolean, plain: string): string {
  return failedBefore ? probablyDeletedMessage : plain;
}

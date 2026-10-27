import { describe, expect, it } from 'vitest';

import {
  canDelete,
  deleteFailedMessage,
  failedBeforeAfter,
  parseDeleteResult,
  probablyDeletedMessage,
  sessionEndedMessageFor,
  type DeleteResult,
} from './delete-account';

describe('parseDeleteResult', () => {
  it('reads each kind Rust answers', () => {
    expect(parseDeleteResult({ kind: 'deleted' })).toEqual({ kind: 'deleted' });
    expect(parseDeleteResult({ kind: 'emailMismatch' })).toEqual({ kind: 'email-mismatch' });
    expect(parseDeleteResult({ kind: 'notFresh' })).toEqual({ kind: 'not-fresh' });
    expect(parseDeleteResult({ kind: 'sessionEnded' })).toEqual({ kind: 'session-ended' });
    expect(parseDeleteResult({ kind: 'failed' })).toEqual({ kind: 'failed' });
  });

  it('never takes something unexpected for a success', () => {
    for (const value of [null, undefined, 'deleted', 1, {}, { kind: 'Deleted' }, { deleted: true }]) {
      expect(parseDeleteResult(value)).toEqual({ kind: 'failed' });
    }
  });
});

describe('deleteFailedMessage', () => {
  it('says what to do for each answer that keeps the form open', () => {
    const kinds: DeleteResult[] = [{ kind: 'email-mismatch' }, { kind: 'not-fresh' }, { kind: 'failed' }];
    const messages = kinds.map(deleteFailedMessage);
    expect(new Set(messages).size).toBe(3);
    expect(messages.every((m) => m !== '')).toBe(true);
    expect(messages[1]).toContain('もう一度ログイン');
  });

  it('has nothing to say for the answers that leave the screen', () => {
    expect(deleteFailedMessage({ kind: 'deleted' })).toBe('');
    expect(deleteFailedMessage({ kind: 'session-ended' })).toBe('');
  });
});

describe('canDelete', () => {
  it('needs an email, and nothing else in flight', () => {
    expect(canDelete('a@example.com', false)).toBe(true);
    expect(canDelete('  ', false)).toBe(false);
    expect(canDelete('a@example.com', true)).toBe(false);
  });
});

describe('probablyDeletedMessage', () => {
  it('tells that the account may be gone already', () => {
    expect(probablyDeletedMessage).toContain('削除されている');
  });
});

describe('failedBeforeAfter', () => {
  it('remembers a failure, and keeps it through a wrong email or an old sign-in', () => {
    expect(failedBeforeAfter(false, { kind: 'failed' })).toBe(true);
    expect(failedBeforeAfter(true, { kind: 'email-mismatch' })).toBe(true);
    expect(failedBeforeAfter(true, { kind: 'not-fresh' })).toBe(true);
    expect(failedBeforeAfter(false, { kind: 'email-mismatch' })).toBe(false);
  });

  it('forgets it when the form is left', () => {
    expect(failedBeforeAfter(true, { kind: 'deleted' })).toBe(false);
    expect(failedBeforeAfter(true, { kind: 'session-ended' })).toBe(false);
  });
});

describe('sessionEndedMessageFor', () => {
  it('says the account may be gone only after a failed try', () => {
    expect(sessionEndedMessageFor(true, 'plain')).toBe(probablyDeletedMessage);
    expect(sessionEndedMessageFor(false, 'plain')).toBe('plain');
  });
});

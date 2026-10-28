import { describe, expect, it } from 'vitest';

import {
  linkNotFreshMessage,
  linkWaitingMessage,
  linkedMessage,
  messageAfterLinkAttempt,
  notLinkedMessage,
  parseAccountsResult,
  parseGoogleLinkResult,
  parseGoogleSignInStart,
  signInStartFailedMessage,
  parseLinkReason,
  LINK_POLL_MAX_MS,
  shouldKeepPolling,
  parseGoogleUnlinkResult,
  startFailedMessage,
  unlinkDoneMessage,
  unlinkNotFreshMessage,
} from './google-outcomes';

const odd = [null, undefined, 'loaded', 1, {}, { kind: 'Loaded' }];

describe('parseAccountsResult', () => {
  it('reads whether Google is linked', () => {
    expect(parseAccountsResult({ kind: 'loaded', googleLinked: true })).toEqual({
      kind: 'loaded',
      googleLinked: true,
    });
    expect(parseAccountsResult({ kind: 'loaded', googleLinked: false })).toEqual({
      kind: 'loaded',
      googleLinked: false,
    });
    expect(parseAccountsResult({ kind: 'sessionEnded' })).toEqual({ kind: 'session-ended' });
  });

  it('never takes something unexpected for an answer', () => {
    for (const value of [...odd, { kind: 'loaded' }, { kind: 'loaded', googleLinked: 'true' }]) {
      expect(parseAccountsResult(value)).toEqual({ kind: 'failed' });
    }
  });
});

describe('parseGoogleLinkResult', () => {
  it('reads each kind Rust answers', () => {
    expect(parseGoogleLinkResult({ kind: 'started' })).toEqual({ kind: 'started' });
    expect(parseGoogleLinkResult({ kind: 'notFresh' })).toEqual({ kind: 'not-fresh' });
    expect(parseGoogleLinkResult({ kind: 'sessionEnded' })).toEqual({ kind: 'session-ended' });
    expect(parseGoogleLinkResult({ kind: 'failed' })).toEqual({ kind: 'failed' });
  });

  it('never takes something unexpected for a start', () => {
    for (const value of odd) expect(parseGoogleLinkResult(value)).toEqual({ kind: 'failed' });
  });
});

describe('parseGoogleUnlinkResult', () => {
  it('reads each kind Rust answers', () => {
    expect(parseGoogleUnlinkResult({ kind: 'unlinked' })).toEqual({ kind: 'unlinked' });
    expect(parseGoogleUnlinkResult({ kind: 'notLinked' })).toEqual({ kind: 'not-linked' });
    expect(parseGoogleUnlinkResult({ kind: 'notFresh' })).toEqual({ kind: 'not-fresh' });
    expect(parseGoogleUnlinkResult({ kind: 'sessionEnded' })).toEqual({ kind: 'session-ended' });
  });

  it('never takes something unexpected for a success', () => {
    for (const value of odd) expect(parseGoogleUnlinkResult(value)).toEqual({ kind: 'failed' });
  });
});

describe('messages', () => {
  it('tells how to fix an old sign-in, for linking and for unlinking', () => {
    expect(linkNotFreshMessage).toContain('もう一度ログイン');
    expect(unlinkNotFreshMessage).toContain('もう一度ログイン');
    expect(linkNotFreshMessage).not.toBe(unlinkNotFreshMessage);
    expect(startFailedMessage({ kind: 'not-fresh' })).toBe(linkNotFreshMessage);
    expect(unlinkDoneMessage({ kind: 'not-fresh' })).toBe(unlinkNotFreshMessage);
  });

  it('has something to say for each answer that leaves the section as it was', () => {
    expect(startFailedMessage({ kind: 'failed' })).not.toBe('');
    expect(unlinkDoneMessage({ kind: 'failed' })).not.toBe('');
    expect(unlinkDoneMessage({ kind: 'unlinked' })).not.toBe('');
    expect(unlinkDoneMessage({ kind: 'not-linked' })).not.toBe('');
    // The answers that send the user back to the sign-in screen have no message here.
    expect(startFailedMessage({ kind: 'session-ended' })).toBe('');
    expect(unlinkDoneMessage({ kind: 'session-ended' })).toBe('');
  });

  it('reads the result of linking from the accounts, not from the browser', () => {
    expect(messageAfterLinkAttempt(true)).toBe(linkedMessage);
    expect(messageAfterLinkAttempt(false)).toBe(notLinkedMessage);
    expect(linkWaitingMessage).toContain('確認する');
  });
});

describe('the reason the web app gave', () => {
  it('is added to the message only when there is one', () => {
    expect(messageAfterLinkAttempt(false, 'state_mismatch')).toContain('state_mismatch');
    expect(messageAfterLinkAttempt(false, 'account_already_linked_to_different_user')).toContain('別のユーザー');
    // A code nobody wrote words for: the generic message, with the code.
    expect(messageAfterLinkAttempt(false, 'something_new')).toContain(notLinkedMessage);
    expect(messageAfterLinkAttempt(false, 'something_new')).toContain('something_new');
    expect(messageAfterLinkAttempt(false, null)).toBe(notLinkedMessage);
    expect(messageAfterLinkAttempt(true, 'state_mismatch')).toBe(linkedMessage);
  });

  it('is shown only when it is a short plain word', () => {
    expect(parseLinkReason('state_mismatch')).toBe('state_mismatch');
    for (const odd of [null, undefined, 1, '', 'a b', '<b>', 'x'.repeat(65)]) {
      expect(parseLinkReason(odd)).toBeNull();
    }
  });
});

describe('shouldKeepPolling', () => {
  it('reads the accounts again for a while after linking was started, then stops', () => {
    expect(shouldKeepPolling(1000, 1000)).toBe(true);
    expect(shouldKeepPolling(1000, 1000 + LINK_POLL_MAX_MS - 1)).toBe(true);
    expect(shouldKeepPolling(1000, 1000 + LINK_POLL_MAX_MS)).toBe(false);
  });
});

describe('signing in with Google', () => {
  it('reads how it started, and never takes something unexpected for a start', () => {
    expect(parseGoogleSignInStart({ kind: 'started' })).toEqual({ kind: 'started' });
    expect(parseGoogleSignInStart({ kind: 'failed', status: 429 })).toEqual({ kind: 'failed', status: 429 });
    expect(parseGoogleSignInStart({ kind: 'failed', status: null })).toEqual({ kind: 'failed', status: null });
    for (const value of [null, undefined, 'started', 1, {}, { kind: 'Started' }]) {
      expect(parseGoogleSignInStart(value)).toEqual({ kind: 'failed', status: null });
    }
  });

  it('says what to do when it did not start', () => {
    expect(signInStartFailedMessage({ kind: 'failed', status: 429 })).toContain('回数');
    expect(signInStartFailedMessage({ kind: 'failed', status: null })).toContain('始められません');
    expect(signInStartFailedMessage({ kind: 'started' })).toBe('');
  });
});

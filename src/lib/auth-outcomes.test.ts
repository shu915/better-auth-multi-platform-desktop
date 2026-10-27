import { describe, expect, it } from 'vitest';

import {
  linkMessage,
  parseLinkResult,
  parseRequestResult,
  parseTakenLinkResult,
  screenAfterRefresh,
  parseSignedIn,
  parseSignOutResult,
  requestMessage,
} from './auth-outcomes';

describe('parseRequestResult', () => {
  it('reads a sent request', () => {
    expect(parseRequestResult({ kind: 'sent' })).toEqual({ kind: 'sent' });
  });

  it('reads a refused request with its status', () => {
    expect(parseRequestResult({ kind: 'failed', reason: 'x', status: 429 })).toEqual({
      kind: 'failed',
      status: 429,
    });
    expect(parseRequestResult({ kind: 'failed', reason: 'x', status: null })).toEqual({
      kind: 'failed',
      status: null,
    });
  });

  it('treats anything unexpected as a failure, never as sent', () => {
    for (const value of [null, undefined, 'sent', 1, [], {}, { kind: 'Sent' }, { kind: 1 }]) {
      expect(parseRequestResult(value)).toEqual({ kind: 'failed', status: null });
    }
  });

  it('ignores a status that is not a number', () => {
    expect(parseRequestResult({ kind: 'failed', status: '429' })).toEqual({
      kind: 'failed',
      status: null,
    });
  });
});

describe('parseSignOutResult', () => {
  it('reads a sign-out, whether or not the web app was told', () => {
    expect(parseSignOutResult({ kind: 'signedOut', serverNotified: false })).toEqual({
      kind: 'signed-out',
    });
    expect(parseSignOutResult({ kind: 'signedOut', serverNotified: true })).toEqual({
      kind: 'signed-out',
    });
  });

  it('treats a failure or anything unexpected as not signed out', () => {
    for (const value of [{ kind: 'failed', reason: 'x' }, null, 'signedOut', {}, 1]) {
      expect(parseSignOutResult(value)).toEqual({ kind: 'failed' });
    }
  });
});

describe('parseSignedIn', () => {
  it('is true only for true', () => {
    expect(parseSignedIn(true)).toBe(true);
    for (const value of [false, null, undefined, 'true', 1, {}]) {
      expect(parseSignedIn(value)).toBe(false);
    }
  });
});

describe('requestMessage', () => {
  it('does not say whether the address is registered', () => {
    expect(requestMessage({ kind: 'sent' })).toContain('メールを送りました');
  });

  it('tells a rate limit apart from other failures', () => {
    expect(requestMessage({ kind: 'failed', status: 429 })).toContain('回数');
    expect(requestMessage({ kind: 'failed', status: 500 })).toContain('送れませんでした');
    expect(requestMessage({ kind: 'failed', status: null })).toContain('送れませんでした');
  });
});

describe('parseLinkResult', () => {
  it('signs in only for a stored session', () => {
    expect(parseLinkResult({ kind: 'stored' })).toEqual({ kind: 'stored' });
  });

  it('keeps a refused link apart from a failed one', () => {
    expect(parseLinkResult({ kind: 'rejected', reason: 'state does not match' })).toEqual({
      kind: 'rejected',
    });
    expect(parseLinkResult({ kind: 'failed', reason: 'exchange refused' })).toEqual({ kind: 'failed' });
  });

  it('shows nothing for an ignored link', () => {
    expect(parseLinkResult({ kind: 'ignored' })).toBeNull();
  });

  it('treats anything unexpected as a failure, never as a sign-in', () => {
    for (const value of [null, undefined, 'stored', 1, [], {}, { kind: 'Stored' }, { kind: 1 }]) {
      expect(parseLinkResult(value)).toEqual({ kind: 'failed' });
    }
  });
});

describe('parseTakenLinkResult', () => {
  it('is null when Rust has nothing to report', () => {
    expect(parseTakenLinkResult(null)).toBeNull();
    expect(parseTakenLinkResult(undefined)).toBeNull();
  });

  it('reads what Rust reports like a link result', () => {
    expect(parseTakenLinkResult({ kind: 'stored' })).toEqual({ kind: 'stored' });
    expect(parseTakenLinkResult({ kind: 'rejected', reason: 'x' })).toEqual({ kind: 'rejected' });
    expect(parseTakenLinkResult({ kind: 'weird' })).toEqual({ kind: 'failed' });
  });
});

describe('linkMessage', () => {
  it('explains a refused link and a failed one differently', () => {
    expect(linkMessage({ kind: 'rejected' })).toContain('期限');
    expect(linkMessage({ kind: 'failed' })).toContain('ログインできませんでした');
  });
});

describe('screenAfterRefresh', () => {
  it('keeps what Rust said about the session when no link was handled', () => {
    expect(screenAfterRefresh(true, null)).toEqual({ signedIn: true, message: null });
    expect(screenAfterRefresh(false, null)).toEqual({ signedIn: false, message: null });
  });

  it('signs in for a stored link even when the session was read just before it was saved', () => {
    expect(screenAfterRefresh(false, { kind: 'stored' })).toEqual({ signedIn: true, message: '' });
    expect(screenAfterRefresh(true, { kind: 'stored' })).toEqual({ signedIn: true, message: '' });
  });

  it('shows a message, and does not sign in, for a refused or failed link', () => {
    const rejected = screenAfterRefresh(false, { kind: 'rejected' });
    expect(rejected.signedIn).toBe(false);
    expect(rejected.message).toContain('期限');
    const failed = screenAfterRefresh(false, { kind: 'failed' });
    expect(failed.signedIn).toBe(false);
    expect(failed.message).toContain('ログインできませんでした');
  });

  it('does not sign anyone out because of a refused link', () => {
    expect(screenAfterRefresh(true, { kind: 'rejected' }).signedIn).toBe(true);
  });
});

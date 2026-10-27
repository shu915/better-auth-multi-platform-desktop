import { describe, expect, it } from 'vitest';

import {
  parseRequestResult,
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

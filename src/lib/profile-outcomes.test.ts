import { describe, expect, it } from 'vitest';

import { parseLoadResult } from './profile-outcomes';

describe('parseLoadResult', () => {
  it('reads a loaded profile', () => {
    expect(
      parseLoadResult({ kind: 'loaded', name: 'Alice', email: 'a@example.com', bio: 'hello' }),
    ).toEqual({ kind: 'loaded', name: 'Alice', email: 'a@example.com', bio: 'hello' });
  });

  it('keeps a bio that could not be read as null, and an empty bio as empty', () => {
    expect(parseLoadResult({ kind: 'loaded', name: 'A', email: 'e', bio: null })).toEqual({
      kind: 'loaded',
      name: 'A',
      email: 'e',
      bio: null,
    });
    expect(parseLoadResult({ kind: 'loaded', name: 'A', email: 'e', bio: '' })).toEqual({
      kind: 'loaded',
      name: 'A',
      email: 'e',
      bio: '',
    });
  });

  it('reads an ended session', () => {
    expect(parseLoadResult({ kind: 'sessionEnded' })).toEqual({ kind: 'session-ended' });
  });

  it('treats anything unexpected as a failure, never as a profile', () => {
    for (const value of [
      null,
      undefined,
      'loaded',
      1,
      [],
      {},
      { kind: 'failed' },
      { kind: 'Loaded', name: 'A', email: 'e', bio: null },
      { kind: 'loaded', email: 'e', bio: null },
      { kind: 'loaded', name: 'A', bio: null },
      { kind: 'loaded', name: 1, email: 'e', bio: null },
      { kind: 'loaded', name: 'A', email: 'e' },
      { kind: 'loaded', name: 'A', email: 'e', bio: 1 },
    ]) {
      expect(parseLoadResult(value)).toEqual({ kind: 'failed' });
    }
  });
});

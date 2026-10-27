import { describe, expect, it } from 'vitest';

import {
  draftsAfterLoad,
  hasChanges,
  isSameGeneration,
  mergeSaved,
  nothingToSaveMessage,
  normalizeNewlines,
  parseSaveResult,
  planSave,
  saveMessage,
  savedFrom,
  savedMessage,
  type SaveResult,
} from './profile-edit';

const values = (name: string, nameDraft: string, savedBio: string, bioDraft: string) => ({
  name,
  nameDraft,
  savedBio,
  bioDraft,
});

describe('planSave', () => {
  it('sends nothing when nothing changed', () => {
    expect(planSave(values('Alice', 'Alice', 'hi', 'hi'))).toEqual({
      sendName: false,
      sendBio: false,
    });
    expect(hasChanges(values('Alice', 'Alice', 'hi', 'hi'))).toBe(false);
  });

  it('sends only what changed', () => {
    expect(planSave(values('Alice', 'Alicia', 'hi', 'hi'))).toEqual({
      sendName: true,
      sendBio: false,
    });
    expect(planSave(values('Alice', 'Alice', 'hi', 'hello'))).toEqual({
      sendName: false,
      sendBio: true,
    });
    expect(hasChanges(values('Alice', 'Bob', 'hi', 'hello'))).toBe(true);
  });

  it('compares the name after trimming, as Rust does', () => {
    expect(planSave(values('Alice', '  Alice ', '', '')).sendName).toBe(false);
    expect(planSave(values('', '   ', '', '')).sendName).toBe(false);
  });

  it('compares the bio after making line breaks one, and keeps its spaces', () => {
    expect(planSave(values('A', 'A', 'a\nb', 'a\r\nb')).sendBio).toBe(false);
    expect(planSave(values('A', 'A', 'a', 'a ')).sendBio).toBe(true);
  });

  it('counts clearing the bio as a change', () => {
    expect(planSave(values('A', 'A', 'hi', '')).sendBio).toBe(true);
  });

  it('does not touch the bio when it is not known (both empty)', () => {
    // While the bio could not be read the form passes empty for both: a name can still be saved.
    expect(planSave(values('Alice', 'Bob', '', ''))).toEqual({ sendName: true, sendBio: false });
  });
});

describe('normalizeNewlines', () => {
  it('makes every line break one', () => {
    expect(normalizeNewlines('a\r\nb\rc\nd')).toBe('a\nb\nc\nd');
  });
});

describe('parseSaveResult', () => {
  it('reads each kind', () => {
    expect(parseSaveResult({ kind: 'nothingToSave' })).toEqual({ kind: 'nothing-to-save' });
    expect(parseSaveResult({ kind: 'sessionEnded' })).toEqual({ kind: 'session-ended' });
    expect(parseSaveResult({ kind: 'saved', name: 'A', bio: null })).toEqual({
      kind: 'saved',
      name: 'A',
      bio: null,
    });
    expect(parseSaveResult({ kind: 'invalid', name: 'empty', bio: 'tooLong' })).toEqual({
      kind: 'invalid',
      name: 'empty',
      bio: 'tooLong',
    });
    expect(
      parseSaveResult({
        kind: 'failed',
        field: 'bio',
        refused: true,
        refusal: null,
        nameSaved: 'Bob',
      }),
    ).toEqual({ kind: 'failed', field: 'bio', refused: true, refusal: null, nameSaved: 'Bob' });
  });

  it('reads a failure that belongs to no field', () => {
    expect(
      parseSaveResult({ kind: 'failed', field: null, refused: false, refusal: null, nameSaved: null }),
    ).toEqual({ kind: 'failed', field: null, refused: false, refusal: null, nameSaved: null });
  });

  it('treats anything unexpected as a failure, never as saved', () => {
    const failed = { kind: 'failed', field: null, refused: false, refusal: null, nameSaved: null };
    for (const value of [null, undefined, 'saved', 1, [], {}, { kind: 'Saved' }, { kind: 1 }]) {
      expect(parseSaveResult(value)).toEqual(failed);
    }
  });

  it('drops values of the wrong type instead of trusting them', () => {
    // Neither value is usable: that is not a save.
    expect(parseSaveResult({ kind: 'saved', name: 1, bio: {} })).toEqual({
      kind: 'failed',
      field: null,
      refused: false,
      refusal: null,
      nameSaved: null,
    });
    expect(parseSaveResult({ kind: 'saved', name: 'A', bio: {} })).toEqual({
      kind: 'saved',
      name: 'A',
      bio: null,
    });
    expect(parseSaveResult({ kind: 'invalid', name: 'weird', bio: 5 })).toEqual({
      kind: 'invalid',
      name: null,
      bio: null,
    });
    expect(
      parseSaveResult({ kind: 'failed', field: 'x', refused: 'yes', refusal: 3, nameSaved: 4 }),
    ).toEqual({ kind: 'failed', field: null, refused: false, refusal: null, nameSaved: null });
  });
});

describe('saveMessage', () => {
  it('says saved, and that nothing changed', () => {
    expect(saveMessage({ kind: 'saved', name: 'A', bio: null })).toBe(savedMessage);
    expect(saveMessage({ kind: 'nothing-to-save' })).toBe(nothingToSaveMessage);
  });

  it('names the problem of each field that was to be sent', () => {
    expect(saveMessage({ kind: 'invalid', name: 'empty', bio: null })).toContain('名前を入力');
    expect(saveMessage({ kind: 'invalid', name: null, bio: 'tooLong' })).toContain('1000');
    const both = saveMessage({ kind: 'invalid', name: 'tooLong', bio: 'invalidCharacter' });
    expect(both).toContain('50');
    expect(both).toContain('使えない文字');
  });

  it('shows the reason the web app gave for a refused name', () => {
    expect(
      saveMessage({ kind: 'failed', field: 'name', refused: true, refusal: 'Enter a name.', nameSaved: null }),
    ).toContain('Enter a name.');
  });

  it('tells a refused bio and a bio that could not be saved apart, and says the name was saved', () => {
    const refused = saveMessage({ kind: 'failed', field: 'bio', refused: true, refusal: null, nameSaved: null });
    expect(refused).toContain('断られました');
    const unsaved = saveMessage({ kind: 'failed', field: 'bio', refused: false, refusal: null, nameSaved: null });
    expect(unsaved).toContain('保存できませんでした');
    expect(unsaved).not.toContain('名前は保存しました');
    const partly = saveMessage({ kind: 'failed', field: 'bio', refused: false, refusal: null, nameSaved: 'Bob' });
    expect(partly).toContain('名前は保存しましたが');
  });

  it('asks to try again for a failure that is not a refusal', () => {
    const text = saveMessage({ kind: 'failed', field: 'name', refused: false, refusal: null, nameSaved: null });
    expect(text).toContain('もう一度');
    expect(saveMessage({ kind: 'failed', field: null, refused: false, refusal: null, nameSaved: null })).toContain(
      'もう一度',
    );
  });
});

describe('draftsAfterLoad', () => {
  const loaded = { name: 'Alice', bio: 'hello' };

  it('fills the drafts when nothing was shown yet', () => {
    expect(draftsAfterLoad(null, { nameDraft: '', bioDraft: '' }, loaded)).toEqual({
      nameDraft: 'Alice',
      bioDraft: 'hello',
    });
  });

  it('replaces a draft that still equals what was shown', () => {
    const shown = { name: 'Al', bio: 'hi' };
    expect(draftsAfterLoad(shown, { nameDraft: 'Al', bioDraft: 'hi' }, loaded)).toEqual({
      nameDraft: 'Alice',
      bioDraft: 'hello',
    });
  });

  it('keeps what the user is typing', () => {
    const shown = { name: 'Al', bio: 'hi' };
    expect(draftsAfterLoad(shown, { nameDraft: 'Alan', bioDraft: 'hi' }, loaded)).toEqual({
      nameDraft: 'Alan',
      bioDraft: 'hello',
    });
    expect(draftsAfterLoad(shown, { nameDraft: 'Al', bioDraft: 'typing…' }, loaded)).toEqual({
      nameDraft: 'Alice',
      bioDraft: 'typing…',
    });
  });

  it('has no bio draft to protect while the bio could not be read', () => {
    const shown = { name: 'Al', bio: null };
    expect(draftsAfterLoad(shown, { nameDraft: 'Al', bioDraft: '' }, loaded)).toEqual({
      nameDraft: 'Alice',
      bioDraft: 'hello',
    });
  });

  it('draws an unread bio as an empty draft', () => {
    expect(
      draftsAfterLoad(null, { nameDraft: '', bioDraft: '' }, { name: 'A', bio: null }),
    ).toEqual({ nameDraft: 'A', bioDraft: '' });
  });
});

describe('savedFrom and mergeSaved', () => {
  const saved = (name: string | null, bio: string | null): SaveResult => ({
    kind: 'saved',
    name,
    bio,
  });
  const failedBio = (nameSaved: string | null): SaveResult => ({
    kind: 'failed',
    field: 'bio',
    refused: false,
    refusal: null,
    nameSaved,
  });

  it('reads what was saved from a save', () => {
    expect(savedFrom(saved('Bob', null))).toEqual({ name: 'Bob', bio: null });
    expect(savedFrom(saved(null, 'new'))).toEqual({ name: null, bio: 'new' });
  });

  it('counts a name saved before the bio failed, but no bio', () => {
    expect(savedFrom(failedBio('Bob'))).toEqual({ name: 'Bob', bio: null });
    expect(savedFrom(failedBio(null))).toEqual({ name: null, bio: null });
  });

  it('saves nothing for the other results', () => {
    for (const result of [
      { kind: 'nothing-to-save' },
      { kind: 'invalid', name: 'empty', bio: null },
      { kind: 'session-ended' },
    ] as SaveResult[]) {
      expect(savedFrom(result)).toEqual({ name: null, bio: null });
    }
  });

  it('puts the saved values over the shown ones, and keeps the rest', () => {
    const profile = { name: 'Al', email: 'a@example.com', bio: 'hi' };
    expect(mergeSaved(profile, { name: 'Bob', bio: null })).toEqual({
      name: 'Bob',
      email: 'a@example.com',
      bio: 'hi',
    });
    expect(mergeSaved(profile, { name: null, bio: 'new' })).toEqual({
      name: 'Al',
      email: 'a@example.com',
      bio: 'new',
    });
    expect(mergeSaved(profile, { name: null, bio: null })).toEqual(profile);
  });
});

describe('isSameGeneration', () => {
  it('drops the answer of a save that started before the screen forgot its user', () => {
    expect(isSameGeneration(3, 3)).toBe(true);
    expect(isSameGeneration(3, 4)).toBe(false);
  });
});

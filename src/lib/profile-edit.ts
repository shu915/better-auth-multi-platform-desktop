// The decisions the profile form makes, and what it says about a save. Pure, so it is tested on its
// own. The rules that decide what may be stored (length, NUL, trimming) live in Rust and are applied
// there before anything is sent; this only decides what to *ask* Rust to send, and how to word the
// answer. The answer holds no secret: only a kind, the names of the fields, and the server's reason.

import { sessionEndedMessage } from './profile-outcomes';

// A line break is one character: the same rule Rust applies before it compares and sends.
export const normalizeNewlines = (text: string): string => text.replace(/\r\n?/g, '\n');

export type ProfileValues = {
  /** The name that is saved now. */
  name: string;
  nameDraft: string;
  /** The bio the Go API has now. */
  savedBio: string;
  bioDraft: string;
};

// Only what changed is sent. The name is compared after trimming; the bio after its line breaks are
// made one (the same comparison as `plan_save` in Rust, so the button and the command agree).
// `trim()` here and in Rust do not strip exactly the same characters (JavaScript strips U+FEFF, Rust
// strips U+0085), so for a name that differs only in one of those, the button can disagree with
// Rust. The web app trims like JavaScript and has the last word, and the screen takes in what it
// saved, so nothing breaks; at worst the button is on (or off) for a change that is (or is not) one.
export function planSave(values: ProfileValues): { sendName: boolean; sendBio: boolean } {
  return {
    sendName: values.nameDraft.trim() !== values.name,
    sendBio: normalizeNewlines(values.bioDraft) !== values.savedBio,
  };
}

export const hasChanges = (values: ProfileValues): boolean => {
  const plan = planSave(values);
  return plan.sendName || plan.sendBio;
};

export type Problem = 'empty' | 'tooLong' | 'invalidCharacter';
export type Field = 'name' | 'bio';

export type SaveResult =
  | { kind: 'nothing-to-save' }
  // Nothing was sent: the input breaks a rule. Only the fields that were to be sent have a problem.
  | { kind: 'invalid'; name: Problem | null; bio: Problem | null }
  // What the servers saved; null for a field that was not sent.
  | { kind: 'saved'; name: string | null; bio: string | null }
  | { kind: 'session-ended' }
  | {
      kind: 'failed';
      // null: not about one field (the app is not set up to reach its servers, say).
      field: Field | null;
      refused: boolean;
      // The reason the web app gave for refusing a name (shown to the user).
      refusal: string | null;
      // The name that was saved before the bio failed.
      nameSaved: string | null;
    };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

const problemOf = (value: unknown): Problem | null =>
  value === 'empty' || value === 'tooLong' || value === 'invalidCharacter' ? value : null;

const stringOrNull = (value: unknown): string | null => (typeof value === 'string' ? value : null);

// Anything unexpected is a failure: the screen must not say "saved" unless Rust said so.
export function parseSaveResult(value: unknown): SaveResult {
  const failed: SaveResult = {
    kind: 'failed',
    field: null,
    refused: false,
    refusal: null,
    nameSaved: null,
  };
  if (!isRecord(value)) return failed;
  switch (value.kind) {
    case 'nothingToSave':
      return { kind: 'nothing-to-save' };
    case 'sessionEnded':
      return { kind: 'session-ended' };
    case 'invalid':
      return { kind: 'invalid', name: problemOf(value.name), bio: problemOf(value.bio) };
    case 'saved': {
      // Rust answers `saved` with at least one saved value. Neither is not a save: say so, rather
      // than telling the user it worked.
      const name = stringOrNull(value.name);
      const bio = stringOrNull(value.bio);
      return name === null && bio === null ? failed : { kind: 'saved', name, bio };
    }
    case 'failed':
      return {
        kind: 'failed',
        field: value.field === 'name' || value.field === 'bio' ? value.field : null,
        refused: value.refused === true,
        refusal: stringOrNull(value.refusal),
        nameSaved: stringOrNull(value.nameSaved),
      };
    default:
      return failed;
  }
}

const NAME_PROBLEM: Record<Problem, string> = {
  empty: '名前を入力してください。',
  tooLong: '名前は 50 文字以内にしてください。',
  invalidCharacter: '名前に使えない文字が含まれています。',
};

const BIO_PROBLEM: Record<Problem, string> = {
  empty: 'bio を入力してください。',
  tooLong: 'bio は 1000 文字以内にしてください。',
  invalidCharacter: 'bio に使えない文字が含まれています。',
};

export const savedMessage = '保存しました。';
export const nothingToSaveMessage = '変更はありません。';
const SAVE_FAILED = '保存できませんでした。入力は残してあります。接続を確かめて、もう一度お試しください。';

// What the form says after a save. `session-ended` is not worded here: the screen goes back to the
// sign-in form with `sessionEndedMessage`.
export function saveMessage(result: Exclude<SaveResult, { kind: 'session-ended' }>): string {
  switch (result.kind) {
    case 'nothing-to-save':
      return nothingToSaveMessage;
    case 'saved':
      return savedMessage;
    case 'invalid': {
      const parts: string[] = [];
      if (result.name !== null) parts.push(NAME_PROBLEM[result.name]);
      if (result.bio !== null) parts.push(BIO_PROBLEM[result.bio]);
      return parts.length > 0 ? parts.join(' ') : SAVE_FAILED;
    }
    case 'failed': {
      if (result.field === 'name') {
        return result.refused
          ? `名前が断られました。${result.refusal ?? ''}`.trim()
          : SAVE_FAILED;
      }
      if (result.field === 'bio') {
        const lead = result.nameSaved !== null ? '名前は保存しましたが、' : '';
        const body = result.refused
          ? 'bio は断られました。1000 文字以内で、使えない文字が含まれていないか確かめてください。'
          : 'bio は保存できませんでした。入力は残してあります。もう一度お試しください。';
        return `${lead}${body}`;
      }
      return SAVE_FAILED;
    }
  }
}

// What is shown (saved now) and what is being typed.
export type Shown = { name: string; bio: string | null };
export type Drafts = { nameDraft: string; bioDraft: string };

// The drafts after the profile was read again (the retry button, a new sign-in). A read that
// finishes later must not overwrite what the user is typing: a draft is replaced only while it still
// equals what was shown (or when nothing was shown yet). A bio that could not be read (null) has no
// draft to protect.
export function draftsAfterLoad(shown: Shown | null, drafts: Drafts, loaded: Shown): Drafts {
  const nameUntouched = shown === null || drafts.nameDraft === shown.name;
  const bioUntouched = shown === null || shown.bio === null || drafts.bioDraft === shown.bio;
  return {
    nameDraft: nameUntouched ? loaded.name : drafts.nameDraft,
    bioDraft: bioUntouched ? (loaded.bio ?? '') : drafts.bioDraft,
  };
}

// What the servers saved, from a save's result: the saved name and bio (null: not saved). A name saved
// before the bio failed counts too, or the next save would send it again.
export function savedFrom(result: SaveResult): { name: string | null; bio: string | null } {
  if (result.kind === 'saved') return { name: result.name, bio: result.bio };
  if (result.kind === 'failed') return { name: result.nameSaved, bio: null };
  return { name: null, bio: null };
}

// What is shown after a save: the saved values replace the old ones.
export function mergeSaved<T extends Shown>(
  profile: T,
  saved: { name: string | null; bio: string | null },
): T {
  return { ...profile, name: saved.name ?? profile.name, bio: saved.bio ?? profile.bio };
}

// A result is applied only if the screen still belongs to whom it was asked for. The generation
// number changes whenever the screen forgets whoever it showed (sign-out, a new sign-in, an ended
// session); the answer of a save that was started before is dropped, or it would show one user's
// values on another user's screen.
export const isSameGeneration = (started: number, now: number): boolean => started === now;

export { sessionEndedMessage };

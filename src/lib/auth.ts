import { invoke } from '@tauri-apps/api/core';

import {
  parseRequestResult,
  parseSignedIn,
  parseSignOutResult,
  parseTakenLinkResult,
  type LinkResult,
  type RequestResult,
  type SignOutResult,
} from './auth-outcomes';
import { parseDeleteResult, type DeleteResult } from './delete-account';
import {
  parseAccountsResult,
  parseGoogleLinkResult,
  parseGoogleUnlinkResult,
  parseLinkReason,
  type AccountsResult,
  type GoogleLinkResult,
  type GoogleUnlinkResult,
} from './google-outcomes';
import { parseSaveResult, type SaveResult } from './profile-edit';
import { parseLoadResult, type LoadResult } from './profile-outcomes';

// Thin calls to the Rust commands. The state, the verifier and the session stay in Rust; the screen
// only asks and shows what came back (see src-tauri/src/auth.rs).

export async function isSignedIn(): Promise<boolean> {
  try {
    return parseSignedIn(await invoke<unknown>('session_status'));
  } catch {
    return false;
  }
}

export async function requestSignInLink(email: string): Promise<RequestResult> {
  try {
    return parseRequestResult(await invoke<unknown>('request_sign_in_link', { email }));
  } catch {
    return { kind: 'failed', status: null };
  }
}

export async function signOut(): Promise<SignOutResult> {
  try {
    return parseSignOutResult(await invoke<unknown>('sign_out'));
  } catch {
    return { kind: 'failed' };
  }
}

// The result of the last mail link Rust handled (once; null when there is none). It comes from the
// Rust command, not from the event: the event is only a nudge, and the screen does not trust what
// an event carries.
export async function takeLinkResult(): Promise<LinkResult | null> {
  try {
    return parseTakenLinkResult(await invoke<unknown>('take_auth_outcome'));
  } catch {
    return null;
  }
}

// Reads the profile through Rust (the name and the email from the web app, the bio from the Go API).
// Rust forgets the session itself when the web app says it is no longer valid.
export async function loadProfile(): Promise<LoadResult> {
  try {
    return parseLoadResult(await invoke<unknown>('load_profile'));
  } catch {
    return { kind: 'failed' };
  }
}

// Saves what changed, through Rust: the name at the web app, the bio at the Go API. Rust checks the
// input against the rules first, and sends nothing if it breaks one. The screen passes what is saved
// now and what is being edited; Rust decides what to send again, and the servers have the last word.
export async function saveProfile(input: {
  savedName: string;
  nameDraft: string;
  savedBio: string;
  bioDraft: string;
}): Promise<SaveResult> {
  try {
    return parseSaveResult(await invoke<unknown>('save_profile', input));
  } catch {
    return parseSaveResult(null);
  }
}

// Deletes the account through Rust (the web app does the deleting). The typed email is only passed on;
// the web app compares it with the account's. Rust forgets the session itself when it is gone.
export async function deleteAccount(confirmEmail: string): Promise<DeleteResult> {
  try {
    return parseDeleteResult(await invoke<unknown>('delete_account', { confirmEmail }));
  } catch {
    return { kind: 'failed' };
  }
}

// Whether Google is linked (the list is read through Rust; the account id never reaches the screen).
export async function loadAccounts(): Promise<AccountsResult> {
  try {
    return parseAccountsResult(await invoke<unknown>('load_accounts'));
  } catch {
    return { kind: 'failed' };
  }
}

// Starts linking Google: Rust opens the system browser. The result of the linking itself is read
// from the accounts after the browser comes back.
export async function linkGoogle(): Promise<GoogleLinkResult> {
  try {
    return parseGoogleLinkResult(await invoke<unknown>('link_google'));
  } catch {
    return { kind: 'failed' };
  }
}

export async function unlinkGoogle(): Promise<GoogleUnlinkResult> {
  try {
    return parseGoogleUnlinkResult(await invoke<unknown>('unlink_google'));
  } catch {
    return { kind: 'failed' };
  }
}

// The reason the web app gave when it turned the last linking down (once; null when there is none).
export async function takeLinkReason(): Promise<string | null> {
  try {
    return parseLinkReason(await invoke<unknown>('take_link_error'));
  } catch {
    return null;
  }
}

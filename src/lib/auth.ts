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

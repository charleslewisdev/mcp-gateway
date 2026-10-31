import type { Env } from "./types.js";

/**
 * Fingerprints the login credentials. Grants store it, so changing the username
 * or password invalidates every grant issued before the change.
 */
export async function credentialId(env: Env): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${env.USERNAME}:${env.PASSWORD_HASH}`)
  );
  return btoa(String.fromCharCode(...new Uint8Array(digest)));
}

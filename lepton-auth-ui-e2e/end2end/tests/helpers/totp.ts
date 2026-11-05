import { authenticator } from "otplib";

const STEP_MS = 30_000;
const lastStepBySecret = new Map<string, number>();

/**
 * 6-digit TOTP for a base32 secret (harness seeds or enroll UI).
 *
 * The server rejects a code whose 30s step it already accepted for that
 * factor, so a second code for the same secret waits for the next step
 * instead of racing the clock.
 */
export async function totpCode(secret: string): Promise<string> {
  const key = normalizeBase32(secret);
  let step = Math.floor(Date.now() / STEP_MS);
  const last = lastStepBySecret.get(key);
  if (last !== undefined && step <= last) {
    const wait = (last + 1) * STEP_MS - Date.now() + 200;
    await new Promise((r) => setTimeout(r, Math.max(wait, 0)));
    step = Math.floor(Date.now() / STEP_MS);
  }
  lastStepBySecret.set(key, step);
  return authenticator.generate(key);
}

/** Strip spaces / lowercase for otplib / authenticator apps. */
export function normalizeBase32(secret: string): string {
  return secret.replace(/\s+/g, "").toUpperCase();
}

/** Read manual-entry secret text from the enroll Scan step. */
export async function totpSecretFromManualLocator(
  locator: import("@playwright/test").Locator,
): Promise<string> {
  const raw = (await locator.innerText()).trim();
  const secret = normalizeBase32(raw);
  if (!secret) {
    throw new Error("empty TOTP manual secret from page");
  }
  return secret;
}

/** Extract `secret=` from an otpauth URI (optional `data-otpauth` seam). */
export function totpSecretFromOtpauthUri(uri: string): string {
  const trimmed = uri.trim();
  if (!trimmed) {
    throw new Error("empty otpauth URI");
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`unparseable otpauth URI: ${trimmed.slice(0, 48)}`);
  }
  const secret = parsed.searchParams.get("secret")?.trim() ?? "";
  if (!secret) {
    throw new Error("otpauth URI missing secret=");
  }
  return normalizeBase32(secret);
}

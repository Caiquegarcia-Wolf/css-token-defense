/**
 * CSS Token Defense — Server-Side Token Generation
 * v3 Render-Proof Edition
 *
 * Generates HMAC-derived tokens embedded in CSS custom properties.
 * Both the property NAME and VALUE are cryptographically derived,
 * making static analysis and regex extraction impossible.
 *
 * Two-secret architecture (Kerckhoffs's Principle):
 *   JWT_SECRET            → Signs the token VALUE. Never leaves the server.
 *   CSS_CLIENT_SECRET     → Derives the property NAME. Public — visible in client JS.
 *                           Knowing this does NOT allow token forgery.
 */

import { createHmac, randomBytes, timingSafeEqual } from "crypto";

// ─── Environment ─────────────────────────────────────────────────────────────

const JWT_SECRET = process.env.JWT_SECRET;
const CSS_CLIENT_SECRET = process.env.NEXT_PUBLIC_CSS_CLIENT_SECRET;

if (!JWT_SECRET) throw new Error("Missing env: JWT_SECRET");
if (!CSS_CLIENT_SECRET) throw new Error("Missing env: NEXT_PUBLIC_CSS_CLIENT_SECRET");

// ─── Config ───────────────────────────────────────────────────────────────────

export const TOKEN_TTL_SECONDS = 120;         // token expires after 2 minutes
export const DECOY_COUNT = 22;                // number of fake CSS properties surrounding the real one
export const ANIMATION_NAME = "__token-gate"; // CSS animation that gates token reading
export const ANIMATION_MS = 350;              // animation duration (ms)

// Paint timing validation thresholds — calibrate per deployment
export const FCP_MIN_MS = 80;                 // impossibly fast = headless benchmark mode
export const FCP_MAX_MS = 12_000;             // impossibly slow = stale replay
export const MIN_HUMAN_DELAY_MS = 400;        // minimum plausible time between page load and form submit

// ─── HMAC helpers ────────────────────────────────────────────────────────────

function hmac(secret: string, data: string): string {
  return createHmac("sha256", secret).update(data).digest("hex");
}

// ─── Token generation ─────────────────────────────────────────────────────────

export interface CssToken {
  /** The CSS custom property name, e.g. "--b3d91f2a" */
  propName: string;
  /** The token value, e.g. "1744624800.a1b2c3d4.a3f2c1e8d9b0a7f4" */
  token: string;
  /** Unix timestamp (seconds) embedded in the token */
  timestamp: number;
  /** Random nonce — ensures uniqueness even within the same second */
  nonce: string;
}

/**
 * Generate a fresh CSS token for server-side embedding.
 * Call once per SSR page render and embed the result in your <style> tag.
 */
export function generateCssToken(): CssToken {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(4).toString("hex"); // 8 hex chars

  // Property name: derived from the CLIENT secret + timestamp + nonce (safe to expose)
  const propHash = hmac(CSS_CLIENT_SECRET!, `css-prop:${timestamp}:${nonce}`);
  const propName = `--${propHash.slice(0, 8)}`;

  // Token value: derived from the SERVER secret (never exposed)
  // 16 hex chars = 64 bits of entropy (vs. old 6 chars = 24 bits)
  const signature = hmac(JWT_SECRET!, `css:${timestamp}:${nonce}`).slice(0, 16);
  const token = `${timestamp}.${nonce}.${signature}`;

  return { propName, token, timestamp, nonce };
}

// ─── Single-use token store ───────────────────────────────────────────────────
// Tokens are burned after first validation — prevents replay attacks within the TTL window.
// In production with multiple instances, replace with Redis SET + EX:
//   if (await redis.sIsMember("used_tokens", token)) return false;
//   await redis.sAdd("used_tokens", token);
//   await redis.expire("used_tokens", TOKEN_TTL_SECONDS);

const usedTokens = new Set<string>();

// Cleanup expired tokens every 2 minutes to prevent memory growth
const usedTokenCleanup = setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  for (const t of usedTokens) {
    const ts = parseInt(t.split(".")[0], 10);
    if (isNaN(ts) || now - ts > TOKEN_TTL_SECONDS) {
      usedTokens.delete(t);
    }
  }
}, 2 * 60 * 1000);
usedTokenCleanup.unref(); // don't prevent process exit

// ─── Token validation ─────────────────────────────────────────────────────────

/**
 * Validate a token submitted by the client.
 * Returns true only if the token is genuine, unexpired, AND never used before.
 * Each token can only be consumed once — subsequent calls return false (single-use).
 */
export function validateCssToken(token: string): boolean {
  if (!token || typeof token !== "string") return false;

  const parts = token.split(".");
  if (parts.length !== 3) return false;

  const [tsStr, nonce, clientSig] = parts;
  const timestamp = parseInt(tsStr, 10);
  if (isNaN(timestamp)) return false;
  if (!/^[0-9a-f]{8}$/.test(nonce)) return false; // nonce must be 8 hex chars

  // Check expiry
  const age = Math.floor(Date.now() / 1000) - timestamp;
  if (age > TOKEN_TTL_SECONDS || age < 0) return false;

  // Single-use: reject if already consumed
  if (usedTokens.has(token)) return false;

  // Constant-time signature comparison (prevents timing attacks)
  const expectedSig = hmac(JWT_SECRET!, `css:${timestamp}:${nonce}`).slice(0, 16);
  try {
    const expected = Buffer.from(expectedSig, "utf8");
    const received = Buffer.from(clientSig, "utf8");
    if (expected.length !== received.length) return false;

    const valid = timingSafeEqual(expected, received);

    // Burn the token on successful validation — can never be used again
    if (valid) usedTokens.add(token);

    return valid;
  } catch {
    return false;
  }
}

export function extractTimestamp(token: string): number {
  return parseInt(token.split(".")[0], 10);
}

// ─── Paint timing validation ──────────────────────────────────────────────────

/**
 * Validate that the client's reported timing is plausible for a real browser.
 * Rejects impossibly fast (headless benchmark), impossibly slow (replay),
 * and suspiciously quick form submissions.
 */
export function validateTimingProof(
  fcp: number | null,
  submissionTs: number,
  tokenTs: number
): boolean {
  const tokenAgeMs = submissionTs - tokenTs * 1000;

  if (tokenAgeMs > TOKEN_TTL_SECONDS * 1000) return false; // expired
  if (tokenAgeMs < MIN_HUMAN_DELAY_MS) return false;        // too fast to be human
  if (fcp === null || fcp === undefined) return false;       // no paint recorded
  if (fcp < FCP_MIN_MS) return false;                        // suspiciously fast
  if (fcp > FCP_MAX_MS) return false;                        // suspiciously slow / replayed

  return true;
}

// ─── Decoy CSS generation ─────────────────────────────────────────────────────

const DECOY_VALUES = [
  "#1A1A2E", "#E94560", "#0F3460", "#533483",
  "16px", "24px", "8px", "32px", "1.5", "0.875rem",
  "rgba(0,0,0,0.1)", "transparent", "inherit", "initial",
  "400", "600", "700", "normal", "bold",
  "0 2px 4px rgba(0,0,0,0.1)", "none", "auto",
];

/**
 * Generate decoy CSS custom properties to surround the real token.
 * All names are pseudo-random hex strings — indistinguishable from the real one.
 */
export function generateDecoyProperties(realPropName: string, seed: string): string {
  const decoys: string[] = [];

  for (let i = 0; i < DECOY_COUNT; i++) {
    const decoyName = `--${hmac(CSS_CLIENT_SECRET!, `decoy:${seed}:${i}`).slice(0, 8)}`;
    if (decoyName === realPropName) continue; // avoid collision (astronomically unlikely)
    const value = DECOY_VALUES[i % DECOY_VALUES.length];
    decoys.push(`  ${decoyName}: ${value};`);
  }

  return decoys.join("\n");
}

// ─── Full CSS block builder ───────────────────────────────────────────────────

/**
 * Build the complete :root CSS block to inject into your SSR page.
 * Includes the real token at a random position among decoys,
 * plus the animation gate definition.
 */
export function buildCssTokenBlock(cssToken: CssToken): {
  styleBlock: string;
  keyframeBlock: string;
} {
  const { propName, token, timestamp, nonce } = cssToken;
  const decoyLines = generateDecoyProperties(propName, `${timestamp}:${nonce}`).split("\n");

  // Insert real token at a random position
  const insertAt = Math.floor(Math.random() * (decoyLines.length + 1));
  decoyLines.splice(insertAt, 0, `  ${propName}: ${token};`);

  const styleBlock = `:root {\n${decoyLines.join("\n")}\n  animation: ${ANIMATION_NAME} ${ANIMATION_MS}ms ease forwards;\n}`;

  const keyframeBlock = `@keyframes ${ANIMATION_NAME} {\n  from { opacity: 0.9999; }\n  to   { opacity: 1; }\n}`;

  return { styleBlock, keyframeBlock };
}

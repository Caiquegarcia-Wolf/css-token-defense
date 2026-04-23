/**
 * CSS Token Defense — Render Environment Store
 * v3 Render-Proof Edition
 *
 * Tracks canvas fingerprints per session to detect:
 *   - Environment switching (same session, different GPU/renderer)
 *   - Known headless browser signatures
 *   - Absent fingerprints (hard failure — real browsers always produce one)
 *
 * In production, replace the in-memory Map with Redis or your session store.
 * The in-memory implementation here is suitable for single-instance deployments
 * or for demonstration purposes.
 */

// ─── Known headless signatures ────────────────────────────────────────────────
// These values were observed from common headless environments.
// Add to this list as new signatures are discovered.

const KNOWN_HEADLESS_FINGERPRINTS = new Set<string>([
  "0",           // no canvas support
  "canvas-error", // canvas exception
  "no-ctx",      // no 2D context
  // Add observed headless hashes here as you collect them
]);

// ─── In-memory session store ──────────────────────────────────────────────────
// Replace with Redis in production:
//   await redis.set(`fp:${sessionId}`, fingerprint, "EX", 3600);
//   const stored = await redis.get(`fp:${sessionId}`);

interface SessionRecord {
  fingerprint: string;
  firstSeen: number;
  requestCount: number;
  flagged: boolean;
}

const sessionStore = new Map<string, SessionRecord>();

// Clean up stale sessions every 10 minutes
const sessionCleanup = setInterval(() => {
  const cutoff = Date.now() - 60 * 60 * 1000; // 1 hour
  for (const [id, record] of sessionStore) {
    if (record.firstSeen < cutoff) sessionStore.delete(id);
  }
}, 10 * 60 * 1000);
sessionCleanup.unref(); // don't prevent process exit

// ─── Validation ───────────────────────────────────────────────────────────────

export interface FingerprintValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Validate a canvas fingerprint against session history.
 *
 * Rules:
 *   1. Absent fingerprint → hard failure
 *   2. Known headless signature → reject
 *   3. First request for session → store and accept
 *   4. Subsequent requests → accept only if fingerprint matches stored value
 */
export function validateRenderEnvironment(
  fingerprint: string | null | undefined,
  sessionId: string
): FingerprintValidationResult {
  // Rule 1: absent fingerprint is a hard failure
  if (!fingerprint || typeof fingerprint !== "string") {
    return { valid: false, reason: "missing-fingerprint" };
  }

  // Rule 2: known headless signature
  if (KNOWN_HEADLESS_FINGERPRINTS.has(fingerprint)) {
    return { valid: false, reason: "known-headless-signature" };
  }

  const existing = sessionStore.get(sessionId);

  if (!existing) {
    // Rule 3: first request — store fingerprint
    sessionStore.set(sessionId, {
      fingerprint,
      firstSeen: Date.now(),
      requestCount: 1,
      flagged: false,
    });
    return { valid: true };
  }

  // Rule 4: subsequent requests — must match
  if (existing.fingerprint !== fingerprint) {
    // Update record to track the anomaly
    existing.flagged = true;
    existing.requestCount++;
    return { valid: false, reason: "environment-mismatch" };
  }

  existing.requestCount++;
  return { valid: true };
}

/**
 * Check if a session has been flagged for environment switching.
 * Use this to apply stricter rate limits or require CAPTCHA.
 */
export function isSessionFlagged(sessionId: string): boolean {
  return sessionStore.get(sessionId)?.flagged ?? false;
}

/**
 * Get session stats (for logging/monitoring).
 */
export function getSessionStats(sessionId: string): SessionRecord | undefined {
  return sessionStore.get(sessionId);
}

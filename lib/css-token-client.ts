/**
 * CSS Token Defense — Client-Side Token Reader
 * v3 Render-Proof Edition
 *
 * Reads the CSS-embedded token ONLY after proving a genuine render cycle occurred:
 *   1. Waits for the CSS animation gate (proves paint-layout-composite happened)
 *   2. Records first-contentful-paint via PerformanceObserver
 *   3. Generates a canvas fingerprint during the paint context
 *
 * This file runs in the browser. The CSS_CLIENT_SECRET is intentionally public —
 * it only derives the property NAME, not the token VALUE. Cannot forge tokens.
 */

const CSS_CLIENT_SECRET = process.env.NEXT_PUBLIC_CSS_CLIENT_SECRET!;
const ANIMATION_NAME = "__token-gate";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface TokenPayload {
  /** The HMAC token read from CSS */
  token: string;
  /** First-contentful-paint timestamp (ms), or null if unavailable */
  fcp: number | null;
  /** Canvas fingerprint hash — ties token to this rendering environment */
  fp: string;
  /** Client timestamp at submission */
  submittedAt: number;
}

// ─── Web Crypto HMAC ──────────────────────────────────────────────────────────

async function hmacHex(secret: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── Canvas fingerprint ───────────────────────────────────────────────────────

/**
 * Generate a canvas fingerprint by drawing text and reading pixel values.
 * GPU-dependent — produces hardware-specific output that is difficult to spoof.
 * Must be called inside a real rendering context (animationend callback).
 */
function generateCanvasFingerprint(): string {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext("2d");
    if (!ctx) return "no-ctx";

    // Draw text with properties that amplify GPU/font rendering differences
    ctx.textBaseline = "top";
    ctx.font = "14px 'Arial'";
    ctx.textBaseline = "alphabetic";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("CSSTokenDefense", 2, 15);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.fillText("v3.render-proof", 4, 17);

    // Hash the pixel data
    const data = canvas.toDataURL();
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      hash = (Math.imul(31, hash) + data.charCodeAt(i)) | 0;
    }
    return Math.abs(hash).toString(16);
  } catch {
    return "canvas-error";
  }
}

// ─── FCP observer ─────────────────────────────────────────────────────────────

function observeFcp(): Promise<number | null> {
  return new Promise((resolve) => {
    // Resolve immediately if FCP already fired
    const existing = performance.getEntriesByName("first-contentful-paint");
    if (existing.length > 0) {
      resolve(Math.round(existing[0].startTime));
      return;
    }

    try {
      const observer = new PerformanceObserver((list) => {
        const entry = list.getEntriesByName("first-contentful-paint")[0];
        if (entry) {
          observer.disconnect();
          resolve(Math.round(entry.startTime));
        }
      });
      observer.observe({ entryTypes: ["paint"] });

      // Fallback: if FCP never fires (headless, hidden tab), resolve null after 5s
      setTimeout(() => resolve(null), 5000);
    } catch {
      resolve(null);
    }
  });
}

// ─── Animation gate ───────────────────────────────────────────────────────────

function waitForAnimationGate(): Promise<void> {
  return new Promise((resolve) => {
    const el = document.documentElement;

    const handler = (e: AnimationEvent) => {
      if (e.animationName === ANIMATION_NAME) {
        el.removeEventListener("animationend", handler);
        resolve();
      }
    };

    el.addEventListener("animationend", handler);

    // Safety fallback: if animationend never fires (e.g. animation was overridden
    // by user CSS or prefers-reduced-motion), proceed after a grace period.
    // This does NOT bypass server validation — timing checks will still apply.
    setTimeout(() => {
      el.removeEventListener("animationend", handler);
      resolve();
    }, 2000);
  });
}

// ─── CSS property reader ──────────────────────────────────────────────────────

/**
 * Derive the CSS property name from the data-ts value.
 * data-ts format: "timestamp:nonce" — both parts are used in the HMAC.
 */
async function readCssPropName(tsStr: string): Promise<string> {
  // tsStr = "timestamp:nonce" — matches server's `css-prop:${timestamp}:${nonce}`
  const hash = await hmacHex(CSS_CLIENT_SECRET, `css-prop:${tsStr}`);
  return `--${hash.slice(0, 8)}`;
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * Read the CSS-embedded token with full render proofs.
 *
 * This function:
 *   1. Starts observing FCP immediately (before the gate)
 *   2. Waits for the CSS animation gate (proves paint occurred)
 *   3. Derives the property name client-side
 *   4. Reads the token from getComputedStyle()
 *   5. Generates a canvas fingerprint in the same paint context
 *   6. Returns the full payload for submission
 *
 * Returns null if the token cannot be read (wrong environment, missing data-ts).
 */
export async function readCssTokenV3(): Promise<TokenPayload | null> {
  const tsStr = document.documentElement.dataset.ts;
  if (!tsStr) {
    console.warn("[css-token] Missing data-ts attribute on <html>");
    return null;
  }

  // Start FCP observation immediately — don't wait for gate
  const fcpPromise = observeFcp();

  // Wait for the animation gate (proves genuine paint cycle)
  await waitForAnimationGate();

  // Derive property name (mirrors server computation)
  const propName = await readCssPropName(tsStr);

  // Read token from computed styles
  const token = getComputedStyle(document.documentElement)
    .getPropertyValue(propName)
    .trim();

  if (!token) {
    console.warn("[css-token] Token property not found:", propName);
    return null;
  }

  // Generate canvas fingerprint (must be in real rendering context)
  const fp = generateCanvasFingerprint();

  // Await FCP (likely already resolved)
  const fcp = await fcpPromise;

  return {
    token,
    fcp,
    fp,
    submittedAt: Date.now(),
  };
}

/**
 * Convenience: attach the token payload to a fetch request body.
 * Merges token fields into your existing payload object.
 */
export async function withCssToken<T extends Record<string, unknown>>(
  payload: T
): Promise<T & { _ta: string; _fcp: number | null; _fp: string; _ts: number }> {
  const tokenPayload = await readCssTokenV3();

  if (!tokenPayload) {
    throw new Error("Failed to read CSS token — ensure page rendered correctly");
  }

  return {
    ...payload,
    _ta: tokenPayload.token,
    _fcp: tokenPayload.fcp,
    _fp: tokenPayload.fp,
    _ts: tokenPayload.submittedAt,
  };
}

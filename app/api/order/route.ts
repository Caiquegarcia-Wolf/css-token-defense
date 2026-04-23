/**
 * CSS Token Defense — Protected API Route
 * Next.js App Router (TypeScript)
 *
 * Demonstrates the full v3 validation chain:
 *   1. CSRF token check
 *   2. CSS token authenticity (HMAC + TTL)
 *   3. Paint timing plausibility (FCP window + minimum human delay)
 *   4. Render environment consistency (canvas fingerprint per session)
 *
 * Each layer is independent — a bypass of one does not help the attacker
 * bypass the others.
 */

import { NextRequest, NextResponse } from "next/server";
import {
  validateCssToken,
  validateTimingProof,
  extractTimestamp,
} from "@/lib/css-token";
import {
  validateRenderEnvironment,
} from "@/lib/render-environment";

// ─── CSRF validation ──────────────────────────────────────────────────────────
// Minimal example — replace with your actual CSRF implementation

import { createHmac, timingSafeEqual } from "crypto";

const JWT_SECRET = process.env.JWT_SECRET!;
const CSRF_TTL_SECONDS = 3600;
const CSRF_MIN_AGE_SECONDS = 1; // must be at least 1s old

function validateCsrfToken(token: string): boolean {
  if (!token || typeof token !== "string") return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [tsStr, sig] = parts;
  const ts = parseInt(tsStr, 10);
  if (isNaN(ts)) return false;

  const age = Math.floor(Date.now() / 1000) - ts;
  if (age > CSRF_TTL_SECONDS || age < CSRF_MIN_AGE_SECONDS) return false;

  const expected = createHmac("sha256", JWT_SECRET)
    .update(`csrf:${ts}`)
    .digest("hex")
    .slice(0, 8);

  // Constant-time comparison (prevents timing attacks)
  try {
    const expectedBuf = Buffer.from(expected, "utf8");
    const receivedBuf = Buffer.from(sig, "utf8");
    if (expectedBuf.length !== receivedBuf.length) return false;
    return timingSafeEqual(expectedBuf, receivedBuf);
  } catch {
    return false;
  }
}

// ─── Session ID extraction ─────────────────────────────────────────────────────

function getSessionId(req: NextRequest): string {
  // In production, use a proper session cookie or JWT sub
  return req.cookies.get("session_id")?.value ?? req.ip ?? "anonymous";
}

// ─── Rate limiting (in-memory, single instance) ────────────────────────────────
// Replace with Redis sliding window in production

const rateLimit = new Map<string, { count: number; resetAt: number }>();

const RATE_LIMIT_REQUESTS = 5;
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute

function checkRateLimit(key: string): boolean {
  const now = Date.now();
  const record = rateLimit.get(key);

  if (!record || now > record.resetAt) {
    rateLimit.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }

  if (record.count >= RATE_LIMIT_REQUESTS) return false;

  record.count++;
  return true;
}

// ─── Route handler ─────────────────────────────────────────────────────────────

export async function POST(req: NextRequest) {
  const ip = req.ip ?? "unknown";

  // Layer 1: Rate limiting
  if (!checkRateLimit(ip)) {
    return NextResponse.json(
      { error: "Rate limit exceeded" },
      { status: 429 }
    );
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const { _csrf, _ta, _fcp, _fp, _ts, ...orderData } = body as {
    _csrf: string;
    _ta: string;
    _fcp: number | null;
    _fp: string;
    _ts: number;
    [key: string]: unknown;
  };

  // Layer 2: CSRF token
  if (!validateCsrfToken(_csrf)) {
    return NextResponse.json(
      { error: "Invalid CSRF token" },
      { status: 403 }
    );
  }

  // Layer 3: CSS token authenticity
  if (!_ta || !validateCssToken(_ta)) {
    return NextResponse.json(
      { error: "Invalid rendering token" },
      { status: 403 }
    );
  }

  // Layer 4: Paint timing plausibility
  const tokenTs = extractTimestamp(_ta);
  if (!validateTimingProof(_fcp, _ts, tokenTs)) {
    return NextResponse.json(
      { error: "Invalid timing proof" },
      { status: 403 }
    );
  }

  // Layer 5: Render environment consistency
  const sessionId = getSessionId(req);
  const envResult = validateRenderEnvironment(_fp, sessionId);
  if (!envResult.valid) {
    return NextResponse.json(
      { error: `Environment validation failed: ${envResult.reason}` },
      { status: 403 }
    );
  }

  // ✅ All layers passed — process the actual request
  console.log("[css-token] Order accepted:", {
    ip,
    sessionId,
    fcp: _fcp,
    tokenAge: Math.floor(Date.now() / 1000) - tokenTs,
  });

  // TODO: replace with your actual business logic
  return NextResponse.json({
    success: true,
    message: "Order processed",
    data: orderData,
  });
}

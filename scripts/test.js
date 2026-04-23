/**
 * CSS Token Defense — Tests
 *
 * Run with: node scripts/test.js
 * No test framework required.
 */

const { createHmac, randomBytes, timingSafeEqual } = require("crypto");

// ── Inline the logic (avoids TS compilation for quick testing) ────────────────

process.env.JWT_SECRET = "test-jwt-secret-do-not-use-in-production";
process.env.CSS_CLIENT_SECRET = "test-css-client-secret";

const JWT_SECRET = process.env.JWT_SECRET;
const CSS_CLIENT_SECRET = process.env.CSS_CLIENT_SECRET;
const TOKEN_TTL_SECONDS = 120;
const FCP_MIN_MS = 80;
const FCP_MAX_MS = 12000;
const MIN_HUMAN_DELAY_MS = 400;

function hmac(secret, data) {
  return createHmac("sha256", secret).update(data).digest("hex");
}

function generateCssToken() {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(4).toString("hex");
  const propName = `--${hmac(CSS_CLIENT_SECRET, `css-prop:${timestamp}:${nonce}`).slice(0, 8)}`;
  const signature = hmac(JWT_SECRET, `css:${timestamp}:${nonce}`).slice(0, 16);
  return { propName, token: `${timestamp}.${nonce}.${signature}`, timestamp, nonce };
}

const usedTokens = new Set();

function validateCssToken(token) {
  if (!token || typeof token !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [tsStr, nonce, clientSig] = parts;
  const timestamp = parseInt(tsStr, 10);
  if (isNaN(timestamp)) return false;
  if (!/^[0-9a-f]{8}$/.test(nonce)) return false;
  const age = Math.floor(Date.now() / 1000) - timestamp;
  if (age > TOKEN_TTL_SECONDS || age < 0) return false;
  if (usedTokens.has(token)) return false;
  const expectedSig = hmac(JWT_SECRET, `css:${timestamp}:${nonce}`).slice(0, 16);
  try {
    const expected = Buffer.from(expectedSig, "utf8");
    const received = Buffer.from(clientSig, "utf8");
    if (expected.length !== received.length) return false;
    const valid = timingSafeEqual(expected, received);
    if (valid) usedTokens.add(token);
    return valid;
  } catch { return false; }
}

function validateTimingProof(fcp, submissionTs, tokenTs) {
  const ageMs = submissionTs - tokenTs * 1000;
  if (ageMs > TOKEN_TTL_SECONDS * 1000) return false;
  if (ageMs < MIN_HUMAN_DELAY_MS) return false;
  if (fcp === null || fcp === undefined) return false;
  if (fcp < FCP_MIN_MS || fcp > FCP_MAX_MS) return false;
  return true;
}

// ── Test runner ───────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ❌ ${name}`);
    console.log(`     ${err.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || "Assertion failed");
}

// ── Token generation ──────────────────────────────────────────────────────────

console.log("\n📋 Token Generation");

test("generates token with correct 3-part format", () => {
  const { token } = generateCssToken();
  const parts = token.split(".");
  assert(parts.length === 3, `Expected 3 parts, got ${parts.length}`);
  assert(!isNaN(parseInt(parts[0])), "Timestamp should be numeric");
  assert(parts[1].length === 8, `Nonce should be 8 hex chars, got ${parts[1].length}`);
  assert(parts[2].length === 16, `Signature should be 16 chars, got ${parts[2].length}`);
});

test("prop name starts with --", () => {
  const { propName } = generateCssToken();
  assert(propName.startsWith("--"), `Expected --, got ${propName}`);
  assert(propName.length === 10, `Expected 10 chars (--XXXXXXXX), got ${propName.length}`);
});

test("same timestamp + nonce produces same prop name", () => {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = "deadbeef";
  const name1 = `--${hmac(CSS_CLIENT_SECRET, `css-prop:${ts}:${nonce}`).slice(0, 8)}`;
  const name2 = `--${hmac(CSS_CLIENT_SECRET, `css-prop:${ts}:${nonce}`).slice(0, 8)}`;
  assert(name1 === name2, "Same inputs should produce same prop name");
});

test("different nonces produce different prop names (same second)", () => {
  const ts = Math.floor(Date.now() / 1000);
  const name1 = `--${hmac(CSS_CLIENT_SECRET, `css-prop:${ts}:aabbccdd`).slice(0, 8)}`;
  const name2 = `--${hmac(CSS_CLIENT_SECRET, `css-prop:${ts}:11223344`).slice(0, 8)}`;
  assert(name1 !== name2, "Different nonces should produce different prop names");
});

test("consecutive tokens have different nonces (same second)", () => {
  const t1 = generateCssToken();
  const t2 = generateCssToken();
  assert(t1.nonce !== t2.nonce, "Nonces should be unique per generation");
  assert(t1.token !== t2.token, "Tokens should be unique per generation");
});

// ── Token validation ──────────────────────────────────────────────────────────

console.log("\n📋 Token Validation");

test("valid token passes", () => {
  const { token } = generateCssToken();
  assert(validateCssToken(token), "Fresh token should be valid");
});

test("tampered signature fails", () => {
  const { token } = generateCssToken();
  const parts = token.split(".");
  const tampered = `${parts[0]}.${parts[1]}.${"f".repeat(16)}`;
  assert(!validateCssToken(tampered), "Tampered token should be invalid");
});

test("tampered nonce fails", () => {
  const { token } = generateCssToken();
  const parts = token.split(".");
  const tampered = `${parts[0]}.00000000.${parts[2]}`;
  assert(!validateCssToken(tampered), "Tampered nonce should invalidate signature");
});

test("expired token fails", () => {
  const oldTs = Math.floor(Date.now() / 1000) - TOKEN_TTL_SECONDS - 1;
  const nonce = "aabbccdd";
  const sig = hmac(JWT_SECRET, `css:${oldTs}:${nonce}`).slice(0, 16);
  const expired = `${oldTs}.${nonce}.${sig}`;
  assert(!validateCssToken(expired), "Expired token should be invalid");
});

test("future token fails", () => {
  const futureTs = Math.floor(Date.now() / 1000) + 9999;
  const nonce = "aabbccdd";
  const sig = hmac(JWT_SECRET, `css:${futureTs}:${nonce}`).slice(0, 16);
  const future = `${futureTs}.${nonce}.${sig}`;
  assert(!validateCssToken(future), "Future token should be invalid");
});

test("empty string fails", () => {
  assert(!validateCssToken(""), "Empty string should be invalid");
});

test("null fails", () => {
  assert(!validateCssToken(null), "Null should be invalid");
});

test("malformed token fails", () => {
  assert(!validateCssToken("notavalidtoken"), "Malformed token should be invalid");
  assert(!validateCssToken("a.b"), "Two-part token should be invalid");
  assert(!validateCssToken("a.b.c.d"), "Four-part token should be invalid");
});

test("invalid nonce format fails", () => {
  const ts = Math.floor(Date.now() / 1000);
  const sig = hmac(JWT_SECRET, `css:${ts}:ZZZZZZZZ`).slice(0, 16);
  assert(!validateCssToken(`${ts}.ZZZZZZZZ.${sig}`), "Non-hex nonce should fail");
});

test("wrong secret fails", () => {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = "aabbccdd";
  const wrongSig = hmac("wrong-secret", `css:${ts}:${nonce}`).slice(0, 16);
  const forged = `${ts}.${nonce}.${wrongSig}`;
  assert(!validateCssToken(forged), "Wrong-secret token should be invalid");
});

// ── Single-use validation ─────────────────────────────────────────────────────

console.log("\n📋 Single-Use Validation");

test("reused token is rejected (single-use)", () => {
  const { token } = generateCssToken();
  assert(validateCssToken(token), "First use should pass");
  assert(!validateCssToken(token), "Second use should fail — token was burned");
  assert(!validateCssToken(token), "Third use should also fail");
});

test("different tokens from same second are independently valid", () => {
  const { token: t1 } = generateCssToken();
  const { token: t2 } = generateCssToken();
  // With nonce, these are always different even in the same second
  assert(t1 !== t2, "Tokens should differ due to nonce");
  assert(validateCssToken(t1), "Token 1 should pass");
  assert(validateCssToken(t2), "Token 2 should also pass (different nonce)");
});

// ── Timing validation ─────────────────────────────────────────────────────────

console.log("\n📋 Timing Validation");

test("valid timing passes", () => {
  const tokenTs = Math.floor(Date.now() / 1000);
  const submissionTs = Date.now() + 2000; // 2 seconds later
  const fcp = 500;
  assert(validateTimingProof(fcp, submissionTs, tokenTs), "Valid timing should pass");
});

test("null FCP fails", () => {
  const tokenTs = Math.floor(Date.now() / 1000);
  assert(!validateTimingProof(null, Date.now() + 2000, tokenTs), "Null FCP should fail");
});

test("impossibly fast FCP fails", () => {
  const tokenTs = Math.floor(Date.now() / 1000);
  assert(!validateTimingProof(10, Date.now() + 2000, tokenTs), "FCP of 10ms should fail");
});

test("impossibly slow FCP fails", () => {
  const tokenTs = Math.floor(Date.now() / 1000);
  assert(!validateTimingProof(99999, Date.now() + 2000, tokenTs), "FCP of 99999ms should fail");
});

test("submission too fast fails", () => {
  const tokenTs = Math.floor(Date.now() / 1000);
  const submissionTs = Date.now() + 100; // only 100ms after token creation — below MIN_HUMAN_DELAY
  assert(!validateTimingProof(500, submissionTs, tokenTs), "Sub-human-delay submission should fail");
});

test("expired submission fails", () => {
  const tokenTs = Math.floor(Date.now() / 1000) - TOKEN_TTL_SECONDS - 1;
  assert(!validateTimingProof(500, Date.now(), tokenTs), "Submission of expired token should fail");
});

// ── Summary ───────────────────────────────────────────────────────────────────

console.log(`\n${"─".repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  console.log("\n⚠️  Some tests failed.");
  process.exit(1);
} else {
  console.log("\n✅ All tests passed.");
}

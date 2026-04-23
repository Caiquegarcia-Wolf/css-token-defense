/**
 * CSS Token Defense — Node.js Server Example (no framework)
 * Works with Express, Fastify, raw http module, etc.
 *
 * Shows:
 *   1. How to generate the CSS token block server-side
 *   2. How to embed it in an HTML response
 *   3. How to validate the token on the receiving endpoint
 */

const { createHmac, randomBytes, timingSafeEqual } = require("crypto");

// ─── Config (use environment variables in production) ─────────────────────────

const JWT_SECRET = process.env.JWT_SECRET || "change-this-server-secret";
const CSS_CLIENT_SECRET =
  process.env.CSS_CLIENT_SECRET || "change-this-public-secret";

const TOKEN_TTL_SECONDS = 120;
const DECOY_COUNT = 22;
const ANIMATION_NAME = "__token-gate";
const ANIMATION_MS = 350;
const FCP_MIN_MS = 80;
const FCP_MAX_MS = 12000;
const MIN_HUMAN_DELAY_MS = 400;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function hmac(secret, data) {
  return createHmac("sha256", secret).update(data).digest("hex");
}

// ─── Token generation ─────────────────────────────────────────────────────────

function generateCssToken() {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(4).toString("hex");
  const propName = `--${hmac(CSS_CLIENT_SECRET, `css-prop:${timestamp}:${nonce}`).slice(0, 8)}`;
  const signature = hmac(JWT_SECRET, `css:${timestamp}:${nonce}`).slice(0, 16);
  const token = `${timestamp}.${nonce}.${signature}`;
  return { propName, token, timestamp, nonce };
}

const DECOY_VALUES = [
  "#1A1A2E", "#E94560", "16px", "24px", "1.5", "rgba(0,0,0,0.1)",
  "transparent", "inherit", "400", "600", "none", "auto", "bold",
  "#0F3460", "0.875rem", "32px", "#533483", "normal", "initial",
  "0 2px 4px rgba(0,0,0,0.1)", "8px", "700",
];

function buildCssBlock(cssToken) {
  const { propName, token, timestamp } = cssToken;
  const lines = [];

  for (let i = 0; i < DECOY_COUNT; i++) {
    const name = `--${hmac(CSS_CLIENT_SECRET, `decoy:${timestamp}:${i}`).slice(0, 8)}`;
    lines.push(`  ${name}: ${DECOY_VALUES[i % DECOY_VALUES.length]};`);
  }

  // Insert real token at random position
  const pos = Math.floor(Math.random() * (lines.length + 1));
  lines.splice(pos, 0, `  ${propName}: ${token};`);

  const styleBlock = `:root {\n${lines.join("\n")}\n  animation: ${ANIMATION_NAME} ${ANIMATION_MS}ms ease forwards;\n}`;
  const keyframeBlock = `@keyframes ${ANIMATION_NAME} {\n  from { opacity: 0.9999; }\n  to   { opacity: 1; }\n}`;

  return { styleBlock, keyframeBlock };
}

// ─── Single-use token store ───────────────────────────────────────────────────
// Each token can only be validated once — prevents replay attacks.
// In production with multiple instances, use Redis SET + EX.

const usedTokens = new Set();

const usedTokenCleanup = setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  for (const t of usedTokens) {
    const ts = parseInt(t.split(".")[0], 10);
    if (isNaN(ts) || now - ts > TOKEN_TTL_SECONDS) usedTokens.delete(t);
  }
}, 2 * 60 * 1000);
usedTokenCleanup.unref();

// ─── Token validation ─────────────────────────────────────────────────────────

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

  // Single-use: reject if already consumed
  if (usedTokens.has(token)) return false;

  const expectedSig = hmac(JWT_SECRET, `css:${timestamp}:${nonce}`).slice(0, 16);
  try {
    const expected = Buffer.from(expectedSig, "utf8");
    const received = Buffer.from(clientSig, "utf8");
    if (expected.length !== received.length) return false;

    const valid = timingSafeEqual(expected, received);

    // Burn the token — can never be used again
    if (valid) usedTokens.add(token);

    return valid;
  } catch {
    return false;
  }
}

function validateTimingProof(fcp, submissionTs, tokenTs) {
  const ageMs = submissionTs - tokenTs * 1000;
  if (ageMs > TOKEN_TTL_SECONDS * 1000) return false;
  if (ageMs < MIN_HUMAN_DELAY_MS) return false;
  if (fcp === null || fcp === undefined) return false;
  if (fcp < FCP_MIN_MS || fcp > FCP_MAX_MS) return false;
  return true;
}

// ─── HTML page builder ────────────────────────────────────────────────────────

function buildHtmlPage(cssToken) {
  const { styleBlock, keyframeBlock } = buildCssBlock(cssToken);

  return `<!DOCTYPE html>
<html lang="pt-BR" data-ts="${cssToken.timestamp}:${cssToken.nonce}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CSS Token Defense Demo</title>
  <style>${styleBlock}</style>
  <style>${keyframeBlock}</style>
</head>
<body>
  <h1>CSS Token Defense — Demo</h1>
  <form id="order-form">
    <input type="text" name="name" placeholder="Seu nome" required>
    <button type="submit">Enviar</button>
  </form>

  <script>
    // Inline the public CSS client secret (safe — see README)
    const CSS_CLIENT_SECRET = "${CSS_CLIENT_SECRET}";
    const ANIMATION_NAME = "${ANIMATION_NAME}";

    async function hmacHex(secret, data) {
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw", enc.encode(secret),
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
      return Array.from(new Uint8Array(sig))
        .map(b => b.toString(16).padStart(2, "0")).join("");
    }

    function generateCanvasFingerprint() {
      try {
        const canvas = document.createElement("canvas");
        canvas.width = 200; canvas.height = 50;
        const ctx = canvas.getContext("2d");
        if (!ctx) return "no-ctx";
        ctx.textBaseline = "alphabetic";
        ctx.font = "14px Arial";
        ctx.fillStyle = "#f60"; ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = "#069"; ctx.fillText("CSSTokenDefense", 2, 15);
        const data = canvas.toDataURL();
        let hash = 0;
        for (let i = 0; i < data.length; i++)
          hash = (Math.imul(31, hash) + data.charCodeAt(i)) | 0;
        return Math.abs(hash).toString(16);
      } catch { return "canvas-error"; }
    }

    async function readToken() {
      const tsStr = document.documentElement.dataset.ts;
      if (!tsStr) return null;

      // Observe FCP
      let fcp = null;
      const existing = performance.getEntriesByName("first-contentful-paint");
      if (existing.length) fcp = Math.round(existing[0].startTime);
      else {
        await new Promise(resolve => {
          try {
            const obs = new PerformanceObserver(list => {
              const e = list.getEntriesByName("first-contentful-paint")[0];
              if (e) { obs.disconnect(); fcp = Math.round(e.startTime); resolve(); }
            });
            obs.observe({ entryTypes: ["paint"] });
            setTimeout(resolve, 5000);
          } catch { resolve(); }
        });
      }

      // Wait for animation gate
      await new Promise(resolve => {
        const el = document.documentElement;
        function handler(e) {
          if (e.animationName === ANIMATION_NAME) {
            el.removeEventListener("animationend", handler);
            resolve();
          }
        }
        el.addEventListener("animationend", handler);
        setTimeout(() => { el.removeEventListener("animationend", handler); resolve(); }, 2000);
      });

      const hash = await hmacHex(CSS_CLIENT_SECRET, "css-prop:" + tsStr);
      const propName = "--" + hash.slice(0, 8);
      const token = getComputedStyle(document.documentElement)
        .getPropertyValue(propName).trim();

      if (!token) return null;

      return { token, fcp, fp: generateCanvasFingerprint(), submittedAt: Date.now() };
    }

    document.getElementById("order-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = await readToken();
      if (!payload) { alert("Security check failed. Refresh and try again."); return; }

      const name = e.target.name.value;
      const res = await fetch("/api/order", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, _ta: payload.token, _fcp: payload.fcp, _fp: payload.fp, _ts: payload.submittedAt }),
      });
      const result = await res.json();
      alert(res.ok ? "Success: " + result.message : "Error: " + result.error);
    });
  </script>
</body>
</html>`;
}

// ─── Express example ──────────────────────────────────────────────────────────
// Uncomment and run: node example/server-express.js

/*
const express = require("express");
const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  const cssToken = generateCssToken();
  res.send(buildHtmlPage(cssToken));
});

app.post("/api/order", (req, res) => {
  const { _ta, _fcp, _fp, _ts, ...data } = req.body;

  if (!validateCssToken(_ta)) {
    return res.status(403).json({ error: "Invalid rendering token" });
  }

  const tokenTs = parseInt(_ta.split(".")[0], 10);
  if (!validateTimingProof(_fcp, _ts, tokenTs)) {
    return res.status(403).json({ error: "Invalid timing proof" });
  }

  res.json({ success: true, message: "Order received", data });
});

app.listen(3000, () => console.log("Demo running at http://localhost:3000"));
*/

// ─── Raw http example ─────────────────────────────────────────────────────────

const http = require("http");

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/") {
    const cssToken = generateCssToken();
    const html = buildHtmlPage(cssToken);
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
    return;
  }

  if (req.method === "POST" && req.url === "/api/order") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      let data;
      try { data = JSON.parse(body); } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON" }));
        return;
      }

      const { _ta, _fcp, _fp, _ts, ...orderData } = data;

      if (!validateCssToken(_ta)) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid rendering token" }));
        return;
      }

      const tokenTs = parseInt(_ta.split(".")[0], 10);
      if (!validateTimingProof(_fcp, _ts, tokenTs)) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid timing proof" }));
        return;
      }

      console.log("[css-token] Order accepted:", { fcp: _fcp, data: orderData });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true, message: "Order received" }));
    });
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`CSS Token Defense demo running at http://localhost:${PORT}`);
  console.log("Open the URL, submit the form, and watch the token validation in terminal.");
});

module.exports = {
  generateCssToken,
  buildCssBlock,
  validateCssToken,
  validateTimingProof,
  buildHtmlPage,
};

/**
 * CSS Token Defense — Vanilla JS Demo
 * No framework required. Drop into any HTML page.
 *
 * Usage:
 *   1. Your server embeds the CSS token block in the <style> tag (see server example)
 *   2. Include this script
 *   3. Call readCssToken() before submitting any form
 *
 * Environment variables are inlined at build time. For vanilla JS without a bundler,
 * replace CSS_CLIENT_SECRET with your actual public secret string.
 */

(function (global) {
  "use strict";

  const ANIMATION_NAME = "__token-gate";

  // ── Web Crypto HMAC ──────────────────────────────────────────────────────────

  async function hmacHex(secret, data) {
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

  // ── Canvas fingerprint ───────────────────────────────────────────────────────

  function generateCanvasFingerprint() {
    try {
      const canvas = document.createElement("canvas");
      canvas.width = 200;
      canvas.height = 50;
      const ctx = canvas.getContext("2d");
      if (!ctx) return "no-ctx";

      ctx.textBaseline = "alphabetic";
      ctx.font = "14px Arial";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("CSSTokenDefense", 2, 15);
      ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
      ctx.fillText("v3.render-proof", 4, 17);

      const data = canvas.toDataURL();
      let hash = 0;
      for (let i = 0; i < data.length; i++) {
        hash = (Math.imul(31, hash) + data.charCodeAt(i)) | 0;
      }
      return Math.abs(hash).toString(16);
    } catch (_) {
      return "canvas-error";
    }
  }

  // ── FCP observer ─────────────────────────────────────────────────────────────

  function observeFcp() {
    return new Promise((resolve) => {
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
        setTimeout(() => resolve(null), 5000);
      } catch (_) {
        resolve(null);
      }
    });
  }

  // ── Animation gate ───────────────────────────────────────────────────────────

  function waitForAnimationGate() {
    return new Promise((resolve) => {
      const el = document.documentElement;

      function handler(e) {
        if (e.animationName === ANIMATION_NAME) {
          el.removeEventListener("animationend", handler);
          resolve();
        }
      }

      el.addEventListener("animationend", handler);
      setTimeout(() => {
        el.removeEventListener("animationend", handler);
        resolve();
      }, 2000);
    });
  }

  // ── Main function ─────────────────────────────────────────────────────────────

  /**
   * Read the CSS-embedded token with full render proofs.
   *
   * @param {string} cssClientSecret - Your NEXT_PUBLIC_CSS_CLIENT_SECRET value
   * @returns {Promise<{token, fcp, fp, submittedAt} | null>}
   */
  async function readCssToken(cssClientSecret) {
    const tsStr = document.documentElement.dataset.ts;
    if (!tsStr) {
      console.warn("[css-token] Missing data-ts on <html>");
      return null;
    }

    // Start FCP observation before gate
    const fcpPromise = observeFcp();

    // Wait for animation gate
    await waitForAnimationGate();

    // Derive property name
    const hash = await hmacHex(cssClientSecret, `css-prop:${tsStr}`);
    const propName = `--${hash.slice(0, 8)}`;

    // Read token
    const token = getComputedStyle(document.documentElement)
      .getPropertyValue(propName)
      .trim();

    if (!token) {
      console.warn("[css-token] Property not found:", propName);
      return null;
    }

    // Canvas fingerprint
    const fp = generateCanvasFingerprint();
    const fcp = await fcpPromise;

    return { token, fcp, fp, submittedAt: Date.now() };
  }

  // ── Export ────────────────────────────────────────────────────────────────────

  global.CssTokenDefense = { readCssToken };
})(window);

// ── Example usage ─────────────────────────────────────────────────────────────
//
// const CSS_SECRET = "your-public-css-client-secret";
//
// document.querySelector("form").addEventListener("submit", async (e) => {
//   e.preventDefault();
//
//   const tokenPayload = await CssTokenDefense.readCssToken(CSS_SECRET);
//   if (!tokenPayload) {
//     alert("Security check failed. Please refresh and try again.");
//     return;
//   }
//
//   const formData = Object.fromEntries(new FormData(e.target));
//
//   await fetch("/api/order", {
//     method: "POST",
//     headers: { "Content-Type": "application/json" },
//     body: JSON.stringify({
//       ...formData,
//       _ta:  tokenPayload.token,
//       _fcp: tokenPayload.fcp,
//       _fp:  tokenPayload.fp,
//       _ts:  tokenPayload.submittedAt,
//     }),
//   });
// });

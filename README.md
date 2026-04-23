# CSS Token Defense

**Using the CSS rendering pipeline as a bot-proof token delivery channel.**

Born from a production incident: **70,000+ bot requests** exhausted MySQL connections across 12 instances of a Brazilian raffle platform. Standard rate limiting wasn't enough. Three versions later, the attack surface is nearly closed.

---

## The Core Idea

The security community has documented CSS as an attack vector — stealing CSRF tokens via CSS injection ([PortSwigger](https://portswigger.net/research/stealing-csrf-tokens-with-css-injection), [Pepe Vila](https://vwzq.net/slides/2019-s3_css_injection_so_hot_right_now.pdf), [Mike Gualtieri](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense)). This technique flips that direction entirely:

> **What if CSS — and the rendering pipeline itself — could prove you are real?**

Instead of hiding the token more cleverly, this system makes the token's validity conditional on observable properties of a genuine browser render cycle. A valid token proves not just that the client knows the secret, but that it **executed a real paint cycle** within a plausible time window.

---

## Evolution

Each version was driven by a concrete attack that bypassed the previous one.

| Version | Core Mechanism | Defeated By | Status |
|---------|---------------|-------------|--------|
| v1 | Fixed CSS property `--text-adjust` carries HMAC token | Regex extraction from HTML source | Superseded |
| v2 | HMAC-derived property name changes every page load | Headless browsers executing real CSS | Superseded |
| **v3** ★ | Render-time proof + environment binding + timing gates | No known automated bypass without full browser stack | **Current** |

---

## How It Works (v3)

The server generates an HMAC-derived token and embeds it in the SSR stylesheet. The property name itself is also cryptographically derived — so there is no fixed name to regex for:

```css
:root {
  --b3d91f2a: 1744624800.a3f2c1;  /* token — name changes every load */
  --f2a19c3d: #1A1A2E;             /* decoy */
  --a8d3e1f0: 16px;                /* decoy */
  /* 20+ more decoys */
  animation: __token-gate 350ms ease forwards;
}
```

Three interlocking mechanisms make the token unforgeable without a real browser:

### 1. CSS Animation Gate

The token is only readable after an `animationend` event fires — an event that requires a genuine **paint-layout-composite** cycle to have completed. A scraper that reads `getComputedStyle()` without waiting cannot construct a timing-valid token.

```javascript
document.documentElement.addEventListener('animationend', async (e) => {
  if (e.animationName !== '__token-gate') return;
  const token = await readCssToken();
  submitWithToken(token);
});
```

### 2. Paint Timing Proof

The client records the `first-contentful-paint` timestamp via the Performance Observer API and includes it in the request payload. The server validates that the reported paint time falls within an acceptable range — not impossibly fast (headless in benchmark mode), not impossibly slow (replay attack).

### 3. Render-Environment Binding

During the `animationend` callback — guaranteed to fire inside a real rendering context — the client generates a **canvas fingerprint** and incorporates it into the token payload. The server stores the fingerprint per session and flags anomalies: environment switching, known headless signatures, or absent fingerprints.

---

## Secret Architecture

Two secrets with deliberately different trust levels:

| Secret | Exposure | Purpose |
|--------|----------|---------|
| `JWT_SECRET` | Server only — never sent to browser | Signs token value. Cannot forge without this. |
| `NEXT_PUBLIC_CSS_CLIENT_SECRET` | Client JS — visible in devtools | Derives property name only. Does not enable token forgery. |

Per **Kerckhoffs's Principle**: even if an attacker reads this repository and reverse-engineers the client JS, they still cannot forge a valid token without `JWT_SECRET`. Security depends on the key, not on secrecy of the mechanism.

---

## Attack Surface

| Attack Vector | Blocked? |
|--------------|----------|
| `curl` / `axios` direct POST | ✅ |
| Fetch CSRF, skip CSS rendering | ✅ |
| Regex scraping HTML source | ✅ |
| Brute-force CSS property names | ✅ (4B+ combinations) |
| Headless browser, no animation wait | ✅ |
| Headless browser, waits for `animationend` | ✅ (FCP timing gate) |
| Replay attack with intercepted token | ✅ (TTL + env binding) |
| Fully instrumented headless + spoofed FCP | ⚠️ Partially (canvas env binding) |
| Human CAPTCHA farm | ❌ By design |

---

## Full Defense Stack

| Layer | Mechanism | Blocks |
|-------|-----------|--------|
| 1 — Rate Limiting | 5 orders/min per IP (sliding window) | Volume attacks |
| 2 — Auto-blocking | IPs exceeding thresholds blocked in memory | Persistent bots |
| 3 — CSRF Token | HMAC(timestamp), min 1s age enforcement | Simple HTTP scripts |
| **4 — CSS Token v3** ★ | Dynamic prop name + render gate + timing + env binding | HTML parsers, regex bots, headless browsers, replay attacks |
| 5 — Content Validation | Bot name patterns, BR phone/DDD validation | Targeted fake data injection |

---

## Honest Assessment

This technique is a **cost-raising defense**, not an impenetrable barrier. The goal is making automated attacks economically unviable for mass bots — not theoretically impossible for every adversary.

**What it does NOT defend against:**

- Fully instrumented headless browsers that correctly simulate the animation lifecycle AND spoof FCP timing
- Human CAPTCHA farms — a human operating a real browser passes every layer by definition
- Targeted, well-resourced adversaries with custom browser automation tooling

---

## Prior Art

All prior CSS security research found treats CSS as an **attack vector**. No prior documentation found of CSS custom properties used as a **defensive** token delivery and render-proof channel.

If you know of prior work in this direction, please open an issue — genuinely interested.

**References:**

- [PortSwigger Research: Stealing CSRF tokens with CSS injection](https://portswigger.net/research/stealing-csrf-tokens-with-css-injection)
- [Mike Gualtieri: "Stealing Data with CSS" (2018)](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense)
- [Pepe Vila: "CSS Injection Primitives" (2019)](https://vwzq.net/slides/2019-s3_css_injection_so_hot_right_now.pdf)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

## Demo

Live demo: **[css-defense-test.onrender.com](https://css-defense-test.onrender.com)**

Fill in the form and submit — the request will pass. Try submitting again **without refreshing**: you'll get `Error: Invalid rendering token`. This is intentional — each token is **single-use** and burned on first validation.

Refresh the page to get a new token. In production, a successful submission redirects the user to a confirmation page, which naturally generates a fresh token — making the single-use behavior completely transparent to real users.

---

The full technical paper (including all three versions, architecture diagrams, and implementation details) is available in [`css-token-defense-paper.docx`](css-token-defense-paper.docx).

---

## Context

| Field | Value |
|-------|-------|
| v1 first implemented | April 13, 2026 |
| v2 (dynamic property names) | April 14, 2026 |
| v3 (render-proof edition) | April 2026 |
| Context | Production anti-bot defense, Brazilian raffle platform |

> *"The security community taught us that CSS can steal tokens. We asked: what if CSS — and the rendering pipeline itself — could prove you are real?"*

---

## License

[MIT](LICENSE)

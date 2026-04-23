/**
 * CSS Token Defense — Root Layout
 * Next.js App Router (TypeScript)
 *
 * This layout demonstrates SSR injection of the CSS token block.
 * The token is generated fresh on every request (server component).
 *
 * Key points:
 *   - data-ts on <html> carries "timestamp:nonce" so the client can derive the prop name
 *   - Two <style> tags: one for the token + decoys, one for the keyframe
 *     (split to reduce the chance of inline detection by naive scanners)
 *   - No JavaScript is needed to inject the token — it's pure CSS/SSR
 */

import type { Metadata } from "next";
import { generateCssToken, buildCssTokenBlock } from "@/lib/css-token";

export const metadata: Metadata = {
  title: "CSS Token Defense — Demo",
  description: "Bot mitigation via CSS rendering pipeline proof",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Generated fresh per request on the server
  const cssToken = generateCssToken();
  const { styleBlock, keyframeBlock } = buildCssTokenBlock(cssToken);

  return (
    <html lang="pt-BR" data-ts={`${cssToken.timestamp}:${cssToken.nonce}`}>
      <head>
        {/* Token block: real token buried among decoys, animation gate attached */}
        <style
          dangerouslySetInnerHTML={{ __html: styleBlock }}
          data-purpose="token-delivery"
        />
        {/* Keyframe block: separated to reduce coupling */}
        <style
          dangerouslySetInnerHTML={{ __html: keyframeBlock }}
          data-purpose="token-gate"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}

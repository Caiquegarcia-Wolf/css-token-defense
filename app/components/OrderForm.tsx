"use client";

/**
 * CSS Token Defense — Example Form Component
 *
 * Demonstrates how to use readCssTokenV3() in a real form.
 * The token is read AFTER the animation gate fires (proving render occurred),
 * then submitted alongside the form data.
 *
 * Key UX note: the animation gate takes ~350ms. For most forms this is
 * imperceptible — the user is still filling in fields during this window.
 * For instant-submit flows (e.g. one-click buy), add a brief loading state.
 */

import { useState } from "react";
import { withCssToken } from "@/lib/css-token-client";

interface FormData {
  name: string;
  phone: string;
  quantity: number;
}

export default function OrderForm() {
  const [formData, setFormData] = useState<FormData>({
    name: "",
    phone: "",
    quantity: 1,
  });
  const [status, setStatus] = useState<
    "idle" | "loading" | "success" | "error"
  >("idle");
  const [message, setMessage] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus("loading");
    setMessage("");

    try {
      // readCssTokenV3() waits for the animation gate internally.
      // withCssToken() merges the token payload into your form data.
      const payload = await withCssToken({
        ...formData,
        _csrf: getCsrfToken(), // your CSRF token implementation
      });

      const response = await fetch("/api/order", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const result = await response.json();

      if (response.ok) {
        setStatus("success");
        setMessage("Pedido realizado com sucesso!");
      } else {
        setStatus("error");
        setMessage(result.error ?? "Erro ao processar pedido");
      }
    } catch (err) {
      setStatus("error");
      setMessage(err instanceof Error ? err.message : "Erro desconhecido");
    }
  };

  return (
    <div className="order-form-container">
      <h2>Fazer Pedido</h2>

      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="name">Nome</label>
          <input
            id="name"
            type="text"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            required
            disabled={status === "loading"}
          />
        </div>

        <div className="field">
          <label htmlFor="phone">Telefone</label>
          <input
            id="phone"
            type="tel"
            value={formData.phone}
            onChange={(e) =>
              setFormData({ ...formData, phone: e.target.value })
            }
            placeholder="(11) 99999-9999"
            required
            disabled={status === "loading"}
          />
        </div>

        <div className="field">
          <label htmlFor="quantity">Quantidade</label>
          <input
            id="quantity"
            type="number"
            min={1}
            max={10}
            value={formData.quantity}
            onChange={(e) =>
              setFormData({ ...formData, quantity: parseInt(e.target.value) })
            }
            required
            disabled={status === "loading"}
          />
        </div>

        <button type="submit" disabled={status === "loading"}>
          {status === "loading" ? "Processando..." : "Enviar Pedido"}
        </button>
      </form>

      {message && (
        <p className={`status-message status-${status}`}>{message}</p>
      )}

      {/* Debug info — remove in production */}
      {process.env.NODE_ENV === "development" && (
        <details>
          <summary>Debug: Token Info</summary>
          <p>
            Token is embedded in CSS and read after the animation gate fires.
            Check the &lt;style&gt; tags in DevTools to see the token among decoys.
          </p>
        </details>
      )}
    </div>
  );
}

// ─── CSRF token helper ────────────────────────────────────────────────────────
// In production, generate this server-side and pass via props or cookie.
// This is a minimal client-side stub for demonstration.

function getCsrfToken(): string {
  // In a real app:
  //   - Generate CSRF on the server during SSR
  //   - Pass as a prop or meta tag
  //   - Read it here
  const meta = document.querySelector<HTMLMetaElement>('meta[name="csrf-token"]');
  return meta?.content ?? "";
}

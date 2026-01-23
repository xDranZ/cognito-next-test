"use client";

import { useEffect, useRef, useState } from "react";

type AuthState = "idle" | "loading" | "error";

function base64UrlEncode(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function createCodeChallenge(verifier: string) {
  const data = new TextEncoder().encode(verifier);
  const digest = await window.crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(digest);
}

function createCodeVerifier() {
  const bytes = new Uint8Array(32);
  window.crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes.buffer);
}

function createRandomValue() {
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes.buffer);
}

function normalizeCognitoDomain(domain: string | undefined) {
  if (!domain) return "";
  return domain.startsWith("http://") || domain.startsWith("https://")
    ? domain
    : `https://${domain}`;
}

export default function Home() {
  const [status, setStatus] = useState<AuthState>("idle");
  const [error, setError] = useState<string | null>(null);
  const handledRef = useRef(false);

  const login = async () => {
    const codeVerifier = createCodeVerifier();
    const codeChallenge = await createCodeChallenge(codeVerifier);
    const state = createRandomValue();
    const nonce = createRandomValue();
    window.sessionStorage.setItem("cognito_pkce_verifier", codeVerifier);
    window.sessionStorage.setItem("cognito_oauth_state", state);
    window.sessionStorage.setItem("cognito_oauth_nonce", nonce);
    const redirectUri = encodeURIComponent(
      process.env.NEXT_PUBLIC_COGNITO_REDIRECT_URI ?? "",
    );
    const scope = encodeURIComponent(
      process.env.NEXT_PUBLIC_COGNITO_SCOPES ?? "openid email",
    );
    const domain = normalizeCognitoDomain(
      process.env.NEXT_PUBLIC_COGNITO_DOMAIN,
    );
    const url =
      `${domain}/oauth2/authorize` +
      `?response_type=code` +
      `&client_id=${process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID}` +
      `&redirect_uri=${redirectUri}` +
      `&scope=${scope}` +
      `&state=${encodeURIComponent(state)}` +
      `&nonce=${encodeURIComponent(nonce)}` +
      `&code_challenge_method=S256` +
      `&code_challenge=${encodeURIComponent(codeChallenge)}`;

    window.location.href = url;
  };

  useEffect(() => {
    if (handledRef.current) return;
    handledRef.current = true;

    const params = new URLSearchParams(window.location.search);
    const errorParam = params.get("error");
    const errorDescription = params.get("error_description");
    if (errorParam) {
      setStatus("error");
      setError(
        errorDescription ? `${errorParam}: ${errorDescription}` : errorParam,
      );
      return;
    }

    const code = params.get("code");
    if (!code) return;

    const returnedState = params.get("state");
    const expectedState = window.sessionStorage.getItem("cognito_oauth_state");
    if (!returnedState || !expectedState || returnedState !== expectedState) {
      setStatus("error");
      setError("invalid_state");
      return;
    }

    const codeVerifier = window.sessionStorage.getItem("cognito_pkce_verifier");
    if (!codeVerifier) {
      setStatus("error");
      setError("missing_code_verifier");
      return;
    }

    const nonce = window.sessionStorage.getItem("cognito_oauth_nonce");
    if (!nonce) {
      setStatus("error");
      setError("missing_nonce");
      return;
    }

    setStatus("loading");
    fetch("/api/cognito/callback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, codeVerifier, nonce }),
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data?.error ?? "token_exchange_failed");
        }
        window.sessionStorage.removeItem("cognito_pkce_verifier");
        window.sessionStorage.removeItem("cognito_oauth_state");
        window.sessionStorage.removeItem("cognito_oauth_nonce");
        window.location.replace("/protected");
      })
      .catch((err: Error) => {
        setStatus("error");
        setError(err.message);
      });
  }, []);

  return (
    <main style={{ padding: 40 }}>
      {status === "loading" && <p>Cargando sesion...</p>}
      {status === "error" && <p style={{ color: "crimson" }}>Error: {error}</p>}
      {status !== "loading" && (
        <button
          onClick={login}
          style={{
            marginTop: 20,
            padding: "10px 20px",
            fontSize: 16,
            cursor: "pointer",
          }}
        >
          Login
        </button>
      )}
    </main>
  );
}

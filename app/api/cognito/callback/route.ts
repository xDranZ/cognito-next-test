import { NextResponse } from "next/server";

function normalizeCognitoDomain(domain: string | undefined) {
  if (!domain) return "";
  return domain.startsWith("http://") || domain.startsWith("https://")
    ? domain
    : `https://${domain}`;
}

function decodeJwtPayload(token: string) {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const json = Buffer.from(payload, "base64").toString("utf8");
  return JSON.parse(json);
}

function getMaxAgeSeconds(token: string | null) {
  if (!token) return 3600;
  const payload = decodeJwtPayload(token) as { exp?: number } | null;
  if (!payload?.exp) return 3600;
  const nowSeconds = Math.floor(Date.now() / 1000);
  const maxAge = payload.exp - nowSeconds;
  return maxAge > 0 ? maxAge : 0;
}

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const codeVerifier = searchParams.get("code_verifier");
  const nonce = searchParams.get("nonce");
  if (!code) {
    return NextResponse.json({ error: "missing_code" }, { status: 400 });
  }
  return exchangeCodeForTokens(code, codeVerifier, nonce);
}

export async function POST(req: Request) {
  let payload: { code?: string; codeVerifier?: string; nonce?: string };
  try {
    payload = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid_json" }, { status: 400 });
  }

  const code = payload.code;
  const codeVerifier = payload.codeVerifier ?? null;
  const nonce = payload.nonce;
  if (!code) {
    return NextResponse.json({ error: "missing_code" }, { status: 400 });
  }
  return exchangeCodeForTokens(code, codeVerifier, nonce);
}

async function exchangeCodeForTokens(
  code: string,
  codeVerifier: string | null,
  nonce?: string | null,
) {
  if (!codeVerifier) {
    return NextResponse.json(
      { error: "missing_code_verifier" },
      { status: 400 },
    );
  }

  const domain = normalizeCognitoDomain(process.env.NEXT_PUBLIC_COGNITO_DOMAIN);
  const clientId = process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID;
  const redirectUri = process.env.NEXT_PUBLIC_COGNITO_REDIRECT_URI;
  if (!domain || !clientId || !redirectUri) {
    return NextResponse.json({ error: "missing_env" }, { status: 500 });
  }

  const tokenUrl = `${domain}/oauth2/token`;
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  };

  const clientSecret = process.env.COGNITO_CLIENT_SECRET;
  if (clientSecret) {
    const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
    headers.Authorization = `Basic ${basic}`;
  }

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers,
    body,
  });

  const text = await response.text();
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(text);
  } catch {
    return NextResponse.json(
      { error: "invalid_token_response", raw: text },
      { status: 502 }
    );
  }

  if (!response.ok) {
    return NextResponse.json(
      { error: "token_exchange_failed", details: data },
      { status: response.status }
    );
  }

  const idToken = typeof data.id_token === "string" ? data.id_token : null;
  const profile = idToken ? decodeJwtPayload(idToken) : null;
  if (!nonce || (profile as { nonce?: string } | null)?.nonce !== nonce) {
    return NextResponse.json({ error: "invalid_nonce" }, { status: 400 });
  }

  const maxAge = getMaxAgeSeconds(idToken);
  const res = NextResponse.json({ ok: true, profile });
  res.cookies.set({
    name: "cognito_id_token",
    value: idToken ?? "",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge,
  });
  return res;
}

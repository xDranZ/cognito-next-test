import { NextResponse } from "next/server";

function normalizeCognitoDomain(domain: string | undefined) {
  if (!domain) return "";
  return domain.startsWith("http://") || domain.startsWith("https://")
    ? domain
    : `https://${domain}`;
}

export async function GET() {
  const domain = normalizeCognitoDomain(process.env.NEXT_PUBLIC_COGNITO_DOMAIN);
  const clientId = process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID;
  const logoutUri =
    process.env.NEXT_PUBLIC_COGNITO_LOGOUT_URI ??
    process.env.NEXT_PUBLIC_COGNITO_REDIRECT_URI ??
    "";

  if (!domain || !clientId || !logoutUri) {
    return NextResponse.json({ error: "missing_env" }, { status: 500 });
  }

  const url =
    `${domain}/logout` +
    `?client_id=${clientId}` +
    `&logout_uri=${encodeURIComponent(logoutUri)}`;

  const res = NextResponse.redirect(url);
  res.cookies.set({
    name: "cognito_id_token",
    value: "",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
  return res;
}

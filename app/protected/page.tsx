import { cookies } from "next/headers";
import { redirect } from "next/navigation";

type Profile = {
  email?: string;
  email_address?: string;
  "cognito:username"?: string;
};

function decodeJwtPayload(token: string) {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const json = Buffer.from(payload, "base64").toString("utf8");
  return JSON.parse(json) as Profile;
}

export default async function ProtectedPage() {
  const cookieStore = await cookies();
  const token = cookieStore.get("cognito_id_token")?.value;
  if (!token) redirect("/");

  let profile: Profile | null = null;
  try {
    profile = decodeJwtPayload(token);
  } catch {
    redirect("/");
  }

  const email =
    profile?.email ??
    profile?.email_address ??
    profile?.["cognito:username"] ??
    null;

  if (!email) redirect("/");

  return (
    <main style={{ padding: 40 }}>
      <h1>Hola {email}!</h1>
      <p>Esta vista esta protegida.</p>
      <a
        href="/api/cognito/logout"
        style={{
          display: "inline-block",
          marginTop: 12,
          padding: "10px 20px",
          fontSize: 16,
          cursor: "pointer",
          border: "1px solid #ccc",
          borderRadius: 6,
        }}
      >
        Cerrar sesion
      </a>
    </main>
  );
}

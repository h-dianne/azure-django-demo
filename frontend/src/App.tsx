import { useEffect, useState } from "react";
import { login, logout, getUser, getAccessTokenSync } from "./auth/oidc";

type Claims = {
  preferred_username?: string;
  email?: string;
  sub?: string;
};

export default function App() {
  const [isAuth, setIsAuth] = useState(false);
  const [claims, setClaims] = useState<Claims | null>(null);

  useEffect(() => {
    getUser().then((u) => {
      if (u) {
        setIsAuth(true);
        // ID token claims live on u.profile
        setClaims(u.profile as Claims);
      }
    });
  }, []);

  async function callAPI() {
  const token = getAccessTokenSync();
  if (!token) {
    alert("No access token – please login first.");
    return;
  }

  try {
    const res = await fetch("http://localhost:8000/api/hello", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const data = await res.json();
    alert(`${res.status}: ${JSON.stringify(data)}`);
  } catch (err) {
    console.error(err);
    alert("Request failed – check console for details.");
  }
}


  return (
    <div style={{ fontFamily: "system-ui, sans-serif", padding: 24 }}>
      <h1>Keycloak × SPA (PKCE) — Minimal Demo</h1>

      {!isAuth ? (
        <button onClick={login} style={{ padding: "8px 14px", marginTop: 12 }}>
          Login
        </button>
      ) : (
        <>
          <div style={{ marginTop: 12 }}>
            <div>Signed in as: <b>{claims?.preferred_username ?? claims?.email ?? claims?.sub}</b></div>
            <div style={{ marginTop: 8 }}>
              <small>Access token present: {getAccessTokenSync() ? "yes" : "no"}</small>
            </div>
          </div>
          <button onClick={logout} style={{ padding: "8px 14px", marginTop: 12 }}>
            Logout
          </button>
          <button onClick={callAPI} style={{ padding: "8px 14px", marginTop: 12, marginLeft: 8 }}>
            Call Backend API
          </button>
        </>
      )}

      <hr style={{ margin: "24px 0" }} />
      <p>
        This simple demo only shows login/logout and who you are (no backend). You can copy the access token from sessionStorage for dev checks.
      </p>
    </div>
  );
}

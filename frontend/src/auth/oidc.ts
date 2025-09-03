import { UserManager, WebStorageStateStore, Log, User } from "oidc-client-ts";

const {
  VITE_OIDC_ISSUER,
  VITE_OIDC_CLIENT_ID,
  VITE_OIDC_REDIRECT_URI,
  VITE_OIDC_SCOPES,
} = import.meta.env;

Log.setLogger(console);
Log.setLevel(Log.INFO); // turn to ERROR if too noisy

export const userManager = new UserManager({
  authority: VITE_OIDC_ISSUER,
  client_id: VITE_OIDC_CLIENT_ID,
  redirect_uri: VITE_OIDC_REDIRECT_URI,
  response_type: "code",
  scope: VITE_OIDC_SCOPES,
  loadUserInfo: false, // keep it simple: rely on ID token claims
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
});

export async function login() {
  await userManager.signinRedirect();
}

export async function handleCallback() {
  const user = await userManager.signinRedirectCallback();
  return user;
}

export async function logout() {
  await userManager.signoutRedirect();
}

export async function getUser(): Promise<User | null> {
  try {
    return await userManager.getUser();
  } catch {
    return null;
  }
}

export function getAccessTokenSync(): string | null {
  const raw = sessionStorage.getItem(
    `oidc.user:${import.meta.env.VITE_OIDC_ISSUER}:${import.meta.env.VITE_OIDC_CLIENT_ID}`
  );
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    return parsed?.access_token ?? null;
  } catch {
    return null;
  }
}


const TOKEN_KEY = "policyguard_token";
const USER_KEY = "policyguard_user";

export type CurrentUser = {
  id: number;
  email: string;
  role: string;
};

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function getCurrentUser(): CurrentUser | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(USER_KEY);
  return raw ? (JSON.parse(raw) as CurrentUser) : null;
}

export function saveSession(token: string, user: CurrentUser) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

/**
 * fetch() wrapper that automatically attaches the JWT, if present.
 * Use this instead of raw fetch() for any call to a protected route.
 */
export async function authFetch(url: string, options: RequestInit = {}) {
  const token = getToken();
  const headers = new Headers(options.headers);

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  return fetch(url, { ...options, headers });
}
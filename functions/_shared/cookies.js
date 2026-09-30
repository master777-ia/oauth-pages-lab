export const OAUTH_TX_COOKIE = "__Host-oauth-tx";
export const SESSION_COOKIE = "__Host-session";

export function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie");

  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const trimmed = cookie.trim();
    const separatorIndex = trimmed.indexOf("=");

    if (separatorIndex === -1) {
      continue;
    }

    const cookieName = trimmed.slice(0, separatorIndex);
    const cookieValue = trimmed.slice(separatorIndex + 1);

    if (cookieName === name) {
      return cookieValue;
    }
  }

  return null;
}

export function createOAuthTransactionCookie(value) {
  return `${OAUTH_TX_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
}

export function clearOAuthTransactionCookie() {
  return `${OAUTH_TX_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function createSessionCookie(value) {
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

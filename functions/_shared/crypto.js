const encoder = new TextEncoder();

export function base64UrlEncode(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function base64UrlDecode(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(normalized + padding);

  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function randomBase64Url(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);

  return base64UrlEncode(bytes);
}

export async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  return base64UrlEncode(new Uint8Array(digest));
}

export async function createCodeChallenge(codeVerifier) {
  return sha256Base64Url(codeVerifier);
}

export function timingSafeEqual(first, second) {
  if (
    typeof first !== "string" ||
    typeof second !== "string" ||
    first.length !== second.length
  ) {
    return false;
  }

  const a = encoder.encode(first);
  const b = encoder.encode(second);

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }

  return difference === 0;
}

export function utf8Bytes(value) {
  return encoder.encode(value);
}

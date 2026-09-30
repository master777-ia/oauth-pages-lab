import { base64UrlDecode, utf8Bytes } from "./crypto.js";

const decoder = new TextDecoder();

function decodeJsonPart(value) {
  try {
    const bytes = base64UrlDecode(value);
    return JSON.parse(decoder.decode(bytes));
  } catch {
    throw new Error("Invalid JWT encoding.");
  }
}

function audienceMatches(aud, expectedAudience) {
  if (typeof aud === "string") {
    return aud === expectedAudience;
  }

  if (Array.isArray(aud)) {
    return aud.includes(expectedAudience);
  }

  return false;
}

export async function validateGoogleIdToken({
  idToken,
  expectedIssuer,
  expectedAudience,
  expectedNonce,
  discoveryUrl,
}) {
  if (!idToken) {
    throw new Error("Google id_token is missing.");
  }

  const parts = idToken.split(".");

  if (parts.length !== 3) {
    throw new Error("Invalid JWT format.");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  const header = decodeJsonPart(encodedHeader);
  const payload = decodeJsonPart(encodedPayload);

  if (header.alg !== "RS256") {
    throw new Error("Unexpected JWT algorithm.");
  }

  if (!header.kid) {
    throw new Error("JWT key identifier is missing.");
  }

  const discoveryResponse = await fetch(discoveryUrl);

  if (!discoveryResponse.ok) {
    throw new Error("Unable to load Google OIDC discovery document.");
  }

  const discovery = await discoveryResponse.json();

  if (
    discovery.issuer !== expectedIssuer ||
    typeof discovery.jwks_uri !== "string"
  ) {
    throw new Error("Unexpected Google OIDC discovery document.");
  }

  const jwksResponse = await fetch(discovery.jwks_uri);

  if (!jwksResponse.ok) {
    throw new Error("Unable to load Google JWKS.");
  }

  const jwks = await jwksResponse.json();

  if (!Array.isArray(jwks.keys)) {
    throw new Error("Invalid Google JWKS.");
  }

  const jwk = jwks.keys.find((key) => key.kid === header.kid);

  if (!jwk) {
    throw new Error("Google signing key was not found.");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["verify"]
  );

  const signature = base64UrlDecode(encodedSignature);
  const signedData = utf8Bytes(
    `${encodedHeader}.${encodedPayload}`
  );

  const signatureIsValid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signature,
    signedData
  );

  if (!signatureIsValid) {
    throw new Error("Invalid Google token signature.");
  }

  const now = Math.floor(Date.now() / 1000);
  const clockSkew = 60;

  if (payload.iss !== expectedIssuer) {
    throw new Error("Invalid Google issuer.");
  }

  if (!audienceMatches(payload.aud, expectedAudience)) {
    throw new Error("Invalid Google audience.");
  }

  if (
    typeof payload.exp !== "number" ||
    payload.exp <= now - clockSkew
  ) {
    throw new Error("Google token is expired.");
  }

  if (
    typeof payload.iat !== "number" ||
    payload.iat > now + clockSkew
  ) {
    throw new Error("Invalid Google token issue time.");
  }

  if (
    !expectedNonce ||
    payload.nonce !== expectedNonce
  ) {
    throw new Error("Invalid Google nonce.");
  }

  if (
    typeof payload.sub !== "string" ||
    payload.sub.length === 0
  ) {
    throw new Error("Google subject is missing.");
  }

  return {
    issuer: payload.iss,
    subject: payload.sub,
    email:
      typeof payload.email === "string"
        ? payload.email
        : null,
    displayName:
      typeof payload.name === "string"
        ? payload.name
        : null,
  };
}

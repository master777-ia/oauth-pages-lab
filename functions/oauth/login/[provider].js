import {
  randomBase64Url,
  sha256Base64Url,
  timingSafeEqual,
} from "../../_shared/crypto.js";

import {
  OAUTH_TX_COOKIE,
  createSessionCookie,
  clearOAuthTransactionCookie,
  getCookie,
} from "../../_shared/cookies.js";

import {
  getProvider,
  isSupportedProvider,
} from "../../_shared/providers.js";

import {
  validateGoogleIdToken,
} from "../../_shared/oidc.js";

function noStoreHeaders(extra = {}) {
  return {
    "Cache-Control": "no-store",
    ...extra,
  };
}

function errorResponse(message, status = 400) {
  return new Response(message, {
    status,
    headers: noStoreHeaders({
      "Set-Cookie": clearOAuthTransactionCookie(),
    }),
  });
}

async function exchangeCode({
  provider,
  code,
  codeVerifier,
}) {
  const body = new URLSearchParams();

  body.set("client_id", provider.clientId);
  body.set("client_secret", provider.clientSecret);
  body.set("code", code);
  body.set("redirect_uri", provider.redirectUri);
  body.set("code_verifier", codeVerifier);
  body.set("grant_type", "authorization_code");

  const response = await fetch(provider.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body,
  });

  if (!response.ok) {
    throw new Error("Token exchange failed.");
  }

  return response.json();
}

async function resolveGoogleIdentity({
  provider,
  tokenResponse,
  nonce,
}) {
  return validateGoogleIdToken({
    idToken: tokenResponse.id_token,
    expectedIssuer: provider.issuer,
    expectedAudience: provider.clientId,
    expectedNonce: nonce,
    discoveryUrl: provider.discoveryUrl,
  });
}

async function resolveGitHubIdentity({
  provider,
  tokenResponse,
}) {
  const accessToken = tokenResponse.access_token;

  if (
    typeof accessToken !== "string" ||
    accessToken.length === 0
  ) {
    throw new Error("GitHub access token missing.");
  }

  if (
    typeof tokenResponse.token_type !== "string" ||
    tokenResponse.token_type.toLowerCase() !== "bearer"
  ) {
    throw new Error("Unexpected GitHub token type.");
  }

  const profileResponse = await fetch(
    provider.userUrl,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "oauth-pages-lab",
      },
    }
  );

  if (!profileResponse.ok) {
    throw new Error("Unable to load GitHub profile.");
  }

  const profile = await profileResponse.json();

  if (!Number.isInteger(profile.id)) {
    throw new Error("Invalid GitHub user id.");
  }

  const basicCredentials = btoa(
    `${provider.clientId}:${provider.clientSecret}`
  );

  const revokeResponse = await fetch(
    `https://api.github.com/applications/${provider.clientId}/grant`,
    {
      method: "DELETE",
      headers: {
        Authorization: `Basic ${basicCredentials}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "Content-Type": "application/json",
        "User-Agent": "oauth-pages-lab",
      },
      body: JSON.stringify({
        access_token: accessToken,
      }),
    }
  );

  if (revokeResponse.status !== 204) {
    throw new Error("GitHub authorization revocation failed.");
  }

  return {
    issuer: provider.issuer,
    subject: String(profile.id),
    email:
      typeof profile.email === "string"
        ? profile.email
        : null,
    displayName:
      typeof profile.name === "string" &&
      profile.name.length > 0
        ? profile.name
        : typeof profile.login === "string"
          ? profile.login
          : null,
  };
}

export async function onRequestGet(context) {
  const providerName = context.params.provider;

  if (!isSupportedProvider(providerName)) {
    return new Response("Not found", {
      status: 404,
      headers: noStoreHeaders(),
    });
  }

  let provider;

  try {
    provider = getProvider(
      providerName,
      context.env
    );
  } catch {
    return errorResponse(
      "OAuth configuration unavailable.",
      500
    );
  }

  const requestUrl = new URL(
    context.request.url
  );

  if (requestUrl.searchParams.has("error")) {
    return errorResponse(
      "Authorization was rejected."
    );
  }

  const code =
    requestUrl.searchParams.get("code");

  const state =
    requestUrl.searchParams.get("state");

  if (!code || !state) {
    return errorResponse(
      "Missing authorization response."
    );
  }

  const transactionCookie = getCookie(
    context.request,
    OAUTH_TX_COOKIE
  );

  if (!transactionCookie) {
    return errorResponse(
      "OAuth transaction cookie missing."
    );
  }

  const transactionHash =
    await sha256Base64Url(
      transactionCookie
    );

  const now = Math.floor(
    Date.now() / 1000
  );

  const transaction = await context.env.DB
    .prepare(
      `
      SELECT
        id_hash,
        provider,
        state_hash,
        nonce,
        code_verifier,
        expires_at
      FROM oauth_transactions
      WHERE id_hash = ?
        AND expires_at > ?
      LIMIT 1
      `
    )
    .bind(transactionHash, now)
    .first();

  if (!transaction) {
    return errorResponse(
      "OAuth transaction invalid or expired."
    );
  }

  if (transaction.provider !== providerName) {
    return errorResponse(
      "OAuth provider mismatch."
    );
  }

  const receivedStateHash =
    await sha256Base64Url(state);

  if (
    !timingSafeEqual(
      transaction.state_hash,
      receivedStateHash
    )
  ) {
    return errorResponse(
      "Invalid OAuth state."
    );
  }

  await context.env.DB
    .prepare(
      `
      DELETE FROM oauth_transactions
      WHERE id_hash = ?
      `
    )
    .bind(transactionHash)
    .run();

  let identity;

  try {
    const tokenResponse =
      await exchangeCode({
        provider,
        code,
        codeVerifier:
          transaction.code_verifier,
      });

    if (providerName === "google") {
      identity =
        await resolveGoogleIdentity({
          provider,
          tokenResponse,
          nonce: transaction.nonce,
        });
    } else {
      identity =
        await resolveGitHubIdentity({
          provider,
          tokenResponse,
        });
    }
  } catch {
    return errorResponse(
      "Identity validation failed."
    );
  }

  const sessionId =
    randomBase64Url(32);

  const sessionHash =
    await sha256Base64Url(
      sessionId
    );

  const createdAt =
    Math.floor(Date.now() / 1000);

  const expiresAt =
    createdAt + 28800;

  await context.env.DB
    .prepare(
      `
      INSERT INTO sessions (
        id_hash,
        issuer,
        subject,
        email,
        display_name,
        expires_at,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
      `
    )
    .bind(
      sessionHash,
      identity.issuer,
      identity.subject,
      identity.email,
      identity.displayName,
      expiresAt,
      createdAt
    )
    .run();

  const headers = new Headers();

  headers.set(
    "Location",
    context.env.PUBLIC_BASE_URL
  );

  headers.set(
    "Cache-Control",
    "no-store"
  );

  headers.append(
    "Set-Cookie",
    clearOAuthTransactionCookie()
  );

  headers.append(
    "Set-Cookie",
    createSessionCookie(sessionId)
  );

  return new Response(null, {
    status: 302,
    headers,
  });
}

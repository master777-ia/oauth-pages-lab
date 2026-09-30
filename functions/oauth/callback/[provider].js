import {
  randomBase64Url,
  sha256Base64Url,
  createCodeChallenge,
} from "../../_shared/crypto.js";

import {
  createOAuthTransactionCookie,
} from "../../_shared/cookies.js";

import {
  getProvider,
  isSupportedProvider,
} from "../../_shared/providers.js";

function noStoreHeaders(extra = {}) {
  return {
    "Cache-Control": "no-store",
    ...extra,
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
    provider = getProvider(providerName, context.env);
  } catch {
    return new Response("OAuth configuration unavailable.", {
      status: 500,
      headers: noStoreHeaders(),
    });
  }

  const transactionId = randomBase64Url(32);
  const state = randomBase64Url(32);
  const codeVerifier = randomBase64Url(32);

  const transactionHash =
    await sha256Base64Url(transactionId);

  const stateHash =
    await sha256Base64Url(state);

  const codeChallenge =
    await createCodeChallenge(codeVerifier);

  const nonce =
    provider.useNonce
      ? randomBase64Url(32)
      : null;

  const expiresAt =
    Math.floor(Date.now() / 1000) + 600;

  await context.env.DB.prepare(
    `
    INSERT INTO oauth_transactions (
      id_hash,
      provider,
      state_hash,
      nonce,
      code_verifier,
      expires_at
    )
    VALUES (?, ?, ?, ?, ?, ?)
    `
  )
    .bind(
      transactionHash,
      providerName,
      stateHash,
      nonce,
      codeVerifier,
      expiresAt
    )
    .run();

  const authorizationUrl =
    new URL(provider.authorizeUrl);

  authorizationUrl.searchParams.set(
    "client_id",
    provider.clientId
  );

  authorizationUrl.searchParams.set(
    "redirect_uri",
    provider.redirectUri
  );

  authorizationUrl.searchParams.set(
    "response_type",
    "code"
  );

  authorizationUrl.searchParams.set(
    "state",
    state
  );

  authorizationUrl.searchParams.set(
    "code_challenge",
    codeChallenge
  );

  authorizationUrl.searchParams.set(
    "code_challenge_method",
    "S256"
  );

  if (providerName === "google") {
    authorizationUrl.searchParams.set(
      "scope",
      "openid email profile"
    );

    authorizationUrl.searchParams.set(
      "nonce",
      nonce
    );
  }

  return new Response(null, {
    status: 302,
    headers: noStoreHeaders({
      Location: authorizationUrl.toString(),
      "Set-Cookie":
        createOAuthTransactionCookie(
          transactionId
        ),
    }),
  });
}

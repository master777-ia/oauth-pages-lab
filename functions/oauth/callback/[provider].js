import {
  randomBase64Url,
  sha256Base64Url,
  timingSafeEqual,
} from "../../_shared/crypto.js";

import {
  OAUTH_TX_COOKIE,
  getCookie,
  clearOAuthTransactionCookie,
  createSessionCookie,
} from "../../_shared/cookies.js";

import {
  getProvider,
  isSupportedProvider,
} from "../../_shared/providers.js";

import {
  validateGoogleIdToken,
} from "../../_shared/oidc.js";

function headers(extra = {}) {
  return {
    "Cache-Control": "no-store",
    ...extra,
  };
}

function fail(message, status = 400) {
  return new Response(message, {
    status,
    headers: headers({
      "Set-Cookie": clearOAuthTransactionCookie(),
    }),
  });
}

export async function onRequestGet(context) {
  const providerName = context.params.provider;

  if (!isSupportedProvider(providerName)) {
    return fail("Unsupported OAuth provider.", 404);
  }

  const url = new URL(context.request.url);

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const oauthError = url.searchParams.get("error");

  if (oauthError) {
    return fail(`OAuth error: ${oauthError}`);
  }

  if (!code || !state) {
    return fail("Missing authorization response.");
  }

  const transactionId = getCookie(
    context.request,
    OAUTH_TX_COOKIE
  );

  if (!transactionId) {
    return fail("OAuth transaction cookie missing.");
  }

  const transactionHash =
    await sha256Base64Url(transactionId);

  const now = Math.floor(Date.now() / 1000);

  const transaction = await context.env.DB
    .prepare(`
      SELECT
        provider,
        state_hash,
        nonce,
        code_verifier,
        expires_at
      FROM oauth_transactions
      WHERE id_hash = ?
        AND provider = ?
        AND expires_at > ?
      LIMIT 1
    `)
    .bind(
      transactionHash,
      providerName,
      now
    )
    .first();

  if (!transaction) {
    return fail("OAuth transaction not found or expired.");
  }

  const receivedStateHash =
    await sha256Base64Url(state);

  if (
    !timingSafeEqual(
      receivedStateHash,
      transaction.state_hash
    )
  ) {
    return fail("Invalid OAuth state.");
  }

  let provider;

  try {
    provider = getProvider(
      providerName,
      context.env
    );
  } catch {
    return fail(
      "OAuth configuration unavailable.",
      500
    );
  }

  const tokenBody = new URLSearchParams();

  tokenBody.set("client_id", provider.clientId);
  tokenBody.set(
    "client_secret",
    provider.clientSecret
  );
  tokenBody.set("code", code);
  tokenBody.set(
    "redirect_uri",
    provider.redirectUri
  );
  tokenBody.set(
    "code_verifier",
    transaction.code_verifier
  );
  tokenBody.set(
    "grant_type",
    "authorization_code"
  );

  let tokenResponse;

  try {
    tokenResponse = await fetch(
      provider.tokenUrl,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded",
          "Accept": "application/json",
        },
        body: tokenBody.toString(),
      }
    );
  } catch {
    return fail(
      "Unable to contact OAuth provider.",
      502
    );
  }

  let tokens;

  try {
    tokens = await tokenResponse.json();
  } catch {
    return fail(
      "Invalid token response.",
      502
    );
  }

  if (
    !tokenResponse.ok ||
    tokens.error
  ) {
    return fail(
      `Token exchange failed: ${
        tokens.error_description ||
        tokens.error ||
        "unknown error"
      }`,
      400
    );
  }

  let identity;

  try {
    if (providerName === "google") {
      identity =
        await validateGoogleIdToken({
          idToken: tokens.id_token,
          expectedIssuer:
            provider.issuer,
          expectedAudience:
            provider.clientId,
          expectedNonce:
            transaction.nonce,
          discoveryUrl:
            provider.discoveryUrl,
        });
    } else if (providerName === "github") {
      const userResponse = await fetch(
        provider.userUrl,
        {
          headers: {
            "Authorization":
              `Bearer ${tokens.access_token}`,
            "Accept":
              "application/vnd.github+json",
            "User-Agent":
              "oauth-pages-lab",
          },
        }
      );

      if (!userResponse.ok) {
        throw new Error(
          "GitHub user request failed."
        );
      }

      const user =
        await userResponse.json();

      identity = {
        issuer: provider.issuer,
        subject: String(user.id),
        email:
          typeof user.email === "string"
            ? user.email
            : null,
        displayName:
          user.name ||
          user.login ||
          null,
      };
    }
  } catch (error) {
    return fail(
      `Identity validation failed: ${
        error?.message || "unknown error"
      }`,
      400
    );
  }

  if (!identity) {
    return fail(
      "Unable to determine user identity.",
      400
    );
  }

  const sessionId =
    randomBase64Url(32);

  const sessionHash =
    await sha256Base64Url(sessionId);

  const sessionExpiresAt =
    now + 28800;

  try {
    await context.env.DB
      .prepare(`
        INSERT INTO sessions (
          id_hash,
          issuer,
          subject,
          email,
          display_name,
          created_at,
          expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        sessionHash,
        identity.issuer,
        identity.subject,
        identity.email,
        identity.displayName,
        now,
        sessionExpiresAt
      )
      .run();

    await context.env.DB
      .prepare(`
        DELETE FROM oauth_transactions
        WHERE id_hash = ?
      `)
      .bind(transactionHash)
      .run();
  } catch (error) {
    return fail(
      `Database error: ${
        error?.message || "unknown error"
      }`,
      500
    );
  }

  const responseHeaders =
    new Headers();

  responseHeaders.set(
    "Location",
    context.env.PUBLIC_BASE_URL
  );

  responseHeaders.set(
    "Cache-Control",
    "no-store"
  );

  responseHeaders.append(
    "Set-Cookie",
    createSessionCookie(sessionId)
  );

  responseHeaders.append(
    "Set-Cookie",
    clearOAuthTransactionCookie()
  );

  return new Response(null, {
    status: 302,
    headers: responseHeaders,
  });
}

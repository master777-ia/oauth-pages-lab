import {
  SESSION_COOKIE,
  getCookie,
} from "../_shared/cookies.js";

import {
  sha256Base64Url,
} from "../_shared/crypto.js";

function noStoreHeaders(extra = {}) {
  return {
    "Cache-Control": "no-store",
    ...extra,
  };
}

export async function onRequestGet(context) {
  const sessionCookie = getCookie(
    context.request,
    SESSION_COOKIE
  );

  if (!sessionCookie) {
    return new Response("Unauthorized", {
      status: 401,
      headers: noStoreHeaders(),
    });
  }

  const sessionHash =
    await sha256Base64Url(sessionCookie);

  const now = Math.floor(Date.now() / 1000);

  const session = await context.env.DB
    .prepare(
      `
      SELECT
        issuer,
        subject,
        email,
        display_name,
        expires_at
      FROM sessions
      WHERE id_hash = ?
        AND expires_at > ?
      LIMIT 1
      `
    )
    .bind(sessionHash, now)
    .first();

  if (!session) {
    return new Response("Unauthorized", {
      status: 401,
      headers: noStoreHeaders(),
    });
  }

  return Response.json(
    {
      issuer: session.issuer,
      subject: session.subject,
      email: session.email,
      displayName: session.display_name,
    },
    {
      headers: noStoreHeaders(),
    }
  );
}

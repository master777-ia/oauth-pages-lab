import {
  SESSION_COOKIE,
  getCookie,
  clearSessionCookie,
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

export async function onRequest(context) {
  if (context.request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: noStoreHeaders({
        Allow: "POST",
      }),
    });
  }

  const origin =
    context.request.headers.get("Origin");

  if (
    origin &&
    origin !== context.env.PUBLIC_BASE_URL
  ) {
    return new Response("Forbidden", {
      status: 403,
      headers: noStoreHeaders(),
    });
  }

  const sessionCookie = getCookie(
    context.request,
    SESSION_COOKIE
  );

  if (sessionCookie) {
    const sessionHash =
      await sha256Base64Url(sessionCookie);

    try {
      await context.env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE id_hash = ?
        `)
        .bind(sessionHash)
        .run();
    } catch (error) {
      return new Response(
        `Logout database error: ${
          error?.message || "unknown error"
        }`,
        {
          status: 500,
          headers: noStoreHeaders(),
        }
      );
    }
  }

  const headers = new Headers();

  headers.set(
    "Location",
    `${context.env.PUBLIC_BASE_URL}/?logout=1`
  );

  headers.set(
    "Cache-Control",
    "no-store, no-cache, must-revalidate"
  );

  headers.set(
    "Pragma",
    "no-cache"
  );

  headers.append(
    "Set-Cookie",
    clearSessionCookie()
  );

  return new Response(null, {
    status: 303,
    headers,
  });
}

export const PROVIDERS = {
  google: {
    name: "google",
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    discoveryUrl: "https://accounts.google.com/.well-known/openid-configuration",
    issuer: "https://accounts.google.com",
    clientIdEnv: "GOOGLE_CLIENT_ID",
    clientSecretEnv: "GOOGLE_CLIENT_SECRET",
    scope: "openid email profile",
    useNonce: true,
  },

  github: {
    name: "github",
    authorizeUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userUrl: "https://api.github.com/user",
    issuer: "https://github.com",
    clientIdEnv: "GITHUB_CLIENT_ID",
    clientSecretEnv: "GITHUB_CLIENT_SECRET",
    scope: null,
    useNonce: false,
  },
};

export function getProvider(name, env) {
  const provider = PROVIDERS[name];

  if (!provider) {
    return null;
  }

  const clientId = env[provider.clientIdEnv];
  const clientSecret = env[provider.clientSecretEnv];

  if (!clientId || !clientSecret || !env.PUBLIC_BASE_URL) {
    throw new Error("OAuth provider configuration is incomplete.");
  }

  return {
    ...provider,
    clientId,
    clientSecret,
    redirectUri: `${env.PUBLIC_BASE_URL}/oauth/callback/${name}`,
  };
}

export function isSupportedProvider(name) {
  return name === "google" || name === "github";
}

// OAuth 2.0 authorization-code flow with PKCE (S256), for MCP clients that
// cannot send a static bearer token (the Gemini web app's custom connector).
// Client credentials are static Worker secrets; consent is auto-approved
// because the client secret plus PKCE is the gate, and the only resource
// owner is the operator who configured the client.
// Code exchange state lives in KV so codes are single-use and short-lived.
import { sign, safeEqual } from "./crypto.js";

export const CODE_TTL = 600; // authorization code lifetime, seconds
export const TOKEN_TTL = 30 * 24 * 3600; // access token lifetime, seconds

const b64u = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const json = (obj, status = 200, headers = {}) =>
  Response.json(obj, { status, headers: { "cache-control": "no-store", ...headers } });

function clientOk(env, id) {
  return !!env.OAUTH_CLIENT_ID && !!id && safeEqual(String(id), env.OAUTH_CLIENT_ID);
}

export function redirectAllowed(env, uri) {
  const list = (env.OAUTH_REDIRECT_URIS || "").split(",").map((s) => s.trim()).filter(Boolean);
  return !!uri && list.includes(uri);
}

export function authorizationServerMetadata(origin) {
  return {
    issuer: origin,
    authorization_endpoint: origin + "/authorize",
    token_endpoint: origin + "/token",
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
  };
}

export function protectedResourceMetadata(origin) {
  return { resource: origin, authorization_servers: [origin] };
}

// GET /authorize: validate the request and immediately redirect with a code.
export async function handleAuthorize(url, env) {
  const p = url.searchParams;
  const clientId = p.get("client_id") || "";
  const redirectUri = p.get("redirect_uri") || "";
  const state = p.get("state") || "";
  const challenge = p.get("code_challenge") || "";
  const method = p.get("code_challenge_method") || "";
  if (p.get("response_type") !== "code") return json({ error: "unsupported_response_type" }, 400);
  if (!clientOk(env, clientId)) return json({ error: "unauthorized_client" }, 400);
  if (!redirectAllowed(env, redirectUri)) return json({ error: "invalid_request", error_description: "redirect_uri not allowlisted" }, 400);
  if (!challenge || method !== "S256") return json({ error: "invalid_request", error_description: "PKCE S256 required" }, 400);
  const code = b64u(crypto.getRandomValues(new Uint8Array(24)));
  await env.ARCHIVES.put("c:" + code, JSON.stringify({ challenge, redirectUri }), { expirationTtl: CODE_TTL });
  const back = new URL(redirectUri);
  back.searchParams.set("code", code);
  if (state) back.searchParams.set("state", state);
  return new Response(null, { status: 302, headers: { location: back.toString(), "cache-control": "no-store" } });
}

async function issueToken(env) {
  const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL;
  const payload = b64u(new TextEncoder().encode(JSON.stringify({ exp })));
  const sig = await sign(env.ENC_SECRET, "oauth:" + payload);
  return payload + "." + sig;
}

// Returns true when the bearer token is an unexpired OAuth-issued token.
export async function oauthTokenValid(env, token) {
  const dot = token.lastIndexOf(".");
  if (dot <= 0) return false;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!safeEqual(sig, await sign(env.ENC_SECRET, "oauth:" + payload))) return false;
  try {
    const { exp } = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
    return typeof exp === "number" && exp > Date.now() / 1000;
  } catch {
    return false;
  }
}

// POST /token: exchange a single-use code (PKCE verified) for an access token.
export async function handleToken(req, env) {
  let form;
  try {
    form = new URLSearchParams(await req.text());
  } catch {
    return json({ error: "invalid_request" }, 400);
  }
  // client_secret_basic also accepted
  const basic = req.headers.get("authorization") || "";
  let clientId = form.get("client_id") || "";
  let clientSecret = form.get("client_secret") || "";
  if (basic.startsWith("Basic ")) {
    try {
      const decoded = new TextDecoder().decode(Uint8Array.from(atob(basic.slice(6)), (c) => c.charCodeAt(0)));
      const i = decoded.indexOf(":");
      clientId = decodeURIComponent(decoded.slice(0, i));
      clientSecret = decodeURIComponent(decoded.slice(i + 1));
    } catch {
      return json({ error: "invalid_client" }, 401);
    }
  }
  if (form.get("grant_type") !== "authorization_code") return json({ error: "unsupported_grant_type" }, 400);
  if (!clientOk(env, clientId) || !env.OAUTH_CLIENT_SECRET || !safeEqual(clientSecret, env.OAUTH_CLIENT_SECRET))
    return json({ error: "invalid_client" }, 401);
  const code = form.get("code") || "";
  const stored = await env.ARCHIVES.get("c:" + code);
  if (stored) await env.ARCHIVES.delete("c:" + code); // single use, even on later failure
  if (!stored) return json({ error: "invalid_grant" }, 400);
  const { challenge, redirectUri } = JSON.parse(stored);
  if ((form.get("redirect_uri") || "") !== redirectUri) return json({ error: "invalid_grant" }, 400);
  const verifier = form.get("code_verifier") || "";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  if (!safeEqual(b64u(digest), challenge)) return json({ error: "invalid_grant" }, 400);
  return json({ access_token: await issueToken(env), token_type: "Bearer", expires_in: TOKEN_TTL });
}

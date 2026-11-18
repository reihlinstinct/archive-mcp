import { handleRpc } from "./mcp.js";
import { detectFormat, readArchive, LIMITS } from "./archive.js";
import { encrypt, decrypt, sign, safeEqual } from "./crypto.js";
import { authorizationServerMetadata, protectedResourceMetadata, handleAuthorize, handleToken, oauthTokenValid } from "./oauth.js";

const TTL = 24 * 3600;
const UPLOAD_LINK_TTL = 900; // one-time /u/ links: 15 minutes

const b64u = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export function makeStore(env, origin) {
  const k = env.ENC_SECRET;
  return {
    origin,
    async put(bytes, name, format) {
      const id = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
      await env.ARCHIVES.put("a:" + id, await encrypt(k, bytes), { expirationTtl: TTL, metadata: { name, format, size: bytes.length } });
      return id;
    },
    async get(id) {
      if (!/^[a-f0-9]{16}$/.test(id || "")) throw new Error("bad archive id");
      const blob = await env.ARCHIVES.get("a:" + id, "arrayBuffer");
      if (!blob) throw new Error("archive not found or expired");
      return decrypt(k, blob);
    },
    async list() {
      const r = await env.ARCHIVES.list({ prefix: "a:" });
      return r.keys.map((x) => ({ id: x.name.slice(2), ...(x.metadata || {}) }));
    },
    async meta(id) {
      const r = await env.ARCHIVES.getWithMetadata("a:" + id, "arrayBuffer");
      return r.metadata;
    },
    async downloadUrl(id) {
      const exp = Math.floor(Date.now() / 1000) + 3600;
      return `${origin}/download/${id}?exp=${exp}&sig=${await sign(k, id + ":" + exp)}`;
    },
    // One-time upload links: the /u/<token> URL is the credential, so random
    // 144-bit tokens, 15-minute TTL, consumed on first upload.
    async putDebug(entry) {
      const t = Date.now().toString(36) + b64u(crypto.getRandomValues(new Uint8Array(4)));
      await env.ARCHIVES.put("d:" + t, entry, { expirationTtl: 3600 });
    },
    async putUploadToken() {
      const t = b64u(crypto.getRandomValues(new Uint8Array(18)));
      await env.ARCHIVES.put("u:" + t, "1", { expirationTtl: UPLOAD_LINK_TTL });
      return t;
    },
    async peekUploadToken(t) {
      return /^[\w-]{20,30}$/.test(t || "") && (await env.ARCHIVES.get("u:" + t)) !== null;
    },
    async takeUploadToken(t) {
      if (!/^[\w-]{20,30}$/.test(t || "")) return false;
      const v = await env.ARCHIVES.get("u:" + t);
      if (v !== null) await env.ARCHIVES.delete("u:" + t);
      return v !== null;
    },
  };
}

// Shared body validation for /upload (bearer token) and /u/<token> (one-time link).
async function acceptArchive(req, url, store) {
  const bytes = new Uint8Array(await req.arrayBuffer());
  if (!bytes.length || bytes.length > LIMITS.maxArchiveBytes) return new Response("size must be 1 byte to 20 MB", { status: 413 });
  try {
    const f = detectFormat(bytes); readArchive(bytes);
    const name = (url.searchParams.get("name") || "upload").replace(/[^\w.-]/g, "_").slice(0, 80);
    const id = await store.put(bytes, name, f);
    return Response.json({ id });
  } catch (e) { return new Response("invalid archive: " + e.message, { status: 400 }); }
}

async function authed(req, env) {
  const h = req.headers.get("authorization") || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : new URL(req.url).searchParams.get("token") || "";
  if (!!env.AUTH_TOKEN && safeEqual(t, env.AUTH_TOKEN)) return true;
  return oauthTokenValid(env, t);
}

const PAGE = `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Archive upload</title>
<body style="font-family:system-ui;max-width:32rem;margin:2rem auto;padding:0 1rem"><h1>Archive upload</h1>
<p>ZIP or tar.gz, up to 20 MB. Stored encrypted for 24 hours. Do not upload personal or family data.</p>
<input id=t type=password placeholder="access token" style="width:100%;margin:.3rem 0"><input id=f type=file accept=".zip,.gz,.tgz,application/zip,application/gzip,application/x-gzip" style="margin:.3rem 0"><br>
<button id=b>Upload</button><pre id=o></pre>
<script>b.onclick=async()=>{const file=f.files[0];if(!file)return;o.textContent="Uploading...";
const r=await fetch("/upload?name="+encodeURIComponent(file.name),{method:"POST",headers:{authorization:"Bearer "+t.value},body:file});
o.textContent=r.ok?"Archive id: "+(await r.json()).id:"Failed: "+r.status+" "+await r.text()}</script>`;

const UPAGE = (tok) => `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Archive upload</title>
<body style="font-family:system-ui;max-width:32rem;margin:2rem auto;padding:0 1rem"><h1>Archive upload</h1>
<p>One-time link: ZIP or tar.gz, up to 20 MB. Stored encrypted for 24 hours. Do not upload personal or family data.</p>
<input id=f type=file accept=".zip,.gz,.tgz,application/zip,application/gzip,application/x-gzip"><br><br>
<button id=b>Upload</button><pre id=o></pre>
<script>b.onclick=async()=>{const file=f.files[0];if(!file)return;o.textContent="Uploading...";
const r=await fetch("/u/${tok}",{method:"POST",body:file});
o.textContent=r.ok?"Done. Archive id: "+(await r.json()).id+" - go back to your chat and say it is uploaded; the assistant can list it.":"Failed: "+r.status+" "+await r.text()}</script>`;

// Browser-based MCP clients (Gemini Developer Mode connect dialog, claude.ai)
// fetch the server cross-origin: metadata, /mcp, and the 401's WWW-Authenticate
// that starts OAuth. Without CORS headers the browser hides all of it and the
// connect flow stalls. Auth here is bearer/OAuth tokens in the Authorization
// header, never cookies, so ACAO * exposes nothing ambient.
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, mcp-protocol-version, mcp-session-id, last-event-id",
  // Without this the browser hides WWW-Authenticate from fetch(), and OAuth
  // discovery (which reads it on the 401) cannot start.
  "access-control-expose-headers": "www-authenticate, mcp-protocol-version, mcp-session-id",
  "access-control-max-age": "86400",
};
const withCors = (res) => {
  const r = new Response(res.body, res);
  for (const [k, v] of Object.entries(CORS)) if (!r.headers.has(k)) r.headers.set(k, v);
  return r;
};

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    return withCors(await route(req, env));
  },
};

async function route(req, env) {
    const url = new URL(req.url);
    const store = makeStore(env, url.origin);
    if (url.pathname === "/" && req.method === "GET") return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" } });
    if (url.pathname === "/.well-known/security.txt") return new Response("Contact: https://github.com/reihlinstinct/archive-mcp/security/advisories/new\nExpires: 2027-11-17T00:00:00Z\n");
    if (url.pathname === "/.well-known/oauth-authorization-server") return Response.json(authorizationServerMetadata(url.origin));
    if (url.pathname === "/.well-known/oauth-protected-resource") return Response.json(protectedResourceMetadata(url.origin));
    if (url.pathname === "/authorize" && req.method === "GET") return handleAuthorize(url, env);
    if (url.pathname === "/token" && req.method === "POST") return handleToken(req, env);
    if (url.pathname.startsWith("/download/") && req.method === "GET") {
      const id = url.pathname.slice(10), exp = url.searchParams.get("exp") || "", sig = url.searchParams.get("sig") || "";
      if (!/^[a-f0-9]{16}$/.test(id) || +exp < Date.now() / 1000 || !safeEqual(sig, await sign(env.ENC_SECRET, id + ":" + exp))) return new Response("forbidden", { status: 403 });
      try {
        const bytes = await store.get(id);
        const m = (await store.meta(id)) || {};
        return new Response(bytes, { headers: { "content-type": "application/octet-stream", "content-disposition": `attachment; filename="${(m.name || "archive").replace(/[^\w.-]/g, "_")}"`, "cache-control": "no-store" } });
      } catch { return new Response("not found", { status: 404 }); }
    }
    if (url.pathname.startsWith("/u/")) {
      const t = url.pathname.slice(3);
      if (req.method === "GET") {
        if (!(await store.peekUploadToken(t))) return new Response("link expired or already used", { status: 410 });
        return new Response(UPAGE(t), { headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" } });
      }
      if (req.method === "POST") {
        if (!(await store.takeUploadToken(t))) return new Response("link expired or already used", { status: 410 });
        return acceptArchive(req, url, store);
      }
      return new Response("method not allowed", { status: 405 });
    }
    if (!(await authed(req, env))) return new Response("unauthorized", { status: 401, headers: { "www-authenticate": `Bearer resource_metadata="${url.origin}/.well-known/oauth-protected-resource"` } });
    if (url.pathname === "/upload" && req.method === "POST") return acceptArchive(req, url, store);
    if (url.pathname === "/mcp") {
      if (req.method === "GET") return new Response("use POST", { status: 405, headers: { allow: "POST" } });
      if (req.method !== "POST") return new Response("method not allowed", { status: 405 });
      let body;
      try { body = await req.json(); } catch { return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }, { status: 400 }); }
      const batch = Array.isArray(body);
      const out = (await Promise.all((batch ? body : [body]).map((m) => handleRpc(m, store)))).filter(Boolean);
      if (!out.length) return new Response(null, { status: 202 });
      return Response.json(batch ? out : out[0]);
    }
    return new Response("not found", { status: 404 });
}

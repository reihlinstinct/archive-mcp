import test from "node:test";
import assert from "node:assert/strict";
import { strToU8 } from "fflate";
import worker from "../src/index.js";
import { writeArchive } from "../src/archive.js";

function kv() { const m = new Map(); return { async put(k, v, o) { m.set(k, { v: v && v.buffer ? v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) : v, meta: o?.metadata }); }, async delete(k) { m.delete(k); }, async get(k) { return m.get(k)?.v ?? null; }, async getWithMetadata(k) { const e = m.get(k); return { value: e?.v, metadata: e?.meta }; }, async list() { return { keys: [...m].map(([name, e]) => ({ name, metadata: e.meta })) }; } }; }
const env = () => ({ AUTH_TOKEN: "tok", ENC_SECRET: "enc", ARCHIVES: kv() });
const call = (e, path, init = {}) => worker.fetch(new Request("https://w.test" + path, init), e);
const auth = { authorization: "Bearer tok" };

test("rejects without token", async () => { assert.equal((await call(env(), "/mcp", { method: "POST", body: "{}" })).status, 401); });
test("upload, mcp read, create, download", async () => {
  const e = env();
  const up = await call(e, "/upload?name=p.zip", { method: "POST", headers: auth, body: writeArchive({ "a.txt": strToU8("hi") }, "zip") });
  const { id } = await up.json();
  const rpc = (name, args) => call(e, "/mcp", { method: "POST", headers: auth, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) }).then((r) => r.json());
  assert.equal((await rpc("read_file", { id, path: "a.txt" })).result.content[0].text, "hi");
  const made = await rpc("create_archive", { format: "zip", name: "o", files: [{ path: "x.txt", content: "y" }] });
  const m = /(https:\/\/w\.test\/download\/[^\s]+)/.exec(made.result.content[0].text);
  const d = await call(e, m[1].replace("https://w.test", ""));
  assert.equal(d.status, 200);
  assert.equal((await call(e, m[1].replace("https://w.test", "").replace(/sig=\w+/, "sig=bad"))).status, 403);
});
test("upload rejects non-archives", async () => { assert.equal((await call(env(), "/upload", { method: "POST", headers: auth, body: "plain text" })).status, 400); });

// OAuth authorization-code + PKCE flow (Gemini web connector path)
const oauthEnv = () => ({ ...env(), OAUTH_CLIENT_ID: "cid", OAUTH_CLIENT_SECRET: "csecret", OAUTH_REDIRECT_URIS: "https://gemini.google.com/callback/mcp" });
const pkce = async (verifier) => {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(d))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

test("oauth discovery metadata", async () => {
  const e = oauthEnv();
  const as = await call(e, "/.well-known/oauth-authorization-server").then((r) => r.json());
  assert.equal(as.authorization_endpoint, "https://w.test/authorize");
  assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
  const pr = await call(e, "/.well-known/oauth-protected-resource").then((r) => r.json());
  assert.equal(pr.resource, "https://w.test");
});

test("oauth flow: authorize, exchange, use token; replay and bad inputs rejected", async () => {
  const e = oauthEnv();
  const verifier = "v-" + "x".repeat(43);
  const challenge = await pkce(verifier);
  const qs = `response_type=code&client_id=cid&redirect_uri=${encodeURIComponent("https://gemini.google.com/callback/mcp")}&state=st&code_challenge=${challenge}&code_challenge_method=S256`;
  const auth = await call(e, "/authorize?" + qs);
  assert.equal(auth.status, 302);
  const loc = new URL(auth.headers.get("location"));
  assert.equal(loc.searchParams.get("state"), "st");
  const code = loc.searchParams.get("code");
  assert.ok(code);
  const exchange = (body) => call(e, "/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
  // wrong verifier
  const bad = await exchange(`grant_type=authorization_code&client_id=cid&client_secret=csecret&code=${code}&redirect_uri=${encodeURIComponent("https://gemini.google.com/callback/mcp")}&code_verifier=wrong`);
  assert.equal(bad.status, 400);
  // code is single-use even after failure
  const replay = await exchange(`grant_type=authorization_code&client_id=cid&client_secret=csecret&code=${code}&redirect_uri=${encodeURIComponent("https://gemini.google.com/callback/mcp")}&code_verifier=${verifier}`);
  assert.equal(replay.status, 400);
  // fresh code, wrong client secret
  const auth2 = await call(e, "/authorize?" + qs);
  const code2 = new URL(auth2.headers.get("location")).searchParams.get("code");
  const badSecret = await exchange(`grant_type=authorization_code&client_id=cid&client_secret=nope&code=${code2}&redirect_uri=${encodeURIComponent("https://gemini.google.com/callback/mcp")}&code_verifier=${verifier}`);
  assert.equal(badSecret.status, 401);
  // fresh code, full exchange
  const auth3 = await call(e, "/authorize?" + qs);
  const code3 = new URL(auth3.headers.get("location")).searchParams.get("code");
  const good = await exchange(`grant_type=authorization_code&client_id=cid&client_secret=csecret&code=${code3}&redirect_uri=${encodeURIComponent("https://gemini.google.com/callback/mcp")}&code_verifier=${verifier}`);
  assert.equal(good.status, 200);
  const { access_token, token_type } = await good.json();
  assert.equal(token_type, "Bearer");
  const mcp = await call(e, "/mcp", { method: "POST", headers: { authorization: "Bearer " + access_token }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
  assert.equal(mcp.status, 200);
  // tampered token rejected
  const tampered = await call(e, "/mcp", { method: "POST", headers: { authorization: "Bearer " + access_token.slice(0, -2) + "zz" }, body: "{}" });
  assert.equal(tampered.status, 401);
});

test("authorize rejects unknown redirect_uri and client", async () => {
  const e = oauthEnv();
  const base = "response_type=code&code_challenge=ch&code_challenge_method=S256";
  assert.equal((await call(e, `/authorize?${base}&client_id=cid&redirect_uri=${encodeURIComponent("https://evil.example/cb")}`)).status, 400);
  assert.equal((await call(e, `/authorize?${base}&client_id=nobody&redirect_uri=${encodeURIComponent("https://gemini.google.com/callback/mcp")}`)).status, 400);
});

test("one-time upload link flow (no bearer token needed)", async () => {
  const e = env();
  const r = await call(e, "/mcp", { method: "POST", headers: auth, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "request_upload_link", arguments: {} } }) }).then((x) => x.json());
  const m = /https:\/\/w\.test\/u\/[\w-]+/.exec(r.result.content[0].text);
  assert.ok(m, "link issued");
  const path = m[0].replace("https://w.test", "");
  const page = await call(e, path); // the link itself is the credential
  assert.equal(page.status, 200);
  const up = await call(e, path, { method: "POST", body: writeArchive({ "a.txt": strToU8("hi") }, "zip") });
  assert.equal(up.status, 200);
  const { id } = await up.json();
  assert.match(id, /^[a-f0-9]{16}$/);
  assert.equal((await call(e, path)).status, 410); // consumed after one upload
  const read = await call(e, "/mcp", { method: "POST", headers: auth, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "read_file", arguments: { id, path: "a.txt" } } }) }).then((x) => x.json());
  assert.equal(read.result.content[0].text, "hi");
});
test("unknown upload tokens get 410, not 401", async () => {
  assert.equal((await call(env(), "/u/" + "a".repeat(24))).status, 410);
});

test("cors: preflight and headers for browser-based MCP clients", async () => {
  const e = env();
  const pre = await call(e, "/mcp", { method: "OPTIONS", headers: { origin: "https://gemini.google.com", "access-control-request-method": "POST", "access-control-request-headers": "authorization, content-type" } });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get("access-control-allow-origin"), "*");
  assert.match(pre.headers.get("access-control-allow-headers"), /authorization/);
  assert.match(pre.headers.get("access-control-allow-headers"), /content-type/);
  assert.match(pre.headers.get("access-control-allow-headers"), /mcp-protocol-version/);
  const meta = await call(e, "/.well-known/oauth-authorization-server", { headers: { origin: "https://gemini.google.com" } });
  assert.equal(meta.headers.get("access-control-allow-origin"), "*");
  const noAuth = await call(e, "/mcp", { method: "POST", headers: { origin: "https://gemini.google.com" }, body: "{}" });
  assert.equal(noAuth.status, 401);
  assert.equal(noAuth.headers.get("access-control-allow-origin"), "*");
  assert.match(noAuth.headers.get("www-authenticate"), /resource_metadata/);
});

test("cors: exposes www-authenticate so browser clients can start OAuth", async () => {
  const r = await call(env(), "/mcp", { method: "POST", headers: { origin: "https://claude.ai" }, body: "{}" });
  assert.equal(r.status, 401);
  assert.match(r.headers.get("access-control-expose-headers"), /www-authenticate/);
  assert.match(r.headers.get("access-control-expose-headers"), /mcp-session-id/);
});

test("list_archives rows carry created timestamps", async () => {
  const e = env();
  await call(e, "/upload?name=t.zip", { method: "POST", headers: auth, body: writeArchive({ "a.txt": strToU8("x") }, "zip") });
  const r = await call(e, "/mcp", { method: "POST", headers: auth, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_archives", arguments: {} } }) }).then((x) => x.json());
  assert.match(r.result.content[0].text, /t\.zip  zip  \d+ bytes  \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/);
});


test("upload pages accept .gz so macOS does not grey out .tar.gz", async () => {
  const page = await call(env(), "/");
  assert.match(await page.text(), /accept="[^"]*\.gz/);
});

test("import_archive_inline: round trip, validation, cap", async () => {
  const e = env();
  const rpc = (name, args) => call(e, "/mcp", { method: "POST", headers: auth, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) }).then((r) => r.json());
  const b64 = (u8) => Buffer.from(u8).toString("base64");
  // tar.gz and zip both import and read back
  for (const fmt of ["zip", "tar.gz"]) {
    const packed = writeArchive({ "readme.txt": strToU8("inline " + fmt) }, fmt);
    const r = await rpc("import_archive_inline", { content_base64: b64(packed), name: "inl" });
    const t = r.result.content[0].text;
    assert.match(t, new RegExp("Imported inl\\." + (fmt === "zip" ? "zip" : "tar\\.gz") + " \\(1 files"));
    const id = /id ([0-9a-f]{16})/.exec(t)[1];
    assert.equal((await rpc("read_file", { id, path: "readme.txt" })).result.content[0].text, "inline " + fmt);
  }
  // invalid base64 and non-archive content fail with helpful errors
  assert.match((await rpc("import_archive_inline", { content_base64: "!!!" })).result.content[0].text, /not valid base64/);
  assert.match((await rpc("import_archive_inline", { content_base64: b64(strToU8("plain text")) })).result.content[0].text, /unsupported format/);
  // over-cap input points to the upload-link route
  const big = Buffer.alloc(24577, 65).toString("base64");
  const over = await rpc("import_archive_inline", { content_base64: big });
  assert.equal(over.result.isError, true);
  assert.match(over.result.content[0].text, /request_upload_link/);
  // whitespace inside the base64 is tolerated
  const packed = writeArchive({ "a.txt": strToU8("ws") }, "zip");
  const chunked = b64(packed).replace(/.{40}/g, "$&\n");
  assert.match((await rpc("import_archive_inline", { content_base64: chunked })).result.content[0].text, /Imported archive\.zip/);
});

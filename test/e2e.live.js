// End-to-end functional tests against a DEPLOYED archive-mcp instance.
// Not part of CI: needs a live Worker and its secrets. Run against a
// throwaway staging instance (see README "Live functional tests").
//
//   BASE=https://<worker>.workers.dev AUTH_TOKEN=... \
//   OAUTH_CLIENT_ID=... OAUTH_CLIENT_SECRET=... REDIRECT_URI=https://example.invalid/cb \
//   node test/e2e.live.js
import { zipSync, strToU8, strFromU8 } from "fflate";
import { writeArchive, readArchive } from "../src/archive.js";
import { redact } from "./redact.js";

const BASE = process.env.BASE;
const TOKEN = process.env.AUTH_TOKEN || "";
const CID = process.env.OAUTH_CLIENT_ID || "";
const CSEC = process.env.OAUTH_CLIENT_SECRET || "";
const RU = process.env.REDIRECT_URI || "https://example.invalid/oauth-callback";
if (!BASE) { console.error("BASE is required"); process.exit(2); }

let pass = 0, fail = 0;
// Failure output goes through redact(): response snippets can contain
// short-lived capability URLs (one-time upload links, signed download
// URLs) that must not land in captured logs.
const check = (name, cond, extra = "") => {
  if (cond) { pass++; console.log("PASS", name); }
  else { fail++; console.log("FAIL", name, redact(extra, [TOKEN, CSEC])); }
};
const rpc = async (name, args, tok = TOKEN) => {
  const r = await fetch(BASE + "/mcp", { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer " + tok }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) });
  const body = await r.json().catch(() => null);
  return { status: r.status, body };
};
const toolText = (b) => b.result?.content?.[0]?.text || "";
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// ---------- auth ----------
{
  const r = await fetch(BASE + "/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  check("auth: no token -> 401", r.status === 401);
  const w = await rpc("list_archives", {}, "wrong-token");
  check("auth: wrong token -> 401", w.status === 401);
  const ok = await rpc("list_archives", {});
  check("auth: bearer token -> tools callable", ok.status === 200);
}
// ---------- OAuth ----------
{
  const meta = await (await fetch(BASE + "/.well-known/oauth-authorization-server")).json();
  check("oauth: discovery metadata", meta.token_endpoint === BASE + "/token" && meta.code_challenge_methods_supported?.[0] === "S256");
  const verifier = b64u(crypto.getRandomValues(new Uint8Array(48)));
  const challenge = b64u(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const q = new URLSearchParams({ response_type: "code", client_id: CID, redirect_uri: RU, state: "s1", code_challenge: challenge, code_challenge_method: "S256" });
  const a = await fetch(BASE + "/authorize?" + q, { redirect: "manual" });
  const loc = a.headers.get("location") || "";
  const code = new URL(loc, RU).searchParams.get("code");
  check("oauth: authorize -> 302 + code", a.status === 302 && !!code);
  const form = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: RU, code_verifier: verifier, client_id: CID, client_secret: CSEC });
  const t1 = await fetch(BASE + "/token", { method: "POST", body: form });
  const tok = t1.status === 200 ? (await t1.json()).access_token : null;
  check("oauth: code exchange -> access token", !!tok);
  check("oauth: code single-use", (await fetch(BASE + "/token", { method: "POST", body: form })).status === 400);
  const bad = new URLSearchParams({ grant_type: "authorization_code", code: "x", redirect_uri: RU, code_verifier: "y", client_id: CID, client_secret: "wrong" });
  check("oauth: bad client secret -> 401", (await fetch(BASE + "/token", { method: "POST", body: bad })).status === 401);
  const viaOauth = await rpc("list_archives", {}, tok || "");
  check("oauth: issued token calls /mcp", viaOauth.status === 200);
  check("oauth: tampered token -> 401", (await rpc("list_archives", {}, (tok || "") + "xx")).status === 401);
}
// ---------- upload + read, tar.gz and zip ----------
const sample = { "README.txt": strToU8("hello archive\nsecond line"), "src/app.py": strToU8("print('hi')\n"), "docs/notes.md": strToU8("# notes\nfindme-marker\n") };
let targzId, zipId;
{
  const up = await fetch(BASE + "/upload?name=sample.tar.gz", { method: "POST", headers: { authorization: "Bearer " + TOKEN }, body: writeArchive(sample, "tar.gz") });
  targzId = up.status === 200 ? (await up.json()).id : null;
  check("upload tar.gz -> id", !!targzId);
  const files = toolText((await rpc("list_files", { id: targzId })).body);
  check("tar.gz: list_files shows all paths", ["README.txt", "src/app.py", "docs/notes.md"].every((p) => files.includes(p)), files.slice(0, 120));
  const read = toolText((await rpc("read_file", { id: targzId, path: "README.txt" })).body);
  check("tar.gz: read_file content", read === "hello archive\nsecond line");
  const found = toolText((await rpc("search", { id: targzId, query: "findme-marker" })).body);
  check("tar.gz: search locates marker", found.includes("docs/notes.md:2"), found.slice(0, 80));
  // Workers KV list is eventually consistent: poll up to 60 s.
  let seen = false;
  for (let i = 0; i < 20 && !seen; i++) {
    seen = toolText((await rpc("list_archives", {})).body).includes(targzId);
    if (!seen) await new Promise((r) => setTimeout(r, 3000));
  }
  check("list_archives contains the upload (KV list lag tolerated, <=60s)", seen);
}
// ---------- one-time upload link ----------
{
  const link = toolText((await rpc("request_upload_link", {})).body);
  const m = /https?:\/\/[^\s]+\/u\/[\w-]+/.exec(link);
  check("request_upload_link -> /u/ link", !!m, link.slice(0, 120));
  const page = await fetch(m[0]);
  check("upload link page loads without token", page.status === 200);
  const up = await fetch(m[0], { method: "POST", body: writeArchive(sample, "zip") });
  zipId = up.status === 200 ? (await up.json()).id : null;
  check("zip uploaded via one-time link", !!zipId);
  check("link consumed (410 on reuse)", (await fetch(m[0])).status === 410);
  const read = toolText((await rpc("read_file", { id: zipId, path: "src/app.py" })).body);
  check("zip: read_file content", read === "print('hi')\n");
}
// ---------- create + download, both formats ----------
{
  const made = toolText((await rpc("create_archive", { format: "zip", name: "edited", base_id: targzId, files: [{ path: "README.txt", content: "replaced" }, { path: "new.txt", content: "added" }], delete_paths: ["src/app.py"] })).body);
  const um = /(https?:\/\/[^\s]+\/download\/[^\s]+)/.exec(made);
  check("create_archive zip from base -> download url", !!um, made.slice(0, 150));
  const dl = await fetch(um[1]);
  const files = dl.status === 200 ? readArchive(new Uint8Array(await dl.arrayBuffer())).files : {};
  check("downloaded zip has edits", strFromU8(files["README.txt"] || []) === "replaced" && strFromU8(files["new.txt"] || []) === "added" && !files["src/app.py"] && !!files["docs/notes.md"]);
  check("tampered download sig -> 403", (await fetch(um[1].replace(/sig=[\w-]+/, "sig=bad"))).status === 403);
  check("expired download -> 403", (await fetch(um[1].replace(/exp=\d+/, "exp=1"))).status === 403);
  const made2 = toolText((await rpc("create_archive", { format: "tar.gz", name: "fresh", files: [{ path: "a/b.txt", content: "deep" }] })).body);
  const um2 = /(https?:\/\/[^\s]+\/download\/[^\s]+)/.exec(made2);
  const dl2 = um2 ? await fetch(um2[1]) : null;
  const f2 = dl2 && dl2.status === 200 ? readArchive(new Uint8Array(await dl2.arrayBuffer())).files : {};
  check("create tar.gz fresh + download + parse", strFromU8(f2["a/b.txt"] || []) === "deep");
}
// ---------- limits and malformed input ----------
{
  const big = "y".repeat(40000);
  const up = await fetch(BASE + "/upload?name=big.tar.gz", { method: "POST", headers: { authorization: "Bearer " + TOKEN }, body: writeArchive({ "big.txt": strToU8(big) }, "tar.gz") });
  const bigId = up.status === 200 ? (await up.json()).id : null;
  const p1 = toolText((await rpc("read_file", { id: bigId, path: "big.txt" })).body);
  check("read_file truncates at 32 KB with hint", p1.length < 33400 && p1.includes("truncated: 40000 bytes total, continue at offset 32768"), p1.slice(-90));
  const p2 = toolText((await rpc("read_file", { id: bigId, path: "big.txt", offset: 32768 })).body);
  check("read_file offset paging completes the file", p2.length === 40000 - 32768 && !p2.includes("truncated"));
  check("oversize upload -> 413", (await fetch(BASE + "/upload?name=x.zip", { method: "POST", headers: { authorization: "Bearer " + TOKEN }, body: new Uint8Array(21 * 1024 * 1024) })).status === 413);
  check("non-archive upload -> 400", (await fetch(BASE + "/upload?name=x.zip", { method: "POST", headers: { authorization: "Bearer " + TOKEN }, body: "plain text" })).status === 400);
  const slip = zipSync({ "../evil.txt": strToU8("x") });
  check("zip-slip upload -> 400", (await fetch(BASE + "/upload?name=x.zip", { method: "POST", headers: { authorization: "Bearer " + TOKEN }, body: slip })).status === 400);
  const trunc = writeArchive(sample, "zip").slice(0, 60);
  check("truncated archive -> 400", (await fetch(BASE + "/upload?name=x.zip", { method: "POST", headers: { authorization: "Bearer " + TOKEN }, body: trunc })).status === 400);
  const empty = await fetch(BASE + "/upload?name=empty.zip", { method: "POST", headers: { authorization: "Bearer " + TOKEN }, body: zipSync({}) });
  const emptyId = empty.status === 200 ? (await empty.json()).id : null;
  const el = emptyId ? toolText((await rpc("list_files", { id: emptyId })).body) : "";
  check("empty archive: accepted, lists 0 files", !!emptyId && el.startsWith("0 files"), "status " + empty.status);
  const missing = (await rpc("read_file", { id: targzId, path: "nope.txt" })).body;
  check("missing file -> isError", missing.result?.isError === true);
  const badid = (await rpc("list_files", { id: "zz" })).body;
  check("bad archive id -> isError", badid.result?.isError === true);
}
// ---------- import_archive (live fetch from GitHub) ----------
{
  const r = toolText((await rpc("import_archive", { url: "https://github.com/reihlinstinct/archive-mcp/archive/refs/heads/main.zip" })).body);
  const im = /id ([a-f0-9]{16})/.exec(r);
  check("import_archive: repo zip imported (redirect hop validated)", !!im && r.includes("src/index.js"), r.slice(0, 150));
  if (im) {
    const lf = toolText((await rpc("list_files", { id: im[1], prefix: "archive-mcp-main/README.md" })).body);
    check("imported archive: README listed", lf.includes("README.md"), lf.slice(0, 100));
    const read = toolText((await rpc("read_file", { id: im[1], path: "archive-mcp-main/README.md", offset: 0, length: 50 })).body);
    check("imported archive: README readable", read.includes("archive-mcp"), read.slice(0, 60));
  }
  check("import_archive: http rejected", (await rpc("import_archive", { url: "http://github.com/x.zip" })).body.result?.isError === true);
  check("import_archive: unknown host rejected", (await rpc("import_archive", { url: "https://evil.example.com/x.zip" })).body.result?.isError === true);
  check("import_archive: 404 surfaces as error", (await rpc("import_archive", { url: "https://github.com/reihlinstinct/archive-mcp/archive/refs/heads/no-such-branch.zip" })).body.result?.isError === true);
}
// ---------- debug diagnostic ----------
{
  const r = toolText((await rpc("debug_echo_context", { probe: "x".repeat(500) })).body);
  check("debug_echo_context echoes structure", r.includes('"length": 500'));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

import test from "node:test";
import assert from "node:assert/strict";
import { strToU8 } from "fflate";
import worker from "../src/index.js";
import { writeArchive } from "../src/archive.js";

function kv() { const m = new Map(); return { async put(k, v, o) { m.set(k, { v: v.buffer ? v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) : v, meta: o?.metadata }); }, async get(k) { return m.get(k)?.v ?? null; }, async getWithMetadata(k) { const e = m.get(k); return { value: e?.v, metadata: e?.meta }; }, async list() { return { keys: [...m].map(([name, e]) => ({ name, metadata: e.meta })) }; } }; }
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

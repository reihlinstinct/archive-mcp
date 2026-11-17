import test from "node:test";
import assert from "node:assert/strict";
import { gzipSync, zipSync, strToU8 } from "fflate";
import { readArchive, writeArchive, safePath, buildTar } from "../src/archive.js";
import { encrypt, decrypt, sign } from "../src/crypto.js";
import { callTool, handleRpc } from "../src/mcp.js";

const files = { "a.txt": strToU8("hello\nworld"), "dir/b.py": strToU8("print(1)\n") };
const mem = () => { const m = new Map(); return { m, async put(b, n, f) { const id = "0".repeat(15) + m.size; m.set(id, b); return id; }, async get(id) { if (!m.has(id)) throw new Error("archive not found or expired"); return m.get(id); }, async list() { return [...m].map(([id, b]) => ({ id, name: "x", format: "zip", size: b.length })); }, async downloadUrl(id) { return "https://x/d/" + id; } }; };

test("zip round trip", () => { const r = readArchive(writeArchive(files, "zip")); assert.equal(r.format, "zip"); assert.deepEqual(Object.keys(r.files).sort(), ["a.txt", "dir/b.py"]); });
test("tar.gz round trip", () => { const r = readArchive(writeArchive(files, "tar.gz")); assert.equal(r.format, "tar.gz"); assert.equal(new TextDecoder().decode(r.files["dir/b.py"]), "print(1)\n"); });
test("long path uses ustar prefix", () => { const p = "d/".repeat(60) + "f.txt"; const r = readArchive(gzipSync(buildTar({ [p]: strToU8("x") }))); assert.ok(r.files[p]); });
test("path traversal rejected", () => { for (const p of ["../x", "a/../../x", "/etc/passwd", "C:/x"]) assert.throws(() => safePath(p)); });
test("traversal in uploaded zip rejected", () => { assert.throws(() => readArchive(zipSync({ "../evil": strToU8("x") }))); });
test("garbage rejected", () => assert.throws(() => readArchive(strToU8("not an archive"))));
test("encryption round trip and tamper", async () => { const e = await encrypt("s", strToU8("data")); assert.equal(new TextDecoder().decode(await decrypt("s", e)), "data"); await assert.rejects(decrypt("other", e)); e[20] ^= 1; await assert.rejects(decrypt("s", e)); });
test("signature is stable per message", async () => { assert.equal(await sign("s", "m"), await sign("s", "m")); assert.notEqual(await sign("s", "m"), await sign("s", "n")); });
test("tools: list, read, search, create with base", async () => {
  const s = mem(); const id = await s.put(writeArchive(files, "zip"));
  assert.match((await callTool("list_files", { id }, s)).content[0].text, /dir\/b.py/);
  assert.equal((await callTool("read_file", { id, path: "a.txt" }, s)).content[0].text, "hello\nworld");
  assert.match((await callTool("search", { id, query: "WORLD" }, s)).content[0].text, /a.txt:2/);
  const r = await callTool("create_archive", { format: "tar.gz", name: "out", base_id: id, files: [{ path: "new.js", content: "1" }], delete_paths: ["a.txt"] }, s);
  assert.match(r.content[0].text, /out\.tar\.gz/);
  const out = readArchive([...s.m.values()].at(-1));
  assert.deepEqual(Object.keys(out.files).sort(), ["dir/b.py", "new.js"]);
});
test("tool errors are reported not thrown", async () => { assert.equal((await callTool("read_file", { id: "zzz", path: "a" }, mem())).isError, true); });
test("rpc: initialize, list, notification, unknown", async () => {
  const s = mem();
  assert.equal((await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, s)).result.tools.length, 5);
  assert.equal(await handleRpc({ jsonrpc: "2.0", method: "notifications/initialized" }, s), null);
  assert.equal((await handleRpc({ jsonrpc: "2.0", id: 2, method: "nope" }, s)).error.code, -32601);
});
test("safePath strips trailing slashes (no regex)", () => {
  assert.equal(safePath("a/b/"), "a/b");
  assert.equal(safePath("a//"), "a");
});
test("tar header has fixed zero mtime", () => {
  const tar = buildTar({ "f.txt": strToU8("x") });
  assert.deepEqual([...tar.subarray(136, 147)], Array(11).fill(48)); // 11x ASCII "0"
  assert.equal(tar[147], 0);
});
test("safePath normalizes long repeated ./ input fast and without regex", () => {
  const p = "./".repeat(10000) + "a/b.txt";
  const t0 = Date.now();
  assert.equal(safePath(p), "a/b.txt");
  assert.ok(Date.now() - t0 < 1000, "normalization must stay linear");
});

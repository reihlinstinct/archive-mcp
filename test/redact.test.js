import test from "node:test";
import assert from "node:assert/strict";
import { redact } from "./redact.js";

test("redact strips one-time upload link tokens", () => {
  const s = "got https://w.workers.dev/u/AbCdEfGhIjKlMnOpQrStUvWx for upload";
  const r = redact(s);
  assert.equal(r, "got https://w.workers.dev/u/<redacted> for upload");
  assert.ok(!r.includes("AbCdEfGhIjKlMnOpQrStUvWx"));
});

test("redact strips download signatures but keeps the archive id", () => {
  const s = "download at https://w.workers.dev/download/0123456789abcdef?exp=1763740000&sig=9f8e7d6c5b4a";
  const r = redact(s);
  assert.equal(r, "download at https://w.workers.dev/download/0123456789abcdef?exp=1763740000&sig=<redacted>");
});

test("redact strips oauth codes and bearer secrets passed explicitly", () => {
  const r = redact("cb https://w.workers.dev/cb?code=abc123def456&state=st, tok hunter2", ["hunter2"]);
  assert.equal(r, "cb https://w.workers.dev/cb?code=<redacted>&state=st, tok <redacted>");
});

test("redact leaves ordinary text untouched", () => {
  const s = "expected 3 files, got 2: [README.md, src/app.py]";
  assert.equal(redact(s, ["", null]), s);
});

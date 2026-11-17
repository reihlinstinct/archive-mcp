// Archive helpers: read/write ZIP and tar.gz in memory. Pure functions, no Worker APIs.
import { unzipSync, zipSync, gunzipSync, gzipSync, strToU8, strFromU8 } from "fflate";

export const LIMITS = {
  maxArchiveBytes: 20 * 1024 * 1024, // compressed upload / output
  maxTotalBytes: 100 * 1024 * 1024, // total uncompressed
  maxFiles: 5000,
  maxReadBytes: 256 * 1024, // per read_file call
};

export function safePath(p) {
  if (typeof p !== "string" || !p) throw new Error("empty path");
  const norm = p.replace(/\\/g, "/").replace(/^(\.\/)+/, "");
  if (norm.startsWith("/") || /^[a-zA-Z]:/.test(norm)) throw new Error("absolute path rejected: " + p);
  const parts = norm.split("/");
  if (parts.some((s) => s === "..")) throw new Error("path traversal rejected: " + p);
  return norm.replace(/\/+$/, "");
}

export function detectFormat(bytes) {
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) return "zip";
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) return "tar.gz";
  throw new Error("unsupported format: expected ZIP or tar.gz");
}

function parseOctal(u8, off, len) {
  const s = strFromU8(u8.subarray(off, off + len)).replace(/\0.*$/, "").trim();
  return s ? parseInt(s, 8) : 0;
}
function cstr(u8, off, len) {
  return strFromU8(u8.subarray(off, off + len)).replace(/\0.*$/, "");
}

export function parseTar(tar) {
  const files = {};
  let off = 0;
  let total = 0;
  let longName = null;
  let count = 0;
  while (off + 512 <= tar.length) {
    const h = tar.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    let name = cstr(h, 0, 100);
    const size = parseOctal(h, 124, 12);
    const type = String.fromCharCode(h[156] || 48);
    const prefix = cstr(h, 345, 155);
    if (prefix) name = prefix + "/" + name;
    off += 512;
    const data = tar.subarray(off, off + size);
    off += Math.ceil(size / 512) * 512;
    if (type === "L") { longName = cstr(data, 0, data.length); continue; }
    if (type === "x" || type === "g") {
      const m = /\d+ path=([^\n]+)\n/.exec(strFromU8(data));
      if (m && type === "x") longName = m[1];
      continue;
    }
    if (longName) { name = longName; longName = null; }
    if (type !== "0" && type !== "\0") continue; // regular files only
    total += size;
    if (++count > LIMITS.maxFiles || total > LIMITS.maxTotalBytes) throw new Error("archive too large");
    files[safePath(name)] = new Uint8Array(data);
  }
  return files;
}

export function buildTar(files) {
  const chunks = [];
  const enc = (s) => strToU8(s);
  for (const [path, data] of Object.entries(files)) {
    const p = safePath(path);
    const h = new Uint8Array(512);
    let name = p, prefix = "";
    if (enc(p).length > 100) {
      const i = p.lastIndexOf("/", 154);
      if (i > 0 && enc(p.slice(i + 1)).length <= 100) { prefix = p.slice(0, i); name = p.slice(i + 1); }
      else throw new Error("path too long: " + p);
    }
    h.set(enc(name), 0);
    h.set(enc("0000644\0"), 100);
    h.set(enc("0000000\0"), 108);
    h.set(enc("0000000\0"), 116);
    h.set(enc(data.length.toString(8).padStart(11, "0") + "\0"), 124);
    h.set(enc("00000000000\0"), 136); // fixed mtime for reproducible output
    h.set(enc("        "), 148);
    h[156] = 48;
    h.set(enc("ustar\0" + "00"), 257);
    h.set(enc(prefix), 345);
    let sum = 0;
    for (const b of h) sum += b;
    h.set(enc(sum.toString(8).padStart(6, "0") + "\0 "), 148);
    chunks.push(h, data, new Uint8Array((512 - (data.length % 512)) % 512));
  }
  chunks.push(new Uint8Array(1024));
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

export function readArchive(bytes) {
  const format = detectFormat(bytes);
  const files = {};
  if (format === "zip") {
    let total = 0, count = 0;
    const raw = unzipSync(bytes, {
      filter: (f) => {
        if (f.name.endsWith("/")) return false;
        total += f.originalSize;
        if (++count > LIMITS.maxFiles || total > LIMITS.maxTotalBytes) throw new Error("archive too large");
        return true;
      },
    });
    for (const [n, d] of Object.entries(raw)) files[safePath(n)] = d;
  } else {
    Object.assign(files, parseTar(gunzipSync(bytes)));
  }
  return { format, files };
}

export function writeArchive(files, format) {
  const total = Object.values(files).reduce((n, d) => n + d.length, 0);
  if (total > LIMITS.maxTotalBytes) throw new Error("output too large");
  const clean = {};
  for (const [p, d] of Object.entries(files)) clean[safePath(p)] = d;
  const out = format === "zip" ? zipSync(clean, { mtime: new Date("2000-01-01") }) : gzipSync(buildTar(clean), { mtime: 0 });
  if (out.length > LIMITS.maxArchiveBytes) throw new Error("output archive exceeds size limit");
  return out;
}

export function isText(u8) {
  const n = Math.min(u8.length, 4096);
  for (let i = 0; i < n; i++) if (u8[i] === 0) return false;
  return true;
}
export { strToU8, strFromU8 };

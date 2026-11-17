// AES-GCM at-rest encryption and HMAC-signed download links. Web Crypto only.
const enc = new TextEncoder();
async function key(secret, usage, info) {
  const base = await crypto.subtle.importKey("raw", enc.encode(secret), "HKDF", false, ["deriveKey"]);
  const alg = usage.includes("sign") ? { name: "HMAC", hash: "SHA-256" } : { name: "AES-GCM", length: 256 };
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("archive-mcp-v1"), info: enc.encode(info) },
    base, alg, false, usage);
}
export async function encrypt(secret, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await key(secret, ["encrypt", "decrypt"], "data"), data));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return out;
}
export async function decrypt(secret, blob) {
  const u = new Uint8Array(blob);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: u.subarray(0, 12) }, await key(secret, ["encrypt", "decrypt"], "data"), u.subarray(12)));
}
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
export async function sign(secret, msg) {
  return hex(await crypto.subtle.sign("HMAC", await key(secret, ["sign", "verify"], "link"), enc.encode(msg)));
}
export function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

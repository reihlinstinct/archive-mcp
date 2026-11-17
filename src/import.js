// Fetch an archive from a public URL: a Google Drive share link, a Dropbox
// share link, or a direct download on GitHub/GitLab. The Worker is public and
// reachable by anyone with the client credentials, so this fetcher is an SSRF
// surface: https only, an explicit host allowlist, manual redirects with every
// hop re-validated, and a hard size cap.
import { detectFormat, readArchive, LIMITS } from "./archive.js";

export const ALLOWED_HOSTS = new Set([
  "drive.usercontent.google.com", // Google Drive direct-download endpoint
  "drive.google.com",
  "docs.google.com",
  "www.dropbox.com",
  "dl.dropboxusercontent.com",
  "github.com",
  "codeload.github.com",
  "objects.githubusercontent.com",
  "raw.githubusercontent.com",
  "media.githubusercontent.com",
  "gitlab.com",
]);

const MAX_HOPS = 3;

// Normalize a user-supplied link into a direct-download URL on an allowlisted
// host. Throws with a user-readable reason when the link cannot be used.
export function normalizeUrl(raw) {
  let u;
  try { u = new URL(String(raw || "").trim()); } catch { throw new Error("invalid URL"); }
  if (u.protocol !== "https:") throw new Error("https links only");
  u.hash = "";
  if (u.hostname === "drive.google.com" || u.hostname === "docs.google.com") {
    const m = /\/file\/d\/([\w-]+)/.exec(u.pathname);
    const id = (m && m[1]) || u.searchParams.get("id") || "";
    if (!id) throw new Error("cannot read this Google Drive link; paste the file's own share link (Drive > Share > Copy link)");
    u = new URL("https://drive.usercontent.google.com/download?id=" + encodeURIComponent(id) + "&export=download&confirm=t");
  } else if (u.hostname === "www.dropbox.com") {
    u.searchParams.set("dl", "1"); // raw file instead of the preview page
  }
  if (!ALLOWED_HOSTS.has(u.hostname))
    throw new Error("host not supported: " + u.hostname + ". Use a Google Drive share link, a Dropbox share link, or a direct download link on GitHub or GitLab.");
  return u;
}

function fileName(res, u) {
  const cd = res.headers.get("content-disposition") || "";
  const star = cd.indexOf("filename*=");
  if (star >= 0) {
    const v = cd.slice(star + 10).split(";")[0].trim().replace(/^"|"$/g, "");
    const i = v.indexOf("''");
    try { return decodeURIComponent(i >= 0 ? v.slice(i + 2) : v); } catch { /* fall through to the plain filename form */ }
  }
  const q = cd.indexOf('filename="');
  if (q >= 0) {
    const e = cd.indexOf('"', q + 10);
    if (e > q + 10) return cd.slice(q + 10, e);
  }
  const seg = u.pathname.split("/").pop() || "";
  try { return decodeURIComponent(seg); } catch { return seg; } // malformed percent-encoding: use it raw, sanitized by the caller
}

// Download and fully validate the archive. Returns { bytes, format, name }.
export async function importFromUrl(raw, fetchImpl = fetch) {
  let u = normalizeUrl(raw);
  for (let hop = 0; hop <= MAX_HOPS; hop++) {
    const res = await fetchImpl(u, { redirect: "manual", headers: { "user-agent": "archive-mcp/1.0", accept: "application/zip,application/gzip,application/octet-stream,*/*" } });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) throw new Error("redirect without a location");
      u = normalizeUrl(new URL(loc, u).toString()); // every redirect hop is re-validated
      continue;
    }
    if (!res.ok) {
      const g = u.hostname.includes("google");
      throw new Error("download failed (HTTP " + res.status + ")" + (g ? " - is the file shared as 'anyone with the link'?" : ""));
    }
    const len = +(res.headers.get("content-length") || 0);
    if (len > LIMITS.maxArchiveBytes) throw new Error("file is over the 20 MB limit");
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (!bytes.length || bytes.length > LIMITS.maxArchiveBytes) throw new Error("file must be 1 byte to 20 MB");
    const format = detectFormat(bytes); // throws unless ZIP or tar.gz
    readArchive(bytes); // full parse: corrupt archives and path traversal rejected here
    const name = (fileName(res, u) || "archive").replace(/[^\w.-]/g, "_").replace(/\.(zip|tar\.gz|tgz)$/i, "").slice(0, 60) || "archive";
    return { bytes, format, name };
  }
  throw new Error("too many redirects");
}

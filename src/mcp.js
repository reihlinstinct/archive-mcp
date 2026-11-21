// Minimal stateless MCP (JSON-RPC 2.0 over streamable HTTP, JSON responses).
import { readArchive, writeArchive, isText, strToU8, strFromU8, safePath, detectFormat, LIMITS } from "./archive.js";
import { importFromUrl } from "./import.js";
import { digestHex } from "./crypto.js";

export const TOOLS = [
  { name: "list_archives", description: "List archives currently on this server (id, name, format, size). Archives expire after 24 hours. Files attached in the chat are NOT here: import a public link with import_archive, or give the user a one-time upload link from request_upload_link.", inputSchema: { type: "object", properties: {} }, annotations: { readOnlyHint: true } },
  { name: "import_archive", description: "Import an archive (ZIP or tar.gz, up to 20 MB) from a public https link the user provides: a Google Drive 'anyone with the link' share link, a Dropbox share link, or a direct download link on GitHub or GitLab. Returns the archive id and its file tree. Use this whenever the user gives you a link to an archive; afterwards use list_files/read_file/search with the returned id.", inputSchema: { type: "object", properties: { url: { type: "string", description: "Public https link to the archive" }, name: { type: "string", description: "Optional display name" } }, required: ["url"] }, annotations: { readOnlyHint: false, openWorldHint: true } },
  { name: "request_upload_link", description: "Get a one-time upload link (valid 15 minutes, one archive up to 20 MB, no access token needed) and give it to the user. Use this when the user's archive is a local file or a chat attachment, which this server cannot see. After they upload, the page shows the new archive id and you can also call list_archives.", inputSchema: { type: "object", properties: {} }, annotations: { readOnlyHint: false } },
  { name: "list_files", description: "List files inside an archive with sizes. Needs an archive id from list_archives or import_archive, or from the user after they upload.", inputSchema: { type: "object", properties: { id: { type: "string" }, prefix: { type: "string" } }, required: ["id"] }, annotations: { readOnlyHint: true } },
  { name: "read_file", description: "Read one text file from an archive. Returns at most 32 KB per call; use offset/length (bytes) to page through large files. Needs an archive id.", inputSchema: { type: "object", properties: { id: { type: "string" }, path: { type: "string" }, offset: { type: "integer" }, length: { type: "integer" } }, required: ["id", "path"] }, annotations: { readOnlyHint: true } },
  { name: "search", description: "Case-insensitive substring search across text files in an archive. Returns path:line matches. Needs an archive id.", inputSchema: { type: "object", properties: { id: { type: "string" }, query: { type: "string" }, max_results: { type: "integer" } }, required: ["id", "query"] }, annotations: { readOnlyHint: true } },
  { name: "debug_echo_context", description: "Diagnostic: echo back exactly what arguments and context the client passed to this tool (keys, types, sizes, short previews). Nothing is stored beyond a 1-hour structural log without file contents. Use only when the user asks what the client sends to this server.", inputSchema: { type: "object", additionalProperties: true }, annotations: { readOnlyHint: true } },
  { name: "edit_file", description: "Edit one text file inside an archive with literal find/replace, applied server-side, so even large files can be edited with tiny arguments (rewriting a whole file through create_archive needs its full content inline, which chat clients cannot generate beyond a few KB). The archive keeps the same id. Editing is read-modify-write with a content revision check: if the archive changed since this call read it (even to different content of the same byte length) the write is refused and the call retries once on fresh content. Truly simultaneous writes can still race, so edit one archive at a time. Edits apply in order; each find must be present or nothing is written. Afterwards repack or download with create_archive (base_id) as usual.", inputSchema: { type: "object", properties: { id: { type: "string" }, path: { type: "string" }, edits: { type: "array", items: { type: "object", properties: { find: { type: "string", description: "Literal text to find; must occur or the whole call fails" }, replace: { type: "string", description: "Replacement text (may be empty)" }, count: { type: "integer", description: "Max replacements, default 1; pass 0 to replace every occurrence" } }, required: ["find", "replace"] } } }, required: ["id", "path", "edits"] }, annotations: { readOnlyHint: false } },
  { name: "create_archive", description: "Create a ZIP or tar.gz from files (path + text content). With base_id, start from that archive: files overwrite or add, delete_paths removes. Returns an id and a short-lived download URL the user can open.", inputSchema: { type: "object", properties: { format: { type: "string", enum: ["zip", "tar.gz"] }, name: { type: "string" }, base_id: { type: "string" }, files: { type: "array", items: { type: "object", properties: { path: { type: "string" }, content: { type: "string" } }, required: ["path", "content"] } }, delete_paths: { type: "array", items: { type: "string" } } }, required: ["format", "name"] }, annotations: { readOnlyHint: false } },
];

const text = (t) => ({ content: [{ type: "text", text: t }] });

// Model-facing guidance (MCP initialize instructions): chat attachments never
// reach this server, so the model must route the user through the upload page
// first instead of trying to read the attachment itself.
export function serverInstructions(store) {
  const page = store && store.origin ? store.origin + "/" : "the server's upload page";
  return "Archive-mcp reads and creates ZIP and tar.gz archives that live on this server; stored archives expire 24 hours after upload. " +
    "Files attached in this chat are never forwarded to this server. When the user gives a public link to an archive " +
    "(Google Drive share link, Dropbox, GitHub, GitLab), import it with import_archive. When the user only has a local file " +
    "or a chat attachment, give them a one-time upload link from request_upload_link (or the upload page at " + page + " with their access token). " +
    "Once an archive is on the server, use list_files, read_file and search with the archive id, and create_archive to build new archives with a download link.";
}
const fail = (t) => ({ content: [{ type: "text", text: t }], isError: true });

// Structural summary of tool input: keys, types, sizes, 200-char previews.
// Enough to see whether the client hands the model a file reference, without
// retaining file contents anywhere.
function summarize(v, d) {
  if (d > 4) return "...";
  if (v === null || v === undefined) return null;
  if (Array.isArray(v)) return { type: "array", length: v.length, items: v.slice(0, 5).map((x) => summarize(x, d + 1)) };
  if (typeof v === "object") {
    const o = {};
    for (const k of Object.keys(v).slice(0, 20)) o[k] = summarize(v[k], d + 1);
    return { type: "object", keys: Object.keys(v).length, value: o };
  }
  if (typeof v === "string") return { type: "string", length: v.length, preview: v.slice(0, 200) };
  return { type: typeof v, value: v };
}

export async function callTool(name, args, store, fetchImpl = fetch, meta) {
  try {
    switch (name) {
      case "list_archives": {
        const items = await store.list();
        return text(items.length ? items.map((i) => `${i.id}  ${i.name}  ${i.format}  ${i.size} bytes  ${i.created ? new Date(i.created).toISOString() : "unknown-time"}`).join("\n") : "No archives yet. Import one with import_archive (public link) or give the user a one-time upload link via request_upload_link.");
      }
      case "import_archive": {
        const imp = await importFromUrl(args.url, fetchImpl);
        const fname = String(args.name || imp.name + "." + (imp.format === "zip" ? "zip" : "tar.gz")).replace(/[^\w.-]/g, "_").slice(0, 80);
        const id = await store.put(imp.bytes, fname, imp.format);
        const { files } = readArchive(imp.bytes);
        const rows = Object.keys(files).sort().map((p) => `${files[p].length}\t${p}`);
        const CAP = 200;
        const extra = rows.length > CAP ? `\n[${rows.length - CAP} more files; call list_files]` : "";
        return text(`Imported ${fname} (${rows.length} files, ${imp.bytes.length} bytes), id ${id}. Expires in 24 hours.\n` + rows.slice(0, CAP).join("\n") + extra);
      }
      case "debug_echo_context": {
        const report = { arguments: summarize(args, 0), client_meta: summarize(meta, 0) };
        if (typeof store.putDebug === "function") await store.putDebug(JSON.stringify(report).slice(0, 4000));
        return text("What the client passed to this tool:\n" + JSON.stringify(report, null, 2));
      }
      case "request_upload_link": {
        const token = await store.putUploadToken();
        return text(`Give the user this one-time upload link (valid 15 minutes, one archive up to 20 MB, no access token needed):\n${store.origin}/u/${token}\nAfter they upload, the page shows the new archive id; you can also call list_archives to find it.`);
      }
      case "list_files": {
        const { files } = readArchive(await store.get(args.id));
        const pre = args.prefix || "";
        const rows = Object.keys(files).filter((p) => p.startsWith(pre)).sort().map((p) => `${files[p].length}\t${p}`);
        return text(`${rows.length} files\n` + rows.join("\n"));
      }
      case "read_file": {
        const { files } = readArchive(await store.get(args.id));
        const d = files[safePath(args.path)];
        if (!d) return fail("no such file: " + args.path);
        if (!isText(d)) return fail(`binary file, ${d.length} bytes`);
        const off = Math.max(0, args.offset | 0);
        const len = Math.min(LIMITS.maxReadBytes, args.length > 0 ? args.length : LIMITS.maxReadBytes);
        const part = d.subarray(off, off + len);
        const more = off + len < d.length ? `\n[truncated: ${d.length} bytes total, continue at offset ${off + len}]` : "";
        return text(strFromU8(part) + more);
      }
      case "search": {
        const { files } = readArchive(await store.get(args.id));
        const q = String(args.query || "").toLowerCase();
        if (!q) return fail("empty query");
        const max = Math.min(args.max_results > 0 ? args.max_results : 100, 500);
        const out = [];
        for (const p of Object.keys(files).sort()) {
          if (!isText(files[p])) continue;
          strFromU8(files[p]).split("\n").forEach((l, i) => { if (out.length < max && l.toLowerCase().includes(q)) out.push(`${p}:${i + 1}: ${l.slice(0, 200)}`); });
        }
        return text(out.length ? out.join("\n") : "no matches");
      }
      case "edit_file": {
        const p = safePath(String(args.path || ""));
        const edits = Array.isArray(args.edits) ? args.edits : [];
        if (!edits.length) return fail("edits must be a non-empty array of {find, replace, count?}");
        // read-modify-write with optimistic concurrency: store.replace refuses
        // (code CONFLICT) if the archive changed since we read it; retry once.
        let attempt = 0, result;
        while (true) {
          try {
            const bytes = await store.get(args.id);
            const format = detectFormat(bytes);
            const { files } = readArchive(bytes);
            const data = files[p];
            if (!data) return fail("no such file: " + args.path);
            if (!isText(data)) return fail(`binary file, ${data.length} bytes - edit_file handles text files only`);
            const orig = strFromU8(data);
            let s = orig;
            let total = 0;
            for (let i = 0; i < edits.length; i++) {
              const f = String(edits[i] && edits[i].find != null ? edits[i].find : "");
              const r = String(edits[i] && edits[i].replace != null ? edits[i].replace : "");
              if (!f) return fail(`edit ${i + 1}: find must be non-empty`);
              if (!s.includes(f)) return fail(`edit ${i + 1}: find text not present, no changes written: ${JSON.stringify(f.slice(0, 80))}`);
              const max = edits[i].count > 0 ? Math.floor(edits[i].count) : edits[i].count === 0 ? Infinity : 1;
              let from = 0, out = "", done = 0;
              while (done < max) {
                const at = s.indexOf(f, from);
                if (at < 0) break;
                out += s.slice(from, at) + r;
                from = at + f.length;
                done++;
              }
              s = out + s.slice(from);
              total += done;
            }
            files[p] = strToU8(s);
            await store.replace(args.id, writeArchive(files, format), { expectSize: bytes.length, expectRev: await digestHex(bytes) });
            // first changed line: where the edited text first diverges from the original
            let d = 0;
            while (d < orig.length && d < s.length && orig[d] === s[d]) d++;
            const ln = s.slice(0, d).split("\n").length;
            const lines = s.split("\n");
            result = text(`Edited ${p} in archive ${args.id} (same id): ${total} replacement${total === 1 ? "" : "s"} across ${edits.length} edit${edits.length === 1 ? "" : "s"}. First change at line ${ln}:\n${p}:${ln}: ${lines[ln - 1] ? lines[ln - 1].slice(0, 200) : ""}`);
            break;
          } catch (e) {
            if (e && e.code === "CONFLICT" && attempt++ === 0) continue;
            throw e;
          }
        }
        return result;
      }
      case "create_archive": {
        if (!["zip", "tar.gz"].includes(args.format)) return fail("format must be zip or tar.gz");
        const files = args.base_id ? readArchive(await store.get(args.base_id)).files : {};
        for (const p of args.delete_paths || []) delete files[safePath(p)];
        for (const f of args.files || []) files[safePath(f.path)] = strToU8(String(f.content));
        const bytes = writeArchive(files, args.format);
        const base = String(args.name || "archive").replace(/[^\w.-]/g, "_").replace(/\.(zip|tar\.gz|tgz)$/i, "");
        const filename = base + (args.format === "zip" ? ".zip" : ".tar.gz");
        const id = await store.put(bytes, filename, args.format);
        const url = await store.downloadUrl(id);
        return text(`Created ${filename} (${Object.keys(files).length} files, ${bytes.length} bytes), id ${id}.\nDownload (valid 1 hour): ${url}`);
      }
      default:
        return fail("unknown tool: " + name);
    }
  } catch (e) {
    return fail(String(e && e.message || e));
  }
}

export async function handleRpc(msg, store) {
  const { id, method, params } = msg;
  const ok = (result) => ({ jsonrpc: "2.0", id, result });
  if (id === undefined) return null; // notification
  switch (method) {
    case "initialize":
      return ok({ protocolVersion: params?.protocolVersion || "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "archive-mcp", version: "0.2.0" }, instructions: serverInstructions(store) });
    case "ping": return ok({});
    case "tools/list": return ok({ tools: TOOLS });
    case "tools/call": return ok(await callTool(params?.name, params?.arguments || {}, store, undefined, params?._meta));
    default: return { jsonrpc: "2.0", id, error: { code: -32601, message: "method not found" } };
  }
}

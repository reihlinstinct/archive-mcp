// Minimal stateless MCP (JSON-RPC 2.0 over streamable HTTP, JSON responses).
import { readArchive, writeArchive, isText, strToU8, strFromU8, safePath, LIMITS } from "./archive.js";

export const TOOLS = [
  { name: "list_archives", description: "List archives the user uploaded (id, name, format, size). They expire after 24 hours.", inputSchema: { type: "object", properties: {} } },
  { name: "list_files", description: "List files inside an archive with sizes.", inputSchema: { type: "object", properties: { id: { type: "string" }, prefix: { type: "string" } }, required: ["id"] } },
  { name: "read_file", description: "Read one text file from an archive. Use offset/length (bytes) for large files.", inputSchema: { type: "object", properties: { id: { type: "string" }, path: { type: "string" }, offset: { type: "integer" }, length: { type: "integer" } }, required: ["id", "path"] } },
  { name: "search", description: "Case-insensitive substring search across text files in an archive. Returns path:line matches.", inputSchema: { type: "object", properties: { id: { type: "string" }, query: { type: "string" }, max_results: { type: "integer" } }, required: ["id", "query"] } },
  { name: "create_archive", description: "Create a ZIP or tar.gz from files (path + text content). With base_id, start from that archive: files overwrite or add, delete_paths removes. Returns an id and a short-lived download URL.", inputSchema: { type: "object", properties: { format: { type: "string", enum: ["zip", "tar.gz"] }, name: { type: "string" }, base_id: { type: "string" }, files: { type: "array", items: { type: "object", properties: { path: { type: "string" }, content: { type: "string" } }, required: ["path", "content"] } }, delete_paths: { type: "array", items: { type: "string" } } }, required: ["format", "name"] } },
];

const text = (t) => ({ content: [{ type: "text", text: t }] });
const fail = (t) => ({ content: [{ type: "text", text: t }], isError: true });

export async function callTool(name, args, store) {
  try {
    switch (name) {
      case "list_archives": {
        const items = await store.list();
        return text(items.length ? items.map((i) => `${i.id}  ${i.name}  ${i.format}  ${i.size} bytes`).join("\n") : "No archives. Upload one on the upload page.");
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
      return ok({ protocolVersion: params?.protocolVersion || "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "archive-mcp", version: "0.1.0" } });
    case "ping": return ok({});
    case "tools/list": return ok({ tools: TOOLS });
    case "tools/call": return ok(await callTool(params?.name, params?.arguments || {}, store));
    default: return { jsonrpc: "2.0", id, error: { code: -32601, message: "method not found" } };
  }
}

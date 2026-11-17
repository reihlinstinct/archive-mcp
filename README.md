# archive-mcp

[![CI](https://github.com/reihlinstinct/archive-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/reihlinstinct/archive-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A remote MCP server (Cloudflare Worker, free tier) that lets an AI client read ZIP and tar.gz files it cannot accept as uploads, and hand code back as a new ZIP or tar.gz.

## How it works

Chat attachments never reach an MCP server, so archives get onto this server first, then the client works with them by id:

1. **From a public link**: give the client a Google Drive "anyone with the link" share link, a Dropbox share link, or a direct download link on GitHub/GitLab. It calls `import_archive`, and the Worker fetches the file server-side (https only, host allowlist, max 20 MB).
2. **From your device**: ask the client for an upload link - it calls `request_upload_link` and hands you a one-time link (15 minutes, no access token). Or open the Worker's root page and upload with your access token.
3. The client then works with the archive by id: `list_archives`, `list_files`, `read_file` (32 KB per call, paged), `search`, `create_archive` (new, or based on an uploaded archive with changes and deletions). `create_archive` returns a download link valid for one hour.

Archives are encrypted at rest (AES-GCM), kept 24 hours in Workers KV, then deleted. **Do not upload personal or family data**: KV replicates globally and the region can't be pinned.

## Connect

- Gemini CLI: `gemini mcp add --transport http -s user archive https://<worker>/mcp --header "Authorization: Bearer <token>"`
- Gemini web app custom connector: add an MCP server at `https://<worker>/mcp` with the OAuth client ID and client secret the operator gave you. The Worker speaks authorization-code + PKCE and serves discovery metadata at `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource`. The connector's redirect URI must be in the Worker's allowlist (Worker secret `OAUTH_REDIRECT_URIS`).

## Deploy

Needs a Cloudflare account (free) and these repo secrets: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`. Then set Worker secrets `AUTH_TOKEN` and `ENC_SECRET` (long random strings) with `npx wrangler secret put`, and run the Deploy workflow.

## Develop

`npm ci && npm test`. Limits: 20 MB archive, 100 MB unpacked, 5000 files, 32 KB per read.

## Security

See [SECURITY.md](SECURITY.md). Reports go through GitHub private vulnerability reporting; the Worker also serves `/.well-known/security.txt`.

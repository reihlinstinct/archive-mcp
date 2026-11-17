# archive-mcp

[![CI](https://github.com/reihlinstinct/archive-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/reihlinstinct/archive-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A remote MCP server (Cloudflare Worker, free tier) that lets an AI client read ZIP and tar.gz files it cannot accept as uploads, and hand code back as a new ZIP or tar.gz.

## How it works

1. Open the Worker's root page, enter your access token, upload an archive (max 20 MB). You get an archive id.
2. Connect your AI client to `https://<worker>/mcp` with `Authorization: Bearer <token>`.
3. The client calls tools: `list_archives`, `list_files`, `read_file`, `search`, `create_archive` (new, or based on an uploaded archive with changes and deletions). `create_archive` returns a download link valid for one hour.

Archives are encrypted at rest (AES-GCM), kept 24 hours in Workers KV, then deleted. **Do not upload personal or family data**: KV replicates globally and the region can't be pinned.

## Connect

- Gemini CLI: `gemini mcp add --transport http -s user archive https://<worker>/mcp --header "Authorization: Bearer <token>"`
- Gemini web app custom connector: add an MCP server at `https://<worker>/mcp` with the OAuth client ID and client secret the operator gave you. The Worker speaks authorization-code + PKCE and serves discovery metadata at `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource`. The connector's redirect URI must be in the Worker's allowlist (Worker secret `OAUTH_REDIRECT_URIS`).

## Deploy

Needs a Cloudflare account (free) and these repo secrets: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`. Then set Worker secrets `AUTH_TOKEN` and `ENC_SECRET` (long random strings) with `npx wrangler secret put`, and run the Deploy workflow.

## Develop

`npm ci && npm test`. Limits: 20 MB archive, 100 MB unpacked, 5000 files, 256 KB per read.

## Security

See [SECURITY.md](SECURITY.md). Reports go through GitHub private vulnerability reporting; the Worker also serves `/.well-known/security.txt`.

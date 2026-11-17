# Security policy

Report vulnerabilities privately through GitHub: Security > Report a vulnerability on this repository.

Design notes: every endpoint except the upload page and signed download links needs a bearer token. Archives are encrypted with AES-GCM before they reach Workers KV and expire after 24 hours. Paths with `..` or absolute paths are rejected in both directions. Size limits: 20 MB archive, 100 MB unpacked, 5000 files.
Do not upload personal, family or regulated data. Workers KV is replicated globally and the region cannot be pinned.

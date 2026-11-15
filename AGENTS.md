# Infrastructure working rules

This repository is a sanitized snapshot of DMIT source code and selected local
release material. `source/opt/...` and `source/usr/...` mirror production paths,
but the live server and its databases remain the authority for current state.

Before changing a service, read the related `README.md`, `CLOUD-HANDOFF.md`,
`source-manifest.json`, and relevant `docs/` entry. Check the live host and
active unit paths read-only before deployment because units and routes can
change. Preserve the current user-requested routing behavior, user access
controls, expiry policy, and all active copies of shared policy modules.

Do not add credentials, private keys, TLS key material, cookies, full private
subscription links, customer or billing data, raw databases, logs, backups,
or runtime-generated configuration. Use placeholders in examples. Every
export-only redaction is recorded in `source-manifest.json`; placeholder
values and paths are not deployable production defaults. Never assume this snapshot alone can
be deployed as-is.

For a change: make a small diff, run relevant tests, compare live file hashes,
back up affected production files, release atomically, and verify the public
endpoint and the full service receipt. Keep rollback evidence outside Git.
Cloud tasks have no production SSH credential until a separately scoped
deployment channel is established.

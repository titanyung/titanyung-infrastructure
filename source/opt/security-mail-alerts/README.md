# Confirmed violation email notifications

Recipient is fixed at `titan@titanyung.top`. This component does not change
subscription contents, account credentials, or traffic accounting tables.

## Post-release format audit and corrections

Actual dedicated-core journals encode ANSI-containing `MESSAGE` fields as JSON
arrays of UTF-8 bytes. The watcher now explicitly decodes those arrays before
stripping ANSI and correlating user/connection evidence. `journalctl --all` was
tested and still returned arrays. The corrected DMIT watcher is deployed and
real authenticated connection contexts are being persisted. A regression test
covers an actual ANSI byte-array shape and a username containing literal `+`.
BWH received the same correction after its temporary management key was
unlocked again. A controlled ordinary HTTPS request through BWH's dedicated
NexIP entry produced a real new authenticated context in the evidence database.

SUI's embedded logger additionally emits context-free syslog lines by default.
Those lines contain the inbound authenticated user, but neither they nor the
outbound line contain the connection ID required for strict correlation. The
watcher does not guess ownership using adjacent lines. The installed binary is
`deposist/s-ui-x 1.5.11`; its full-context stdout formatter was verified in an
isolated network namespace using only synthetic users/data. Both hosts have
the identical installed binary hash. Only persistent log options `level: info`,
`output: stdout`, and `timestamp: true` were then changed, with backup/CAS and
exact verification that all non-log configuration was unchanged. Do not add
`disable_color`: the installed version rejects that JSON field.

Production ordinary HTTPS tests through the actual SUI ports (DMIT 8443 and
BWH 443) both returned HTTP 200 with successful TLS verification. Each controlled
request yielded exactly one full-CID authenticated journal entry and exactly one
new user context in the watcher database. The old traffic collector matched only
one copy of the entry, so the extra stdout log did not double the accounting.
All four entrypoint sources are now observable and report no errors.

An unrelated proxyHive connectivity failure was investigated after release.
The runtime HTTP endpoint is `178.93.182.237:45224`; protocol, endpoint, username,
and password match the pre-release snapshot and persistent private map. Every
non-BT outbound matches that snapshot. SUI's non-BT outbound rows also match the
release backup byte for byte. No provider value was changed to hide the failure.

## Live release on 2026-10-26 (Asia/Singapore)

| Server | Protected entrypoints | Backup |
| --- | --- | --- |
| DMIT | SUI and dedicated direct/static core | `/var/backups/security-bt-DMIT-20261025T172631Z` |
| BWH | SUI and dedicated multi-egress core | `/var/backups/security-bt-BWH-20261025T173553Z` |

Separate logging-only backups:

| Server | Backup | SUI listener ports |
| --- | --- | --- |
| DMIT | `/var/backups/sui-context-log-DMIT-20261025T181349Z` | 8443, 29503, 29504, 29505 |
| BWH | `/var/backups/sui-context-log-BWH-20261025T181442Z` | 443 |

Both hosts now have the same persistent services:

- `security-bt-quarantine.service`: `127.0.0.1:18115`. A bounded SOCKS refusal
  endpoint. It accepts no SOCKS method and implements no DNS, external connect,
  CONNECT, or UDP relay. Its systemd policy disallows non-loopback IP traffic.
- `security-confirmed-events.service`: read-only journal watcher, own SQLite
  evidence database `/var/lib/security-mail-alerts/confirmed-events.db`, local API
  `127.0.0.1:18114`. It does not write to the existing traffic database.

SUI's persistent database route and outbounds were changed using a backup and
compare-and-swap transaction. Each dedicated renderer has a small
`security_bt_policy_hook` immediately before returning its generated config.
Generated runtime files alone were not used as the persistent configuration.
The original BitTorrent reject rule is retained behind the quarantine rule.

The first VPS is the notification source. The active subscription entrances are
DMIT and BWH; downstream ByteVirt is not separately emailed for the same flow.
Retired NoSLA and GoMami are not modified. This release monitors the explicit BT
policy. Subscription request/IP thresholds remain risk indicators rather than
confirmed violations. Generic UDP rejection, fallback rejection, DNS names
containing `bittorrent`, and protocol sniff alone do not generate notifications.

## Evidence and performance

The BT-only route uses an exclusively reserved outbound tag
`violation-bt-quarantine`, targeting the local refusal endpoint. An authenticated
inbound user, connection ID, process epoch, and an INFO outbound hit of that
exclusive tag are required. The configured tag is revalidated on each hit.
Changing/removing that exclusive policy stops trusting its hits.

This avoids enabling DEBUG in production. Current sing-box rejects a connection
before invoking connection trackers, so the normal gRPC connection stream does
not provide rejected BT events. The former traffic collector's test for the
word `bittorrent` in an ordinary inbound log is not used.

Isolated loopback fixtures with the already installed core confirmed:

- real TCP BT handshake and UDP tracker traffic hit the BT-specific tag;
- ordinary HTTP reaches the existing fallback reject and does not hit the tag;
- every possible fixture outbound is loopback; no external BT traffic is sent;
- INFO logging suffices, and no DEBUG lines are emitted.

No synthetic violation was inserted into either production outbox. Tests use
synthetic users only in isolated local listeners/databases. Existing real user
requests and risk alerts are not repurposed as test violations.

The watcher ignores irrelevant log lines, checkpoints their latest cursor at
most twice per second, writes batches of up to 128 entries or 200 ms in one
transaction, and prunes expired connection context once per minute. Its journal
cursor, user context, and event proof persist across restarts. First activation
sets an exact current journal baseline, so it does not email historical events.
A DMIT 3-second process sample after this optimization used approximately 1.33%
CPU. After the logging correction, another 3-second sample measured DMIT SUI
0.67% and watcher 0.67%, BWH SUI 0% and watcher 0.67%. These are short samples
rather than load-test capacity claims.

## Mail and source transports

`alerts.py` provides the durable outbox and localhost status/events API (18112).
States are `pending_config`, `queued`, `sending`, `retry`, and `sent`. Failed SMTP
attempts back off and retry. A source event ID is enqueued once. A deterministic
Message-ID is reused after retry; SMTP delivery is at least once, since a crash
after remote acceptance but before local acknowledgement may repeat that ID.

The DMIT worker's local source reads only the new confirmed-events database.
The BWH source uses a separate root-0600 Ed25519 key:

```json
{"id":"bwh-confirmed","type":"ssh","host":"root@45.78.70.23","port":26274,"identity":"/root/.ssh/security-events-bwh","known_hosts":"/var/lib/user-daily-traffic/bwh-known-hosts","poll_seconds":5}
```

BWH authorization uses `restrict`, `from="179.255.136.79"`, and exactly
`/usr/bin/python3 -I /opt/security-mail-alerts/export_confirmed_events.py` as its
forced command. It accepts only `bt-events <after_id> <limit>` with bounded
non-negative integers, up to 1000 events and 2 MB. It opens SQLite read-only.
Arbitrary SSH commands were tested and rejected. It does not reuse or expand
the daily accounting key. The pinned hostkeys were copied from the previously
validated connection rather than an unauthenticated fresh keyscan.

Incremental response:

```json
{"max_id":123,"events":[{"id":123,"ts":1792940000,"user":"example","source":"BWH/SUI","kind":"bt-block","detail":"..."}],"coverage":{"sources":[{"source_id":"BWH/SUI","last_seen":1792940000,"last_error":null,"policy_verified_at":1792940000,"policy":{"observable":true,"confirmed_rules":["bittorrent → loopback 拒绝"],"evidence":"authenticated user + connection id + exclusive quarantine outbound","log_level":"info"},"observable":true}],"confirmed_kinds":["bt-block"],"subscription_risk_is_violation":false}}
```

`limit=0` returns only the current monotonic high watermark and no old events.
`max_id` for a nonempty bounded batch is the last returned event, avoiding skips
when more than 1000 events are pending. Sequence high watermark survives event
retention. Unattributed events are never assigned to a guessed user.

SMTP credentials are currently a required user-supplied setting, not something
the application can infer. The existing domain MX is Feishu. All tested DMIT
outbound TCP 25 attempts to its MX servers timed out; no SMTP envelope or message
was sent. Direct MX delivery is not a working substitute for a configured relay.
The protected UI defaults to Feishu SSL SMTP on `smtp.feishu.cn:465` and accepts
the mailbox's third-party client password. It never returns that password.
Until configured, new confirmed events remain durably pending.

The central worker and both confirmed sources are now live. Verification read
`monitoring_ready=true`, two host groups/four healthy runtime sources and
`state=pending_config`, with no synthetic production events. Worker rollback is
`/var/backups/mail-confirmed-sources.gJXcZj`. SSH reads are bounded at 2 MB/10 s,
pin the host key, disable forwarding/PTY and invoke no local shell. Health is
allowlisted and cached; a policy verification older than 15 seconds is not
reported as observable. SMTP private values and source command/key paths never
appear in the status response.

The final UI shows recent notification states, source freshness, Feishu help
and editable mailbox defaults. Its backup is
`/var/backups/mail-ui-complete.GEHH8u`. The user currently cannot find the
third-party-client setting: only the installed Feishu desktop client generates
personal mailbox passwords, with administrator enablement required. Public
mailboxes instead enable IMAP/SMTP in the Admin Console's mailbox edit page.
No actual mail delivery has been claimed or recorded by this release.

The configuration plugin reuses existing admin authentication, exact Origin,
and the existing TOTP/view-key verifier. Nginx must forward
`X-Forwarded-Host $http_host` so the externally used port is checked. Saving and
manual test both require that existing protection. A manually requested test
mail is explicitly titled `[测试通知]`, never falsely described as misconduct.

## Verification and rollback

Run local tests without the conflicting user-site Flask dependencies:

```powershell
python -s -m unittest discover -s ops/security-mail-alerts -p 'test_*.py' -v
node --check ui/violation-mail-ui.js
```

The final root validation recorded 29 passing backend tests and 83 passing UI
fixture assertions, plus JavaScript syntax validation and the existing real
mobile-layout check. Installed-binary logger evidence is saved in
`qa-output/sui-stdout-proof.json`.

The complete Python suite currently has 26 passing tests, including the SSH
transport/health additions. The final UI has 80 synthetic cross-viewport
checks and a read-only production mobile check. No test called the live send
endpoint. Temporary browser Basic Auth users and credential JSON were removed.

The rollback helper verifies that neither the route nor the renderer has changed
since this release. It restores only this release's route/outbound and renderer,
preserving users, subscriptions, historical traffic, and evidence data. It then
restarts the two cores and disables only these new security services. Restore
the separate logging-only change **first**, so the subsequent BT policy CAS
matches its exact expected configuration. DMIT example:

```sh
python3 /opt/security-mail-alerts/enable_sui_context_logging.py \
  --host DMIT --ports 8443 29503 29504 29505 \
  --restore /var/backups/sui-context-log-DMIT-20261025T181349Z

python3 /opt/security-mail-alerts/rollback_bt_policy.py \
  --backup /var/backups/security-bt-DMIT-20261025T172631Z \
  --renderer /opt/dmit-direct-staging/render.py --unit dmit-direct-staging
```

BWH follows the same order:

```sh
python3 /opt/security-mail-alerts/enable_sui_context_logging.py \
  --host BWH --ports 443 \
  --restore /var/backups/sui-context-log-BWH-20261025T181442Z

python3 /opt/security-mail-alerts/rollback_bt_policy.py \
  --backup /var/backups/security-bt-BWH-20261025T173553Z \
  --renderer /opt/bwh-multi-egress-stage/render_stage.py --unit bwh-multi-egress-stage
```

Do not restore an entire old SUI database over newly added users. If unrelated
configuration changed after release, either helper refuses the conflicting CAS
rather than overwriting those later changes.

Primary implementation references:

- https://sing-box.sagernet.org/configuration/route/rule_action/
- https://sing-box.sagernet.org/configuration/outbound/socks/
- https://github.com/SagerNet/sing-box/blob/7054cac5124465ffdb145870d7c01885566711b1/route/route.go
- https://github.com/deposist/s-ui-x/blob/main/core/log.go

# Daily per-user traffic accounting

Current topology (2026-11-05): DMIT and ByteVirt remain active and zorocloud is added. BWH and the other retired hosts are centrally archived; their historical counters remain. New DMIT→zorocloud observations are assigned to the authenticated user and the zorocloud peer. Relay application bytes are measured; remote egress remains explicitly marked as a forwarding-side estimate. See the current [service inventory](../gomami-migration/live-20260930/五台服务器服务清单与到期迁移计划.md). Older deployment details below describe their original dates.

The daily ledger is an application-byte accounting view. Its three columns
describe different logical boundaries and must not be added into a total.
All days use Asia/Singapore (UTC+08:00).

## Meaning of the columns

* `ingress`: authenticated user's application upload plus download observed
  on the first VPS (DMIT or BWH). An exit VPS never contributes ingress.
* `relay`: application bytes forwarded to an explicitly identified relay or
  residential proxy. A confirmed direct or rejected flow has an evidenced
  zero relay claim. An unknown route has no relay claim.
* `egress`: direct destination application bytes, or application bytes sent
  via an identified final exit. Residential proxy forwarding is marked
  `estimated=true, meter_basis=forwarded_application`; the provider's NIC is
  not being measured. An actual exit observer contributes egress only.

For a direct first-hop connection the same native application stream provides
ingress and egress evidence. This is not presented as two independent sensors.
If real exit observation is available, its priority 200 supersedes the
forwarder estimate (priority 100), per day/user/exit peer; the two are never
added together. Partial exit observation can undercount that authority and
must retain its collection gap rather than being called a complete sensor.

## Storage and integration

`DailyLedger.record(observations, observed_at=...)` accepts cumulative
connection counters from the hot ingest path. The identity consists of host,
runtime, native connection UUID and creation time in milliseconds. The same
identity must have stable user and role claims through NEW/UPDATE/CLOSED.
Only counter differences are charged, so an identical CLOSED replay does not
double count. A connection predating ledger activation is baselined, with a
visible gap, instead of charging its entire lifetime to today.

Positive deltas are assigned to their observation day. This does not split
past lifetime totals according to connection start time. A reconnect gap may
attribute missed final bytes to the recovery day; the gap remains visible.

Each host stores a small local `/var/lib/user-daily-traffic/daily.db`.
Initialize the central DMIT database with `source_key='DMIT'` before importing
other hosts. `export_snapshot` reads a consistent SQLite transaction; do not
copy an active DB/WAL file. `import_snapshot` atomically replaces one remote
source's rollups and is idempotent. It rejects an unexpected source key or
changed instance ID and ignores an older revision. Exports contain only the
host's local rows, never its mirrored rows, preventing loops.

The protected transport must use its existing trusted management identity.
Snapshot payloads contain usernames and traffic, so they are not public
subscription endpoints. Counter maintenance is bounded and indexed; no
periodic scan of the existing million-row unified ledger is necessary.

## Reader contract

`read_daily(path, from_day, to_day, user='', host='', limit=100, offset=0)`
returns one row per known user/day, three role objects or `null`, provenance,
estimated flags, source freshness, collection gaps, and totals over all
filtered rows before pagination. Literal usernames such as `a+b` are preserved.

Each role object includes `bytes`, `upload`, `download`, `estimated` and
`sources`. Each source carries host, peer, collector, meter basis, priority,
counter values, last observation and owning source key.

`register_users` records the enabled cohort from authenticated runtime
configuration, so idle users are not silently omitted. Without a complete
zero-usage proof their rows have `not_observed` and null roles; a day predating
that registry has `before_collection`. Neither state is converted to zero.

## Audited limitations

* Native dedicated sing-box collection covers all direct, dialer and static
  outbounds, using NEW/UPDATE/CLOSED and final cumulative reconciliation.
* Existing S-UI sessions are observed about once per second. A connection
  opening and closing between polls can be missed. Its source must retain
  a polling-quality gap and must not claim complete native observation.
* Existing S-UI daily `stats` does not cover the separate dedicated runtime.
  It cannot be used as a complete substitute or added to session totals.
* The old unified connection table stores latest lifetime counters. Grouping
  those by connection start time is not a correct per-day reconstruction.
* Only reliable, uniquely attributed historical hourly buckets may be
  backfilled. Some old HK route classes mix observers and can duplicate the
  same stream, so their historical totals remain excluded with a gap.
* Retired GoMami and NoSLA are not given new collection. Their archived
  statistics and existing retention behavior stay separate.
* A managed static proxy has no provider-side per-user NIC export. Its egress
  column remains a forwarding application estimate unless a real exit source
  becomes available.

The existing canonical expiry policy also gates this ledger. A confirmed
host/peer expiry stops the whole route's accounting at UTC+8 midnight.
Frozen daily summaries are retained beyond active retention and exported for
mirroring; connection caches and ordinary active summaries may still be pruned.
The reader exposes the business cutoff separately from the genuine last sample.

Run the candidate tests with:

```text
python -m unittest discover -s ops/user-daily-traffic -p test_*.py -v
```

# DMIT 运行服务快照（2026-11-15）

只读查询 `systemctl` 中 `ActiveState=active` 的服务和计时器。完整的 **82 个确切 unit 名称、substate、ExecStart/WorkingDirectory 对应的源码根**见 [`live-services.json`](live-services.json)。该快照只表示查询时刻；部署前须重新核对，不能由 `active` 推断所有业务探测通过。

| 作用 | 当前活跃 unit | 代码或模板来源 |
| --- | --- | --- |
| DMIT 主路由与客户端入口 | `dmit-direct-staging.service`、`dmit-direct-public.service`、`dmit-routing-bootstrap.service`、`dmit-routing-raw-guard.service`、`dmit-main-business-health.service`、34 个 `dmit-client-v2-*.service`、4 个 `dmit-routing-hkt-*.service`、`dmit-routing-reconcile.timer`、`dmit-client-deadline.timer` | `/opt/submerge-routing`、`/opt/submerge-client-policy`；本机运行时配置和主程序二进制未导出 |
| 订阅、管理与账号访问 | `submerge.service`、`submerge-user-access.service`、`submerge-access-worker.service`、`submerge-access.service`、`submerge-admin.service`、`submerge-delivery-qr.service`、`submerge-security.service`、`submerge-staging.service`、`subscription-user-enrollment.timer`、`submerge-access-backup.timer` | `/opt/submerge`、`/opt/submerge-topology`、`/opt/submerge-user-access`、`/opt/submerge-staging`，并导入 `/opt/submerge-client-policy` |
| AI 边缘与安全中心 | `dmit-ai-edge-control.service`、`lazycat-edge.service`、`lazycat-edge-google-bridge.service`、`lazycat-edge-edge-native-reader.service`、`security-center-lazycat-accounts.service`、`security-center-node-audit.timer`、`security-bt-quarantine.service`、`security-confirmed-events.service`、`security-mail-alerts.service` | `/opt/submerge-edge`、`/usr/local/lib/lazycat-edge`、`/opt/submerge-security-center`、`/opt/security-mail-alerts`；其他主机上的边缘源码需另取 |
| 跑酷资格与选择 | `paoluz-pools.service`、`paoluz-qualification.service`、`paoluz-authority-reader.service` | `/opt/paoluz-pools`；实际供应商数据与凭证不在源码快照中 |
| 统一流量和访问记录 | `sg-traffic-collector.service`、`sg-traffic-dashboard.service`、`sg-whole-traffic-collector.service`、`dmit-static-egress-collector.service`、`dmit-static-connection-events.service`、`dmit-ai-primary-events.service`、`dmit-ai-secondary-events.service`、`user-daily-api.service`、`user-daily-native.service` | `/opt/sg-traffic-dashboard`、`/opt/sg-traffic-dashboard-expiry-prod`、`/opt/static-connection-events`、`/opt/user-daily-traffic` |
| 账单系统 | `ledger-system.service`、`ledger-backup.timer`、`ledger-cert-renew.timer` | `/opt/ledger-system`；SQLite 数据、环境变量和证书均不在源码快照中 |
| S-UI | `s-ui.service` | 线上 `/usr/local/s-ui` 主要是二进制及数据库，未纳入白名单源码；本地有独立的 `sui-src` 与 `sui-x-src` 上游源码快照，需核对现役版本 |

`dmit-routing-reconcile.service` 是计时器唤醒的 oneshot，查询时非 active；要看 `Result`、`ExecMainStatus` 和完整回执验证结果。`security-center-node-audit.service` 也是定时任务，查询时未列入 active 服务。

源码归档排除 `/etc` 运行配置、`/var/lib` 数据、SSH/TLS 私钥、数据库、日志、缓存、备份和虚拟环境。它是安全审查用的代码快照，不是可直接部署的整机备份。

# Titanyung 基础设施：云端工作仓库

本仓库是 DMIT、Lazycat SG、ByteVirt HK 等服务的**脱敏源码与操作文档快照**，供从公司电脑、笔记本或手机开启云端 Codex 工作。它不是服务器磁盘的镜像，也不包含登录凭据或业务数据库。仓库中的版本用于评审和复现修改；**线上实际状态始终以服务器只读核查结果为准**。文中状态的核验日期见各节，后续操作前必须重新核实。

2026-11-15 的初始清单覆盖 DMIT 主路由与订阅、Ledger 账单系统、统一流量后台、安全中心、用户日流量、静态连接事件及跑酷相关模块；另附 Lazycat SG 边缘和 ByteVirt HK 流量后台的源码快照。每台机器的具体文件数与哈希见各自的 `source-manifest.json`。本仓库**尚不包含全部主机的完整源码和第三方 S-UI 本体源码**；不要用它重建未收录的服务。

## 服务关系

```text
用户客户端
  ├─ 订阅入口 node.titanyung.click:31877
  │    └─ 用户状态、客户端策略与可见分组
  └─ DMIT 主入口及路由
       ├─ 香港业务 → ByteVirt HK ISP；香港跑酷节点作健康兜底
       ├─ AI 业务 → 现有 AI 分组/StarHub、Singtel 出口
       ├─ 非中国大陆其他业务 → ByteVirt HK ISP；YouTube 属于此组
       └─ 相关 AI 边缘：DMIT 本机及 Lazycat SG

DMIT 上另有随包维护的 Ledger、统一流量后台、安全中心、
用户日流量和静态连接事件等服务；这些模块按各自的发布说明验收。
```

2026-11-13 的路由验收记录了 8 个顶层订阅分组。电脑 AI 默认先选 Lazycat SG → StarHub，手机 AI 默认先选 Lazycat SG → uzuma SG-Singtel1；Mytvsuper、Viu TV 和其他香港业务默认 DMIT → ByteVirt HK ISP。跑酷节点是按健康状态启用的备用出口。**不要从这份快照推断当前出口仍健康，发布前要检查实时选择和服务状态。**

## DMIT 服务与源码范围

完整的 [82 个活跃服务/计时器清单](docs/live-services.md) 和对应 [机器读取结果](docs/live-services.json) 已随包保存。

2026-11-15 对 DMIT 做只读 `systemctl` 盘点，查询时共有 **82 个 active 的服务/计时器**。下表列代表性单元和已纳入的源码根；`active` 仅表示进程或计时器状态，不能代替业务探测。

| 作用 | 代表性单元 | 源码根或覆盖情况 |
| --- | --- | --- |
| 主路由、客户端入站和健康检查 | `dmit-direct-staging.service`、`dmit-routing-raw-guard.service`、`dmit-main-business-health.service`、`dmit-routing-reconcile.timer`，以及多条 `dmit-client-v2-*` | `/opt/submerge-routing`、`/opt/submerge-client-policy`；运行配置和主程序二进制不在仓库中 |
| 订阅、后台与用户访问 | `submerge.service`、`submerge-user-access.service`、`submerge-access-worker.service`、`submerge-admin.service`、`submerge-security.service`、`subscription-user-enrollment.timer` | `/opt/submerge`、`/opt/submerge-topology`、`/opt/submerge-user-access`、`/opt/submerge-staging`；公开订阅入口 `https://node.titanyung.click:31877/sub/<用户名>` |
| AI 边缘与安全中心 | `dmit-ai-edge-control.service`、`lazycat-edge.service`、`security-center-lazycat-accounts.service`、`security-center-node-audit.timer` | `/opt/submerge-edge`、DMIT 上的 `/usr/local/lib/lazycat-edge`、`/opt/submerge-security-center`；Lazycat SG 的边缘源码另见 `peers/lazycat-sg/` |
| 跑酷资格与备用节点 | `paoluz-pools.service`、`paoluz-qualification.service`、`paoluz-authority-reader.service` | `/opt/paoluz-pools`；供应商数据和凭据不在仓库中 |
| 统一流量、用户日流量和静态连接事件 | `sg-traffic-dashboard.service`、`sg-traffic-collector.service`、`user-daily-api.service`、`dmit-static-connection-events.service` | `/opt/sg-traffic-dashboard`、`/opt/sg-traffic-dashboard-expiry-prod`、`/opt/user-daily-traffic`、`/opt/static-connection-events` |
| Ledger 账单系统 | `ledger-system.service`、`ledger-backup.timer`、`ledger-cert-renew.timer` | `/opt/ledger-system`；SQLite 数据、环境变量和证书不在仓库中 |
| 第三方 S-UI | `s-ui.service` | 线上主要为第三方二进制和数据库；**本仓库未收录其完整本体源码** |

`dmit-routing-reconcile.service` 是按需运行的 oneshot，查询时即使不是 active，也要核对它的 `Result`、`ExecMainStatus` 和最新完整回执。2026-11-15 对 X 发布所做的只读复核确认了新回执与公开订阅验收；其他服务还需各自的业务检查。

仓库也包含 Ledger、统一流量后台、安全中心、用户日流量、静态连接事件及跑酷模块的 DMIT 源码快照；**包含源码不等于已验收当前网站可用性**。NAS、文档、任务等网站及其他主机的完整部署状态不能由本仓库推断；扩展工作范围时先做各自的只读清单和备份。2026-11-13 的记录中，流量后台首页需要登录（HTTP 401），未见此前的 HTTP 504；这不是对今天可用性的保证。

## 其他主机的源码快照

| 主机 | 已收录源码 | 运行资料边界 |
| --- | --- | --- |
| Lazycat SG | `peers/lazycat-sg/source/usr/local/lib/lazycat-edge/` | 边缘 Python 模块；`/etc/lazycat-edge` 的私有运行配置未导出 |
| ByteVirt HK | `peers/bytevirt-hk/source/opt/hk-traffic-dashboard/` | 香港流量后台 Python 与安装脚本；`/etc/sing-box`、数据库和密钥未导出 |

每台主机的哈希清单在各自目录。DMIT 的目录为 `source/`，其他主机放在 `peers/<主机>/source/`，相同的绝对路径不会互相覆盖。2026-11-15 还只读核对了 StarHub、Lazycat HKT、ByteVirt Taiwan 和 Zoro SG：这四处现役出口主要由 `sing-box` 二进制和 `/etc` 私有配置运行，没有独立的活动自定义源码目录可安全导出；要在云端修改其路由，需另行制作脱敏配置模板并重新核对线上值。

## 源码与发布边界

导出时只对工作包副本做了明确的脱敏，线上文件保持原样：

| 文件 | 工作包中的处理 |
| --- | --- |
| `source/opt/submerge-user-access/production_adapter.py` | `native_secret` 的本机默认路径换成部署占位路径 |
| `source/opt/submerge-routing/client_bootstrap.py` | 离线测试口令换成占位值 |
| `source/opt/submerge-user-access/purge_codecs.py` | 禁用节点的示例口令和 URI 用户信息换成占位值 |
| `/opt/ledger-system/tests/test_app.py` | 测试口令较多，整份测试文件未导出 |

`source-manifest.json` 记录了脱敏字段、线上原文件哈希及导出副本哈希。**含占位值的文件不可直接覆盖线上文件。**

- 主策略模块在 DMIT 的 `/opt/submerge-routing/`、`/opt/submerge-topology/`、`/opt/submerge-user-access/`、`/opt/submerge-client-policy/` 等目录有多份活动副本。客户端策略还在 `/opt/submerge/`。一次修改必须核对并更新所有确认为活动的副本。
- 配置计划、生成后的运行配置、账户数据库和发布回执属于**线上运行态**，不能把仓库里的旧副本直接覆盖到服务器。
- 仓库应保留候选源码、测试、发布说明和非敏感的 SHA-256 清单。每次发布仍需核对实际线上基线、做私有备份、原子替换、检查主服务和公开订阅，并取得新的四层协调回执。
- 不得把历史快照当作活动模块。2026-11-14 的 X 修改特意没有触碰 `/root/topology-20261105/client_policy.py`。

## X 归入 AI 分组：已完成四层协调

2026-11-14 已将 `x.com`、`twitter.com`、`twimg.com`、`t.co` 的服务端和订阅规则划入现有 AI 分组。DMIT 的 14 个受管入站均已生成相应规则；电脑、手机公开订阅样本中的 X→AI 和 YouTube 原例外已核对。原有 AI 默认顺序和香港分流没有因此改变。

首次全量协调曾因 DMIT 到 Lazycat SG 管理入口 `178.94.15.19:32939` 超时而失败；**这是已恢复的历史故障，不是当前未完成事项**。2026-11-15 只读复核确认：新的 `full-layer-catchup.json` 已完成，客户端、边缘、统计三层 `verified=true`；该回执修改时间为 **2026-11-14 21:41 新加坡时间**，证据 SHA-256 为 `a31d0b78a2209c81d1fb2b5e4ea1509600995370481db4055b079fddc76bca89`。使用本次发布备份标识 `20261114T103618Z-1134889` 执行 `release.py --mode verify`，返回 `x_ai_public_samples=ok` 和 `x_ai_release_verified=ok`。今后如再次修改，应取得**新发布对应的新回执**，不能复用这一次的成功证据。

另有计划中的 uzuma HKT 到期清理，触发点是 **2026-12-10 00:00 新加坡时间**。这属于未来执行项；跨日期修复时先检查它是否已实际发生，不要用旧仓库内容重新启用已到期线路。

## 离线路由测试

在仓库根目录运行，无需生产配置或网络连接：

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s release/x-ai-route -p 'test_*.py' -v
```

测试加载仓库内的策略源码，并使用合成夹具覆盖 X→AI、YouTube 例外、
设备默认和 HKT 到期边界。夹具范围与测试限制见
[离线路由测试说明](release/x-ai-route/README.md)。

## 不进入仓库的内容

SSH 私钥、密码、令牌、Cookie、TLS 私钥、`.env`、真实订阅完整链接、用户数据库、访问日志、消费/账单数据、含用户凭据的运行配置、服务器私有备份，以及任何从生产导出的原始敏感数据。需要排障时只提交脱敏的字段、哈希和结果状态。

云端工作和部署方式见 [CLOUD-HANDOFF.md](CLOUD-HANDOFF.md)。

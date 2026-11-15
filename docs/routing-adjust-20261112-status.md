# 2026-11-13 路由调整状态

## 当前线上规则

- 保留 8 个顶层订阅分组。电脑订阅的 AI 默认先选 Lazycat SG → Lazycat StarHub；手机订阅先选 Lazycat SG → uzuma SG-Singtel1。
- Mytvsuper、Viu TV 和其他香港业务默认 DMIT → ByteVirt HK ISP；只有自有香港线路不健康时，才允许跑酷香港最快节点兜底。
- 非中国大陆的其他业务默认 DMIT → ByteVirt HK ISP；uzuma HKT 和 HINET NAT 暂可手动选择，随后才是跑酷全部节点。YouTube 归入该业务组。
- 香港主线路健康时，真实 Mihomo 的跑酷 HK gate 为 REJECT 是正常保护。2026-11-13 验收时已有 11 个合格香港备用候选。

## 已部署和验收

- 即时顺序于 2026-11-12 22:20 左右部署；私有备份 `/root/routing-adjust-20261112/backup-20261112T142024Z`。
- Lazycat → StarHub 本地隧道已改由 Lazycat 主动建立。ChatGPT/Claude 的 StarHub 出口实测为新加坡 AS4657，边缘健康证明通过。私有备份：Lazycat `/root/lazycat-starhub-local-20261112T162600Z-823321`、StarHub `/root/lazycat-starhub-local-20261112T162603Z-60668`、DMIT `/root/lazycat-starhub-local-dmit-20261112T162558Z-2669825`。
- 跑酷资格文件仅在有效内容变化时改写，避免订阅生成时碰上无意义的文件哈希变动；备份 `/root/routing-adjust-20261112/qualification-backup-20261112T164453Z-2717806`。
- 跑酷权威检查进程增加单个锁文件的写入例外，锁竞争时最多等待 10 秒，超时仍拒绝放行。备份 `/root/routing-adjust-20261112/reader-lock-20261112T170349Z-2763535` 和 `/root/routing-adjust-20261112/reader-lock-wait-backup-20261112T171408Z-2790668`。部署后连续 3 个周期的 DMIT/Lazycat 真实证明均通过。
- 活跃用户统计查询限时为 180 秒，统计准备限时为 240 秒；发布前还有总运行时间保护。备份 `/root/routing-adjust-20261112/stats-timeout2-backup-20261112T170652Z-2771355`。2026-11-13 01:10:20 +08 完整协调成功，主服务、边缘、客户端、统计四层凭据均通过，正式统计清单已激活；回执 SHA-256 `677044860233c5f493ecae06dd94959984c4bf39f7bf766ef00af05649d671b9`。
- uzuma HKT 的未来到期清理规则于 2026-11-13 01:17:49 +08 安装；备份 `/root/routing-adjust-20261112/expiry-backups/20261112T171749Z-2801122`。定时器已启用，触发点为 **2026-12-10 00:00:00 新加坡时间**。届时清理当前路由、订阅、公开统计中的 HKT，并停用四个相关公网 socket 及配套 service；历史统计保留。当前 HKT 仍可手选，日期边界测试通过。发布后协调器返回 `already_current` 且 Result=success；账户恢复 worker 已恢复 active。
- 2026-11-13 01:23:50 +08，定时协调自动触发并返回 `already_current`、Result=success；随后电脑与手机订阅仍为 HTTP 200，权威检查的 DMIT/Lazycat 两端均 verified=true。
- 公开 `wrt` 电脑与 `hm15pro+` 手机 Clash 订阅均返回 HTTP 200，8 个顶层分组及上述默认顺序已核对。流量后台首页返回 HTTP 401（需要登录），未出现之前的 504。

## 观察事项

- 完整协调期间曾有一次公开订阅 HTTP 503，后续电脑和手机订阅连续复测均为 200。保留对协调窗口的监测。
- 到期清理的未来实际执行只能在 2026-12-10 触发后验收；当前已验证定时器、安装文件、边界测试和到期前行为。

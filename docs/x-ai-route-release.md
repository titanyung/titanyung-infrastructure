# X 进入 AI 分组：DMIT 受控发布

本目录仅是发布器。候选源码固定为上级目录的 `server_route_policy.py` 和 `client_policy.py`。不修改 `/root/topology-20261105` 历史快照。

## 私有 stage

DMIT 上先创建 `0700` 的 `/root/x-ai-route-20261114/stage/` 和 `stage/candidate/`。放置：

- `stage/release.py`：本目录发布器；
- `stage/candidate/server_route_policy.py`：SHA-256 `d6f0c64f4e61864ff1db7b92552ccf76696a421a4c7efa0aab5ad5dda74a34d3`；
- `stage/candidate/client_policy.py`：SHA-256 `ec5e482b2c11ff1e1e4426e748797aa904c6cd6d31d4166e21213d97d9a9fce0`。

候选目录与发布器隔开，不能出现在 Python 搜索路径中。生产活动副本各四份，发布器会逐一校验原 SHA-256，原子安装，保留私有备份。服务端原 SHA 为 `d011ae889331bd4a4a0835d01e64d95e1974a604927543b8ee6ab8ae5c64389b`，客户端原 SHA 为 `4b1240e74c26f485e0c2e7da75333b3a31f1a274cc55765f33e37f3363c127e4`。

## 发布

在 DMIT 服务器以 root 顺序执行：

```sh
python3 /root/x-ai-route-20261114/stage/release.py --mode check
python3 /root/x-ai-route-20261114/stage/release.py --mode apply
systemctl start dmit-routing-reconcile.service
systemctl show dmit-routing-reconcile.service --property=Result,ExecMainStatus
python3 /root/x-ai-route-20261114/stage/release.py --mode verify --backup '<apply 输出的 backup 目录名>'
```

`apply` 只在预检、后台任务空闲、备份后来源再次一致时替换八个活动副本。它暂停相关写入者，验证新生成的全部托管入站 X 规则和 YouTube 例外、运行服务主 ACK、正式订阅样本，再挪走旧协调回执并恢复写入者。正式订阅抓取最多等待 30 秒，只对暂时的连接错误、超时和指定 HTTP 状态重试；内容或规则不符立即失败。旧回执必须挪走：其内容没有绑定模块或主配置哈希；若保留旧回执，协调器可能误判 `already_current`。随后 `dmit-routing-reconcile.service` 应重新检验主服务、边缘、订阅与统计层并写入新回执。`verify` 用指定备份目录核对旧回执、更新时序、新回执、三层证据、八副本 SHA、服务及正式订阅样本。

若任何副本替换、主配置、ACK 或公开订阅验证在挪走旧回执前失败，发布器只恢复已经改动的副本，并以旧规则重建主配置，再核对旧 PLAN/RUNTIME、主 ACK 和原有完整回执。只有全部复核通过才恢复写入者。若挪走回执后出错，保持新的发布状态，先检查私有备份、服务和新旧回执；不要简单恢复旧回执掩盖未完成的三层协调。

`apply` 输出的 `backup` 位于 `/root/x-ai-route-20261114/backups/`，其中有八个原模块、原 PLAN/RUNTIME/RECEIPT 和清单。只有在明确验证当前代码仍是本次新 SHA、且确认无更新的计划或用户变更后，才可依据该备份人工回退。回退必须重新生成并核对主 ACK，再运行完整协调验证，不能只复制旧 JSON。若发布器提示 `writers_remain_paused_for_manual_review`，请保留暂停状态排查，不要直接重启所有写入服务。

# 离线路由回归测试

从仓库根目录运行（只需 Python 标准库）：

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s release/x-ai-route -p 'test_*.py' -v
```

测试直接加载 `source/opt/submerge-routing/` 的服务端策略和
`source/opt/submerge-client-policy/` 的客户端策略，不依赖未收录的历史
`server-candidate`、`client-candidate` 或 `expiry-release/candidate` 目录。

`client_fixture.py` 新建合成路由合同、12 条链路的 IP 测试站点、普通/测试
订阅的前端绑定及 SG/HK 机场缓存。测试使用真实策略生成器与校验器；
`new_topology` 仅提供旧版展示常量，并在每项测试结束后恢复。

覆盖 X→AI 规则顺序、完整主机的目的地址修正、YouTube 例外、
手机/电脑/路由器的 AI 默认，以及 HKT 到期边界前后的普通和测试订阅。

所有 `.invalid` 域名、口令、证书指纹和端口均为测试值。两个公网地址
仅用于满足源码的固定 DMIT 身份和公网字面量校验，测试不会连接它们，
不会请求订阅或读取生产配置。这些夹具不可用于生产部署，测试通过也
不能代替真实出口、服务 ACK 或四层发布验收。

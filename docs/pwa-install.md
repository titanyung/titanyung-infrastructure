# DMIT 三个管理后台的 PWA 安装资源

2026-10-07 部署于 DMIT：

| 后台 | 页面 | 清单 | 安装范围 |
| --- | --- | --- | --- |
| S-UI | `https://node.titanyung.click:31876/sui/` 与 `https://dnode.titanyung.click:31876/sui/` | `/__pwa/sui.webmanifest` | `/sui/` |
| 统一流量与访问中心 | `https://dnode.titanyung.click:31880/` | `/__pwa/traffic.webmanifest` | `/` |
| Submerge 安全中心 | `https://dsub.titanyung.click:9443/security/` | `/__pwa/security.webmanifest` | `/security/` |

各入口通过 Nginx 把 manifest 和同域脚本注入 HTML；公开的 `/__pwa/` 只含安装清单、PNG 图标、注册脚本、Service Worker 和不含数据的启动跳转页。流量后台与安全中心原有的 HTTP Basic 登录仍在。Service Worker 只对页面导航执行网络请求，**不缓存后台页面、API 响应、凭证或访问记录**。

本地 `build_icons.py` 可重新生成 192/512 PNG 图标。`live/` 是部署前从 DMIT 获取并经补丁修改的四份 Nginx 配置；`pwa-*.conf` 是三个静态资源片段。`deploy-dmit.sh` 校验原文件哈希与服务状态、备份四份原配置、检查 `nginx -t` 后才重新加载；发生错误会恢复原配置。生产备份在 `/root/pwa-three-admins-20261007-01/backup`。流量站点的 `sites-enabled/sg-traffic-dashboard` 是软链接，实际修改目标为 `sites-available/sg-traffic-dashboard`。

部署时发现 SCP 保留了上传目录的 700 权限，曾使静态资源返回 403；已将 `/var/www/pwa/assets` 及三个图标子目录设为 755，并把该步骤写入部署脚本。修正后四个 S-UI 清单入口请求（含两个域名）、流量和安全中心清单、Service Worker、抽查图标与安全中心公开跳转页均返回 200。S-UI 登录 HTML 中已出现清单及注册脚本，三个后台相关服务仍 active。流量后台和安全中心未使用管理员密码访问；其 HTML 注入由 Nginx 配置检查和源页面 `</head>` 标记核对，浏览器内的最终安装操作应在用户正常登录后确认。

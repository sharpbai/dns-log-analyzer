# DNS V2 第一阶段：四层可观测性（开发状态）

## 口径
- **Unbound**：查询日志中的完整响应行，按事件时间（Unix 秒）归属 UTC 分钟。未完成的 `IN` 行不算完整响应。
- **fanout**：CoreDNS 定制 `{when} {combined}` 日志，按完成时刻归属 UTC 分钟。该层记录竞速层响应，不等于唯一客户端请求数。
- **domestic**：同样基于 CoreDNS 定制时间戳，统计国内分支响应；RCODE 为 `-` 的行独立统计，不能直接视为最终客户端失败。
- **rripfilter**：每 60 秒原子交换的过滤器计数，按日志产生的结束分钟归属；`rejected_ipv4/ipv6` 是被拒绝的 IP 数量，不是查询数。
- **overseas**：使用 `dnsproxy.log` 的 `upstream exchange completed`，统计成功/失败上游交换与耗时，不代表最终客户端请求；`overseas.stdout` 只有启动信息。
- 每层独立计数，不允许跨层相加为“唯一请求数”。不保存原始域名、客户端 IP 或逐请求数据。

## 当前本地实现
- `dns_log_analyzer/v2.py`：事件时间解析、SQLite 分钟计数、延迟分桶、增量文件检查点。
- `dns_log_analyzer/v2_watch.py`：inotify + 周期性补采，支持初次从 EOF 开始，避免旧日志无时间戳造成污染。
- `scripts/v2_summary.py`：输出最近 N 个完整 UTC 分钟的 JSON。
- `web/systemd/dns-v2-collector.service`：独立采集服务模板；部署前必须核对生产实际源码路径与日志访问权限。
- 与现有 V1 SmartDNS / dnsproxy 采集进程并行，暂不替换既有 dashboard。

## 风险与待验收
1. 日志轮转后如旧 inode 尚未消费完，当前 V2 watcher 不能自动从旧文件追赶；生产轮转策略需验证。
2. `from_end` 仅首次启用；检查点持久化后不会跳过后续日志。
3. 分钟延迟分位数为直方图插值估计，最末开区间无法给出准确分位数。
4. 海外分支已接入上游交换日志；网页仪表盘接入仍待完成。
5. 生产必须遵循 Git commit 发布，先核对生产路径、工作树、数据库与服务，再启用采集器。

## 2026-11-14 生产验收
- local-57: `dns-v2-collector.service` 增量采集运行中，原 V1 服务保持独立；`--from-end` 首次跳过历史日志，后续从 SQLite offset 继续。
- 五层：unbound、domestic、fanout、rripfilter、overseas，海外仅统计 dnsproxy 上游交换。
- local-193: `/dns-stat/v2/`，分钟级 timer 从 local-57 受限 SSH 强制命令获取 1/5/60/1440 分钟 JSON，HTTPS 页面与数据均已验收 200。
- 安全：上游错误状态统一聚合为 `status:ok` 或 `status:error`，不持久化带域名/URL 的原始错误内容；已清理上线初期两条不合规 metric key。
- CPU 观察：海外接入后 V2 Python 进程约 0.5% CPU、RSS 约 19 MiB，systemd CPUQuota=25%、MemoryMax=256M。
- 轮转：已通过模拟 `copytruncate` 与 rename 的 checkpoint 测试；由于 copytruncate 在复制到截断间存在固有竞态，**不承诺极端并发下绝对零丢失**。如需要严格无损，应调整生产日志轮转协议与写入端 reopen 机制。
- 限制：时间戳统一 UTC 存储、页面按北京时间显示；跨层不可相加；分位数为分桶估计；新文件替换/截断时可能重新读取新文件（不是周期性全量扫描）。

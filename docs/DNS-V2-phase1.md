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

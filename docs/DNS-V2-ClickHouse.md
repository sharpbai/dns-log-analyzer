# DNS V2 ClickHouse 原始事件存储（2026-11-14）

## 部署

- 数据节点：local-193；独立容器 dns-v2-clickhouse（ClickHouse 25.8，Docker network=none，无对外监听，2 CPU、6 GiB 内存、pids-limit 4096）
- 持久化目录：/srv/dns-v2-clickhouse/data
- 表：dns_v2.events；按 UTC 日期分区；TTL 30 天；原始域名和客户端 IP 只允许授权运维访问
- 采集：local-193 的 dns-v2-clickhouse-ingest.timer 每分钟通过受限 SSH 从 local-57 读取 Unbound、fanout、domestic 的有界日志增量；每次每源最多读取约 1 MiB
- 游标：/var/lib/dns-v2-ingest/{unbound,fanout,domestic}.json；只有 ClickHouse 确认写入后更新
- 事件 ID：源、inode、日志字节偏移量的稳定 64 位哈希，ReplacingMergeTree 对重试写入最终去重
- 原有 V1/V2 分钟聚合继续运行，尚未迁移到 ClickHouse
- 当前尚未采集 fanout 内部 winner/both_failed 决策与 rripfilter 过滤前后 IP：需修改插件增加结构化日志
- Unbound 原始日志的时间精度为秒，不能伪装成微秒精度

## 运维

查看状态：

```sh
systemctl status dns-v2-clickhouse-ingest.timer
systemctl status dns-v2-clickhouse-ingest.service
docker stats --no-stream dns-v2-clickhouse
docker exec dns-v2-clickhouse clickhouse-client --query 'SELECT source,count() FROM dns_v2.events GROUP BY source'
docker exec dns-v2-clickhouse clickhouse-client --query 'SELECT database,table,sum(rows),sum(data_compressed_bytes) FROM system.parts WHERE active=1 GROUP BY database,table'
```

注意：logrotate 当前采用 copytruncate，极端并发时可能发生日志截断竞态。游标检测到文件变短会重置并打印 WARNING，但**不能保证轮转瞬间无损**。正式无损要求需更改日志写入和轮转协议。请监控 WARNING 与采集延迟。

容量基线：初始 15,658 条事件在 ClickHouse events 表的活动数据压缩约 495 KB（约 31.6 B/事件，不包含元数据、系统日志、临时分区和未来过滤明细）。不能据此直接承诺 30 天的最终总空间。

恢复：服务停止后保留持久化数据目录；游标文件需与数据备份一致，避免重放或漏采。数据库没有对外开放端口。

## Unbound dnstap 请求-响应关联（2026-11-14）

生产 Unbound 1.17.1 已启用 `dnstap` 的 CLIENT_QUERY/CLIENT_RESPONSE；捕获服务 `dns-v2-dnstap-capture.service` 通过 `fstrm_capture` 将二进制帧按约一分钟分文件写入 `/home/duobeigw/dns-lab/logs/dnstap/`。此项变更经过独立 15553 端口隔离验证，生产配置备份位于 `conf/unbound.conf.pre-dnstap-20261114`。

- local-57：`scripts/v2_dnstap_export.py` 解析 Frame Streams + protobuf wire，DNS 报文头、问题域名及 ns 时间戳。匹配键为客户端 IP/端口、传输协议、DNS ID、域名、类型、类，窗口 5 秒。
- local-193：`dns-v2-dnstap-ingest.timer` 每分钟经受限 SSH 拉取**已关闭**的文件，逐文件写入 ClickHouse，确认成功后记录文件名游标 `/var/lib/dns-v2-ingest/dnstap-files.json`。事件来源 `unbound_dnstap`，包含 `query_time`、`match_status`、`client_port`、`dns_id`、`protocol`。
- 原始 dnstap 二进制文件由 `dns-v2-dnstap-prune.timer` 每 15 分钟删除修改时间超过 240 分钟的文件；结构化数据仍按 ClickHouse 30 天 TTL 保存。
- 初次生产样本：1,483 条响应中 matched 1,429（96.36%）、ambiguous 48（3.24%）、unmatched_response 6（0.40%）。**不是 100% 无损保证**，文件跨分钟边界和 DNS ID 重复可造成歧义；统计耗时仅使用 matched。
- 旧的 Unbound 文本日志继续存在，V1/V2 分钟聚合不变；但 ClickHouse 原始 Unbound 文本导入停止，后续新事件只用 `unbound_dnstap`，避免重复长期存储。旧 `unbound` 表记录自然随 TTL 到期。

检查命令：

```sh
systemctl is-active dns-v2-dnstap-capture.service dns-lab-unbound.service dns-v2-dnstap-prune.timer
systemctl is-active dns-v2-dnstap-ingest.timer
journalctl -u dns-v2-dnstap-ingest.service --no-pager -n 15
docker exec dns-v2-clickhouse clickhouse-client --query 'SELECT match_status,count() FROM dns_v2.events WHERE source = '\''unbound_dnstap'\'' GROUP BY match_status'
```

## 2026-11-14：停止 Unbound 文本查询日志

- local-57 生产配置 `conf/unbound.conf`：`log-queries: no`、`log-replies: no`、`log-servfail: no`；dnstap CLIENT_QUERY/CLIENT_RESPONSE 继续开启。变更前备份：`conf/unbound.conf.pre-no-text-20261114`。
- `dns_log_analyzer/v2_watch.py` 已排除 Unbound stdout 采集，其余 fanout、domestic、rripfilter、overseas 继续使用现有采集。
- local-193 `web/v2/collect.py` 从 ClickHouse `unbound_dnstap` 生成 L1 及全局入口统计，不再依赖旧文本 rollup。只有 matched 记录参与延迟分位数；缓存命中标志暂不可用。
- 生产验证：网页 HTTP 200、V2 四窗口 JSON 正常、Unbound 解析正常、V1/V2 采集服务 active。V1 的 SmartDNS/dnsproxy 采集不受影响。
- 尚未完成：fanout 决策日志、rripfilter 逐次过滤详情、overseas 完整原始事件的 ClickHouse 采集。现有聚合指标并不代表原始数据均已就绪。

## 四层结构化事件采集（2026-11-14）

详见 [DNS V2 四层原始事件采集与验收](DNS-V2-Layered-Raw-Events.md)。L1 dnstap、L2 fanout 竞速决策与分支结果、L3 rripfilter 逐次过滤、L4 dnsproxy DoH 交换已分别写入 ClickHouse 30 天事件表；V2 页面展示胜出率、过滤事件、TOP 域名/来源和数据新鲜度。注意 Unbound 看到的 192.168.0.59 可能是 DNS 转发器而非真实终端。

## Unbound 原生缓存/递归统计（2026-11-14）

- local-57 已开启 `prefetch: yes`，`cache-min-ttl: 0` 和 `serve-expired: no` 不变。配置备份：`/home/duobeigw/dns-lab/conf/unbound.conf.pre-prefetch-20261114`。
- 管理接口仅使用 Unix Socket `/home/duobeigw/dns-lab/run/unbound-control.sock`，`control-use-cert: no` 仅适用于本地 Unix Socket，未开放 TCP 8953。配置备份：`conf/unbound.conf.pre-control-20261114`。
- 受限 SSH 用户 `dnsstat` 不直接拥有管理 Socket 权限；通过 `/etc/sudoers.d/dns-v2-unbound-stats` 仅允许以 `duobeigw` 身份执行固定的只读统计脚本 `scripts/v2_unbound_stats.py`。脚本与目录为 root 所有，不可由 dnsstat 修改。
- local-193 的 `dns-v2-unbound-stats.timer` 每分钟约第 20 秒通过受限 SSH 拉取 `stats_noreset`；ClickHouse 表 `dns_v2.unbound_stats` 保留 30 天。
- 原生采集字段：queries、cachehits、cachemiss、prefetch、expired、recursivereplies、requestlist avg/max/current/overwritten/exceeded、recursion avg/median、tcpusage、time.up。
- V2 页面在每个时间窗口取**窗口内首尾两个采样点**的计数器差值，计算 `Δcachehits/(Δcachehits+Δcachemiss)`；单个样本显示“样本不足”，Unbound 重启后 uptime 回退或计数器回退时不跨重启计算。
- `prefetch` 是后台预取触发计数，不是缓存命中；`requestlist.exceeded` 是请求队列超限计数。递归平均/中位耗时来自最新原生累计统计，并非窗口内的递归耗时分位数。
- 验收：管理接口返回真实计数器；第一次采集和后续采集写入 ClickHouse 成功，定时器 active，V2 页面 HTTP 200。

### DNSPROXY 最终响应口径（2026-11-14）

`local-57` 新增 `dns-v2-dnsproxy-final.service`：通过只读环回 UDP 15404 抓包，按客户端端口、DNS ID、域名及 QTYPE 匹配请求/响应，每个最终 DNS 应答写一条 `dns_v2_dnsproxy_final` 日志到 `dnsproxy-final.log`。它**不**是四路上游交换日志，也不依赖 fanout 哪个分支胜出。当前仅覆盖 UDP；TCP 尚未采集，采集进程重启或丢包时可能遗漏请求。需定期检查采集进程和日志新鲜度。

`local-193` 通过受限 SSH `v2-raw-overseas_final` 增量采集到 `dns_v2.dnsproxy_final_responses`，V2 L4 顶部五项指标由最终响应计算：`(NOERROR + NXDOMAIN) / 最终响应数`、P50/P95/P99、耗时 ≥3s 次数。下方四上游健康详情继续使用 `dns_v2.overseas_exchanges`。原生源文件：`scripts/v2_dnsproxy_final_capture.py`；部署单元：`ops/dns-v2-dnsproxy-final.service`；日志轮转：`ops/dns-v2-dnsproxy-final.logrotate`。

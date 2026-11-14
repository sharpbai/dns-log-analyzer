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

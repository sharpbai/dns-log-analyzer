# DNS V2 四层原始事件采集与验收（2026-11-14）

## 生产链路与存储

local-57：Unbound 53 → CoreDNS fanout 127.0.0.1:15372 → 国内 rripfilter 127.0.0.1:15370 / 海外 dnsproxy 127.0.0.1:15404。local-193：独立 ClickHouse dns_v2，按日分区、事件 TTL 30 天，不开放数据库端口。

| 来源 | 原始内容 | ClickHouse 表 |
| --- | --- | --- |
| L1 Unbound | dnstap CQ/CR 匹配、域名、客户端 IP/端口、DNS ID、RCODE、耗时、匹配质量 | events（source=unbound_dnstap） |
| L2 fanout | 竞速胜出地址、RCODE、决策耗时、失败原因 | fanout_decisions |
| L2 fanout | 国内/海外每个上游分支的 response/error/canceled、耗时 | fanout_upstream_events |
| L3 rripfilter | accept/partial/drop/bypass/upstream_error/transport_error、过滤前后 IPv4/IPv6、过滤耗时、丢弃原因 | rripfilter_events |
| L4 dnsproxy | 每次上游交换的域名、类型、DoH 地址、协议、耗时、状态 | overseas_exchanges |
| L2/L3 兼容 | CoreDNS 响应文本 | events（source=fanout/domestic） |

全部每分钟增量采集。原始文本日志约 4 小时，ClickHouse 事件 30 天。Unbound 文本查询与响应日志已关闭；V1/V2 原有分钟聚合保留。

## 关键口径

- L1：以 dnstap CLIENT_RESPONSE 为入口响应数，仅 matched 计算端到端耗时。ambiguous 和 unmatched_response 不伪造耗时。dnstap 不提供缓存命中标志。
- L2：竞速决策与分支结果分别计数，不能把两个分支结果相加作为入口请求。winner=127.0.0.1:15370 为国内，winner=127.0.0.1:15404 为海外。canceled 是主动取消败者，不能当成上游故障。
- L3：drop 的 reason=all_filtered 或 no_terminal_answer 区分全部 IP 被拒与上游原本没有终端记录。upstream_error 为上游 DNS RCODE 非成功且插件不向下游写消息；transport_error 为没有 WriteMsg。原始 IP、接受 IP、拒绝 IP 均保留；IP 列表可能有重复。
- L4：一个 dnsproxy 查询可能并发两个 DoH 上游，overseas_exchanges 不能当成客户端请求数。
- TOP 客户端：Unbound 看到的 IP 可能是 OpenWrt DNS 转发器（例如 local-59），不是最终 Wi-Fi 终端。若要还原真实终端 IP，需要 local-59 DNS 入口采集或调整客户端 DNS 路由。
- 各层不能简单相加。跨进程目前没有唯一 trace ID，跨层域名/DNS ID/时间关联仅能尽力而为。

## 代码与运维

- fanout：gwtools dns/coredns-log-when/instrument-fanout.py、build-fanout.sh；TomTonic/fanout v1.18.0、CoreDNS v1.15.0。
- rripfilter：gwtools dns/rripfilter/filter.go、build.sh；CoreDNS v1.14.0。
- 采集：dns-log-analyzer scripts/v2_raw_export.py；local-57 受限 SSH 只读导出；local-193 dns-v2-clickhouse-ingest.timer 增量拉取，成功写入后才更新游标。
- 页面：https://local-193.vipstreamers.cn/dns-stat/v2/。五个原始事件表的最新事件延迟超过 240 秒标为 stale（页面状态，不是主动告警）。
- 二进制备份：local-57 /home/duobeigw/dns-lab/bin/coredns-fanout-amd64.pre-v2-events-20261114 和 coredns-rripfilter-amd64.pre-v2-events-20261114。回滚恢复原二进制、重启对应服务并验收 53 端口。
- 日志轮转 copytruncate 仍存在极端并发下少量事件丢失的理论风险；ReplacingMergeTree 只提供重复写入最终去重，不能恢复源端丢失。

## 验收

- 隔离 15572 fanout：真实国内/海外解析成功，验证胜出分支、败者 canceled 事件。
- 隔离 15570 rripfilter：百度 A 查询成功，验证过滤前后 IP、过滤耗时、drop 原因。
- 生产 53：百度 A 与 Google AAAA 查询成功；Unbound、fanout、domestic、overseas、dnstap、V1/V2 采集均 active。
- ClickHouse 原始事件表持续写入，V2 页面 HTTP 200。代码单元测试 41 项运行、1 项跳过。完整 fanout 测试中有 DoH3 网络依赖用例在 Mac 环境超时，定向竞速/配置测试通过。

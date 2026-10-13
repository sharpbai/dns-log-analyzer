# dns-log-analyzer

轻量级 dnsmasq / AdGuard dnsproxy 日志结构化入库工具，Python 3.11+，仅依赖标准库。

## 目标
- 增量读取两个独立日志源，解析后写入 SQLite
- 保留原始行用于重新解析，结构化事件单独存储
- 批量事务、WAL、读取位置持久化，重启后续读
- 对截断和日志轮转作基本检测；无解析匹配的行也入 raw_logs
- **不负责**跨进程 DNS 请求关联，也不直接宣称成功率/耗时

## 运行
```bash
python3 -m dns_log_analyzer --db ./dns.sqlite3 --dnsmasq /var/log/dnsmasq.log --dnsproxy /var/log/dnsproxy.log
python3 -m dns_log_analyzer --db ./dns.sqlite3 --follow --interval 2
python3 -m dns_log_analyzer --db ./dns.sqlite3 --stats
```
建议先以有日志读取权限的用户运行。不要把数据库、真实 DNS 日志、IP 或内部域名提交到 Git。

## 数据结构
- `raw_logs`: 原始日志、来源、文件 inode、偏移量、解析标记
- `dns_events`: 时间、级别、事件、查询编号、客户端、域名、记录类型、上游、协议、耗时和错误
- `checkpoints`: 每个来源的 inode、偏移量、文件头指纹和更新日期

注意：dnsproxy 的 `elapsed` 可能仅是连接耗时，不应视为完整 DNS 解析耗时。日志量较大时请控制原始日志/SQLite 的保留期。当前实现仅追踪活动日志文件；轮转期间若未及时读取，可能遗漏已改名的尾部日志。copytruncate 在复制与截断之间本身也可能丢失极少量日志。部署为服务前请先测试这些边界。

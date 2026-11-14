CREATE DATABASE IF NOT EXISTS dns_v2;
CREATE TABLE IF NOT EXISTS dns_v2.events (
 event_time DateTime64(6,'UTC'),
 source LowCardinality(String),
 client_ip String,
 domain String,
 qtype LowCardinality(String),
 rcode LowCardinality(String),
 duration_us UInt64,
 cache_flag Nullable(UInt8),
 response_bytes UInt32,
 event_id UInt64,
 ingested_at DateTime DEFAULT now()
) ENGINE=ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (source,event_time,event_id)
TTL toDateTime(event_time) + INTERVAL 30 DAY DELETE
SETTINGS index_granularity=8192;
CREATE TABLE IF NOT EXISTS dns_v2.minute_rollups (
 minute DateTime('UTC'),
 source LowCardinality(String),
 metric LowCardinality(String),
 total UInt64
) ENGINE=SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (minute,source,metric);

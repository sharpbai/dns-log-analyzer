CREATE TABLE IF NOT EXISTS dns_v2.fanout_decisions (
 event_time DateTime64(6,'UTC'),
 domain String,
 qtype UInt16,
 dns_id UInt16,
 winner LowCardinality(String),
 reason LowCardinality(String),
 rcode Int16,
 duration_us UInt64,
 upstream_us Int64,
 event_id UInt64,
 ingested_at DateTime DEFAULT now()
) ENGINE=ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (event_time,event_id)
TTL toDateTime(event_time) + INTERVAL 30 DAY DELETE;
CREATE TABLE IF NOT EXISTS dns_v2.rripfilter_events (
 event_time DateTime64(6,'UTC'),
 domain String,
 qtype UInt16,
 dns_id UInt16,
 action LowCardinality(String),
 upstream_rcode UInt16,
 original_ips Array(String),
 accepted_ips Array(String),
 rejected_ips Array(String),
 elapsed_us UInt64,
 event_id UInt64,
 ingested_at DateTime DEFAULT now()
) ENGINE=ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (event_time,event_id)
TTL toDateTime(event_time) + INTERVAL 30 DAY DELETE;

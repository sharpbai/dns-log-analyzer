CREATE TABLE IF NOT EXISTS dns_v2.fanout_upstream_events (
 event_time DateTime64(6,'UTC'),
 domain String,
 qtype UInt16,
 dns_id UInt16,
 upstream String,
 outcome LowCardinality(String),
 rcode Int16,
 duration_us UInt64,
 event_id UInt64,
 ingested_at DateTime DEFAULT now()
) ENGINE=ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (event_time,event_id)
TTL toDateTime(event_time) + INTERVAL 30 DAY DELETE;

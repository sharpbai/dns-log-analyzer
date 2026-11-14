CREATE TABLE IF NOT EXISTS dns_v2.overseas_exchanges (
 event_time DateTime64(6,'UTC'),
 domain String,
 qtype LowCardinality(String),
 dns_id UInt16,
 upstream String,
 protocol LowCardinality(String),
 duration_us UInt64,
 status LowCardinality(String),
 event_id UInt64,
 ingested_at DateTime DEFAULT now()
) ENGINE=ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (event_time,event_id)
TTL toDateTime(event_time) + INTERVAL 30 DAY DELETE;

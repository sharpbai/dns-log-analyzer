CREATE TABLE IF NOT EXISTS dns_v2.unbound_stats (
 sampled_at DateTime64(3,'UTC'),
 uptime_seconds Float64,
 queries UInt64,
 cachehits UInt64,
 cachemiss UInt64,
 prefetch UInt64,
 expired UInt64,
 recursivereplies UInt64,
 requestlist_avg Float64,
 requestlist_max UInt64,
 requestlist_overwritten UInt64,
 requestlist_exceeded UInt64,
 requestlist_current UInt64,
 recursion_avg_seconds Float64,
 recursion_median_seconds Float64,
 tcpusage UInt64,
 ingested_at DateTime DEFAULT now()
) ENGINE=ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(sampled_at)
ORDER BY sampled_at
TTL toDateTime(sampled_at) + INTERVAL 30 DAY DELETE;

ALTER TABLE dns_v2.events ADD COLUMN IF NOT EXISTS query_time Nullable(DateTime64(6,'UTC'));
ALTER TABLE dns_v2.events ADD COLUMN IF NOT EXISTS match_status LowCardinality(String) DEFAULT '';
ALTER TABLE dns_v2.events ADD COLUMN IF NOT EXISTS client_port UInt16 DEFAULT 0;
ALTER TABLE dns_v2.events ADD COLUMN IF NOT EXISTS dns_id UInt16 DEFAULT 0;
ALTER TABLE dns_v2.events ADD COLUMN IF NOT EXISTS protocol LowCardinality(String) DEFAULT '';

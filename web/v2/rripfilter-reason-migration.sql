ALTER TABLE dns_v2.rripfilter_events ADD COLUMN IF NOT EXISTS reason LowCardinality(String) DEFAULT '';
ALTER TABLE dns_v2.rripfilter_events ADD COLUMN IF NOT EXISTS filter_us UInt64 DEFAULT 0;

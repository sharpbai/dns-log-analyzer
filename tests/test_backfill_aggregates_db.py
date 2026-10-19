import importlib.util
import sqlite3
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location("agg",Path(__file__).resolve().parents[1]/"scripts"/"backfill_aggregates_db.py")
agg=importlib.util.module_from_spec(spec);spec.loader.exec_module(agg)
class AggregateBackfillTests(unittest.TestCase):
    def test_idempotent_and_late_insert(self):
        db=sqlite3.connect(":memory:")
        db.executescript("""
        CREATE TABLE smartdns_requests(ts TEXT,duration_ms INTEGER);
        CREATE TABLE dnsproxy_upstream_attempts(first_seen TEXT,identity TEXT,upstream TEXT,status TEXT,duration_ms REAL);
        CREATE TABLE dnsproxy_packet_events(ts TEXT);
        CREATE TABLE dnsproxy_cache_events(ts TEXT);
        INSERT INTO smartdns_requests VALUES('2026-10-18T08:00:00',0);
        INSERT INTO dnsproxy_upstream_attempts VALUES('2026-10-18T08:00:02','g:1:exact:2','google','success',45);
        INSERT INTO dnsproxy_packet_events VALUES('2026-10-18T08:00:05');
        """)
        agg.setup(db)
        for _ in range(2):agg.aggregate_hour(db,"2026-10-18T08:00:00")
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE source='smartdns' AND dimension='total'").fetchone()[0],1)
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE dimension='attempts:google'").fetchone()[0],1)
        db.execute("INSERT INTO smartdns_requests VALUES('2026-10-18T08:00:03',18)")
        agg.aggregate_hour(db,"2026-10-18T08:00:00")
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE source='smartdns' AND dimension='total'").fetchone()[0],2)
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE source='smartdns' AND dimension='cache_hits'").fetchone()[0],1)
        self.assertEqual(db.execute("SELECT count(*) FROM aggregate_hour_progress").fetchone()[0],1)
        db.close()
if __name__=="__main__":unittest.main()

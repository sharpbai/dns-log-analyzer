import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]/"scripts"
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/(name+".py"))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
agg=load("backfill_aggregates_db")
summary=load("dns_summary")
prune=load("prune_dns_details")

class SmartDNSRollupTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE smartdns_requests(id INTEGER PRIMARY KEY, ts TEXT, duration_ms INTEGER)")
        self.db.execute("CREATE TABLE dnsproxy_upstream_attempts(identity TEXT,first_seen TEXT,upstream TEXT,status TEXT,duration_ms REAL)")
        self.db.execute("CREATE TABLE dnsproxy_requests(first_seen TEXT)")
        self.db.execute("CREATE TABLE dnsproxy_packet_events(ts TEXT)")
        self.db.execute("CREATE TABLE dnsproxy_cache_events(ts TEXT)")
        agg.setup(self.db)
        self.db.executemany("INSERT INTO smartdns_requests(ts,duration_ms) VALUES(?,?)",[
            ("2026-10-19T10:00:01",0),("2026-10-19T10:00:02",0),
            ("2026-10-19T10:01:03",27),("2026-10-19T10:01:04",180)])
        self.db.commit()
    def tearDown(self):self.db.close()
    def test_hourly_rollup_is_idempotent(self):
        agg.aggregate_hour(self.db,"2026-10-19T10:00:00")
        agg.aggregate_hour(self.db,"2026-10-19T10:00:00")
        result=dict(self.db.execute("SELECT dimension,sum(total) FROM dns_hourly_aggregates WHERE source='smartdns' GROUP BY dimension"))
        self.assertEqual(result,{"total":4,"cache_hits":2})
    def test_summary_uses_smartdns(self):
        result=summary.collect(self.db,"2026-10-19T10:00:00","2026-10-19T11:00:00")
        self.assertEqual(result["smartdns"]["total"],4)
        self.assertEqual(result["smartdns"]["cache_hit_rate"],50)
        self.assertNotIn("dnsmasq",result)
    def test_prune_fails_closed_without_triggers(self):
        agg.aggregate_hour(self.db,"2026-10-19T10:00:00")
        import datetime as dt
        with self.assertRaisesRegex(RuntimeError,"triggers"):
            prune.validate(self.db,dt.datetime(2026,10,20,11))
if __name__=="__main__":unittest.main()

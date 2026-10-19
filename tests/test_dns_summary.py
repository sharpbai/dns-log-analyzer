import importlib.util
import sqlite3
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location("summary",Path(__file__).resolve().parents[1]/"scripts"/"dns_summary.py")
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE smartdns_requests(ts TEXT,duration_ms INTEGER)")
        self.db.execute("CREATE TABLE dnsproxy_upstream_attempts(first_seen TEXT,identity TEXT,upstream TEXT,status TEXT,duration_ms REAL)")
        self.db.execute("CREATE TABLE dnsproxy_packet_events(ts TEXT)")
        self.db.execute("CREATE TABLE dnsproxy_cache_events(ts TEXT)")
    def tearDown(self):self.db.close()
    def test_zero_ms_estimate(self):
        self.db.executemany("INSERT INTO smartdns_requests VALUES(?,?)",[("2026-10-16T01:00:00",0),("2026-10-16T01:00:01",0),("2026-10-16T01:00:02",20),("2026-10-17T00:00:00",0)])
        d=mod.summarize(self.db,"2026-10-16T00:00:00","2026-10-17T00:00:00")
        self.assertEqual(d["total"],3);self.assertEqual(d["cache_hits"],2);self.assertAlmostEqual(d["cache_hit_rate"],66.667)
    def test_upstream_histogram(self):
        self.db.execute("INSERT INTO smartdns_requests VALUES('2026-10-16T00:00:00',0)")
        self.db.execute("INSERT INTO dnsproxy_upstream_attempts VALUES('2026-10-16T00:00:00','g:1:exact:1','google','success',45)")
        d=mod.collect(self.db,"2026-10-16T00:00:00","2026-10-17T00:00:00")
        self.assertEqual(d["smartdns"]["total"],1)
        self.assertEqual(d["dnsproxy"]["latency_distribution"]["total"],1)
if __name__=="__main__":unittest.main()

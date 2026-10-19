import importlib.util
import sqlite3
import unittest
from pathlib import Path
root=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,root/"scripts"/(name+".py"))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
summary=load("dns_summary");backfill=load("backfill_aggregates_db")
class AggregateQueryTests(unittest.TestCase):
    def test_rollups_survive_detail_prune(self):
        db=sqlite3.connect(":memory:")
        db.executescript("""
        CREATE TABLE smartdns_requests(ts TEXT,duration_ms INTEGER);
        CREATE TABLE dnsproxy_upstream_attempts(first_seen TEXT,identity TEXT,upstream TEXT,status TEXT,duration_ms REAL);
        CREATE TABLE dnsproxy_packet_events(ts TEXT);
        CREATE TABLE dnsproxy_cache_events(ts TEXT);
        INSERT INTO smartdns_requests VALUES('2026-10-18T08:00:00',0);
        INSERT INTO dnsproxy_upstream_attempts VALUES('2026-10-18T08:00:02','g:1:exact:2','google','success',45);
        INSERT INTO dnsproxy_packet_events VALUES('2026-10-18T08:00:03');
        INSERT INTO dnsproxy_cache_events VALUES('2026-10-18T08:00:04');
        """)
        backfill.setup(db);backfill.aggregate_hour(db,"2026-10-18T08:00:00")
        before=summary.collect(db,"2026-10-18T08:00:00","2026-10-18T09:00:00")
        for table in ("smartdns_requests","dnsproxy_upstream_attempts","dnsproxy_packet_events","dnsproxy_cache_events"):
            db.execute("DELETE FROM "+table)
        after=summary.collect(db,"2026-10-18T08:00:00","2026-10-18T09:00:00")
        self.assertEqual(before,after)
        self.assertEqual(after["smartdns"]["total"],1)
        self.assertEqual(after["dnsproxy"]["latency_distribution"]["total"],1)
        db.close()
if __name__=="__main__":unittest.main()

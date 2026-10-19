import sqlite3
import unittest
from dns_log_analyzer.incremental import install_dnsproxy_triggers,install_event_triggers

class ProxyIncrementalTests(unittest.TestCase):
    def test_exact_only_bins_and_updates(self):
        db=sqlite3.connect(":memory:")
        db.execute("CREATE TABLE dnsproxy_upstream_attempts(id INTEGER PRIMARY KEY,identity TEXT,first_seen TEXT,upstream TEXT,status TEXT,duration_ms REAL)")
        install_dnsproxy_triggers(db)
        db.execute("INSERT INTO dnsproxy_upstream_attempts(identity,first_seen,upstream,status,duration_ms) VALUES(?,?,?,?,?)",
                   ("g:1:exact:1","2026-10-19T10:01:01","google","success",55))
        db.execute("INSERT INTO dnsproxy_upstream_attempts(identity,first_seen,upstream,status,duration_ms) VALUES(?,?,?,?,?)",
                   ("g:1:send:2","2026-10-19T10:01:02","google","sent",None))
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE dimension=\x27attempts:google\x27").fetchone()[0],1)
        self.assertEqual(db.execute("SELECT total FROM dns_latency_bins WHERE bin=1").fetchone()[0],1)
        db.execute("UPDATE dnsproxy_upstream_attempts SET status=\x27failed\x27,duration_ms=NULL WHERE id=1")
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE dimension=\x27failed:google\x27").fetchone()[0],1)
        self.assertEqual(db.execute("SELECT total FROM dns_latency_bins WHERE bin=1").fetchone()[0],0)
        db.close()

    def test_packet_cache_insert_counts(self):
        db=sqlite3.connect(":memory:")
        db.execute("CREATE TABLE dnsproxy_packet_events(id INTEGER PRIMARY KEY,ts TEXT)")
        db.execute("CREATE TABLE dnsproxy_cache_events(id INTEGER PRIMARY KEY,ts TEXT)")
        install_event_triggers(db)
        db.execute("INSERT INTO dnsproxy_packet_events(ts) VALUES(?)",("2026-10-19T10:01:02",))
        db.execute("INSERT INTO dnsproxy_cache_events(ts) VALUES(?)",("2026-10-19T10:01:02",))
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE dimension=\x27packet_events\x27").fetchone()[0],1)
        self.assertEqual(db.execute("SELECT total FROM dns_minute_aggregates WHERE dimension=\x27cache_events\x27").fetchone()[0],1)
        db.close()

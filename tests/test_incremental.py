import sqlite3
import unittest
from dns_log_analyzer.incremental import install_dnsmasq_triggers

class IncrementalTests(unittest.TestCase):
    def test_insert_update_and_rollback(self):
        db=sqlite3.connect(":memory:")
        db.execute("CREATE TABLE dnsmasq_requests(id INTEGER PRIMARY KEY,first_seen TEXT,state TEXT,result TEXT,cache_seen INTEGER,forwarded INTEGER)")
        install_dnsmasq_triggers(db)
        db.execute("INSERT INTO dnsmasq_requests(first_seen,state,result,cache_seen,forwarded) VALUES(?,?,?,?,?)",
                   ("2026-10-19T10:05:01","pending",None,0,0))
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE dimension=\x27unconfirmed\x27").fetchone()[0],1)
        db.execute("UPDATE dnsmasq_requests SET state=\x27answered\x27,result=\x27NXDOMAIN\x27,cache_seen=1 WHERE id=1")
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE dimension=\x27success\x27").fetchone()[0],1)
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE dimension=\x27unconfirmed\x27").fetchone()[0],0)
        db.commit()
        try:
            with db:
                db.execute("UPDATE dnsmasq_requests SET result=\x27SERVFAIL\x27 WHERE id=1")
                raise RuntimeError()
        except RuntimeError:
            pass
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE dimension=\x27success\x27").fetchone()[0],1)
        db.execute("DELETE FROM dnsmasq_requests WHERE id=1")
        self.assertEqual(db.execute("SELECT total FROM dns_hourly_aggregates WHERE dimension=\x27total\x27").fetchone()[0],1)

import tempfile
import unittest
from pathlib import Path
from dns_log_analyzer.requests import open_db, ingest

class ProductionCompatibilityTests(unittest.TestCase):
    def test_packet_cache_and_replay_dedup(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/"proxy.log"
            db=open_db(str(Path(root)/"dns.sqlite3"))
            path.write_text(
                "2026/10/19 10:00:01.000001 DEBUG handling new packet\n"
                "2026/10/19 10:00:02.000001 DEBUG replying from cache\n"
            )
            ingest(db,"dnsproxy",path)
            self.assertEqual(db.execute("SELECT count(*) FROM dnsproxy_packet_events").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT count(*) FROM dnsproxy_cache_events").fetchone()[0],1)
            ingest(db,"dnsproxy",path)
            self.assertEqual(db.execute("SELECT count(*) FROM dnsproxy_packet_events").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT count(*) FROM dnsproxy_cache_events").fetchone()[0],1)
            db.close()

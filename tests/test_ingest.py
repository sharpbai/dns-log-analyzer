import tempfile
import unittest
from pathlib import Path
from dns_log_analyzer.parsers import parse
from dns_log_analyzer.__main__ import connect, ingest

class TestIngest(unittest.TestCase):
    def test_dnsmasq(self):
        line="Oct 13 19:16:20 dnsmasq[3224430]: 63406 192.168.0.59/18754 forwarded clientservices.googleapis.com to 223.5.5.5"
        e=parse("dnsmasq",line,2026)
        self.assertEqual(e["upstream"],"223.5.5.5")
        self.assertEqual(e["domain"],"clientservices.googleapis.com")
    def test_dnsproxy(self):
        line='2026/10/13 19:11:01.379143 ERROR exchange failed prefix=dnsproxy upstream=tcp://9.9.9.9:53 question=";test.com.\\tIN\\t A" duration=13.341138234s err="EOF"'
        e=parse("dnsproxy",line)
        self.assertEqual(e["upstream"],"tcp://9.9.9.9:53")
        self.assertAlmostEqual(e["duration_ms"],13341.138234)
    def test_resume_and_truncate(self):
        with tempfile.TemporaryDirectory() as td:
            log=Path(td)/"masq.log"
            db=connect(str(Path(td)/"test.sqlite3"))
            line="Oct 13 19:16:20 dnsmasq[12]: 1 127.0.0.1/123 query[A] example.com from 127.0.0.1\n"
            log.write_text(line)
            self.assertEqual(ingest(db,"dnsmasq",log)[0],1)
            self.assertEqual(ingest(db,"dnsmasq",log)[0],0)
            log.write_text(line+line)
            self.assertEqual(ingest(db,"dnsmasq",log)[0],2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0],2)

if __name__ == "__main__":
    unittest.main()

import sqlite3
import tempfile
import unittest
from pathlib import Path
from dns_log_analyzer.v2 import schema,ingest,summary,parse_line

DOM='[INFO] 2026-11-13T23:45:12.123456789+08:00 127.0.0.1:52039 - 30953 "A IN a453.z.akamai.net. udp 46 true 1232" NOERROR qr,rd,ra 100 0.066939854s "0"'
STATS='2026-11-14T00:11:58.708732043+08:00 rripfilter_stats interval=60s queries=354 accept=105 partial=0 drop=92 bypass=97 upstream_error=60 rejected_ipv4=384 rejected_ipv6=3'
UNBOUND='[1794570667] unbound[2861590:0] info: 192.168.0.59 safebrowsing.googleapis.com. HTTPS IN NOERROR 0.005906 0 102'
class V2Tests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_line("domestic",DOM)[0],"2026-11-13T15:45:00")
        self.assertEqual(parse_line("domestic",DOM)[1]["rcode:NOERROR"],1)
        self.assertEqual(parse_line("rripfilter",STATS)[1]["upstream_error"],60)
        self.assertEqual(parse_line("unbound",UNBOUND)[1]["rcode:NOERROR"],1)
        self.assertIsNone(parse_line("domestic",DOM.replace("2026-11-13T23:45:12.123456789+08:00","{when}")))
    def test_incremental_and_truncate(self):
        with tempfile.TemporaryDirectory() as d:
            db=sqlite3.connect(":memory:");schema(db)
            path=Path(d)/"domestic.stdout"
            path.write_text(DOM+"\n")
            self.assertEqual(ingest(db,"domestic",path),1)
            self.assertEqual(ingest(db,"domestic",path),0)
            path.write_text(DOM.replace("NOERROR","SERVFAIL")+"\n")
            self.assertEqual(ingest(db,"domestic",path),1)
            data=summary(db,"2026-11-13T15:45:00","2026-11-13T15:46:00")["layers"]["domestic"]
            self.assertEqual(data["metrics"]["requests"],2)
            self.assertEqual(data["metrics"]["rcode:SERVFAIL"],1)
    def test_partial_line_and_stats(self):
        with tempfile.TemporaryDirectory() as d:
            db=sqlite3.connect(":memory:");schema(db)
            path=Path(d)/"domestic.stdout"
            path.write_text(DOM[:-4])
            self.assertEqual(ingest(db,"domestic",path),0)
            with path.open("a") as f:f.write(DOM[-4:]+"\n")
            self.assertEqual(ingest(db,"domestic",path),1)
            stats=Path(d)/"stats.stdout";stats.write_text(STATS+"\n")
            self.assertEqual(ingest(db,"rripfilter",stats),1)
            self.assertEqual(summary(db,"2026-11-13T16:11:00","2026-11-13T16:12:00")["layers"]["rripfilter"]["metrics"]["queries"],354)
    def test_from_end(self):
        with tempfile.TemporaryDirectory() as d:
            db=sqlite3.connect(":memory:");schema(db)
            p=Path(d)/"f";p.write_text(DOM+"\n")
            self.assertEqual(ingest(db,"fanout",p,from_end=True),0)
            with p.open("a") as f:f.write(DOM+"\n")
            self.assertEqual(ingest(db,"fanout",p),1)
if __name__=="__main__":unittest.main()

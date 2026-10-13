import tempfile
import unittest
from pathlib import Path
from dns_log_analyzer.requests import open_db, ingest

class RequestTests(unittest.TestCase):
 def test_request_aggregation(self):
  with tempfile.TemporaryDirectory() as d:
   m=Path(d)/"masq.log";p=Path(d)/"proxy.log"
   m.write_text("Oct 13 19:06:44 dnsmasq[12]: 123 192.168.0.2/1234 query[A] example.com from 192.168.0.2\nOct 13 19:06:44 dnsmasq[12]: 123 192.168.0.2/1234 forwarded example.com to 127.0.0.1#4053\nOct 13 19:06:45 dnsmasq[12]: 123 192.168.0.2/1234 reply example.com is 1.2.3.4\n")
   p.write_text("2026/10/13 19:06:44.100000 DEBUG sending request addr=1.1.1.1:53 proto=udp qtype=A qname=example.com.\n")
   db=open_db(str(Path(d)/"test.db"))
   self.assertEqual(ingest(db,"dnsmasq",m),3)
   self.assertEqual(ingest(db,"dnsproxy",p),1)
   self.assertEqual(db.execute("SELECT COUNT(*) FROM dnsmasq_requests").fetchone()[0],1)
   self.assertEqual(db.execute("SELECT forwarded,response_count FROM dnsmasq_requests").fetchone(),(1,1))
   self.assertEqual(db.execute("SELECT COUNT(*) FROM dnsproxy_upstream_attempts").fetchone()[0],0)
   self.assertEqual(ingest(db,"dnsmasq",m),0)

 def test_completion_only_and_incremental_append(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"proxy.log";db=open_db(str(Path(d)/"test.db"))
   sent="2026/10/13 23:00:04.100000 DEBUG sending request addr=tcp://1.1.1.1:53 proto=tcp qtype=A qname=example.com.\n"
   success='2026/10/13 23:00:04.690634 DEBUG exchange successfully finished prefix=dnsproxy upstream=tcp://1.1.1.1:53 question=";example.com.\\tIN\\t A" duration=988.434279ms\n'
   failure='2026/10/13 23:00:05.690634 ERROR exchange failed prefix=dnsproxy upstream=tcp://9.9.9.9:53 question=";bad.example.\\tIN\\t HTTPS" duration=12.3s err="EOF"\n'
   p.write_text(sent)
   self.assertEqual(ingest(db,"dnsproxy",p),1)
   self.assertEqual(db.execute("SELECT COUNT(*) FROM dnsproxy_upstream_attempts").fetchone()[0],0)
   with p.open("a") as stream:stream.write(success+failure)
   self.assertEqual(ingest(db,"dnsproxy",p),2)
   self.assertEqual(ingest(db,"dnsproxy",p),0)
   rows=db.execute("SELECT domain,qtype,status,duration_ms FROM dnsproxy_upstream_attempts ORDER BY id").fetchall()
   self.assertEqual(rows[0][:3],("example.com","A","success"))
   self.assertAlmostEqual(rows[0][3],988.434279)
   self.assertEqual(rows[1][:3],("bad.example","HTTPS","failed"))
   self.assertAlmostEqual(rows[1][3],12300)
 def test_copytruncate_and_concurrency(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"proxy.log";db=open_db(str(Path(d)/"test.db"))
   one='2026/10/13 23:00:04.690634 DEBUG exchange successfully finished prefix=dnsproxy upstream=8.8.8.8:53 question=";same.example.\\tIN\\t A" duration=10ms\n'
   p.write_text(one+one)
   self.assertEqual(ingest(db,"dnsproxy",p),2)
   self.assertEqual(db.execute("SELECT COUNT(*) FROM dnsproxy_upstream_attempts").fetchone()[0],2)
   p.write_text(one)
   self.assertEqual(ingest(db,"dnsproxy",p),1)
   self.assertEqual(db.execute("SELECT COUNT(*) FROM parser_diagnostics WHERE reason='rotation_or_truncation_detected'").fetchone()[0],1)

if __name__=="__main__":unittest.main()

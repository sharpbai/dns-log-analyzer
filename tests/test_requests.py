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
   self.assertEqual(db.execute("SELECT COUNT(*) FROM dnsproxy_upstream_attempts").fetchone()[0],1)
   self.assertEqual(ingest(db,"dnsmasq",m),0)
if __name__=="__main__":unittest.main()

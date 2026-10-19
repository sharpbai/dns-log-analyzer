import argparse,importlib.util,sqlite3,unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location("summary",Path(__file__).resolve().parents[1]/"scripts"/"dns_summary.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class FakeDateTime(datetime):
 @classmethod
 def now(cls):return cls(2026,10,19,23,12,43)
class MinuteWindowTests(unittest.TestCase):
 def test_natural_boundaries(self):
  with patch.object(m,"datetime",FakeDateTime):
   for key,expected in (("minute1",("2026-10-19T23:11:00","2026-10-19T23:12:00")),("minute5",("2026-10-19T23:05:00","2026-10-19T23:10:00"))):
    a=argparse.Namespace(period=key,days=None,start=None,end=None)
    self.assertEqual(m.period(a),expected)
 def test_only_minute_aggregate_no_details(self):
  db=sqlite3.connect(":memory:")
  db.executescript("""CREATE TABLE dns_hourly_aggregates(source TEXT,hour TEXT,dimension TEXT,total INTEGER,updated_at TEXT);
  CREATE TABLE dns_minute_aggregates(source TEXT,minute TEXT,dimension TEXT,total INTEGER);
  CREATE TABLE dns_latency_bins(hour TEXT,upstream TEXT,bin INTEGER,total INTEGER);
  INSERT INTO dns_minute_aggregates VALUES('smartdns','2026-10-19T23:05:00','total',7);
  INSERT INTO dns_minute_aggregates VALUES('smartdns','2026-10-19T23:09:00','total',9);
  INSERT INTO dns_minute_aggregates VALUES('smartdns','2026-10-19T23:10:00','total',100);
  INSERT INTO dns_minute_aggregates VALUES('smartdns','2026-10-19T23:11:00','total',3);""")
  five=m.collect_aggregate_only(db,"2026-10-19T23:05:00","2026-10-19T23:10:00")
  one=m.collect_aggregate_only(db,"2026-10-19T23:11:00","2026-10-19T23:12:00")
  self.assertEqual(five["smartdns"]["total"],16)
  self.assertEqual(one["smartdns"]["total"],3)
if __name__=="__main__":unittest.main()

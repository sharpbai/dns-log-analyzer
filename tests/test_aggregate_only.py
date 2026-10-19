import importlib.util,sqlite3,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location("dns_summary",Path(__file__).resolve().parents[1]/"scripts"/"dns_summary.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class AggregateOnlyTests(unittest.TestCase):
 def test_no_details_and_missing_hours_allowed(self):
  db=sqlite3.connect(":memory:")
  db.executescript("""
  CREATE TABLE dns_hourly_aggregates(source TEXT,hour TEXT,dimension TEXT,total INTEGER,updated_at TEXT);
  CREATE TABLE dns_minute_aggregates(source TEXT,minute TEXT,dimension TEXT,total INTEGER);
  CREATE TABLE dns_latency_bins(hour TEXT,upstream TEXT,bin INTEGER,total INTEGER);
  INSERT INTO dns_hourly_aggregates VALUES('smartdns','2026-10-19T16:00:00','total',10,'now');
  INSERT INTO dns_hourly_aggregates VALUES('smartdns','2026-10-19T16:00:00','cache_hits',8,'now');
  INSERT INTO dns_minute_aggregates VALUES('smartdns','2026-10-19T18:30:00','total',4);
  INSERT INTO dns_minute_aggregates VALUES('smartdns','2026-10-19T18:30:00','cache_hits',3);
  """)
  # Deliberately no request-level tables or aggregate progress table.
  r=m.collect_aggregate_only(db,"2026-10-19T00:00:00","2026-10-19T18:45:00")
  self.assertEqual(r["smartdns"]["total"],14)
  self.assertEqual(r["smartdns"]["cache_hits"],11)
  self.assertEqual(r["dnsproxy"]["latency_distribution"]["total"],0)
 def test_empty_aggregates_return_zero(self):
  db=sqlite3.connect(":memory:")
  db.executescript("""CREATE TABLE dns_hourly_aggregates(source TEXT,hour TEXT,dimension TEXT,total INTEGER,updated_at TEXT);
  CREATE TABLE dns_minute_aggregates(source TEXT,minute TEXT,dimension TEXT,total INTEGER);
  CREATE TABLE dns_latency_bins(hour TEXT,upstream TEXT,bin INTEGER,total INTEGER);""")
  self.assertEqual(m.collect_aggregate_only(db,"2026-10-19T00:00:00","2026-10-19T19:00:00")["smartdns"]["total"],0)
if __name__=="__main__":unittest.main()

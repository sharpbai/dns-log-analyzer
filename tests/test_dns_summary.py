import importlib.util
import sqlite3
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "dnsmasq_summary", Path(__file__).resolve().parents[1] / "scripts" / "dns_summary.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class SummaryTests(unittest.TestCase):
    def test_disjoint_classes_and_denominators(self):
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE dnsmasq_requests(first_seen TEXT,state TEXT,result TEXT)")
        rows = [
            ("2026-10-16T01:00:00","answered","1.2.3.4"),
            ("2026-10-16T01:00:00","answered",None),
            ("2026-10-16T01:00:00","answered","NXDOMAIN"),
            ("2026-10-16T01:00:00","answered","SERVFAIL"),
            ("2026-10-16T01:00:00","answered","duplicate"),
            ("2026-10-16T01:00:00","forwarded",None),
        ]
        db.executemany("INSERT INTO dnsmasq_requests VALUES(?,?,?)",rows)
        result = mod.summarize(db,"2026-10-16T00:00:00","2026-10-17T00:00:00")
        self.assertEqual([result[k] for k in ("total","success","failure","duplicate","unconfirmed")],[6,3,1,1,1])
        self.assertEqual(result["confirmed_success_rate"],75)
        self.assertEqual(result["overall_success_rate"],50)

if __name__ == "__main__":
    unittest.main()

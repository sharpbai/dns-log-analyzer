import importlib.util
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

spec=importlib.util.spec_from_file_location("prune",Path(__file__).resolve().parents[1]/"scripts"/"prune_dns_details.py")
prune=importlib.util.module_from_spec(spec)
spec.loader.exec_module(prune)

class RetentionSafetyTests(unittest.TestCase):
    def test_missing_rollups_block_deletion(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=sqlite3.connect(str(Path(tmp)/"test.sqlite"))
            for table,(col,_,_) in prune.DETAILS.items():
                db.execute(f"CREATE TABLE {table} ({col} TEXT)")
            db.execute("INSERT INTO smartdns_requests VALUES('2026-10-01T00:00:00')")
            with self.assertRaises(RuntimeError):
                prune.validate(db,datetime(2026,10,19))
            self.assertEqual(db.execute("SELECT count(*) FROM smartdns_requests").fetchone()[0],1)
            db.close()

if __name__=="__main__":
    unittest.main()

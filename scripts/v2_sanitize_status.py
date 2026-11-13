#!/usr/bin/env python3
"""One-time, transactional removal of accidental verbose overseas status keys."""
import argparse
import sqlite3
def sanitize(db):
    rows=db.execute("""SELECT minute,metric,total FROM v2_rollups
      WHERE source='overseas' AND metric LIKE 'status:%'
      AND metric NOT IN ('status:ok','status:error')""").fetchall()
    with db:
        for minute,metric,total in rows:
            db.execute("""INSERT INTO v2_rollups(source,minute,metric,total)
              VALUES('overseas',?,'status:error',?)
              ON CONFLICT(source,minute,metric) DO UPDATE SET total=total+excluded.total""",(minute,total))
            db.execute("DELETE FROM v2_rollups WHERE source='overseas' AND minute=? AND metric=?",(minute,metric))
    return len(rows)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--db",required=True)
    a=p.parse_args()
    db=sqlite3.connect(a.db,timeout=30)
    try:print("sanitized_status_keys",sanitize(db))
    finally:db.close()
if __name__=="__main__":main()

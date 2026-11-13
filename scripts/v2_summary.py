#!/usr/bin/env python3
"""JSON summary for V2 layered metrics, UTC windows; no request details."""
import argparse
import datetime as dt
import json
import sqlite3
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dns_log_analyzer.v2 import schema,summary,UTC
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--db",required=True)
    p.add_argument("--minutes",type=int,default=5)
    p.add_argument("--end",help="ISO8601 UTC end; default latest complete minute")
    a=p.parse_args()
    if a.minutes<1 or a.minutes>10080:p.error("minutes must be 1..10080")
    end=dt.datetime.fromisoformat(a.end.replace("Z","+00:00")) if a.end else dt.datetime.now(UTC)
    if end.tzinfo is None:p.error("--end must include timezone")
    end=end.astimezone(UTC).replace(second=0,microsecond=0)
    start=end-dt.timedelta(minutes=a.minutes)
    db=sqlite3.connect(f"file:{a.db}?mode=ro",uri=True)
    try:
        data=summary(db,start.strftime("%Y-%m-%dT%H:%M:00"),end.strftime("%Y-%m-%dT%H:%M:00"))
        data["generated_at"]=dt.datetime.now(UTC).isoformat()
        print(json.dumps(data,ensure_ascii=False))
    finally:db.close()
if __name__=="__main__":main()

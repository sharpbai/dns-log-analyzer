#!/usr/bin/env python3
"""Guarded 24-hour detail pruning. Never runs without explicit --apply."""
import argparse
import datetime as dt
import sqlite3

SOURCES = {
    "smartdns_requests": ("ts", "smartdns", "total"),
    "dnsproxy_upstream_attempts": ("first_seen", "dnsproxy", "attempts:"),
    "dnsproxy_packet_events": ("ts", "dnsproxy", "packet_events"),
    "dnsproxy_cache_events": ("ts", "dnsproxy", "cache_events"),
}
DETAILS = dict(SOURCES, dnsproxy_requests=("first_seen",None,None))

def validate(db, cutoff):
    if not {"aggregate_hour_progress","dns_hourly_aggregates"}.issubset(
        {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}):
        raise RuntimeError("aggregate tables missing")
    earliest = None
    for table,(column,_,_) in DETAILS.items():
        value = db.execute(f"SELECT min({column}) FROM {table}").fetchone()[0]
        if value is not None:
            earliest = min(earliest,value) if earliest else value
    if earliest is None:
        return
    triggers={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    required={"agg_smartdns_insert","agg_upstream_insert","agg_upstream_update",
              "agg_event_packet_events","agg_event_cache_events"}
    if not required.issubset(triggers):
        raise RuntimeError("incremental triggers missing: "+str(sorted(required-triggers)))
    # Aggregation coverage is checked against the actual rows below.
    # Do not require an hourly progress marker for each historical empty hour.
    for table,(column,source,dimension) in SOURCES.items():
        condition = " AND identity LIKE " + chr(39)+"%:exact:%"+chr(39) if dimension == "attempts:" else ""
        count = db.execute(f"SELECT count(*) FROM {table} WHERE {column}<?" + condition,
                           (cutoff.isoformat(timespec="seconds"),)).fetchone()[0]
        if dimension == "attempts:":
            rolled = db.execute("""SELECT coalesce(sum(total),0) FROM dns_hourly_aggregates
                 WHERE source='dnsproxy' AND dimension LIKE 'attempts:%' AND hour<?""",
                 (cutoff.isoformat(timespec="seconds"),)).fetchone()[0]
            # Older aggregate hours before current detail retention are allowed.
            if rolled < count:
                raise RuntimeError(f"aggregate shortfall for {table}")
        else:
            rolled = db.execute("""SELECT coalesce(sum(total),0) FROM dns_hourly_aggregates
                 WHERE source=? AND dimension=? AND hour<?""",
                 (source,dimension,cutoff.isoformat(timespec="seconds"))).fetchone()[0]
            if rolled < count:
                raise RuntimeError(f"aggregate shortfall for {table}")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--db",required=True)
    p.add_argument("--apply",action="store_true")
    p.add_argument("--retention-hours",type=int,default=24)
    p.add_argument("--batch-size",type=int,default=1000)
    args=p.parse_args()
    if args.retention_hours!=24 or args.batch_size<1 or args.batch_size>10000:
        p.error("only 24-hour retention with batch size 1..10000 is supported")
    cutoff=(dt.datetime.now()-dt.timedelta(hours=24)).replace(minute=0,second=0,microsecond=0)
    with sqlite3.connect(args.db,timeout=30) as db:
        db.execute("PRAGMA busy_timeout=30000")
        validate(db,cutoff)
        if not args.apply:
            print("VALIDATED ONLY: no records deleted; cutoff",cutoff.isoformat())
            return
        for table,(column,_,_) in DETAILS.items():
            total=0
            while True:
                with db:
                    db.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {column}<? LIMIT ?)",
                               (cutoff.isoformat(timespec="seconds"),args.batch_size))
                    removed=db.execute("SELECT changes()").fetchone()[0]
                total+=removed
                if removed==0:
                    break
            print(table,total,flush=True)
    print("done; no VACUUM performed")

if __name__=="__main__":
    main()

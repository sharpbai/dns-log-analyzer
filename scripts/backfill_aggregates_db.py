#!/usr/bin/env python3
"""Bounded, resumable aggregation from an existing request-level SQLite database.

Never reads DNS log files and never deletes request details.
Each hour is replaced atomically, making retries idempotent.
"""
import argparse
import datetime as dt
import json
import sqlite3
import time

BOUNDS = [50,100,150,200,250,300,400,500,700,1000,1500,3000]
TABLES = {
    "smartdns_requests": "ts",
    "dnsproxy_upstream_attempts": "first_seen",
    "dnsproxy_packet_events": "ts",
    "dnsproxy_cache_events": "ts",
}

def setup(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS dns_minute_aggregates(
      source TEXT NOT NULL, minute TEXT NOT NULL, dimension TEXT NOT NULL,
      total INTEGER NOT NULL, PRIMARY KEY(source,minute,dimension));
    CREATE TABLE IF NOT EXISTS dns_hourly_aggregates(
      source TEXT NOT NULL, hour TEXT NOT NULL, dimension TEXT NOT NULL,
      total INTEGER NOT NULL, updated_at TEXT NOT NULL,
      PRIMARY KEY(source,hour,dimension));
    CREATE TABLE IF NOT EXISTS dns_latency_histograms(
      source TEXT NOT NULL, hour TEXT NOT NULL, upstream TEXT NOT NULL,
      bounds_json TEXT NOT NULL, counts_json TEXT NOT NULL,
      total INTEGER NOT NULL, updated_at TEXT NOT NULL,
      PRIMARY KEY(source,hour,upstream));
    CREATE TABLE IF NOT EXISTS dns_latency_bins(hour TEXT NOT NULL,upstream TEXT NOT NULL,bin INTEGER NOT NULL,total INTEGER NOT NULL,PRIMARY KEY(hour,upstream,bin));
    CREATE TABLE IF NOT EXISTS aggregate_hour_progress(
      hour TEXT PRIMARY KEY, completed_at TEXT NOT NULL);
    """)
    db.commit()

def aggregate_hour(db, hour):
    start = dt.datetime.fromisoformat(hour)
    end = (start + dt.timedelta(hours=1)).isoformat(timespec="seconds")
    start = start.isoformat(timespec="seconds")
    stamp = dt.datetime.now().isoformat(timespec="seconds")
    with db:
        db.execute("DELETE FROM dns_hourly_aggregates WHERE hour=?", (start,))
        db.execute("DELETE FROM dns_minute_aggregates WHERE minute>=? AND minute<?", (start,end))
        db.execute("DELETE FROM dns_latency_histograms WHERE hour=?", (start,))
        db.execute("DELETE FROM dns_latency_bins WHERE hour=?", (start,))
        def store(source, dimension, count, minute):
            db.execute("INSERT INTO dns_minute_aggregates(source,minute,dimension,total) VALUES(?,?,?,?)", (source,minute,dimension,count))
            db.execute("INSERT INTO dns_hourly_aggregates(source,hour,dimension,total,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(source,hour,dimension) DO UPDATE SET total=total+excluded.total,updated_at=excluded.updated_at", (source,start,dimension,count,stamp))
        # Completed hours are rebuilt from existing SmartDNS records only.
        for minute,total,cache in db.execute("""
          SELECT substr(ts,1,16)||':00',count(*),coalesce(sum(duration_ms=0),0)
          FROM smartdns_requests WHERE ts>=? AND ts<?
          GROUP BY substr(ts,1,16)""",(start,end)).fetchall():
            for name,n in (("total",total),("cache_hits",cache)):
                store("smartdns",name,n,minute)
        for table,source in (("dnsproxy_packet_events","packet_events"),("dnsproxy_cache_events","cache_events")):
            for minute,n in db.execute(f"SELECT substr(ts,1,16)||':00',count(*) FROM {table} WHERE ts>=? AND ts<? GROUP BY substr(ts,1,16)",(start,end)).fetchall():
                store("dnsproxy",source,n,minute)
        # Stream per upstream rather than materializing all durations in Python.
        for upstream,total,failed in db.execute("""
          SELECT coalesce(upstream,'(unknown)'),count(*),coalesce(sum(status='failed'),0)
          FROM dnsproxy_upstream_attempts
          WHERE first_seen>=? AND first_seen<? AND identity LIKE '%:exact:%'
          GROUP BY coalesce(upstream,'(unknown)')""",(start,end)).fetchall():
            counts=[0]*(len(BOUNDS)+1)
            cursor=db.execute("""
              SELECT duration_ms FROM dnsproxy_upstream_attempts
              WHERE first_seen>=? AND first_seen<? AND identity LIKE '%:exact:%'
              AND coalesce(upstream,'(unknown)')=? AND status='success'
              AND duration_ms IS NOT NULL""",(start,end,upstream))
            for (duration,) in cursor:
                idx=next((i for i,b in enumerate(BOUNDS) if duration<b),len(BOUNDS))
                counts[idx]+=1
            db.executemany("INSERT INTO dns_latency_bins VALUES(?,?,?,?)",((start,upstream,i,n) for i,n in enumerate(counts)))
            db.execute("INSERT INTO dns_latency_histograms VALUES(?,?,?,?,?,?,?)",
                       ("dnsproxy",start,upstream,json.dumps(BOUNDS),json.dumps(counts),sum(counts),stamp))
            for name,n in (("attempts:"+upstream,total),("failed:"+upstream,failed)):
                db.execute("INSERT INTO dns_hourly_aggregates VALUES(?,?,?,?,?)",( "dnsproxy",start,name,n,stamp))
        db.execute("INSERT OR REPLACE INTO aggregate_hour_progress VALUES(?,?)",(start,stamp))

def run(db, start, end, refresh=False):
    setup(db)
    current=dt.datetime.fromisoformat(start)
    if current.minute or current.second or current.microsecond:
        raise ValueError("start must be an exact hour boundary")
    stop=dt.datetime.fromisoformat(end)
    if current >= stop or stop.minute or stop.second or stop.microsecond or stop > dt.datetime.now().replace(minute=0,second=0,microsecond=0):
        raise ValueError("end must be an exact hour boundary")
    completed=0
    expected=int((stop-current).total_seconds()//3600)
    began=time.monotonic()
    while current < stop:
        hour=current.isoformat(timespec="seconds")
        done=db.execute("SELECT 1 FROM aggregate_hour_progress WHERE hour=?",(hour,)).fetchone()
        if refresh or not done:
            aggregate_hour(db,hour)
            print("completed",hour,flush=True)
        completed+=1
        elapsed=time.monotonic()-began
        print(f"progress {completed}/{expected} ({100*completed/expected:.1f}%) elapsed={elapsed:.1f}s eta={elapsed/completed*(expected-completed):.1f}s",flush=True)
        current+=dt.timedelta(hours=1)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--db",required=True)
    p.add_argument("--start",required=True)
    p.add_argument("--end",required=True)
    p.add_argument("--refresh",action="store_true",help="recompute completed hours")
    a=p.parse_args()
    with sqlite3.connect(a.db,timeout=30) as db:
        db.execute("PRAGMA busy_timeout=30000")
        run(db,a.start,a.end,a.refresh)
if __name__=="__main__":
    main()

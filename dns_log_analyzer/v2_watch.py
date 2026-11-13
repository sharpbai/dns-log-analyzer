"""Dedicated DNS V2 incremental watcher; isolated from the V1 collector."""
import argparse
import signal
import sqlite3
import sys
import time
from pathlib import Path
from .v2 import SOURCES,ingest,schema
from .watch import Watcher

def collect(db,paths,first=False):
    results={}
    for source,path in paths.items():
        try:
            results[source]=ingest(db,source,path,from_end=first)
        except (OSError,sqlite3.Error,ValueError) as exc:
            print(f"v2 {source}: {type(exc).__name__}: {exc}",file=sys.stderr,flush=True)
    return results

def run(db,paths,interval=15,once=False,from_end=False):
    watcher=None if once else Watcher(paths)
    stopped=False
    def stop(*_):
        nonlocal stopped
        stopped=True
    if not once:
        signal.signal(signal.SIGTERM,stop)
        signal.signal(signal.SIGINT,stop)
    try:
        print("v2 initial",collect(db,paths,from_end),flush=True)
        if once:return
        while not stopped:
            dirty,overflow=watcher.wait(interval)
            if overflow:dirty=set(paths)
            if not dirty:dirty=set(paths)
            # Independent checkpoints allow rripfilter and domestic to read
            # the same file without double-counting each other's metrics.
            print("v2 update",collect(db,{s:paths[s] for s in dirty}),flush=True)
    finally:
        if watcher:watcher.close()
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--db",required=True)
    p.add_argument("--log-dir",default="/home/duobeigw/dns-lab/logs")
    p.add_argument("--once",action="store_true")
    p.add_argument("--from-end",action="store_true")
    p.add_argument("--interval",type=float,default=15)
    a=p.parse_args()
    if a.interval<=0:p.error("interval must be positive")
    base=Path(a.log_dir)
    paths={s:base/(( "domestic" if s=="rripfilter" else s)+".stdout") for s in SOURCES}
    db=sqlite3.connect(a.db,timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    schema(db)
    try:run(db,paths,a.interval,a.once,a.from_end)
    finally:db.close()
if __name__=="__main__":main()

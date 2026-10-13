"""One-off historical backfill. Run with the collector stopped.

Creates a fresh SQLite database from the available logs, and only replaces the
production DB after successful import and integrity validation. Caller handles
service stop/start and backup.
"""
import argparse
import gzip
import os
import sqlite3
import tempfile
from pathlib import Path
from dns_log_analyzer.requests import ingest,open_db

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",required=True)
    p.add_argument("--dnsmasq",default="/var/log/dnsmasq.log")
    p.add_argument("--dnsproxy",default="/var/log/dnsproxy.log")
    p.add_argument("--date",default="2026-10-13")
    args=p.parse_args()
    output=Path(args.output)
    if output.exists():
        p.error("output database already exists")
    db=open_db(str(output))
    with tempfile.TemporaryDirectory(prefix="dns-backfill-") as work:
        # Oldest to newest; only archives whose contents are from the target date.
        proxy=Path(args.dnsproxy)
        archives=[]
        for n in range(6,0,-1):
            path=Path(str(proxy)+f".{n}.gz")
            if path.exists():archives.append(path)
        for archive in archives:
            target=Path(work)/archive.name.replace(".gz",".txt")
            with gzip.open(archive,"rb") as src,target.open("wb") as dest:
                while True:
                    block=src.read(1024*1024)
                    if not block:break
                    dest.write(block)
            # Log files are short-lived; verify they belong to the requested day.
            with target.open("rb") as f:
                first=f.readline().decode("utf8","replace")
            if not first.startswith(args.date.replace("-","/")):
                print("skipping non-target archive",archive,flush=True)
                continue
            print("archive",archive,ingest(db,"dnsproxy",target),flush=True)
        print("dnsproxy live",ingest(db,"dnsproxy",proxy),flush=True)
        print("dnsmasq live",ingest(db,"dnsmasq",args.dnsmasq),flush=True)
    result=db.execute("PRAGMA integrity_check").fetchone()[0]
    if result!="ok":raise RuntimeError("integrity_check: "+result)
    for table in ("dnsmasq_requests","dnsproxy_requests","dnsproxy_upstream_attempts"):
        print(table,db.execute("SELECT COUNT(*) FROM "+table).fetchone()[0],flush=True)
    print("checkpoints",db.execute("SELECT source,offset,generation FROM ingest_checkpoints").fetchall(),flush=True)
    db.close()
if __name__=="__main__":
    main()

"""SQLite writer and resumable file readers."""
import argparse
import hashlib
import os
import sqlite3
import time
from pathlib import Path
from .parsers import parse

EVENT_FIELDS = ("ts", "level", "event", "query_id", "client", "domain", "qtype", "upstream", "protocol", "duration_ms", "duration_kind", "result", "error", "fields")

def connect(path):
    db = sqlite3.connect(path, timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=30000")
    db.execute("CREATE TABLE IF NOT EXISTS raw_logs(id INTEGER PRIMARY KEY, source TEXT NOT NULL, device INTEGER NOT NULL, inode INTEGER NOT NULL, offset INTEGER NOT NULL, raw TEXT NOT NULL, parsed INTEGER NOT NULL, UNIQUE(source,device,inode,offset))")
    db.execute("CREATE TABLE IF NOT EXISTS dns_events(raw_id INTEGER PRIMARY KEY REFERENCES raw_logs(id), source TEXT NOT NULL, ts TEXT, level TEXT, event TEXT, query_id TEXT, client TEXT, domain TEXT, qtype TEXT, upstream TEXT, protocol TEXT, duration_ms REAL, duration_kind TEXT, result TEXT, error TEXT, fields TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS checkpoints(source TEXT PRIMARY KEY, path TEXT NOT NULL, device INTEGER NOT NULL, inode INTEGER NOT NULL, offset INTEGER NOT NULL, head_hash TEXT NOT NULL, updated_at TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON dns_events(source,ts)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_events_upstream ON dns_events(upstream,ts)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_events_domain ON dns_events(domain,ts)")
    db.commit()
    return db

def _head(path):
    with open(path, "rb") as f: return hashlib.sha256(f.read(4096)).hexdigest()

def ingest(db, source, path, from_end=False, batch_size=500):
    path = Path(path)
    st = path.stat()
    head = _head(path)
    cp = db.execute("SELECT device,inode,offset,head_hash FROM checkpoints WHERE source=?", (source,)).fetchone()
    if cp and cp[0] == st.st_dev and cp[1] == st.st_ino and cp[2] <= st.st_size and cp[3] == head:
        start = cp[2]
    else:
        start = st.st_size if from_end and cp is None else 0
    total = unparsed = 0
    with path.open("rb") as f:
        f.seek(start)
        while True:
            rows = []
            for _ in range(batch_size):
                offset = f.tell()
                data = f.readline()
                if not data: break
                if not data.endswith(b"\n"):
                    f.seek(offset)
                    break
                line = data.decode("utf-8", "replace").rstrip("\r\n")
                rows.append((offset, line, parse(source, line)))
            if not rows: break
            with db:
                for offset, line, event in rows:
                    cur = db.execute("INSERT OR IGNORE INTO raw_logs(source,device,inode,offset,raw,parsed) VALUES(?,?,?,?,?,?)", (source, st.st_dev, st.st_ino, offset, line, int(event is not None)))
                    if cur.rowcount and event:
                        db.execute("INSERT INTO dns_events(raw_id,source," + ",".join(EVENT_FIELDS) + ") VALUES(" + ",".join(["?"] * 16) + ")", (cur.lastrowid, source, *(event[k] for k in EVENT_FIELDS)))
                    total += 1
                    unparsed += int(event is None)
                db.execute("INSERT INTO checkpoints(source,path,device,inode,offset,head_hash,updated_at) VALUES(?,?,?,?,?,?,datetime('now')) ON CONFLICT(source) DO UPDATE SET path=excluded.path,device=excluded.device,inode=excluded.inode,offset=excluded.offset,head_hash=excluded.head_hash,updated_at=excluded.updated_at", (source, str(path), st.st_dev, st.st_ino, f.tell(), head))
    return total, unparsed

def main():
    p = argparse.ArgumentParser(description="Incremental dnsmasq/dnsproxy log ingestion")
    p.add_argument("--db", default="./dns.sqlite3")
    p.add_argument("--dnsmasq", default="/var/log/dnsmasq.log")
    p.add_argument("--dnsproxy", default="/var/log/dnsproxy.log")
    p.add_argument("--follow", action="store_true")
    p.add_argument("--from-end", action="store_true")
    p.add_argument("--interval", type=float, default=2)
    p.add_argument("--stats", action="store_true")
    args = p.parse_args()
    db = connect(args.db)
    if args.stats:
        for row in db.execute("SELECT source,COUNT(*),SUM(parsed) FROM raw_logs GROUP BY source"):
            print(f"{row[0]}: raw={row[1]} parsed={row[2]}")
        return
    while True:
        for source, path in (("dnsmasq", args.dnsmasq), ("dnsproxy", args.dnsproxy)):
            try:
                n, bad = ingest(db, source, path, from_end=args.from_end)
                if n: print(f"{source}: lines={n} unparsed={bad}", flush=True)
            except (OSError, sqlite3.Error) as e:
                print(f"{source}: {type(e).__name__}: {e}", flush=True)
        args.from_end = False
        if not args.follow: break
        time.sleep(args.interval)

if __name__ == "__main__":
    main()

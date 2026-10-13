"""Request-level storage: no raw debug lines retained."""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from .parsers import parse

def open_db(path):
    db=sqlite3.connect(path,timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS dnsmasq_requests(
      id INTEGER PRIMARY KEY, identity TEXT UNIQUE, first_seen TEXT, last_seen TEXT,
      client TEXT, domain TEXT, qtype TEXT, cache_seen INTEGER DEFAULT 0,
      forwarded INTEGER DEFAULT 0, upstream TEXT, response_count INTEGER DEFAULT 0,
      result TEXT, state TEXT DEFAULT 'pending');
    CREATE TABLE IF NOT EXISTS dnsproxy_requests(
      id INTEGER PRIMARY KEY, identity TEXT UNIQUE, first_seen TEXT, last_seen TEXT,
      client TEXT, domain TEXT, qtype TEXT, state TEXT DEFAULT 'observed');
    CREATE TABLE IF NOT EXISTS dnsproxy_upstream_attempts(
      id INTEGER PRIMARY KEY, identity TEXT UNIQUE, first_seen TEXT, last_seen TEXT,
      domain TEXT, qtype TEXT, upstream TEXT, protocol TEXT, status TEXT DEFAULT 'sent',
      duration_ms REAL, error TEXT, request_id INTEGER);
    CREATE TABLE IF NOT EXISTS ingest_checkpoints(
      source TEXT PRIMARY KEY, path TEXT, device INTEGER, inode INTEGER,
      offset INTEGER, head_hash TEXT, updated_at TEXT);
    CREATE TABLE IF NOT EXISTS parser_diagnostics(
      source TEXT, reason TEXT, count INTEGER DEFAULT 0,
      PRIMARY KEY(source,reason));
    CREATE INDEX IF NOT EXISTS idx_masq_time ON dnsmasq_requests(first_seen);
    CREATE INDEX IF NOT EXISTS idx_proxy_time ON dnsproxy_requests(first_seen);
    CREATE INDEX IF NOT EXISTS idx_attempt_time ON dnsproxy_upstream_attempts(first_seen);
    CREATE INDEX IF NOT EXISTS idx_attempt_upstream ON dnsproxy_upstream_attempts(upstream);
    """)
    return db

def diagnostic(db,source,reason):
    db.execute("INSERT INTO parser_diagnostics(source,reason,count) VALUES(?,?,1) ON CONFLICT(source,reason) DO UPDATE SET count=count+1",(source,reason))

def process_dnsmasq(db,e,offset):
    if not e or not e["query_id"] or not e["client"]:return diagnostic(db,"dnsmasq","unparsed")
    fields=json.loads(e["fields"])
    identity=f'{fields["pid"]}:{e["query_id"]}:{e["client"]}'
    # A new query line defines a new request generation. Query IDs may be reused.
    if e["event"]=="query":
        identity+=f':{offset}'
        db.execute("INSERT OR IGNORE INTO dnsmasq_requests(identity,first_seen,last_seen,client,domain,qtype) VALUES(?,?,?,?,?,?)",(identity,e["ts"],e["ts"],e["client"],e["domain"],e["qtype"]))
        return
    row=db.execute("SELECT id FROM dnsmasq_requests WHERE identity LIKE ? AND first_seen<=? ORDER BY id DESC LIMIT 1",(identity+":%",e["ts"])).fetchone()
    if not row:return diagnostic(db,"dnsmasq","orphan_event")
    rid=row[0]
    if e["event"]=="forwarded":
        db.execute("UPDATE dnsmasq_requests SET last_seen=?,forwarded=1,upstream=?,state='forwarded' WHERE id=?",(e["ts"],e["upstream"],rid))
    elif e["event"]=="cached":
        db.execute("UPDATE dnsmasq_requests SET last_seen=?,cache_seen=1 WHERE id=?",(e["ts"],rid))
    elif e["event"] in ("reply","config"):
        db.execute("UPDATE dnsmasq_requests SET last_seen=?,response_count=response_count+1,result=COALESCE(?,result),state='answered' WHERE id=?",(e["ts"],e["result"],rid))
    else:diagnostic(db,"dnsmasq","other_event")

def process_dnsproxy(db,e,offset):
    if not e:return diagnostic(db,"dnsproxy","unparsed")
    event=e["event"]
    if event=="handling request":
        db.execute("INSERT OR IGNORE INTO dnsproxy_requests(identity,first_seen,last_seen,client,domain,qtype) VALUES(?,?,?,?,?,?)",(f"line:{offset}",e["ts"],e["ts"],e["client"],e["domain"],e["qtype"]))
    elif event=="sending request":
        db.execute("INSERT OR IGNORE INTO dnsproxy_upstream_attempts(identity,first_seen,last_seen,domain,qtype,upstream,protocol) VALUES(?,?,?,?,?,?,?)",(f"line:{offset}",e["ts"],e["ts"],e["domain"],e["qtype"],e["upstream"],e["protocol"]))
    elif event=="exchange failed":
        # Do not guess the matching request under concurrency.
        fields=json.loads(e["fields"])
        question=fields.get("question","")
        match=re.search(r";([^\\t ]+?)[.]?(?:\\\\t|\\t)IN(?:\\\\t|\\t)\\s*(\\w+)",question)
        domain=match.group(1).rstrip(".") if match else e["domain"]
        qtype=match.group(2) if match else e["qtype"]
        candidates=[]
        if e["upstream"] and domain and qtype:
            candidates=db.execute("SELECT id FROM dnsproxy_upstream_attempts WHERE status='sent' AND upstream=? AND domain=? AND qtype=? AND first_seen<=? AND (julianday(?) - julianday(first_seen))*86400 BETWEEN 0 AND 120",(e["upstream"],domain,qtype,e["ts"],e["ts"])).fetchall()
        if len(candidates)==1:
            db.execute("UPDATE dnsproxy_upstream_attempts SET status='failed',last_seen=?,duration_ms=?,error=? WHERE id=?",(e["ts"],e["duration_ms"],e["error"],candidates[0][0]))
        else:
            db.execute("INSERT OR IGNORE INTO dnsproxy_upstream_attempts(identity,first_seen,last_seen,domain,qtype,upstream,protocol,status,duration_ms,error) VALUES(?,?,?,?,?,?,?,?,?,?)",(f"failure:{offset}",e["ts"],e["ts"],domain,qtype,e["upstream"],e["protocol"],"failed_unmatched",e["duration_ms"],e["error"]))
            diagnostic(db,"dnsproxy","ambiguous_or_orphan_failure")
    elif event in ("exchange successfully finished","response received","resolved"):
        diagnostic(db,"dnsproxy","unmatched_completion")
    elif event in ("in","out","dialing","connection succeeded","no hosts records found","handling new udp packet"):
        pass
    else:diagnostic(db,"dnsproxy","ignored_event")

def head_hash(path):
    with open(path,"rb") as f:return hashlib.sha256(f.read(4096)).hexdigest()

def ingest(db,source,path,from_end=False,batch_size=1000):
    path=Path(path);st=path.stat();h=head_hash(path)
    cp=db.execute("SELECT device,inode,offset,head_hash FROM ingest_checkpoints WHERE source=?",(source,)).fetchone()
    start=cp[2] if cp and cp[0]==st.st_dev and cp[1]==st.st_ino and cp[2]<=st.st_size and cp[3]==h else (st.st_size if from_end and cp is None else 0)
    total=0
    with path.open("rb") as f:
        f.seek(start)
        while True:
            batch=[]
            for _ in range(batch_size):
                offset=f.tell();data=f.readline()
                if not data:break
                if not data.endswith(b"\n"):f.seek(offset);break
                batch.append((offset,data.decode("utf8","replace").rstrip("\r\n")))
            if not batch:break
            with db:
                for offset,line in batch:
                    e=parse(source,line)
                    (process_dnsmasq if source=="dnsmasq" else process_dnsproxy)(db,e,offset)
                db.execute("INSERT INTO ingest_checkpoints VALUES(?,?,?,?,?,?,datetime('now')) ON CONFLICT(source) DO UPDATE SET path=excluded.path,device=excluded.device,inode=excluded.inode,offset=excluded.offset,head_hash=excluded.head_hash,updated_at=excluded.updated_at",(source,str(path),st.st_dev,st.st_ino,f.tell(),h))
            total+=len(batch)
    return total

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--db",default="./dns-requests.sqlite3")
    p.add_argument("--dnsmasq",default="/var/log/dnsmasq.log")
    p.add_argument("--dnsproxy",default="/var/log/dnsproxy.log")
    p.add_argument("--follow",action="store_true")
    p.add_argument("--from-end",action="store_true")
    p.add_argument("--interval",type=float,default=2)
    p.add_argument("--stats",action="store_true")
    a=p.parse_args();db=open_db(a.db)
    if a.stats:
        for table in ("dnsmasq_requests","dnsproxy_requests","dnsproxy_upstream_attempts"):
            print(table,db.execute("SELECT COUNT(*) FROM "+table).fetchone()[0])
        print("diagnostics",db.execute("SELECT * FROM parser_diagnostics").fetchall())
        return
    while True:
        for source,path in (("dnsmasq",a.dnsmasq),("dnsproxy",a.dnsproxy)):
            try:
                n=ingest(db,source,path,a.from_end)
                if n:print(source,n,flush=True)
            except (OSError,sqlite3.Error) as exc:print(source,type(exc).__name__,str(exc),flush=True)
        a.from_end=False
        if not a.follow:break
        time.sleep(a.interval)
if __name__=="__main__":main()

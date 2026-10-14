"""Request-level storage: no raw debug lines retained."""
import argparse
import datetime as dt
import hashlib
import gzip
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
    CREATE INDEX IF NOT EXISTS idx_masq_identity_prefix ON dnsmasq_requests(identity COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS idx_proxy_time ON dnsproxy_requests(first_seen);
    CREATE INDEX IF NOT EXISTS idx_attempt_time ON dnsproxy_upstream_attempts(first_seen);
    CREATE INDEX IF NOT EXISTS idx_attempt_upstream ON dnsproxy_upstream_attempts(upstream);
    """)
    if 'generation' not in [x[1] for x in db.execute('PRAGMA table_info(ingest_checkpoints)')]:
        db.execute('ALTER TABLE ingest_checkpoints ADD COLUMN generation INTEGER DEFAULT 0')
        db.commit()
    return db

def diagnostic(db,source,reason):
    db.execute("INSERT INTO parser_diagnostics(source,reason,count) VALUES(?,?,1) ON CONFLICT(source,reason) DO UPDATE SET count=count+1",(source,reason))

def process_dnsmasq(db,e,offset,generation=0):
    if not e or not e["query_id"] or not e["client"]:return diagnostic(db,"dnsmasq","unparsed")
    fields=json.loads(e["fields"])
    identity=f'{fields["pid"]}:{e["query_id"]}:{e["client"]}'
    # A new query line defines a new request generation. Query IDs may be reused.
    if e["event"]=="query":
        identity+=f':{generation}:{offset}'
        db.execute("INSERT OR IGNORE INTO dnsmasq_requests(identity,first_seen,last_seen,client,domain,qtype) VALUES(?,?,?,?,?,?)",(identity,e["ts"],e["ts"],e["client"],e["domain"],e["qtype"]))
        return
    row=db.execute("SELECT id FROM dnsmasq_requests WHERE identity LIKE ? AND first_seen<=? ORDER BY id DESC LIMIT 1",(identity+f":{generation}:%",e["ts"])).fetchone()
    if not row:return diagnostic(db,"dnsmasq","orphan_event")
    rid=row[0]
    if e["event"]=="forwarded":
        db.execute("UPDATE dnsmasq_requests SET last_seen=?,forwarded=1,upstream=?,state='forwarded' WHERE id=?",(e["ts"],e["upstream"],rid))
    elif e["event"]=="cached":
        db.execute("UPDATE dnsmasq_requests SET last_seen=?,cache_seen=1,response_count=CASE WHEN response_count=0 THEN 1 ELSE response_count END,result=COALESCE(?,result),state='answered' WHERE id=?",(e["ts"],e["result"],rid))
    elif e["event"] in ("reply","config"):
        db.execute("UPDATE dnsmasq_requests SET last_seen=?,response_count=response_count+1,result=COALESCE(?,result),state='answered' WHERE id=?",(e["ts"],e["result"],rid))
    else:diagnostic(db,"dnsmasq","other_event")

def process_dnsproxy(db,e,offset,generation=0):
    if not e:return diagnostic(db,"dnsproxy","unparsed")
    event=e["event"]
    if event=="handling request":
        db.execute("INSERT OR IGNORE INTO dnsproxy_requests(identity,first_seen,last_seen,client,domain,qtype) VALUES(?,?,?,?,?,?)",(f"g:{generation}:line:{offset}",e["ts"],e["ts"],e["client"],e["domain"],e["qtype"]))
    elif event in ("exchange successfully finished","exchange failed"):
        fields=json.loads(e["fields"])
        question=fields.get("question","").replace(chr(92)+"t",chr(9))
        match=re.search(r";([^\s]+)\s+IN\s+(\w+)",question)
        if not match:
            diagnostic(db,"dnsproxy","completion_without_question")
            return
        domain,qtype=match.group(1).rstrip("."),match.group(2)
        status="success" if event=="exchange successfully finished" else "failed"
        db.execute("INSERT OR IGNORE INTO dnsproxy_upstream_attempts(identity,first_seen,last_seen,domain,qtype,upstream,protocol,status,duration_ms,error) VALUES(?,?,?,?,?,?,?,?,?,?)",(f"g:{generation}:completion:{offset}",e["ts"],e["ts"],domain,qtype,e["upstream"],e["protocol"],status,e["duration_ms"],e["error"]))
    elif event=="upstream exchange completed":
        status="success" if e["result"]=="ok" else "failed"
        elapsed=e["duration_ms"]
        if elapsed is None or elapsed < 0:
            return diagnostic(db,"dnsproxy","completion_invalid_duration")
        start=(dt.datetime.fromisoformat(e["ts"])-dt.timedelta(milliseconds=elapsed)).isoformat()
        error=None if status=="success" else e["result"]
        db.execute("INSERT OR IGNORE INTO dnsproxy_upstream_attempts(identity,first_seen,last_seen,domain,qtype,upstream,protocol,status,duration_ms,error) VALUES(?,?,?,?,?,?,?,?,?,?)",(f"g:{generation}:exact:{offset}",start,e["ts"],e["domain"].rstrip(".") if e["domain"] else None,e["qtype"],e["upstream"],e["protocol"],status,elapsed,error))
    elif event=="sending request":
        if e["ts"] >= "2026-10-14T02:43:17": return
        db.execute("INSERT OR IGNORE INTO dnsproxy_upstream_attempts(identity,first_seen,last_seen,domain,qtype,upstream,protocol,status) VALUES(?,?,?,?,?,?,?,?)",(f"g:{generation}:send:{offset}",e["ts"],e["ts"],e["domain"],e["qtype"],e["upstream"],e["protocol"],"sent"))
    elif event=="response received":
        if e["ts"] >= "2026-10-14T02:43:17": return
        rows=db.execute("SELECT id,first_seen FROM dnsproxy_upstream_attempts WHERE upstream=? AND protocol=? AND status='sent' AND first_seen BETWEEN ? AND ? ORDER BY id LIMIT 3",(e["upstream"],e["protocol"],(dt.datetime.fromisoformat(e["ts"])-dt.timedelta(seconds=4)).isoformat(),e["ts"])).fetchall()
        if len(rows)==1:
            rid,started=rows[0]
            try: elapsed=(dt.datetime.fromisoformat(e["ts"])-dt.datetime.fromisoformat(started)).total_seconds()*1000
            except ValueError: elapsed=-1
            if 0<=elapsed<=4000:
                db.execute("UPDATE dnsproxy_upstream_attempts SET last_seen=?,status=?,duration_ms=? WHERE id=?",(e["ts"],"success" if e["result"]=="ok" else "failed",elapsed,rid))
            else:diagnostic(db,"dnsproxy","response_outside_window")
        elif len(rows)>1:
            diagnostic(db,"dnsproxy","ambiguous_upstream_response")
        else:diagnostic(db,"dnsproxy","orphan_upstream_response")
    elif event=="resolved":
        pass
    elif event in ("in","out","dialing","connection succeeded","no hosts records found","handling new udp packet"):
        pass
    else:diagnostic(db,"dnsproxy","ignored_event")

def head_hash(path):
    with open(path,"rb") as f:return hashlib.sha256(f.read(4096)).hexdigest()

def _digest(stream, n):
    stream.seek(0)
    return hashlib.sha256(stream.read(min(n,4096))).hexdigest()

def _consume(db,source,stream,start,generation,batch_size):
    stream.seek(start)
    total=0
    while True:
        batch=[]
        for _ in range(batch_size):
            offset=stream.tell(); line=stream.readline()
            if not line: break
            if not line.endswith(bytes([10])): stream.seek(offset); break
            batch.append((offset,line.decode('utf8','replace').rstrip(chr(10)+chr(13))))
        if not batch: break
        with db:
            for offset,line in batch:
                e=parse(source,line)
                if source=='dnsmasq': process_dnsmasq(db,e,offset,generation)
                else: process_dnsproxy(db,e,offset,generation)
        total+=len(batch)
    return total,stream.tell()

def ingest(db,source,path,from_end=False,batch_size=1000):
    path=Path(path); st=path.stat()
    cp=db.execute('SELECT device,inode,offset,head_hash,generation FROM ingest_checkpoints WHERE source=?',(source,)).fetchone()
    with path.open('rb') as live:
        same=bool(cp and (cp[0],cp[1])==(st.st_dev,st.st_ino))
        valid=bool(same and cp[2]<=st.st_size and _digest(live,cp[2])==cp[3])
        generation=cp[4] if cp else 0
        total=0
        if cp and not valid:
            recovered=False
            for archive in (Path(str(path)+'.1'),Path(str(path)+'.1.gz')):
                if not archive.exists():continue
                try:
                    opener=gzip.open if archive.suffix=='.gz' else open
                    with opener(archive,'rb') as old:
                        if _digest(old,cp[2])!=cp[3]:continue
                        old.seek(0,2)
                        if old.tell()<cp[2]:continue
                        count,_=_consume(db,source,old,cp[2],generation,batch_size)
                        total+=count; recovered=True; break
                except (OSError,EOFError):continue
            with db:
                diagnostic(db,source,'rotation_or_truncation_detected')
                if not recovered:diagnostic(db,source,'unrecovered_rotation_gap')
            generation+=1
        start=cp[2] if valid else (st.st_size if from_end and cp is None else 0)
        count,offset=_consume(db,source,live,start,generation,batch_size)
        total+=count
        digest=_digest(live,offset)
        with db:
            db.execute("INSERT INTO ingest_checkpoints(source,path,device,inode,offset,head_hash,updated_at,generation) VALUES(?,?,?,?,?,?,datetime('now'),?) ON CONFLICT(source) DO UPDATE SET path=excluded.path,device=excluded.device,inode=excluded.inode,offset=excluded.offset,head_hash=excluded.head_hash,updated_at=excluded.updated_at,generation=excluded.generation",(source,str(path),st.st_dev,st.st_ino,offset,digest,generation))
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

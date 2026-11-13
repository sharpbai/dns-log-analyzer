"""DNS V2 event-time minute aggregates, SQLite checkpoints and histogram rollups.

Each layer is independent: counts across layers must never be added as unique
client requests. No raw DNS names or client IPs are persisted.
"""
import argparse
import datetime as dt
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from zoneinfo import ZoneInfo
from .parsers import parse as parse_existing

UTC=dt.timezone.utc
UNBOUND=re.compile(r'^\[(\d+)\] unbound\[[^]]+\] info: \S+ \S+ (\S+) IN (\S+) ([\d.]+) ([01]) (\d+)\s*$')
COREDNS=re.compile(r'^\[INFO\] (\S+) \S+ - \d+ "([A-Z0-9]+) IN \S+ (udp|tcp) [^"]+" (\S+) \S+ (\d+) ([\d.]+)s')
STATS=re.compile(r'^(\S+) rripfilter_stats interval=60s (.*)$')
FIELDS=re.compile(r'(\w+)=(\d+)')
BOUNDS=(1,5,10,25,50,100,200,500,1000,2000,3000,5000)
SOURCES=("unbound","fanout","domestic","rripfilter","overseas")
def minute(timestamp):
    return timestamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:00")
def iso(value):
    return dt.datetime.fromisoformat(value.replace("Z","+00:00"))
def schema(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS v2_offsets(
      source TEXT PRIMARY KEY,path TEXT NOT NULL,device INTEGER NOT NULL,
      inode INTEGER NOT NULL,offset INTEGER NOT NULL,head_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS v2_rollups(
      source TEXT NOT NULL,minute TEXT NOT NULL,metric TEXT NOT NULL,
      total INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(source,minute,metric));
    CREATE TABLE IF NOT EXISTS v2_latency_bins(
      source TEXT NOT NULL,minute TEXT NOT NULL,bin INTEGER NOT NULL,
      total INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(source,minute,bin));
    CREATE TABLE IF NOT EXISTS v2_diagnostics(
      source TEXT NOT NULL,reason TEXT NOT NULL,total INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY(source,reason));
    """)
    db.commit()
def bucket(ms):
    return next((i for i,b in enumerate(BOUNDS) if ms<b),len(BOUNDS))
def add(db,source,minute,metric,value=1):
    db.execute("""INSERT INTO v2_rollups VALUES(?,?,?,?)
      ON CONFLICT(source,minute,metric) DO UPDATE SET total=total+excluded.total""",
      (source,minute,metric,value))
def diagnostic(db,source,reason):
    db.execute("""INSERT INTO v2_diagnostics VALUES(?,?,1)
      ON CONFLICT(source,reason) DO UPDATE SET total=total+1""",(source,reason))
def parse_line(source,line):
    if source=="overseas":
        event=parse_existing("dnsproxy",line)
        if not event:return None
        if event["event"]!="upstream exchange completed":return None
        when=dt.datetime.fromisoformat(event["ts"]).replace(tzinfo=ZoneInfo("Asia/Shanghai"))
        status=event["result"] or "unknown"
        metrics={"exchanges":1,"status:"+status:1}
        if event["qtype"]:metrics["qtype:"+event["qtype"]]=1
        if event["protocol"]:metrics["transport:"+event["protocol"]]=1
        if event["duration_ms"] is None:return minute(when),metrics,None
        return minute(when),metrics,event["duration_ms"]
    if source=="unbound":
        m=UNBOUND.match(line)
        if not m:return None
        epoch,qtype,rcode,seconds,cache,size=m.groups()
        return minute(dt.datetime.fromtimestamp(int(epoch),UTC)),{"requests":1,"rcode:"+rcode:1,"qtype:"+qtype:1,"cache_flag:"+cache:1},float(seconds)*1000
    if source in ("fanout","domestic"):
        m=COREDNS.match(line)
        if not m:return None
        stamp,qtype,transport,rcode,size,seconds=m.groups()
        try:when=iso(stamp)
        except ValueError:return None
        if when.tzinfo is None:return None
        return minute(when),{"requests":1,"rcode:"+rcode:1,"qtype:"+qtype:1,"transport:"+transport:1},float(seconds)*1000
    if source=="rripfilter":
        m=STATS.match(line)
        if not m:return None
        try:when=iso(m.group(1))
        except ValueError:return None
        if when.tzinfo is None:return None
        # A completed interval is attributed to its ending minute.
        return minute(when),{k:int(v) for k,v in FIELDS.findall(m.group(2))},None
    return None
def head_digest(path,size):
    with path.open("rb") as f:return hashlib.sha256(f.read(min(4096,size))).hexdigest()
def ingest(db,source,path,from_end=False,max_lines=50000):
    if source not in SOURCES:raise ValueError(source)
    path=Path(path)
    st=path.stat()
    cp=db.execute("SELECT path,device,inode,offset,head_hash FROM v2_offsets WHERE source=?",(source,)).fetchone()
    digest=head_digest(path,min(st.st_size,4096))
    # Compare only when the previous checkpoint's first 4096 bytes still exist.
    unchanged=bool(cp and cp[0]==str(path) and cp[1:3]==(st.st_dev,st.st_ino) and cp[3]<=st.st_size)
    if unchanged and head_digest(path,min(cp[3],4096))!=cp[4]:unchanged=False
    start=cp[3] if unchanged else (st.st_size if cp is None and from_end else 0)
    processed=0
    with path.open("rb") as f,db:
        f.seek(start)
        for _ in range(max_lines):
            pos=f.tell()
            raw=f.readline()
            if not raw:break
            if not raw.endswith(b"\n"):
                f.seek(pos)
                break
            line=raw.decode("utf-8","replace").rstrip()
            event=parse_line(source,line)
            if event:
                when,metrics,latency=event
                for name,value in metrics.items():add(db,source,when,name,value)
                if latency is not None:
                    db.execute("""INSERT INTO v2_latency_bins VALUES(?,?,?,1)
                      ON CONFLICT(source,minute,bin) DO UPDATE SET total=total+1""",
                      (source,when,bucket(latency)))
                processed+=1
            elif ("rripfilter_stats" in line if source=="rripfilter" else
                  " info: " in line if source=="unbound" else "[INFO]" in line):
                diagnostic(db,source,"unparsed")
        db.execute("""INSERT INTO v2_offsets VALUES(?,?,?,?,?,?)
          ON CONFLICT(source) DO UPDATE SET path=excluded.path,device=excluded.device,
          inode=excluded.inode,offset=excluded.offset,head_hash=excluded.head_hash""",
          (source,str(path),st.st_dev,st.st_ino,f.tell(),head_digest(path,min(f.tell(),4096))))
    return processed
def summary(db,start,end):
    result={}
    for source,metric,total in db.execute("""SELECT source,metric,SUM(total) FROM v2_rollups
        WHERE minute>=? AND minute<? GROUP BY source,metric""",(start,end)):
        result.setdefault(source,{"metrics":{},"latency_ms":{}})["metrics"][metric]=total
    for source,bin_index,total in db.execute("""SELECT source,bin,SUM(total) FROM v2_latency_bins
        WHERE minute>=? AND minute<? GROUP BY source,bin""",(start,end)):
        result.setdefault(source,{"metrics":{},"latency_ms":{}})["latency_ms"][bin_index]=total
    for source in SOURCES:
        data=result.setdefault(source,{"metrics":{},"latency_ms":{}})
        counts=[data["latency_ms"].get(i,0) for i in range(len(BOUNDS)+1)]
        data["latency_ms"]={"bounds_ms":BOUNDS,"counts":counts,"total":sum(counts),
            "p50":quantile(counts,.5),"p95":quantile(counts,.95),"p99":quantile(counts,.99),
            "ge3s":sum(counts[BOUNDS.index(3000)+1:])}
    return {"window":{"start":start,"end":end,"timezone":"UTC"},"layers":result}
def quantile(counts,p):
    total=sum(counts)
    if not total:return None
    threshold=total*p;seen=0
    for i,n in enumerate(counts):
        if seen+n>=threshold:
            if i==len(BOUNDS):return None
            low=0 if i==0 else BOUNDS[i-1]
            return round(low+(BOUNDS[i]-low)*(threshold-seen)/n,2)
        seen+=n
    return None
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--db",required=True)
    p.add_argument("--source",choices=SOURCES,required=True)
    p.add_argument("--path",required=True)
    p.add_argument("--from-end",action="store_true")
    a=p.parse_args()
    db=sqlite3.connect(a.db,timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    schema(db)
    print(json.dumps({"processed":ingest(db,a.source,a.path,a.from_end)}))
if __name__=="__main__":main()

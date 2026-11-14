"""Local-only source migration helper; never run on production."""
from pathlib import Path
import shutil
root=Path(__file__).resolve().parent
def change(name, fn):
    p=root/name
    old=p.read_text()
    new=fn(old)
    assert new!=old, name
    backup=p.with_suffix(p.suffix+".pre-smartdns-local")
    if not backup.exists(): shutil.copy2(p,backup)
    p.write_text(new)
    print("UPDATED",name)
def backfill(s):
    s=s.replace('"dnsmasq_requests": "first_seen"', '"smartdns_requests": "ts"')
    a=s.index("        for minute,total,ok,bad,dup,cache in db.execute(")
    b=s.index("        for table,source in",a)
    s=s[:a]+'''        # Completed hours are rebuilt from existing SmartDNS records only.
        for minute,total,cache in db.execute("""
          SELECT substr(ts,1,16)||':00',count(*),coalesce(sum(duration_ms=0),0)
          FROM smartdns_requests WHERE ts>=? AND ts<?
          GROUP BY substr(ts,1,16)""",(start,end)).fetchall():
            for name,n in (("total",total),("cache_hits",cache)):
                store("smartdns",name,n,minute)
'''+s[b:]
    return s
def prune(s):
    s=s.replace('    start = dt.datetime.fromisoformat(earliest)', '    start = dt.datetime.fromisoformat(earliest)')
    a=s.index('    start = dt.datetime.fromisoformat(earliest)')
    b=s.index('    for table,(column,source,dimension) in SOURCES.items():',a)
    s=s[:a]+'''    triggers={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    required={"agg_smartdns_insert","agg_upstream_insert","agg_upstream_update",
              "agg_event_packet_events","agg_event_cache_events"}
    if not required.issubset(triggers):
        raise RuntimeError("incremental triggers missing: "+str(sorted(required-triggers)))
    # Aggregation coverage is checked against the actual rows below.
    # Do not require an hourly progress marker for each historical empty hour.
'''+s[b:]
    return s
def summary(s):
    a=s.index("def summarize(")
    b=s.index("def collect_aggregated(",a)
    s=s[:a]+'''def summarize(db,start,end):
 t,cache=db.execute("SELECT count(*),coalesce(sum(duration_ms=0),0) FROM smartdns_requests WHERE ts>=? AND ts<?",(start,end)).fetchone()
 return dict(total=t,cache_hits=cache,cache_hit_rate=pct(cache,t))
'''+s[b:]
    a=s.index('    tail = {"total":0')
    b=s.index('        for source, table in',a)
    s=s[:a]+'''    tail={"total":0,"cache_hits":0}
    if stop < b:
        vals=db.execute("SELECT count(*),coalesce(sum(duration_ms=0),0) FROM smartdns_requests WHERE ts>=? AND ts<?",(stop,b)).fetchone()
        tail=dict(zip(tail,vals))
'''+s[b:]
    a=s.index('    def m(k):')
    b=s.index('    all_counts =',a)
    s=s[:a]+'''    def m(k):return metrics.get(("smartdns",k),0)+tail.get(k,0)
    total,cache=m("total"),m("cache_hits")
'''+s[b:]
    a=s.index('        dnsmasq=dict(')
    b=s.index('        dnsproxy=dict(',a)
    s=s[:a]+'''        smartdns=dict(total=total,cache_hits=cache,cache_hit_rate=pct(cache,total),
          cache_estimate="time=0ms; not an authoritative cache-hit flag"),
'''+s[b:]
    a=s.index(' t,dup,ok,bad,cache=db.execute(',s.index('def collect(db,a,b):'))
    b=s.index(' ups=[]',a)
    s=s[:a]+''' t,cache=db.execute("SELECT count(*),coalesce(sum(duration_ms=0),0) FROM smartdns_requests WHERE ts>=? AND ts<?",(a,b)).fetchone()
'''+s[b:]
    a=s.index('return dict(window=dict(start=a,end=b),dnsmasq=dict(')
    b=s.index('dnsproxy=dict(',a)
    s=s[:a]+'''return dict(window=dict(start=a,end=b),smartdns=dict(total=t,cache_hits=cache,cache_hit_rate=pct(cache,t),cache_estimate="time=0ms; not an authoritative cache-hit flag"),'''+s[b:]
    s=s.replace('m=d["dnsmasq"]','m=d["smartdns"]')
    a=s.index(' section("DNSMASQ")')
    b=s.index(' section("DNSPROXY")',a)
    s=s[:a]+''' section("SMARTDNS")
 line(f"总查询 {n(m['total'])}  0ms请求 {n(m['cache_hits'])}  0ms比例 {rate(m['cache_hit_rate'])}")
'''+s[b:]
    return s
change("backfill_aggregates_db.py",backfill)
change("prune_dns_details.py",prune)
change("dns_summary.py",summary)

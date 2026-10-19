#!/usr/bin/env python3
import argparse,json,sqlite3,sys
from pathlib import Path
from datetime import datetime,timedelta
def period(a):
 now=datetime.now();day=now.replace(hour=0,minute=0,second=0,microsecond=0)
 if (a.start or a.end) and (a.period or a.days):raise ValueError("时间参数冲突")
 if a.days is not None and a.period:raise ValueError("时间参数冲突")
 if a.days is not None:
  if a.days<1:raise ValueError("days must be positive")
  x,y=now-timedelta(days=a.days),now
 elif a.start or a.end:x,y=datetime.fromisoformat(a.start) if a.start else day,datetime.fromisoformat(a.end) if a.end else now
 elif a.period in ("minute1","minute5"):
  step=1 if a.period=="minute1" else 5
  y=now.replace(minute=(now.minute//step)*step,second=0,microsecond=0)
  x=y-timedelta(minutes=step)
 elif a.period=="yesterday":x,y=day-timedelta(days=1),day
 elif a.period=="week":x,y=day-timedelta(days=day.weekday()),now
 elif a.period=="month":x,y=day.replace(day=1),now
 elif a.period=="last7":x,y=now-timedelta(days=7),now
 else:x,y=day,now
 if x>=y:raise ValueError("start must precede end")
 return x.isoformat(timespec="seconds"),y.isoformat(timespec="seconds")
def pct(x,n):return round(100*x/n,3) if n else None
def quant(x,p):return round(sorted(x)[int((len(x)-1)*p)],1) if x else None
def quant_hist(bounds,counts,p):
 total=sum(counts)
 if not total:return None
 rank=max(1,int((total-1)*p)+1); seen=0
 for i,count in enumerate(counts):
  seen+=count
  if seen>=rank:return bounds[i] if i<len(bounds) else None
 return None
def summarize(db,start,end):
 t,cache=db.execute("SELECT count(*),coalesce(sum(duration_ms=0),0) FROM smartdns_requests WHERE ts>=? AND ts<?",(start,end)).fetchone()
 return dict(total=t,cache_hits=cache,cache_hit_rate=pct(cache,t))
def collect_aggregated(db, a, b):
    """Use completed hourly buckets plus at most one current-hour detail tail."""
    from datetime import datetime
    start = datetime.fromisoformat(a)
    end = datetime.fromisoformat(b)
    if start.minute or start.second or start.microsecond:
        return None
    boundary = end.replace(minute=0, second=0, microsecond=0)
    if boundary < start:
        return None
    stop = boundary.isoformat(timespec="seconds")
    hours = int((boundary - start).total_seconds() // 3600)
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required = {"dns_hourly_aggregates", "dns_latency_bins", "aggregate_hour_progress"}
    if not required.issubset(tables) or hours == 0:
        return None
    covered = db.execute(
        "SELECT count(*) FROM aggregate_hour_progress WHERE hour>=? AND hour<?",
        (a, stop)).fetchone()[0]
    if covered != hours:
        return None
    metrics = {}
    for source, dimension, count in db.execute(
        "SELECT source,dimension,sum(total) FROM dns_hourly_aggregates WHERE hour>=? AND hour<? GROUP BY source,dimension",
        (a, stop)):
        metrics[(source, dimension)] = int(count)
    names = set()
    upstream = {}
    bounds = [50,100,150,200,250,300,400,500,700,1000,1500,3000]
    for name, bin_index, amount in db.execute(
        "SELECT upstream,bin,sum(total) FROM dns_latency_bins WHERE hour>=? AND hour<? GROUP BY upstream,bin",
        (a, stop)):
        values = [0]*13
        values[bin_index] = amount
        dest = upstream.setdefault(name, [0]*13)
        for i, value in enumerate(values):
            dest[i] += value
        names.add(name)
    for source, dimension in metrics:
        if source == "dnsproxy" and dimension.startswith("attempts:"):
            names.add(dimension[9:])
    # Only the unfinished tail reads details. Historical hours never do.
    tail={"total":0,"cache_hits":0}
    if stop < b:
        vals=db.execute("SELECT count(*),coalesce(sum(duration_ms=0),0) FROM smartdns_requests WHERE ts>=? AND ts<?",(stop,b)).fetchone()
        tail=dict(zip(tail,vals))
        for source, table in (("packet_events","dnsproxy_packet_events"),("cache_events","dnsproxy_cache_events")):
            if table in tables:
                metrics[("dnsproxy",source)] = metrics.get(("dnsproxy",source),0) + db.execute(
                    f"SELECT count(*) FROM {table} WHERE ts>=? AND ts<?",(stop,b)).fetchone()[0]
        for name, status, duration in db.execute(
            "SELECT upstream,status,duration_ms FROM dnsproxy_upstream_attempts WHERE first_seen>=? AND first_seen<? AND identity LIKE '%:exact:%'",
            (stop,b)):
            name = name or "(unknown)"
            names.add(name)
            metrics[("dnsproxy","attempts:"+name)] = metrics.get(("dnsproxy","attempts:"+name),0)+1
            if status == "failed":
                metrics[("dnsproxy","failed:"+name)] = metrics.get(("dnsproxy","failed:"+name),0)+1
            if status == "success" and duration is not None:
                counts = upstream.setdefault(name,[0]*13)
                i = next((i for i, limit in enumerate(bounds) if duration < limit),12)
                counts[i] += 1
    def m(k):return metrics.get(("smartdns",k),0)+tail.get(k,0)
    total,cache=m("total"),m("cache_hits")
    all_counts = [0]*13
    ups = []
    for name in names:
        counts = upstream.get(name,[0]*13)
        for i,v in enumerate(counts):
            all_counts[i] += v
        n = metrics.get(("dnsproxy","attempts:"+name),0)
        bad = metrics.get(("dnsproxy","failed:"+name),0)
        ups.append(dict(name=name,total=n,failed=bad,success_rate=pct(n-bad,n),
                        p50=quant_hist(bounds,counts,.5),p95=quant_hist(bounds,counts,.95),
                        p99=quant_hist(bounds,counts,.99),over_3s=counts[-1]))
    ups.sort(key=lambda item:-item["total"])
    packet = metrics.get(("dnsproxy","packet_events"),0)
    cached = metrics.get(("dnsproxy","cache_events"),0)
    return dict(window=dict(start=a,end=b),
        smartdns=dict(total=total,cache_hits=cache,cache_hit_rate=pct(cache,total),
          cache_estimate="time=0ms; not an authoritative cache-hit flag"),
        dnsproxy=dict(packet_events=packet,cache_events=cached,cache_event_ratio=pct(cached,packet),
          upstreams=ups,latency_distribution=dict(bounds_ms=bounds,counts=all_counts,
            total=sum(all_counts),p50=quant_hist(bounds,all_counts,.5),
            p95=quant_hist(bounds,all_counts,.95),p99=quant_hist(bounds,all_counts,.99),
            p999=quant_hist(bounds,all_counts,.999),ge1s=sum(all_counts[10:]),
            ge3s=all_counts[-1],
            scope="successful upstream exchanges; not deduplicated client requests; bucket-estimated quantiles"),
          final_latency="N/A: unpaired upstream events"))

def collect_aggregate_only(db,a,b):
 """Return only existing aggregate rows; never inspect request-level tables."""
 from datetime import datetime,timedelta
 start,end=datetime.fromisoformat(a),datetime.fromisoformat(b)
 minute_window=(end-start).total_seconds()<=300
 hourly_start=(start+timedelta(hours=1)).replace(minute=0,second=0,microsecond=0) if (start.minute or start.second) else start
 hourly_end=end.replace(minute=0,second=0,microsecond=0)
 bounds=[50,100,150,200,250,300,400,500,700,1000,1500,3000]
 metrics={}
 for source,dimension,n in db.execute(
  "SELECT source,dimension,sum(total) FROM dns_hourly_aggregates WHERE hour>=? AND hour<? GROUP BY source,dimension",
  (hourly_start.isoformat(timespec="seconds"),hourly_end.isoformat(timespec="seconds"))) :
  metrics[(source,dimension)]=int(n)
 # Minute rows only for the currently unfinished hour. Do not double count
 # completed hourly buckets or require a historical progress marker.
 tail_start=start if minute_window else end.replace(minute=0,second=0,microsecond=0)
 if tail_start<start:tail_start=start
 for source,dimension,n in db.execute(
  "SELECT source,dimension,sum(total) FROM dns_minute_aggregates WHERE minute>=? AND minute<? GROUP BY source,dimension",
  (tail_start.isoformat(timespec="seconds"),b)):
  metrics[(source,dimension)]=metrics.get((source,dimension),0)+int(n)
 names=set()
 for (source,dimension),n in metrics.items():
  if source=="dnsproxy" and dimension.startswith(("attempts:","failed:")):
   names.add(dimension.split(":",1)[1])
 upstream={name:[0]*13 for name in names}
 for name,bin_index,n in db.execute(
  "SELECT upstream,bin,sum(total) FROM dns_latency_bins WHERE hour>=? AND hour<? GROUP BY upstream,bin",(hourly_start.isoformat(timespec="seconds"),hourly_end.isoformat(timespec="seconds"))) :
  upstream.setdefault(name,[0]*13)[int(bin_index)]+=int(n)
 names.update(upstream)
 ups=[]
 all_counts=[0]*13
 for name in names:
  counts=upstream.get(name,[0]*13)
  all_counts=[x+y for x,y in zip(all_counts,counts)]
  n=metrics.get(("dnsproxy","attempts:"+name),0)
  bad=metrics.get(("dnsproxy","failed:"+name),0)
  ups.append(dict(name=name,total=n,failed=bad,success_rate=pct(n-bad,n),
    p50=quant_hist(bounds,counts,.5),p95=quant_hist(bounds,counts,.95),
    p99=quant_hist(bounds,counts,.99),over_3s=counts[-1]))
 ups.sort(key=lambda u:-u["total"])
 def m(source,key):return metrics.get((source,key),0)
 total=m("smartdns","total");hits=m("smartdns","cache_hits")
 packets=m("dnsproxy","packet_events");cached=m("dnsproxy","cache_events")
 return dict(window=dict(start=a,end=b),
  smartdns=dict(total=total,cache_hits=hits,cache_hit_rate=pct(hits,total),
    cache_estimate="time=0ms; not an authoritative cache-hit flag"),
  dnsproxy=dict(packet_events=packets,cache_events=cached,cache_event_ratio=pct(cached,packets),
   upstreams=ups,latency_distribution=dict(bounds_ms=bounds,counts=all_counts,total=sum(all_counts),
    p50=quant_hist(bounds,all_counts,.5),p95=quant_hist(bounds,all_counts,.95),
    p99=quant_hist(bounds,all_counts,.99),p999=quant_hist(bounds,all_counts,.999),
    ge1s=sum(all_counts[10:]),ge3s=all_counts[-1],
    scope="completed-hour upstream aggregates; current-hour latency excluded"),
   final_latency="N/A: unpaired upstream events"))

def collect(db,a,b):
 aggregated=collect_aggregated(db,a,b)
 if aggregated is not None:return aggregated
 t,cache=db.execute("SELECT count(*),coalesce(sum(duration_ms=0),0) FROM smartdns_requests WHERE ts>=? AND ts<?",(a,b)).fetchone()
 ups=[]
 all_durations=[]
 bins=[50,100,150,200,250,300,400,500,700,1000,1500,3000]
 histogram=[0]*13
 # Exact completions only. Histograms merge by adding counts; quantiles are
 # bucket estimates and never claim precision within an individual bucket.
 rows=db.execute("""SELECT first_seen,upstream,status,duration_ms FROM dnsproxy_upstream_attempts WHERE identity LIKE '%:exact:%' AND first_seen>=? AND first_seen<?""",(a,b))
 by_up={}
 for ts,name,status,duration in rows:
  item=by_up.setdefault(name,[0,0,[0]*(len(bins)+1)]);item[0]+=1;item[1]+=int(status=='failed')
  if status=='success' and duration is not None:
   i=next((i for i,bound in enumerate(bins) if duration<bound),len(bins));item[2][i]+=1
 for name,(n,failed,counts) in sorted(by_up.items(),key=lambda x:-x[1][0]):
  total=sum(counts);p50=quant_hist(bins,counts,.5);p95=quant_hist(bins,counts,.95);p99=quant_hist(bins,counts,.99)
  over3=counts[-1]
  ups.append(dict(name=name,total=n,failed=failed,success_rate=pct(n-failed,n),p50=p50,p95=p95,p99=p99,over_3s=over3))
  for i,count in enumerate(counts):histogram[i]+=count
 tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
 packet=db.execute("SELECT count(*) FROM dnsproxy_packet_events WHERE ts>=? AND ts<?",(a,b)).fetchone()[0] if 'dnsproxy_packet_events' in tables else 0
 cached=db.execute("SELECT count(*) FROM dnsproxy_cache_events WHERE ts>=? AND ts<?",(a,b)).fetchone()[0] if 'dnsproxy_cache_events' in tables else 0
 return dict(window=dict(start=a,end=b),smartdns=dict(total=t,cache_hits=cache,cache_hit_rate=pct(cache,t),cache_estimate="time=0ms; not an authoritative cache-hit flag"),dnsproxy=dict(packet_events=packet,cache_events=cached,cache_event_ratio=pct(cached,packet),upstreams=ups,latency_distribution=dict(bounds_ms=bins,counts=histogram,total=sum(histogram),p50=quant_hist(bins,histogram,.5),p95=quant_hist(bins,histogram,.95),p99=quant_hist(bins,histogram,.99),p999=quant_hist(bins,histogram,.999),ge1s=sum(histogram[10:]),ge3s=histogram[-1],scope="successful upstream exchanges; not deduplicated client requests; bucket-estimated quantiles"),final_latency="N/A: unpaired upstream events"))
def show(d,color):
 import shutil
 def style(s,n):return ("\033["+n+"m"+s+"\033[0m") if color else s
 m=d["smartdns"];p=d["dnsproxy"];width=shutil.get_terminal_size((96,24)).columns
 compact=width<86
 def n(v):return f"{v:,}"
 def rate(v):return "N/A" if v is None else f"{v:.2f}%"
 def latency(v):return "-" if v is None else f"{v:.0f}"
 def line(s):print(s)
 def section(title):line(style("─ "+title+" "+"─"*max(0,(min(width,100)-len(title)-3)),"36"))
 line(style("DNS SUMMARY  •  local-57  •  READ ONLY","1;36"))
 line(f"{d['window']['start']}  →  {d['window']['end']}")
 section("SMARTDNS")
 line(f"总查询 {n(m['total'])}  0ms请求 {n(m['cache_hits'])}  0ms比例 {rate(m['cache_hit_rate'])}")
 section("DNSPROXY")
 line(f"请求事件 {n(p['packet_events'])}  缓存事件 {n(p['cache_events'])}  事件比例 {rate(p['cache_event_ratio'])}")
 section("UPSTREAM / SUCCESSFUL EXCHANGES (ms)")
 if compact:
  line(f"{'UPSTREAM':<23} {'OK%':>8} {'P50':>6} {'P95':>6} {'P99':>6} {'≥3s':>5}")
 else:
  line(f"{'UPSTREAM':<37} {'OK%':>9} {'P50':>7} {'P95':>7} {'P99':>7} {'≥3s':>6}")
 for u in p['upstreams']:
  name=u['name'].replace("https://","DoH ").replace(":443/dns-query","").replace(":53"," UDP")
  if compact:name=name.replace("cloudflare-dns.com","Cloudflare").replace("dns.google","Google")
  if compact:line(f"{name[:23]:<23} {rate(u['success_rate']):>8} {latency(u['p50']):>6} {latency(u['p95']):>6} {latency(u['p99']):>6} {u['over_3s']:>5}")
  else:line(f"{name[:37]:<37} {rate(u['success_rate']):>9} {latency(u['p50']):>7} {latency(u['p95']):>7} {latency(u['p99']):>7} {u['over_3s']:>6}")
 line(style("注：上游耗时非客户端最终耗时；无可靠配对时最终 P99 不统计。","2"))
def main():
 p=argparse.ArgumentParser(prog="dns-summary",description="DNS 只读综合仪表盘；默认终端 TUI，不动态刷新")
 p.add_argument("period",nargs="?",choices=["minute1","minute5","today","yesterday","week","month","last7"])
 p.add_argument("--days",type=int);p.add_argument("--start");p.add_argument("--end")
 p.add_argument("--aggregate-only",action="store_true");p.add_argument("--db",default="/var/lib/dns-log-analyzer/requests.sqlite3")
 g=p.add_mutually_exclusive_group();g.add_argument("--plain",action="store_true");g.add_argument("--json",action="store_true")
 a=p.parse_args()
 try:
  x,y=period(a)
  with sqlite3.connect(Path(a.db).resolve().as_uri()+"?mode=ro",uri=True) as db:d=collect_aggregate_only(db,x,y) if a.aggregate_only else collect(db,x,y)
 except (ValueError,sqlite3.Error,OSError) as e:p.error(str(e))
 if a.json:print(json.dumps(d,ensure_ascii=False,indent=2))
 else:show(d,sys.stdout.isatty() and not a.plain)
if __name__=="__main__":main()

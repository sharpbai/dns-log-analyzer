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
 elif a.period=="yesterday":x,y=day-timedelta(days=1),day
 elif a.period=="week":x,y=day-timedelta(days=day.weekday()),now
 elif a.period=="month":x,y=day.replace(day=1),now
 elif a.period=="last7":x,y=now-timedelta(days=7),now
 else:x,y=day,now
 if x>=y:raise ValueError("start must precede end")
 return x.isoformat(timespec="seconds"),y.isoformat(timespec="seconds")
def pct(x,n):return round(100*x/n,3) if n else None
def quant(x,p):return round(sorted(x)[int((len(x)-1)*p)],1) if x else None
def summarize(db,start,end):
 t,dup,ok,bad=db.execute("""SELECT count(*),coalesce(sum(result='duplicate'),0),coalesce(sum(state='answered' AND (result IS NULL OR result NOT IN ('SERVFAIL','REFUSED','duplicate'))),0),coalesce(sum(result IN ('SERVFAIL','REFUSED')),0) FROM dnsmasq_requests WHERE first_seen>=? AND first_seen<?""",(start,end)).fetchone()
 return dict(total=t,success=ok,failure=bad,duplicate=dup,unconfirmed=t-dup-ok-bad,confirmed_success_rate=100*ok/(ok+bad) if ok+bad else None,overall_success_rate=100*ok/t if t else None)
def collect(db,a,b):
 t,dup,ok,bad,cache=db.execute("""SELECT count(*),sum(result='duplicate'),sum(state='answered' AND (result IS NULL OR result NOT IN ('SERVFAIL','REFUSED','duplicate'))),sum(result IN ('SERVFAIL','REFUSED')),sum(cache_seen=1 AND forwarded=0) FROM dnsmasq_requests WHERE first_seen>=? AND first_seen<?""",(a,b)).fetchone()
 t,dup,ok,bad,cache=[v or 0 for v in (t,dup,ok,bad,cache)]
 ups=[]
 all_durations=[]
 bins=[50,100,150,200,250,300,400,500,700,1000,1500,3000]
 histogram=[0]*13
 for name,n,failed in db.execute("""SELECT upstream,count(*),sum(status='failed') FROM dnsproxy_upstream_attempts WHERE identity LIKE '%:exact:%' AND first_seen>=? AND first_seen<? GROUP BY upstream ORDER BY count(*) DESC""",(a,b)):
  durations=[v[0] for v in db.execute("""SELECT duration_ms FROM dnsproxy_upstream_attempts WHERE identity LIKE '%:exact:%' AND first_seen>=? AND first_seen<? AND upstream=? AND status='success' AND duration_ms IS NOT NULL""",(a,b,name))]
  ups.append(dict(name=name,total=n,failed=failed or 0,success_rate=pct(n-(failed or 0),n),p50=quant(durations,.5),p95=quant(durations,.95),p99=quant(durations,.99),over_3s=sum(v>=3000 for v in durations)))
  all_durations.extend(durations)
  for duration in durations:
   for i,limit in enumerate(bins):
    if duration<limit:
     histogram[i]+=1
     break
   else:histogram[-1]+=1
 packet=db.execute("SELECT count(*) FROM dnsproxy_packet_events WHERE ts>=? AND ts<?",(a,b)).fetchone()[0]
 cached=db.execute("SELECT count(*) FROM dnsproxy_cache_events WHERE ts>=? AND ts<?",(a,b)).fetchone()[0]
 return dict(window=dict(start=a,end=b),dnsmasq=dict(total=t,success=ok,failed=bad,duplicate=dup,unconfirmed=t-dup-ok-bad,confirmed_success_rate=pct(ok,ok+bad),overall_success_rate=pct(ok,t),cache_hits=cache,cache_hit_rate=pct(cache,t)),dnsproxy=dict(packet_events=packet,cache_events=cached,cache_event_ratio=pct(cached,packet),upstreams=ups,latency_distribution=dict(bounds_ms=bins,counts=histogram,total=len(all_durations),p50=quant(all_durations,.5),p95=quant(all_durations,.95),p99=quant(all_durations,.99),p999=quant(all_durations,.999),ge1s=sum(histogram[10:]),ge3s=histogram[-1],scope="successful upstream exchanges; not deduplicated client requests"),final_latency="N/A: unpaired upstream events"))
def show(d,color):
 import shutil
 def style(s,n):return ("\033["+n+"m"+s+"\033[0m") if color else s
 m=d["dnsmasq"];p=d["dnsproxy"];width=shutil.get_terminal_size((96,24)).columns
 compact=width<86
 def n(v):return f"{v:,}"
 def rate(v):return "N/A" if v is None else f"{v:.2f}%"
 def latency(v):return "-" if v is None else f"{v:.0f}"
 def line(s):print(s)
 def section(title):line(style("─ "+title+" "+"─"*max(0,(min(width,100)-len(title)-3)),"36"))
 line(style("DNS SUMMARY  •  local-57  •  READ ONLY","1;36"))
 line(f"{d['window']['start']}  →  {d['window']['end']}")
 section("DNSMASQ")
 line(f"确认成功 {style(rate(m['confirmed_success_rate']),'32'):>8}   全量成功 {style(rate(m['overall_success_rate']),'32'):>8}   缓存命中 {rate(m['cache_hit_rate'])}")
 line(f"总查询 {n(m['total'])}  成功 {n(m['success'])}  失败 {n(m['failed'])}  未确认 {n(m['unconfirmed'])}  重复 {n(m['duplicate'])}")
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
 p.add_argument("period",nargs="?",choices=["today","yesterday","week","month","last7"])
 p.add_argument("--days",type=int);p.add_argument("--start");p.add_argument("--end")
 p.add_argument("--db",default="/var/lib/dns-log-analyzer/requests.sqlite3")
 g=p.add_mutually_exclusive_group();g.add_argument("--plain",action="store_true");g.add_argument("--json",action="store_true")
 a=p.parse_args()
 try:
  x,y=period(a)
  with sqlite3.connect(Path(a.db).resolve().as_uri()+"?mode=ro",uri=True) as db:d=collect(db,x,y)
 except (ValueError,sqlite3.Error,OSError) as e:p.error(str(e))
 if a.json:print(json.dumps(d,ensure_ascii=False,indent=2))
 else:show(d,sys.stdout.isatty() and not a.plain)
if __name__=="__main__":main()

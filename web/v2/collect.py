#!/usr/bin/env python3
"""Fetch read-only DNS V2 aggregate snapshots from local-57 over restricted SSH."""
import json
import os
import subprocess
import tempfile
from datetime import datetime,timezone
BOUNDS=(1,5,10,25,50,100,200,500,1000,2000,3000,5000)
def unbound_from_clickhouse(start,end):
    start=datetime.fromisoformat(start.replace("Z","+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    end=datetime.fromisoformat(end.replace("Z","+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    where=f"source = 'unbound_dnstap' AND event_time >= '{start}' AND event_time < '{end}'"
    query=("SELECT count(),countIf(rcode = '2'),countIf(rcode = '3'),"
           "countIf(qtype = '1'),countIf(qtype = '28'),"
           "quantileExactIf(0.5)(duration_us,match_status = 'matched'),"
           "quantileExactIf(0.95)(duration_us,match_status = 'matched'),"
           "quantileExactIf(0.99)(duration_us,match_status = 'matched'),"
           "countIf(match_status = 'matched'),countIf(match_status = 'ambiguous'),"
           "countIf(match_status = 'unmatched_response') FROM dns_v2.events WHERE "+where+" FORMAT JSONEachRow")
    cmd=["docker","exec","dns-v2-clickhouse","clickhouse-client","--query",query]
    result=subprocess.run(cmd,capture_output=True,text=True,timeout=20,check=True)
    vals=list(json.loads(result.stdout).values())
    total,servfail,nxdomain,a,aaaa,p50,p95,p99,matched,ambiguous,unmatched=vals
    bins_query=("SELECT multiIf("+" ,".join(f"duration_us < {b*1000},{i}" for i,b in enumerate(BOUNDS))+f",{len(BOUNDS)}) AS bucket,count() AS n FROM dns_v2.events WHERE "+where+" AND match_status = 'matched' GROUP BY bucket FORMAT JSONEachRow")
    b=subprocess.run(["docker","exec","dns-v2-clickhouse","clickhouse-client","--query",bins_query],capture_output=True,text=True,timeout=20,check=True)
    counts=[0]*(len(BOUNDS)+1)
    for line in b.stdout.splitlines():
        entry=json.loads(line);counts[int(entry["bucket"])]=int(entry["n"])
    latency={"bounds_ms":BOUNDS,"counts":counts,"total":matched,"p50":p50/1000 if matched else None,"p95":p95/1000 if matched else None,"p99":p99/1000 if matched else None,"ge3s":sum(counts[BOUNDS.index(3000)+1:])}
    metrics={"requests":total,"rcode:SERVFAIL":servfail,"rcode:NXDOMAIN":nxdomain,"qtype:A":a,"qtype:AAAA":aaaa}
    return {"metrics":metrics,"latency_ms":latency}, {"responses":total,"latency_ms":{k:latency[k] for k in ("p50","p95","p99")},"failure_count":servfail,"failure_rate":round(100*servfail/total,3) if total else None,"cache_flag_hits":None,"cache_flag_rate":None,"qtypes":{"A":a,"AAAA":aaaa},"qps":None,"scope":"unbound_dnstap_responses","match_quality":{"matched":matched,"ambiguous":ambiguous,"unmatched_response":unmatched}}

def ch_rows(query):
    result=subprocess.run(["docker","exec","dns-v2-clickhouse","clickhouse-client","--query",query+" FORMAT JSONEachRow"],capture_output=True,text=True,timeout=20,check=True)
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
def source_health():
    tables=('events','fanout_decisions','fanout_upstream_events','rripfilter_events','overseas_exchanges')
    now=datetime.now(timezone.utc)
    out={}
    for table in tables:
        extra=" WHERE source='unbound_dnstap'" if table=='events' else ''
        rows=ch_rows(f"SELECT max(event_time) AS latest,count() AS n FROM dns_v2.{table}"+extra)
        row=rows[0] if rows else {}
        latest=row.get('latest')
        if latest and latest!='1970-01-01 00:00:00.000000':
            stamp=datetime.fromisoformat(latest.replace(' ','T')).replace(tzinfo=timezone.utc)
            lag=max(0,(now-stamp).total_seconds())
        else:lag=None
        out[table]={'latest':latest,'lag_seconds':round(lag) if lag is not None else None,'status':'ready' if lag is not None and lag<240 else 'stale'}
    return out

def layer_details(start,end):
    start=datetime.fromisoformat(start.replace("Z","+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    end=datetime.fromisoformat(end.replace("Z","+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    where=f"event_time >= '{start}' AND event_time < '{end}'"
    def counts(table,column):
        return {str(r["key"]):int(r["n"]) for r in ch_rows(f"SELECT {column} AS key,count() AS n FROM dns_v2.{table} WHERE {where} GROUP BY key")}
    return {"fanout_winners":counts('fanout_decisions','winner'),"fanout_reasons":counts('fanout_decisions','reason'),
      "fanout_upstream_outcomes":counts('fanout_upstream_events','outcome'),"filter_actions":counts('rripfilter_events','action'),
      "overseas_upstreams":counts('overseas_exchanges','upstream'),
      "top_domains":ch_rows(f"SELECT domain,count() AS n FROM dns_v2.events WHERE {where} AND source='unbound_dnstap' GROUP BY domain ORDER BY n DESC LIMIT 5"),
      "top_clients":ch_rows(f"SELECT client_ip,count() AS n FROM dns_v2.events WHERE {where} AND source='unbound_dnstap' GROUP BY client_ip ORDER BY n DESC LIMIT 5")}

from pathlib import Path
TARGET=Path("/srv/dns-stat/current/v2/data")
SSH=["/usr/bin/ssh","-i","/etc/dns-stat/id_ed25519","-o","BatchMode=yes",
     "-o","StrictHostKeyChecking=yes","-o","UserKnownHostsFile=/etc/dns-stat/known_hosts",
     "-o","ConnectTimeout=5","dnsstat@192.168.0.57"]
health=source_health()
for period in (1,5,60,1440):
    result=subprocess.run(SSH+[f"v2-minute{period}"],capture_output=True,text=True,timeout=25,check=True)
    data=json.loads(result.stdout)
    if not isinstance(data.get("layers"),dict) or not isinstance(data.get("window"),dict):
        raise ValueError("Invalid V2 snapshot")
    unbound,global_data=unbound_from_clickhouse(data["window"]["start"],data["window"]["end"])
    data["layers"]["unbound"]=unbound
    start=datetime.fromisoformat(data["window"]["start"].replace("Z","+00:00"))
    end=datetime.fromisoformat(data["window"]["end"].replace("Z","+00:00"))
    seconds=(end-start).total_seconds()
    global_data["qps"]=round(global_data["responses"]/seconds,3) if seconds>0 else None
    data["global"]=global_data
    data["source_health"]=health
    data["details"]=layer_details(data["window"]["start"],data["window"]["end"])
    data["generated_at"]=datetime.now(timezone.utc).isoformat()
    fd,name=tempfile.mkstemp(prefix=f".minute{period}.",suffix=".tmp",dir=TARGET)
    try:
        with os.fdopen(fd,"w") as out:json.dump(data,out,ensure_ascii=False)
        os.chmod(name,0o644)
        os.replace(name,TARGET/f"minute{period}.json")
    finally:
        if os.path.exists(name):os.unlink(name)

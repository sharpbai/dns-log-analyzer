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
           "quantileTDigestIf(0.5)(duration_us,match_status = 'matched'),"
           "quantileTDigestIf(0.95)(duration_us,match_status = 'matched'),"
           "quantileTDigestIf(0.99)(duration_us,match_status = 'matched'),"
           "countIf(match_status = 'matched'),countIf(match_status = 'ambiguous'),"
           "countIf(match_status = 'unmatched_response') FROM dns_v2.events WHERE "+where+" FORMAT JSONEachRow")
    cmd=["docker","exec","dns-v2-clickhouse","clickhouse-client","--max_threads=2","--query",query]
    result=subprocess.run(cmd,capture_output=True,text=True,timeout=20,check=True)
    vals=list(json.loads(result.stdout).values())
    total,servfail,nxdomain,a,aaaa,p50,p95,p99,matched,ambiguous,unmatched=vals
    bins_query=("SELECT multiIf("+" ,".join(f"duration_us < {b*1000},{i}" for i,b in enumerate(BOUNDS))+f",{len(BOUNDS)}) AS bucket,count() AS n FROM dns_v2.events WHERE "+where+" AND match_status = 'matched' GROUP BY bucket FORMAT JSONEachRow")
    b=subprocess.run(["docker","exec","dns-v2-clickhouse","clickhouse-client","--max_threads=2","--query",bins_query],capture_output=True,text=True,timeout=20,check=True)
    counts=[0]*(len(BOUNDS)+1)
    for line in b.stdout.splitlines():
        entry=json.loads(line);counts[int(entry["bucket"])]=int(entry["n"])
    latency={"bounds_ms":BOUNDS,"counts":counts,"total":matched,"p50":p50/1000 if matched else None,"p95":p95/1000 if matched else None,"p99":p99/1000 if matched else None,"ge3s":sum(counts[BOUNDS.index(3000)+1:])}
    metrics={"requests":total,"rcode:SERVFAIL":servfail,"rcode:NXDOMAIN":nxdomain,"qtype:A":a,"qtype:AAAA":aaaa}
    return {"metrics":metrics,"latency_ms":latency}, {"responses":total,"latency_ms":{k:latency[k] for k in ("p50","p95","p99")},"failure_count":servfail,"failure_rate":round(100*servfail/total,3) if total else None,"cache_flag_hits":None,"cache_flag_rate":None,"qtypes":{"A":a,"AAAA":aaaa},"qps":None,"scope":"unbound_dnstap_responses","match_quality":{"matched":matched,"ambiguous":ambiguous,"unmatched_response":unmatched}}

def ch_rows(query):
    result=subprocess.run(["docker","exec","dns-v2-clickhouse","clickhouse-client","--max_threads=2","--query",query+" FORMAT JSONEachRow"],capture_output=True,text=True,timeout=20,check=True)
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
def unbound_cache_stats(start,end):
    # The sample cadence is one minute. Include the immediately preceding
    # sample, otherwise a rolling 1m window almost always contains only one.
    a=datetime.fromisoformat(start.replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    b=datetime.fromisoformat(end.replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    fields='sampled_at,uptime_seconds,queries,cachehits,cachemiss,prefetch,recursivereplies,requestlist_exceeded,requestlist_overwritten,requestlist_current,recursion_avg_seconds,recursion_median_seconds'
    prior=ch_rows(f"SELECT {fields} FROM dns_v2.unbound_stats WHERE sampled_at < '{a}' ORDER BY sampled_at DESC LIMIT 1")
    inside=ch_rows(f"SELECT {fields} FROM dns_v2.unbound_stats WHERE sampled_at >= '{a}' AND sampled_at < '{b}' ORDER BY sampled_at")
    rows=prior+inside
    if not inside:return {'status':'no_samples','samples':0}
    latest=inside[-1]
    result={'status':'insufficient_samples','samples':len(inside),'latest':latest}
    if len(rows)<2:return result
    keys=('queries','cachehits','cachemiss','prefetch','recursivereplies','requestlist_exceeded','requestlist_overwritten')
    delta={k:0 for k in keys}
    valid=0; resets=0
    for old,new in zip(rows,rows[1:]):
        old_ts=datetime.fromisoformat(old['sampled_at'].replace(' ','T'))
        new_ts=datetime.fromisoformat(new['sampled_at'].replace(' ','T'))
        # Avoid comparing samples separated by a collection outage.
        if not 0<(new_ts-old_ts).total_seconds()<=150:continue
        if new['uptime_seconds']<=old['uptime_seconds'] or any(new[k]<old[k] for k in keys):
            resets+=1
            continue
        for k in keys:delta[k]+=int(new[k]-old[k])
        valid+=1
    denom=delta['cachehits']+delta['cachemiss']
    result.update(status='ready' if denom else ('counter_reset' if resets else 'no_queries'),
                  delta=delta,hit_rate=round(100*delta['cachehits']/denom,2) if denom else None,
                  valid_intervals=valid,reset_intervals=resets)
    return result

def domestic_filter_details(start,end):
    a=datetime.fromisoformat(start.replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    b=datetime.fromisoformat(end.replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    where=f"event_time >= '{a}' AND event_time < '{b}'"
    q=("SELECT count() total,countIf(action='accept') accept,countIf(action='bypass') bypass,"
       "countIf(action='drop') drop_count,countIf(action='partial') partial,"
       "countIf(action='upstream_error') upstream_error,countIf(action='transport_error') transport_error,"
       "countIf(reason='all_filtered') all_filtered,countIf(reason='no_terminal_answer') no_terminal_answer,"
       "countIf(upstream_rcode=2) upstream_servfail,countIf(upstream_rcode=3) upstream_nxdomain,"
       "quantileTDigest(0.5)(filter_us) filter_p50,quantileTDigest(0.95)(filter_us) filter_p95,"
       "quantileTDigest(0.99)(filter_us) filter_p99,quantileTDigest(0.95)(elapsed_us) elapsed_p95,"
       "sum(arrayCount(x -> position(x, ':') = 0, rejected_ips)) rejected_ipv4,"
       "sum(arrayCount(x -> position(x, ':') > 0, rejected_ips)) rejected_ipv6 "
       f"FROM dns_v2.rripfilter_events WHERE {where}")
    r=ch_rows(q)[0];total=int(r['total'])
    tops=ch_rows("SELECT domain,count() drops,"
                 "sum(arrayCount(x -> position(x, ':') = 0, rejected_ips)) rejected_ipv4,"
                 "sum(arrayCount(x -> position(x, ':') > 0, rejected_ips)) rejected_ipv6 "
                 f"FROM dns_v2.rripfilter_events WHERE {where} AND action='drop' "
                 "GROUP BY domain ORDER BY drops DESC LIMIT 5")
    r['accept_rate']=round(100*(r['accept']+r['bypass']+r['partial'])/total,2) if total else None
    r['drop_rate']=round(100*r['drop_count']/total,2) if total else None
    r['top_dropped_domains']=tops
    return r

def entrance_failure_domains(start,end):
    """Rank final L1 Unbound dnstap response failures, not upstream attempts.

    RCODE is stored as a numeric string. NXDOMAIN (3) is not a DNS
    infrastructure failure; do not include it in this ranking.
    """
    a=datetime.fromisoformat(start.replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    b=datetime.fromisoformat(end.replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    return ch_rows(
        "SELECT domain,count() AS failures,"
        "countIf(rcode='2') AS servfail,"
        "countIf(rcode='5') AS refused,"
        "countIf(rcode='1') AS formerr,"
        "countIf(rcode='4') AS notimp "
        "FROM dns_v2.events "
        f"WHERE event_time >= '{a}' AND event_time < '{b}' "
        "AND source='unbound_dnstap' AND rcode IN ('2','5','1','4') "
        "AND domain != '' "
        "GROUP BY domain ORDER BY failures DESC, domain ASC LIMIT 5")

def overseas_branch_health(start,end):
    a=datetime.fromisoformat(start.replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    b=datetime.fromisoformat(end.replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    q=("SELECT count() responses,countIf(rcode=0) noerror,countIf(rcode=3) nxdomain,"
       "countIf(rcode=2) servfail,quantileTDigest(0.5)(duration_us) p50,"
       "quantileTDigest(0.95)(duration_us) p95,quantileTDigest(0.99)(duration_us) p99,"
       "countIf(duration_us>=3000000) ge3s "
       f"FROM dns_v2.dnsproxy_final_responses WHERE event_time >= '{a}' AND event_time < '{b}'")
    r=ch_rows(q)[0];n=r['responses']
    r['success_rate']=round(100*(r['noerror']+r['nxdomain'])/n,2) if n else None
    for k in ('p50','p95','p99'):r[k+'_ms']=round(r[k]/1000,2) if n else None
    return r

def dnsproxy_health(start,end):
    a=datetime.fromisoformat(start.replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    b=datetime.fromisoformat(end.replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    where=f"event_time >= '{a}' AND event_time < '{b}'"
    upstreams=[('Cloudflare DoH','https://cloudflare-dns.com:443/dns-query'),('Google DoH','https://dns.google:443/dns-query'),('Cloudflare UDP','1.1.1.1:53'),('Google UDP','8.8.8.8:53')]
    q=("SELECT upstream,count() total,countIf(status='ok') ok,"
       "quantileTDigestIf(0.5)(duration_us,status='ok') p50,"
       "quantileTDigestIf(0.95)(duration_us,status='ok') p95,"
       "quantileTDigestIf(0.99)(duration_us,status='ok') p99,"
       "countIf(duration_us>=1000000) ge1s,countIf(duration_us>=2000000) ge2s,"
       "countIf(duration_us>=3000000) ge3s "
       f"FROM dns_v2.overseas_exchanges WHERE {where} GROUP BY upstream")
    by={r['upstream']:r for r in ch_rows(q)}
    items=[]
    for label,addr in upstreams:
        r=by.get(addr);n=int(r['total']) if r else 0;ok=int(r['ok']) if r else 0
        items.append(dict(name=label,address=addr,total=n,ok=ok,errors=n-ok,
                          success_rate=round(100*ok/n,2) if n else None,
                          p50=round(r['p50']/1000,2) if ok else None,
                          p95=round(r['p95']/1000,2) if ok else None,
                          p99=round(r['p99']/1000,2) if ok else None,
                          ge1s=int(r['ge1s']) if r else 0,ge2s=int(r['ge2s']) if r else 0,
                          ge3s=int(r['ge3s']) if r else 0))
    # At most 60 buckets per window, to keep 24h snapshots small.
    bucket=60 if (datetime.fromisoformat(b)-datetime.fromisoformat(a)).total_seconds()<=3600 else 1800
    trend=ch_rows("SELECT toStartOfInterval(event_time,INTERVAL "+str(bucket)+" SECOND) bucket,upstream,"
                  "quantileTDigestIf(0.95)(duration_us,status='ok')/1000 p95,countIf(status='ok') ok "
                  f"FROM dns_v2.overseas_exchanges WHERE {where} AND upstream IN ("+
                  ','.join("'"+x[1]+"'" for x in upstreams)+") GROUP BY bucket,upstream ORDER BY bucket")
    return {'upstreams':items,'trend':[dict(time=r['bucket'],upstream=r['upstream'],p95=round(r['p95'],2) if r['ok'] else None,samples=r['ok']) for r in trend], 'bucket_seconds':bucket}

def source_health():
    tables=('events','fanout_decisions','fanout_upstream_events','rripfilter_events','overseas_exchanges','dnsproxy_final_responses')
    now=datetime.now(timezone.utc)
    out={}
    for table in tables:
        extra=" WHERE source='unbound_dnstap'" if table=='events' else ''
        rows=ch_rows(f"SELECT max(event_time) AS latest FROM dns_v2.{table}"+extra)
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
    data["cache_stats"]=unbound_cache_stats(data["window"]["start"],data["window"]["end"])
    data["global"]["cache_flag_rate"]=data["cache_stats"].get("hit_rate")
    data["domestic_filter_details"]=domestic_filter_details(data["window"]["start"],data["window"]["end"])
    data["entrance_failure_domains"]=entrance_failure_domains(data["window"]["start"],data["window"]["end"])
    data["overseas_branch_health"]=overseas_branch_health(data["window"]["start"],data["window"]["end"])
    data["dnsproxy_health"]=dnsproxy_health(data["window"]["start"],data["window"]["end"])
    data["details"]=layer_details(data["window"]["start"],data["window"]["end"])
    data["generated_at"]=datetime.now(timezone.utc).isoformat()
    fd,name=tempfile.mkstemp(prefix=f".minute{period}.",suffix=".tmp",dir=TARGET)
    try:
        with os.fdopen(fd,"w") as out:json.dump(data,out,ensure_ascii=False)
        os.chmod(name,0o644)
        os.replace(name,TARGET/f"minute{period}.json")
    finally:
        if os.path.exists(name):os.unlink(name)

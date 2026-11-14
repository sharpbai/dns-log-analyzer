#!/usr/bin/env python3
"""Sample read-only Unbound counters and persist to ClickHouse once per minute."""
import json,subprocess,datetime
SSH=['/usr/bin/ssh','-i','/etc/dns-stat/id_ed25519','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/etc/dns-stat/known_hosts','-o','ConnectTimeout=5','dnsstat@192.168.0.57']
MAP={'queries':'total.num.queries','cachehits':'total.num.cachehits','cachemiss':'total.num.cachemiss','prefetch':'total.num.prefetch','expired':'total.num.expired','recursivereplies':'total.num.recursivereplies','requestlist_avg':'total.requestlist.avg','requestlist_max':'total.requestlist.max','requestlist_overwritten':'total.requestlist.overwritten','requestlist_exceeded':'total.requestlist.exceeded','requestlist_current':'total.requestlist.current.all','recursion_avg_seconds':'total.recursion.time.avg','recursion_median_seconds':'total.recursion.time.median','tcpusage':'total.tcpusage','uptime_seconds':'time.up'}
def main():
    r=subprocess.run(SSH+['v2-unbound-stats'],capture_output=True,text=True,timeout=12,check=True)
    data=json.loads(r.stdout)
    row={k:data['counters'].get(v,0) for k,v in MAP.items()}
    row['sampled_at']=datetime.datetime.fromtimestamp(data['sampled_at'],datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    payload=json.dumps(row,separators=(',',':'))+'\n'
    result=subprocess.run(['docker','exec','-i','dns-v2-clickhouse','clickhouse-client','--query','INSERT INTO dns_v2.unbound_stats FORMAT JSONEachRow'],input=payload,capture_output=True,text=True,timeout=15)
    if result.returncode:raise RuntimeError(result.stderr[:800])
    print('unbound stats',row['sampled_at'],row['cachehits'],row['cachemiss'],row['prefetch'],flush=True)
if __name__=='__main__':main()

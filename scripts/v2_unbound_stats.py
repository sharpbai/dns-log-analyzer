#!/usr/bin/env python3
"""Read allowlisted Unbound counters from local Unix control socket."""
import json,subprocess,time
CMD=['/home/duobeigw/dns-lab/packages/root/usr/sbin/unbound-control','-c','/home/duobeigw/dns-lab/conf/unbound.conf','stats_noreset']
KEYS={'total.num.queries','total.num.cachehits','total.num.cachemiss','total.num.prefetch','total.num.expired','total.num.recursivereplies','total.requestlist.avg','total.requestlist.max','total.requestlist.overwritten','total.requestlist.exceeded','total.requestlist.current.all','total.recursion.time.avg','total.recursion.time.median','total.tcpusage','time.up'}
def main():
    output=subprocess.run(CMD,capture_output=True,text=True,timeout=5,check=True).stdout
    values={}
    for line in output.splitlines():
        if '=' not in line:continue
        k,v=line.split('=',1)
        if k in KEYS:values[k]=float(v) if '.' in v else int(v)
    required={'total.num.queries','total.num.cachehits','total.num.cachemiss','total.num.prefetch','time.up'}
    if not required.issubset(values):raise RuntimeError('Missing Unbound statistics')
    print(json.dumps({'sampled_at':time.time(),'counters':values},separators=(',',':')))
if __name__=='__main__':main()

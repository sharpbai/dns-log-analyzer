#!/usr/bin/env python3
"""Observe final dnsproxy UDP replies at its local listener, not four upstream attempts."""
import collections,datetime,json,subprocess,sys,time
PORT=15404
FIELDS=['frame.time_epoch','ip.src','udp.srcport','ip.dst','udp.dstport','dns.id','dns.flags.response','dns.flags.rcode','dns.qry.name','dns.qry.type']
CMD=['/usr/bin/tshark','-i','lo','-n','-l','-Q','-f',f'udp port {PORT}','-T','fields','-E','separator=,']
for field in FIELDS:CMD+=['-e',field]
def main():
    pending=collections.OrderedDict()
    proc=subprocess.Popen(CMD,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
    try:
        for line in proc.stdout:
            parts=line.rstrip('\n').split(',')
            if len(parts)!=len(FIELDS):continue
            stamp,src,sport,dst,dport,ident,qr,rcode,domain,qtype=parts
            try:
                t=float(stamp);port=int(sport);dport=int(dport);dnsid=int(ident,0);qt=int(qtype)
            except ValueError:continue
            # Query/reply are matched by DNS ID, client UDP port, name and type.
            if dport==PORT and qr=='0':
                key=(port,dnsid,domain.lower(),qt)
                pending[key]=t;pending.move_to_end(key)
            elif port==PORT and qr=='1':
                key=(dport,dnsid,domain.lower(),qt)
                start=pending.pop(key,None)
                if start is None or t<start:continue
                try:code=int(rcode,0)
                except ValueError:continue
                event={'ts':datetime.datetime.fromtimestamp(t,datetime.timezone.utc).isoformat(),
                       'domain':domain.lower().rstrip('.')+'.','qtype':qt,'dns_id':dnsid,
                       'rcode':code,'duration_us':round((t-start)*1000000),'protocol':'udp'}
                print('dns_v2_dnsproxy_final '+json.dumps(event,separators=(',',':')),flush=True)
            # Bounded memory: prune old unmatched requests.
            if len(pending)>15000:
                cutoff=t-15
                while pending and (len(pending)>12000 or next(iter(pending.values()))<cutoff):
                    pending.popitem(last=False)
    finally:
        proc.terminate()
        proc.wait(timeout=3)
if __name__=='__main__':main()

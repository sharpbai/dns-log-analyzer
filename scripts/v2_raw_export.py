#!/usr/bin/env python3
"""Bounded read-only DNS log export for a restricted SSH forced command."""
import argparse,datetime as dt,hashlib,json,re
from pathlib import Path
BASE=Path('/home/duobeigw/dns-lab/logs')
PATHS={s:BASE/(s+'.stdout') for s in ('unbound','fanout','domestic')}
PATHS['overseas']=BASE/'dnsproxy.log'
PATHS['overseas_final']=BASE/'dnsproxy-final.log'
OVERSEAS=re.compile(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+) DEBUG upstream exchange completed addr=(\S+) proto=(\S+) qtype=(\S+) qname=(\S+) id=(\d+) duration=([\d.]+)(ms|s|µs|us) status=(\S+)')
UNBOUND=re.compile(r'^\[(\d+)\].*? info: (\S+) (\S+) (\S+) IN (\S+) ([\d.]+) ([01]) (\d+)$')
COREDNS=re.compile(r'^\[INFO\] (\S+) (\S+) - (\d+) "([^"]+)" (\S+) (\S+) (\d+) ([\d.]+)s')
def parse(source,line):
    if source=='unbound':
        m=UNBOUND.match(line)
        if not m:return None
        ts,client,domain,qtype,rcode,duration,cache,size=m.groups()
        when=dt.datetime.fromtimestamp(int(ts),dt.timezone.utc)
        return [when.isoformat(),source,client,domain,qtype,rcode,int(float(duration)*1e6),int(cache),int(size)]
    m=COREDNS.match(line)
    if not m:return None
    ts,client,ident,question,rcode,flags,size,duration=m.groups()
    parts=question.split()
    if len(parts)<3:return None
    when=dt.datetime.fromisoformat(ts).astimezone(dt.timezone.utc)
    return [when.isoformat(),source,client,parts[2],parts[0],rcode,int(float(duration)*1e6),None,int(size)]
def export(source,inode,offset,max_bytes=1048576):
    path=PATHS[source]
    stat=path.stat()
    if source=='overseas' and inode==0 and offset==0:
        return {'rotation':False,'inode':stat.st_ino,'offset':stat.st_size,'events':[],'details':[]}
    if inode and inode!=stat.st_ino:
        # Explicit rotation signal: do not silently skip a lost archive.
        return {'rotation':True,'inode':stat.st_ino,'offset':0,'events':[]}
    if offset>stat.st_size:
        return {'rotation':True,'inode':stat.st_ino,'offset':0,'events':[]}
    events=[]
    details=[]
    if source=='overseas':max_bytes=8388608
    with path.open('rb') as f:
        f.seek(offset)
        stop=min(stat.st_size,offset+max_bytes)
        while f.tell()<stop:
            pos=f.tell()
            raw=f.readline()
            if not raw.endswith(b'\n'):
                f.seek(pos)
                break
            line=raw.decode('utf-8','replace').rstrip()
            if source=='overseas_final' and line.startswith('dns_v2_dnsproxy_final '):
                try:
                    detail=json.loads(line.split(' ',1)[1]);detail['event_id']=int.from_bytes(hashlib.blake2b(f'{source}:{stat.st_ino}:{pos}'.encode(),digest_size=8).digest(),'big');details.append(detail)
                except (ValueError,KeyError):pass
            if source=='overseas':
                match=OVERSEAS.match(line)
                if match:
                    stamp,addr,proto,qtype,qname,dnsid,duration,unit,status=match.groups()
                    factor={'ms':1000,'s':1000000,'us':1,'µs':1}[unit]
                    detail={'ts':stamp.replace('/','-').replace(' ','T')+'+08:00','domain':qname,'qtype':qtype,'dns_id':int(dnsid),'upstream':addr,'protocol':proto,'duration_us':int(float(duration)*factor),'status':status}
                    detail['event_id']=int.from_bytes(hashlib.blake2b(f'{source}:{stat.st_ino}:{pos}'.encode(),digest_size=8).digest(),'big')
                    details.append(detail)
            tag=('dns_v2_fanout_upstream ' if 'dns_v2_fanout_upstream ' in line else 'dns_v2_fanout ') if source=='fanout' else 'dns_v2_rripfilter ' if source=='domestic' else ''
            if tag and tag in line:
                try:
                    detail=json.loads(line.split(tag,1)[1])
                    if source=='fanout':detail['event_kind']='upstream' if 'upstream' in tag else 'decision'
                    detail['event_id']=int.from_bytes(hashlib.blake2b(f'{source}:{stat.st_ino}:{pos}'.encode(),digest_size=8).digest(),'big')
                    details.append(detail)
                except (ValueError,KeyError):pass
            item=parse(source,line)
            if item:
                key=f'{source}:{stat.st_ino}:{pos}'.encode()
                item.append(int.from_bytes(hashlib.blake2b(key,digest_size=8).digest(),'big'))
                events.append(item)
        next_offset=f.tell()
    return {'rotation':False,'inode':stat.st_ino,'offset':next_offset,'events':events,'details':details}
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',required=True,choices=PATHS)
    p.add_argument('--inode',type=int,default=0)
    p.add_argument('--offset',type=int,default=0)
    a=p.parse_args()
    if a.inode<0 or a.offset<0:raise SystemExit('invalid cursor')
    print(json.dumps(export(a.source,a.inode,a.offset),separators=(',',':')))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Bounded read-only DNS log export for a restricted SSH forced command."""
import argparse,datetime as dt,hashlib,json,re
from pathlib import Path
BASE=Path('/home/duobeigw/dns-lab/logs')
PATHS={s:BASE/(s+'.stdout') for s in ('unbound','fanout','domestic')}
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
    if inode and inode!=stat.st_ino:
        # Explicit rotation signal: do not silently skip a lost archive.
        return {'rotation':True,'inode':stat.st_ino,'offset':0,'events':[]}
    if offset>stat.st_size:
        return {'rotation':True,'inode':stat.st_ino,'offset':0,'events':[]}
    events=[]
    with path.open('rb') as f:
        f.seek(offset)
        stop=min(stat.st_size,offset+max_bytes)
        while f.tell()<stop:
            pos=f.tell()
            raw=f.readline()
            if not raw.endswith(b'\n'):
                f.seek(pos)
                break
            item=parse(source,raw.decode('utf-8','replace').rstrip())
            if item:
                key=f'{source}:{stat.st_ino}:{pos}'.encode()
                item.append(int.from_bytes(hashlib.blake2b(key,digest_size=8).digest(),'big'))
                events.append(item)
        next_offset=f.tell()
    return {'rotation':False,'inode':stat.st_ino,'offset':next_offset,'events':events}
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',required=True,choices=PATHS)
    p.add_argument('--inode',type=int,default=0)
    p.add_argument('--offset',type=int,default=0)
    a=p.parse_args()
    if a.inode<0 or a.offset<0:raise SystemExit('invalid cursor')
    print(json.dumps(export(a.source,a.inode,a.offset),separators=(',',':')))
if __name__=='__main__':main()

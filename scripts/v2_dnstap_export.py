#!/usr/bin/env python3
"""Read closed dnstap Frame Streams files; match CQ/CR using DNS transaction identity."""
import argparse,datetime as dt,hashlib,ipaddress,json,re,struct
from collections import defaultdict,deque
from pathlib import Path
BASE=Path('/home/duobeigw/dns-lab/logs/dnstap')
FILE_RE=re.compile(r'^\d{8}-\d{6}\.fstrm$')
def varint(b,i):
    value=0;shift=0
    while i<len(b):
        x=b[i];i+=1;value|=(x&127)<<shift
        if x<128:return value,i
        shift+=7
    raise ValueError('truncated varint')
def fields(b):
    out={};i=0
    while i<len(b):
        tag,i=varint(b,i);n=tag>>3;wire=tag&7
        if wire==0:v,i=varint(b,i)
        elif wire==2:
            length,i=varint(b,i);v=b[i:i+length];i+=length
        elif wire==1:v=b[i:i+8];i+=8
        elif wire==5:v=b[i:i+4];i+=4
        else:raise ValueError('unsupported protobuf wire type')
        out[n]=v
    return out
def dns_name(b,i):
    labels=[];seen=set();end=None
    for _ in range(128):
        if i>=len(b):raise ValueError('short DNS name')
        length=b[i]
        if length&0xc0==0xc0:
            if i+1>=len(b):raise ValueError('short DNS pointer')
            dest=((length&63)<<8)|b[i+1]
            if dest in seen:raise ValueError('DNS pointer loop')
            seen.add(dest)
            if end is None:end=i+2
            i=dest;continue
        if length==0:return '.'.join(labels)+'.',end or i+1
        if length>63 or i+1+length>len(b):raise ValueError('bad DNS label')
        labels.append(b[i+1:i+1+length].decode('ascii','replace').lower());i+=1+length
    raise ValueError('DNS name too long')
def dns_fields(packet):
    if len(packet)<12:raise ValueError('short DNS packet')
    dnsid,flags,qd,an,ns,ar=struct.unpack_from('!6H',packet)
    if qd<1:raise ValueError('no DNS question')
    name,pos=dns_name(packet,12)
    if pos+4>len(packet):raise ValueError('short question')
    qtype,qclass=struct.unpack_from('!HH',packet,pos)
    return dnsid,name,qtype,qclass,flags&15
def frames(path):
    with path.open('rb') as f:
        while True:
            head=f.read(4)
            if not head:break
            if len(head)<4:break
            length=struct.unpack('!I',head)[0]
            if length==0:
                ctrl=f.read(4)
                if len(ctrl)<4:break
                f.seek(struct.unpack('!I',ctrl)[0],1);continue
            if length>1000000:raise ValueError('oversize frame')
            frame=f.read(length)
            if len(frame)<length:break
            yield frame
def decode(frame):
    outer=fields(frame)
    if 14 not in outer:return None
    m=fields(outer[14])
    kind=m.get(1)
    if kind not in (5,6):return None
    packet=m.get(10 if kind==5 else 14)
    if not packet:return None
    dnsid,domain,qtype,qclass,rcode=dns_fields(packet)
    sec=m.get(8 if kind==5 else 12)
    ns=m.get(9 if kind==5 else 13,0)
    if isinstance(ns,bytes):ns=int.from_bytes(ns,'little')
    if sec is None:return None
    ip=str(ipaddress.ip_address(m[4]))
    port=m.get(6,0)
    protocol='tcp' if m.get(3)==2 else 'udp'
    stamp=sec*1000000000+ns
    key=(ip,port,protocol,dnsid,domain,qtype,qclass)
    return kind,key,stamp,rcode,len(packet)
def export_file(name):
    if not FILE_RE.fullmatch(name):raise ValueError('invalid filename')
    path=BASE/name
    if not path.is_file():raise FileNotFoundError(name)
    active=max((p.name for p in BASE.glob('*.fstrm') if FILE_RE.fullmatch(p.name)),default='')
    if name==active:raise ValueError('file still active')
    pending=defaultdict(deque);rows=[];queries=responses=matched=ambiguous=0
    for frame in frames(path):
        try:event=decode(frame)
        except (ValueError,KeyError,IndexError):continue
        if not event:continue
        kind,key,stamp,rcode,size=event
        if kind==5:
            queries+=1
            pending[key].append(stamp)
            continue
        responses+=1
        queue=pending.get(key)
        candidates=[t for t in queue or () if 0<=stamp-t<=5_000_000_000]
        status='matched' if len(candidates)==1 else 'ambiguous' if len(candidates)>1 else 'unmatched_response'
        query_ns=candidates[0] if len(candidates)==1 else None
        if status=='matched':
            matched+=1
            queue.remove(query_ns)
        elif status=='ambiguous':ambiguous+=1
        ip,port,proto,dnsid,domain,qtype,qclass=key
        iso=lambda ns:dt.datetime.fromtimestamp(ns//1_000_000_000,dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')+'.'+f'{ns%1_000_000_000//1000:06d}'
        ident=int.from_bytes(hashlib.blake2b(f'{name}:{len(rows)}'.encode(),digest_size=8).digest(),'big')
        rows.append({'event_time':iso(stamp),'source':'unbound_dnstap','client_ip':ip,'domain':domain,'qtype':str(qtype),'rcode':str(rcode),'duration_us':(stamp-query_ns)//1000 if query_ns is not None else 0,'cache_flag':None,'response_bytes':size,'event_id':ident,'query_time':iso(query_ns) if query_ns is not None else None,'match_status':status,'client_port':port,'dns_id':dnsid,'protocol':proto})
    return {'file':name,'queries':queries,'responses':responses,'matched':matched,'ambiguous':ambiguous,'events':rows}
def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['list','file']);p.add_argument('name',nargs='?')
    a=p.parse_args()
    if a.action=='list':
        names=sorted(p.name for p in BASE.glob('*.fstrm') if FILE_RE.fullmatch(p.name))
        print(json.dumps(names[:-1]));return
    if not a.name:raise SystemExit('missing filename')
    print(json.dumps(export_file(a.name),separators=(',',':')))
if __name__=='__main__':main()

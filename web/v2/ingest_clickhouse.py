#!/usr/bin/env python3
"""Pull bounded DNS raw events from local-57; checkpoint only after CH acknowledgement."""
import json,os,re,subprocess,tempfile
from pathlib import Path
STATE=Path('/var/lib/dns-v2-ingest')
SSH=['/usr/bin/ssh','-i','/etc/dns-stat/id_ed25519','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/etc/dns-stat/known_hosts','-o','ConnectTimeout=5','dnsstat@192.168.0.57']
FIELDS=['event_time','source','client_ip','domain','qtype','rcode','duration_us','cache_flag','response_bytes','event_id']
def ingest(source):
    cursor=STATE/(source+'.json')
    state=json.loads(cursor.read_text()) if cursor.exists() else {'inode':0,'offset':0}
    command=f'v2-raw-{source} {state["inode"]} {state["offset"]}'
    result=subprocess.run(SSH+[command],capture_output=True,text=True,timeout=30,check=True)
    batch=json.loads(result.stdout)
    if batch['rotation']:
        # Never silently claim continuity when logrotate replaced/truncated a file.
        print(f'WARNING {source}: rotation/truncation; previous offset={state["offset"]}',flush=True)
    events=batch['events']
    if events:
        payload=''.join(json.dumps(dict(zip(FIELDS,[event[0].replace('T',' ').replace('+00:00','')]+event[1:])),separators=(',',':'))+'\n' for event in events)
        result=subprocess.run(['docker','exec','-i','dns-v2-clickhouse','clickhouse-client',
          '--query','INSERT INTO dns_v2.events FORMAT JSONEachRow'],input=payload,text=True,
          capture_output=True,timeout=60)
        if result.returncode:raise RuntimeError('ClickHouse insert failed: '+result.stderr[:1200])
    new={'inode':batch['inode'],'offset':batch['offset']}
    fd,tmp=tempfile.mkstemp(prefix='.'+source,dir=STATE)
    try:
        with os.fdopen(fd,'w') as f:json.dump(new,f)
        os.replace(tmp,cursor)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return len(events),new['offset']
def main():
    STATE.mkdir(parents=True,exist_ok=True)
    for source in ('unbound','fanout','domestic'):
        count,offset=ingest(source)
        print(source,count,offset,flush=True)
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Pull completed dnstap minute files into ClickHouse; durable per-file checkpoint."""
import json,os,subprocess,tempfile
from pathlib import Path
STATE=Path('/var/lib/dns-v2-ingest/dnstap-files.json')
SSH=['/usr/bin/ssh','-i','/etc/dns-stat/id_ed25519','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/etc/dns-stat/known_hosts','-o','ConnectTimeout=5','dnsstat@192.168.0.57']
def remote(command):
    p=subprocess.run(SSH+[command],capture_output=True,text=True,timeout=45)
    if p.returncode:raise RuntimeError('dnstap export failed: '+p.stderr[:300])
    return json.loads(p.stdout)
def save(items):
    STATE.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=STATE.parent,prefix='.dnstap-')
    try:
        with os.fdopen(fd,'w') as f:json.dump(sorted(items),f)
        os.replace(tmp,STATE)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
def main():
    seen=set(json.loads(STATE.read_text())) if STATE.exists() else set()
    files=remote('v2-dnstap-list')
    for name in files:
        if name in seen:continue
        batch=remote('v2-dnstap-file '+name)
        events=batch['events']
        if events:
            payload=''.join(json.dumps(e,separators=(',',':'))+'\n' for e in events)
            p=subprocess.run(['docker','exec','-i','dns-v2-clickhouse','clickhouse-client','--query',
              'INSERT INTO dns_v2.events FORMAT JSONEachRow'],input=payload,text=True,capture_output=True,timeout=60)
            if p.returncode:raise RuntimeError('ClickHouse dnstap insert failed: '+p.stderr[:600])
        seen.add(name);save(seen)
        print(name,'queries',batch['queries'],'responses',batch['responses'],'matched',batch['matched'],'ambiguous',batch['ambiguous'],flush=True)
    # Drop old checkpoint names; files themselves are retained separately for four hours.
    if len(seen)>600:save(set(sorted(seen)[-500:]))
if __name__=='__main__':main()

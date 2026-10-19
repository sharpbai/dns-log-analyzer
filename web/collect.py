#!/usr/bin/env python3
import json,os,subprocess,tempfile,time
from datetime import datetime,timezone
from pathlib import Path
base=Path("/srv/dns-stat/current/data")
ssh=["/usr/bin/ssh","-i","/etc/dns-stat/id_ed25519","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","UserKnownHostsFile=/etc/dns-stat/known_hosts","-o","ConnectTimeout=5","dnsstat@192.168.0.57"]
periods={"today":60,"yesterday":3600,"week":3600,"month":3600,"last7":3600}
for period,interval in periods.items():
 target=base/(period+".json")
 if target.exists() and time.time()-target.stat().st_mtime<interval:continue
 proc=subprocess.run(ssh+[period],capture_output=True,text=True,timeout=55,check=True)
 data=json.loads(proc.stdout)
 if not all(isinstance(data.get(k),dict) for k in ("smartdns","dnsproxy","window")):raise ValueError("Invalid JSON")
 data["generated_at"]=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
 fd,name=tempfile.mkstemp(dir=base,prefix="."+period+".",suffix=".tmp")
 try:
  with os.fdopen(fd,"w") as out:json.dump(data,out,ensure_ascii=False,indent=2)
  os.chmod(name,0o644);os.replace(name,target)
 finally:
  if os.path.exists(name):os.unlink(name)

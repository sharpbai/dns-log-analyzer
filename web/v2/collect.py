#!/usr/bin/env python3
"""Fetch read-only DNS V2 aggregate snapshots from local-57 over restricted SSH."""
import json
import os
import subprocess
import tempfile
from datetime import datetime,timezone
from pathlib import Path
TARGET=Path("/srv/dns-stat/current/v2/data")
SSH=["/usr/bin/ssh","-i","/etc/dns-stat/id_ed25519","-o","BatchMode=yes",
     "-o","StrictHostKeyChecking=yes","-o","UserKnownHostsFile=/etc/dns-stat/known_hosts",
     "-o","ConnectTimeout=5","dnsstat@192.168.0.57"]
for period in (1,5,60,1440):
    result=subprocess.run(SSH+[f"v2-minute{period}"],capture_output=True,text=True,timeout=25,check=True)
    data=json.loads(result.stdout)
    if not isinstance(data.get("layers"),dict) or not isinstance(data.get("window"),dict):
        raise ValueError("Invalid V2 snapshot")
    data["generated_at"]=datetime.now(timezone.utc).isoformat()
    fd,name=tempfile.mkstemp(prefix=f".minute{period}.",suffix=".tmp",dir=TARGET)
    try:
        with os.fdopen(fd,"w") as out:json.dump(data,out,ensure_ascii=False)
        os.chmod(name,0o644)
        os.replace(name,TARGET/f"minute{period}.json")
    finally:
        if os.path.exists(name):os.unlink(name)

#!/usr/bin/env python3
"""Synchronize SG subscription identities to the HK AnyTLS inbound."""

import base64
import gzip
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import yaml

MAP = Path("/etc/nginx/conf.d/subscription-profile-title.conf")
CACHE = Path("/var/lib/submerge/hk_users.json")
URL = "https://dsub.titanyung.click:31878/sub/{subid}?format=clash"
SSH = ["ssh", "-i", "/root/.ssh/hk-submerge-transfer", "-p", "8586",
       "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
       "root@61.15.36.199"]

REMOTE = r'''import base64,gzip,json,os,shutil,subprocess,sys,time
users=json.loads(gzip.decompress(base64.b64decode(sys.stdin.read())).decode())
path="/etc/sing-box/config.json"
with open(path,encoding="utf-8") as f: cfg=json.load(f)
inbound=next(x for x in cfg.get("inbounds",[]) if x.get("type")=="anytls")
legacy=[u for u in inbound.get("users",[]) if u.get("name")=="legacy-old-config" and u.get("password")]
desired=users+legacy
if inbound.get("users")==desired:
    print(json.dumps({"changed":False,"users":len(users)})); raise SystemExit(0)
inbound["users"]=desired
tmp=path+".sync-new"
with open(tmp,"w",encoding="utf-8") as f: json.dump(cfg,f,ensure_ascii=False,indent=2); f.write("\n")
check=subprocess.run(["/usr/bin/sing-box","check","-c",tmp],capture_output=True,text=True)
if check.returncode: raise SystemExit(check.stderr)
shutil.copy2(path,path+".bak-sync-"+time.strftime("%Y%m%d-%H%M%S",time.gmtime()))
os.replace(tmp,path)
subprocess.run(["systemctl","restart","sing-box.service"],check=True)
print(json.dumps({"changed":True,"users":len(users)}))
'''

SERVICE = """[Unit]
Description=Synchronize SG subscription users to HK AnyTLS
After=network-online.target submerge.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/submerge/sync_hk_users.py
"""

TIMER = """[Unit]
Description=Periodic HK AnyTLS user synchronization

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=20s
Persistent=true

[Install]
WantedBy=timers.target
"""


def install():
    Path("/etc/systemd/system/submerge-hk-user-sync.service").write_text(SERVICE, encoding="utf-8")
    Path("/etc/systemd/system/submerge-hk-user-sync.timer").write_text(TIMER, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "submerge-hk-user-sync.timer"], check=True)
    print("installed")


def load_users():
    pairs = re.findall(r'"/sub/([A-Za-z0-9_.:+-]+)"\s+"([^"]+)";', MAP.read_text(encoding="utf-8"))
    users = []
    cache = {"version": 2, "users": {}}
    now = int(time.time())
    ctx = ssl.create_default_context()
    for subid, name in pairs:
        with urllib.request.urlopen(URL.format(subid=subid), timeout=20, context=ctx) as response:
            cfg = yaml.safe_load(response.read().decode("utf-8")) or {}
        password = next((str(p["password"]) for p in cfg.get("proxies", [])
                         if isinstance(p, dict) and str(p.get("type", "")).lower() == "anytls"
                         and p.get("password")), None)
        if not password:
            raise RuntimeError("missing AnyTLS credential for " + subid)
        users.append({"name": name, "password": password})
        cache["users"][subid] = {"name": name, "password": password, "last_seen": now}
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600); os.replace(tmp, CACHE)
    return users


def main():
    if "--install" in sys.argv:
        return install()
    users = load_users()
    packed = base64.b64encode(gzip.compress(json.dumps(users, ensure_ascii=False).encode(), 9)).decode()
    code64 = base64.b64encode(REMOTE.encode()).decode()
    code = f"import base64;exec(base64.b64decode('{code64}'))"
    proc = subprocess.run(SSH + ["python3 -c " + shlex.quote(code)], input=packed,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=75)
    if proc.returncode:
        print(proc.stderr, file=sys.stderr); raise SystemExit(proc.returncode)
    print(proc.stdout.strip())


if __name__ == "__main__":
    main()

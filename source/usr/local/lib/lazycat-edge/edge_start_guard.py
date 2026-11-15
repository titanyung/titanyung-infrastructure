"""Boot/start condition: an interrupted deny-all must never revive old users."""
import hashlib,json,sys
from pathlib import Path
from edge_apply import read_private,strict_json,canonical,validate_manifest,validate_config

def allowed(identity,state,manifest):
 if state.get('edge_id')!=identity['edge_id'] or manifest.get('edge_id')!=identity['edge_id']:return False
 if state.get('pending_enforcement')=='service_stopped_no_accounts':return False
 if not manifest.get('accounts',{}).get('usernames'):return False
 generation=manifest.get('generation');sha=hashlib.sha256(canonical(manifest)).hexdigest()
 committed=(generation,sha)==(state.get('current_generation'),state.get('current_manifest_sha256'))
 pending=(generation,sha)==(state.get('pending_generation'),state.get('highest_manifest_sha256'))
 return (committed and state.get('current_enforcement')=='running_verified') or (pending and state.get('pending_enforcement')=='running_verified')

def check():
 identity=strict_json(read_private('/etc/lazycat-edge/identity.json',16384))
 root=Path(identity['install_root']);state=strict_json(read_private(root/'state.json',128*1024))
 current=(root/'current').resolve(strict=True)
 if not current.is_relative_to(root/'generations'):return False
 manifest=strict_json(read_private(current/'manifest.json',128*1024))
 if current!=root/'generations'/str(manifest['generation']).zfill(20):return False
 if not allowed(identity,state,manifest):return False
 validate_manifest(manifest,hashlib.sha256(canonical(manifest)).hexdigest(),root,identity['edge_id'])
 config=strict_json(read_private(current/manifest['config_path'],8*1024*1024))
 validate_config(config,manifest,current)
 return True

if __name__=='__main__':
 try:result=check()
 except Exception:result=False
 raise SystemExit(0 if result else 1)

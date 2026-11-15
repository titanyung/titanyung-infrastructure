"""Separate observed failure from missing/unknown health evidence."""
import copy,ipaddress,math
from routing_contract import PEERS
ASNS={'lazycat-starhub':{'4657'},'uzuma-starhub':{'4657'},'uzuma-singtel':{'45143'}}
SITES={'chatgpt.com','claude.ai'}

def qualify(proof,cache,*,lookup,now):
    if not isinstance(proof,dict):return {'status':'invalid','qualification_state':'unknown','checked_at':now}
    value=copy.deepcopy(proof)
    rows=value.get('paths',[])
    if value.get('status')!='completed' or not isinstance(rows,list) or not all(isinstance(row,dict) for row in rows):
        return dict(value,qualification_state='unknown',checked_at=now)
    # Installed edge_probe keeps its historic label enumeration and emits a
    # missing Zoro diagnostic on a V3/V4 three-peer executor. It also includes
    # the ordinary Cloudflare diagnostic after the two actual AI requests.
    # Normalize only these exact, reviewed extras, never arbitrary peers.
    extras=[row for row in rows if row.get('label') not in PEERS]
    if extras and not(len(extras)==1 and extras[0].get('label')=='zoro-sg'
            and extras[0].get('status')=='outbound_missing' and extras[0].get('checks')==[]):
        return dict(value,qualification_state='unknown',checked_at=now)
    rows=[row for row in rows if row.get('label') in PEERS]
    if {row.get('label') for row in rows}!=set(PEERS) or len(rows)!=3:
        return dict(value,qualification_state='unknown',checked_at=now)
    value['paths']=rows
    if extras:value['ignored_legacy_missing_labels']=['zoro-sg']
    for row in rows:
        checks=row.get('checks',[]);tag=row['label'];states=[];origins=[]
        if not isinstance(checks,list) or not all(isinstance(r,dict) for r in checks):
            row.update(healthy=False,health_state='unknown');continue
        diagnostics=[item for item in checks if item.get('site') not in SITES]
        if diagnostics and not(len(diagnostics)==1 and diagnostics[0].get('site')=='www.cloudflare.com'
                and diagnostics[0].get('diagnostic_only') is True):
            row.update(healthy=False,health_state='unknown');continue
        checks=[item for item in checks if item.get('site') in SITES]
        if len(checks)!=2 or {item.get('site') for item in checks}!=SITES:
            row.update(healthy=False,health_state='unknown');continue
        row['checks']=checks
        if diagnostics:row['diagnostic_checks']=diagnostics
        for check in checks:
            rc=check.get('returncode')
            if type(rc) is not int:
                elapsed=check.get('time_seconds')
                timeout_executed=(check.get('status')=='request_timeout' and type(elapsed) in (int,float)
                    and math.isfinite(elapsed) and 0<elapsed<=15)
                states.append('unhealthy' if timeout_executed else 'unknown');continue
            if rc<0:states.append('unknown');continue
            if rc!=0 or check.get('http_status')!=200 or check.get('status')!='observed':
                states.append('unhealthy');continue
            try:ip=ipaddress.ip_address(check.get('ip'))
            except (TypeError,ValueError):states.append('unhealthy');continue
            if check.get('loc')!='SG' or ip.version!=4 or not ip.is_global:
                states.append('unhealthy');continue
            try:origin=lookup(str(ip),cache)
            except Exception:states.append('unknown');continue
            if not isinstance(origin,dict) or not isinstance(origin.get('asns'),list):states.append('unknown');continue
            network=set(origin['asns'])
            if not network:states.append('unknown');continue
            states.append('healthy' if network<=ASNS[tag] else 'unhealthy')
            origins.append(dict(origin,site=check['site'],ip=str(ip)))
        # Both required sites must work. A completed definite failure makes
        # this path unusable even if the other site's origin is unknown.
        # Missing execution alone never becomes a failed-path assertion.
        state='unhealthy' if 'unhealthy' in states else 'unknown' if 'unknown' in states else 'healthy'
        row.update(healthy=state=='healthy',health_state=state,network_origins=origins,
            status='verified_access_network' if state=='healthy' else 'ai_access_network_'+state)
    value.update(qualification_state='unknown' if any(row['health_state']=='unknown' for row in rows) else 'qualified',checked_at=now)
    return value

def bootstrap_mode(proof,front,*,now):
    from starhub_selection_v4 import choose
    if not isinstance(proof,dict) or proof.get('front')!=front or proof.get('qualification_state')!='qualified' \
        or type(proof.get('checked_at')) not in (int,float) or not 0<=now-proof['checked_at']<=30:
        raise ValueError('fresh_bootstrap_qualification_required')
    return choose(proof,now=now)['mode']

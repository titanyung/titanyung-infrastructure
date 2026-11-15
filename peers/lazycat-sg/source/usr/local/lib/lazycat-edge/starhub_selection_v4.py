"""Qualified health drives failover; latency is diagnostic, never default theft."""
import copy
from edge_ai_policy_v4 import PEER_TAGS,MODES

def choose(proof,previous_state=None,now=None):
    if not isinstance(proof,dict) or proof.get('status')!='completed' or proof.get('qualification_state')!='qualified':
        raise ValueError('qualified_ai_health_required')
    paths=proof.get('paths',[]) if isinstance(proof,dict) else []
    rows={r.get('label'):r for r in paths if isinstance(r,dict)}
    if len(paths)!=3 or set(rows)!=set(PEER_TAGS) or any(type(row.get('healthy')) is not bool for row in rows.values()):
        raise ValueError('complete_three_peer_health_required')
    health={tag:proof.get('status')=='completed' and rows.get(tag,{}).get('healthy') is True for tag in PEER_TAGS}
    L,S,U=(health[tag] for tag in PEER_TAGS)
    selected='lazycat-starhub' if L else 'uzuma-starhub' if U else None
    mode='ai-z'+str(int(U))+'s'+str(int(S))+'l'+str(int(L))+'p'+('l' if L else 'u' if U else 'n')
    if mode not in MODES:raise ValueError('invalid_preferred_health_mode')
    diagnostics={tag:[check.get('time_seconds') for check in rows.get(tag,{}).get('checks',[])] for tag in PEER_TAGS}
    state={'schema':4,'mode':mode,'health':health,'selected_starhub':selected,'latency_diagnostics':diagnostics,'checked_at':now}
    return {'mode':mode,'health':health,'selected_starhub':selected,'state':state,
        'latency_diagnostics':copy.deepcopy(diagnostics),'selection_basis':'explicit_lazycat_default_then_healthy_backup'}

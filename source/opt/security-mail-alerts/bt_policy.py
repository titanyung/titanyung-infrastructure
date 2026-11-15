"""BT-specific fail-closed INFO evidence policy, independent of user secrets."""
import copy
import json
import sqlite3

TAG = 'violation-bt-quarantine'
PORT = 18115
OUTBOUND = {'type': 'socks', 'tag': TAG, 'server': '127.0.0.1',
            'server_port': PORT, 'version': '5', 'connect_timeout': '1s'}
MATCH = {'protocol': ['bittorrent'], 'action': 'route', 'outbound': TAG}


def apply_policy(original, add_outbound=True):
    config = copy.deepcopy(original)
    route = config.setdefault('route', {})
    rules = route.setdefault('rules', [])
    if not any(r.get('action') == 'sniff' for r in rules):
        rules.insert(0, {'action': 'sniff'})
    existing = [r for r in rules if r.get('outbound') == TAG]
    if existing and existing != [MATCH]:
        raise ValueError('quarantine_rule_conflict')
    if not existing:
        # Must precede every ordinary route/technical UDP reject. Original
        # protocol reject stays as the rollback policy; quarantine never forwards.
        position = next((i for i, r in enumerate(rules) if r.get('action') not in ('sniff', 'hijack-dns')), len(rules))
        rules.insert(position, copy.deepcopy(MATCH))
    if not any(r.get('protocol') == ['bittorrent'] and r.get('action') == 'reject' for r in rules):
        rules.insert(rules.index(MATCH) + 1, {'protocol': ['bittorrent'], 'action': 'reject'})
    if add_outbound:
        outbounds = config.setdefault('outbounds', [])
        found = [x for x in outbounds if x.get('tag') == TAG]
        if found and found != [OUTBOUND]:
            raise ValueError('quarantine_outbound_conflict')
        if not found:
            outbounds.append(copy.deepcopy(OUTBOUND))
    return config


def verify_policy(config, outbound):
    if outbound != OUTBOUND:
        raise ValueError('quarantine_outbound_not_loopback_rejector')
    rules = config.get('route', {}).get('rules', [])
    matches = [r for r in rules if r.get('outbound') == TAG]
    if matches != [MATCH]:
        raise ValueError('quarantine_tag_not_exclusive_to_bt')
    if config.get('route', {}).get('final') == TAG:
        raise ValueError('quarantine_tag_used_as_final')
    for item in config.get('outbounds', []):
        if item.get('detour') == TAG or TAG in item.get('outbounds', []):
            raise ValueError('quarantine_tag_used_by_other_outbound')
    return True


def read_policy(source):
    if source.get('policy_sqlite'):
        with sqlite3.connect('file:' + source['policy_sqlite'] + '?mode=ro', uri=True) as db:
            config = json.loads(db.execute("SELECT value FROM settings WHERE key='config'").fetchone()[0])
            row = db.execute('SELECT type,options FROM outbounds WHERE tag=?', (TAG,)).fetchone()
            if not row:
                raise ValueError('quarantine_outbound_absent')
            outbound = dict(json.loads(row[1]), type=row[0], tag=TAG)
    else:
        with open(source['policy_path'], encoding='utf-8') as stream:
            config = json.load(stream)
        outbound = next((x for x in config.get('outbounds', []) if x.get('tag') == TAG), {})
    verify_policy(config, outbound)
    # SUI's embedded logger sends a context-free syslog line by default. Its
    # optional stdout writer emits the full formatter (including connection ID).
    # Do not confuse a healthy process/valid reject policy with attributable logs.
    observable = not source.get('policy_sqlite') or config.get('log', {}).get('output') == 'stdout'
    result = {'confirmed_rules': ['bittorrent → loopback 拒绝'], 'observable': observable,
            'evidence': 'authenticated user + connection id + exclusive quarantine outbound',
            'log_level': config.get('log', {}).get('level', 'info')}
    if not observable:
        result['evidence_gap'] = 'embedded_logger_omits_connection_id'
    return result

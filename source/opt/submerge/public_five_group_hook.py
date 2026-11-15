"""Private-map/policy adapter for the public five-group merger hook.

Place this beside ``merge_sub.py`` only after independent public-path QA and
operator review. The existing /sub/<username> Nginx route and trial handling
stay in ``merge_sub.py``; call ``apply_public_five_group`` immediately before
YAML serialization. No server is opened and no existing database is written.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections import Counter
from contextlib import closing
from datetime import datetime
from pathlib import Path
from expiry_policy import SINGAPORE_TZ
from five_group_stage import (
    ALL_KEYS, PROVIDER_DEFAULT_KEYS, ProviderMatch,
)
from public_five_group import (
    build_public_five_group, required_credential_services,
)
from trial_expiry import prune_trial_profile


SUI_DB_URI = 'file:/usr/local/s-ui/db/s-ui.db?mode=ro'
POLICY_PATH = Path('/var/lib/submerge-public/policy.json')
READY_PATH = Path('/var/lib/submerge-public/ready-users.json')
MAP_PATHS = {
    'dmit': Path('/var/lib/submerge-public/dmit-users.json'),
    'bwh': Path('/var/lib/submerge-public/bwh-users.json'),
    'gomami': Path('/var/lib/submerge-public/gomami-users.json'),
    'nosla': Path('/var/lib/submerge-public/nosla-users.json'),
    'hkt': Path('/var/lib/submerge-public/hkt-users.json'),
}


def _private_json(path: Path):
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise ValueError('public_hook_requires_root')
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(str(path), flags)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('public_hook_private_permissions_invalid')
        raw = source.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError('public_hook_private_file_too_large')

    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('public_hook_duplicate_json_key')
            value[key] = item
        return value

    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs)


def _ordinary_accounts():
    with closing(sqlite3.connect(SUI_DB_URI, uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        rows = db.execute(
            'SELECT enable,name,sub_secret,inbounds FROM clients').fetchall()
    enabled_rows, trial = [], set()
    for enabled, name, secret, inbound_raw in rows:
        if (enabled != 1 or not isinstance(name, str) or not name or
                not isinstance(secret, str) or not secret):
            continue
        try:
            inbound = json.loads(inbound_raw or '[]')
        except (TypeError, ValueError):
            # A broken new S-UI row must not interrupt existing subscribers.
            if name != 'test':
                enabled_rows.append((secret, name, False))
            continue
        if not isinstance(inbound, list):
            if name != 'test':
                enabled_rows.append((secret, name, False))
            continue
        if name == 'test':
            # The legacy test account is assigned only the auxiliary S-UI
            # inbounds [2,3,4], not the ordinary first hop [1]. It must
            # remain a trial identity without entering the ordinary cohort.
            if (inbound and all(type(item) is int and item > 0
                                for item in inbound) and
                    len(set(inbound)) == len(inbound)):
                trial.add(secret)
        else:
            enabled_rows.append((secret, name, any(
                type(item) is int and item == 1 for item in inbound)))

    # No identity with an ambiguous S-UI secret or username may be served.
    # Keep such a row local to that subscriber instead of taking down others.
    secret_counts = Counter(secret for secret, _, _ in enabled_rows)
    name_counts = Counter(name for _, name, _ in enabled_rows)
    enabled_ordinary = {
        secret: name for secret, name, eligible in enabled_rows
        if eligible and secret_counts[secret] == 1 and name_counts[name] == 1 and
        secret not in trial
    }

    if os.path.lexists(str(READY_PATH)):
        # Committed only after every real exit is provisioned and probed.
        # S-UI enablement alone never admits a subscriber to the six groups.
        manifest = _private_json(READY_PATH)
        if (not isinstance(manifest, dict) or
                set(manifest) != {'schema', 'users'} or
                type(manifest['schema']) is not int or
                manifest['schema'] != 1 or
                not isinstance(manifest['users'], dict)):
            raise ValueError('public_hook_ready_manifest_invalid')
        ready = manifest['users']
        matched = {
            secret: name for secret, name in ready.items()
            if (isinstance(secret, str) and secret and
                isinstance(name, str) and name and
                enabled_ordinary.get(secret) == name)
        }
        matched_names = Counter(matched.values())
        ordinary = {secret for secret, name in matched.items()
                    if matched_names[name] == 1}
    else:
        # Migration fallback for the original 16 provisioned users only.
        # Install ready-users.json before extending any private credential map.
        anchor = _private_json(MAP_PATHS['dmit'])
        if not isinstance(anchor, dict) or len(anchor) != 16:
            raise ValueError('public_hook_legacy_anchor_invalid')
        ordinary = set(anchor).intersection(enabled_ordinary)

    # If trial data itself is ambiguous, no trial profile is issued; ordinary
    # subscribers remain available. The ambiguous secret is excluded above.
    nontrial_secrets = {secret for _, name, secret, _ in rows
                        if name != 'test' and isinstance(secret, str)}
    active_trial = (next(iter(trial)) if len(trial) == 1 and
                    trial.isdisjoint(nontrial_secrets) else None)
    return frozenset(ordinary), active_trial


def _credential_maps(now=None):
    maps = {}
    for service in required_credential_services(now):
        payload = _private_json(MAP_PATHS[service])
        if service == 'nosla':
            if (not isinstance(payload, dict) or
                    payload.get('schema') != 1 or
                    payload.get('server') != '216.23.117.226' or
                    payload.get('loopback_port') != 2450 or
                    payload.get('tls_server_name') != 'nosla-hk.internal' or
                    not isinstance(payload.get('users'), dict)):
                raise ValueError('public_hook_nosla_map_schema_invalid')
            payload = payload['users']
        if not isinstance(payload, dict):
            raise ValueError('public_hook_credential_map_invalid')
        maps[service] = payload
    return maps


def _policy():
    policy = _private_json(POLICY_PATH)
    if (not isinstance(policy, dict) or policy.get('version') != 2 or
            policy.get('verified_public') is not True or
            not isinstance(policy.get('route_evidence'), dict) or
            set(policy['route_evidence']) != ALL_KEYS or
            not isinstance(policy.get('provider_matches'), dict) or
            set(policy['provider_matches']) != set(PROVIDER_DEFAULT_KEYS)):
        raise ValueError('public_hook_policy_invalid')
    # The builder applies the exact active-route expiry mapping. The policy
    # records all 27 identities so a later expiry cannot resurrect a route.
    evidence = policy['route_evidence']
    if any(not isinstance(value, str) or not value.strip() or
           'pending' in value.lower() for value in evidence.values()):
        raise ValueError('public_hook_route_evidence_unverified')
    providers = {}
    used_matches = {}
    for name, rows in policy['provider_matches'].items():
        if not isinstance(rows, list) or not rows:
            raise ValueError('public_hook_provider_rules_missing')
        providers[name] = []
        for row in rows:
            if (not isinstance(row, dict) or
                    set(row) != {'rule_type', 'value', 'evidence'} or
                    not isinstance(row['evidence'], str) or
                    not row['evidence'].strip() or
                    'pending' in row['evidence'].lower()):
                raise ValueError('public_hook_provider_evidence_invalid')
            match = ProviderMatch(row['rule_type'], row['value'])
            match.render('DIRECT', provider=name)
            identity = (match.rule_type, match.value)
            if identity in used_matches and used_matches[identity] != name:
                raise ValueError('public_hook_provider_match_conflict')
            used_matches[identity] = name
            providers[name].append(match)
    return evidence, providers


def apply_public_five_group(
    merged: dict, sub_secret: str, *, now=None, direct_country=None,
) -> dict:
    """Return unchanged test account; fail closed for unaudited identities."""
    if now is None:
        now = datetime.now(SINGAPORE_TZ)
    ordinary, trial = _ordinary_accounts()
    if sub_secret == trial:
        return prune_trial_profile(merged, now=now)
    if sub_secret not in ordinary:
        raise ValueError('public_hook_subscriber_not_in_ordinary_cohort')
    evidence, providers = _policy()
    maps = _credential_maps(now)
    return build_public_five_group(
        merged, sub_secret=sub_secret, ordinary=ordinary, trial=trial,
        credential_maps=maps, route_evidence=evidence,
        provider_matches=providers, now=now,
        direct_country=direct_country,
    )

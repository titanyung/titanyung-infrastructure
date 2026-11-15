#!/usr/bin/env python3
"""Post-switch public HTTPS subscription QA; never prints private URLs."""

import json
import os
import sqlite3
import ssl
import subprocess
import tempfile
import urllib.parse
import urllib.request

import yaml

from five_group_stage import ALL_KEYS, HK_KEYS, OTHER_KEYS, _label


BIN = '/var/lib/submerge-staging/mihomo-v1.19.32-stage'
BASE = 'https://node.titanyung.click:31877/sub/'
with sqlite3.connect('file:/usr/local/s-ui/db/s-ui.db?mode=ro', uri=True) as db:
    db.execute('PRAGMA query_only=ON')
    rows = db.execute('SELECT enable,name,sub_secret,inbounds FROM clients').fetchall()
ordinary = sorted(secret for enabled, name, secret, raw in rows
                  if enabled == 1 and name != 'test' and secret and
                  1 in json.loads(raw or '[]'))
trial = [secret for enabled, name, secret, raw in rows
         if enabled == 1 and name == 'test' and secret and
         json.loads(raw or '[]')]
if len(ordinary) != 16 or len(set(ordinary)) != 16 or len(trial) != 1:
    raise ValueError('release_public_cohort_changed')


def fetch(secret, *, literal_plus=False):
    encoded = urllib.parse.quote(secret, safe='+' if literal_plus else '')
    request = urllib.request.Request(
        BASE + encoded + '?format=clash',
        headers={'User-Agent': 'ClashMetaForAndroid/2.11.14.Meta'})
    with urllib.request.urlopen(request, timeout=50,
                                context=ssl.create_default_context()) as response:
        if (response.status != 200 or
                'no-store' not in response.headers.get('Cache-Control', '').lower() or
                response.headers.get('Age') is not None):
            raise ValueError('release_public_status_or_cache_invalid')
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError('release_public_profile_too_large')
    document = yaml.safe_load(raw)
    if not isinstance(document, dict):
        raise ValueError('release_public_yaml_invalid')
    return document, raw


def syntax(raw):
    with tempfile.TemporaryDirectory(prefix='release-syntax-',
                                     dir='/var/lib/submerge-staging') as directory:
        os.chmod(directory, 0o700)
        path = os.path.join(directory, 'profile.yaml')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
        checked = subprocess.run(['nice', '-n', '15', BIN, '-t', '-f', path,
                                  '-d', directory], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=35)
        if checked.returncode:
            raise ValueError('release_public_mihomo_syntax_failed')


for secret in ordinary:
    document, raw = fetch(secret)
    groups = document.get('proxy-groups') or []
    if [group.get('name') for group in groups] != [
            '全部节点', 'google全系 & AI', 'HK&HK流媒体',
            'VPS访问', '非中国大陆的其他', '自动']:
        raise ValueError('release_public_group_order_invalid')
    if (not groups[5].get('hidden') or groups[5].get('type') != 'select' or
            groups[0].get('proxies', [None])[0] != '自动' or
            [len(groups[index].get('proxies', [])) for index in (1, 2, 4)] !=
            [9, 12, 6]):
        raise ValueError('release_public_group_shape_invalid')
    if (groups[2].get('proxies') != [_label(key) for key in HK_KEYS] or
            groups[4].get('proxies') != [_label(key) for key in OTHER_KEYS]):
        raise ValueError('release_public_hk_or_other_members_invalid')
    nodes = {node.get('name'): node for node in document.get('proxies', [])}
    if not {_label(key) for key in ALL_KEYS}.issubset(nodes):
        raise ValueError('release_public_route_inventory_invalid')
    if any(node.get('server') in ('127.0.0.1', '::1', 'localhost')
           for node in nodes.values()):
        raise ValueError('release_public_loopback_node')
    rules = document['rules']
    if (rules[-1] != 'MATCH,全部节点' or
            rules.index('GEOSITE,cn,DIRECT') >=
            rules.index('GEOIP,HK,HK&HK流媒体') or
            'DOMAIN,app.proxyhive.io,' + _label('ph_dmit') not in rules):
        raise ValueError('release_public_rule_invalid')
    if (document['dns'].get('enable') is not True or
            document['dns'].get('enhanced-mode') != 'fake-ip' or
            document['dns'].get('ipv6') is not False):
        raise ValueError('release_public_dns_invalid')
    if document.get('tun', {}).get('enable') and \
            'tcp://any:53' not in document['tun'].get('dns-hijack', []):
        raise ValueError('release_public_dns_hijack_invalid')
    syntax(raw)

trial_doc, trial_raw = fetch(trial[0])
trial_names = [node.get('name') for node in trial_doc.get('proxies', [])]
if (len(trial_names) != 6 or
        trial_names.count('BWH→ByteVirt香港ISP（2026-11-24到期）') != 1 or
        'BWH→ByteVirt香港ISP（11.22到期）' in trial_names):
    raise ValueError('release_public_trial_shape_invalid')
syntax(trial_raw)

plus = [secret for secret in ordinary if '+' in secret]
for secret in plus:
    canonical, _ = fetch(secret)
    literal, _ = fetch(secret, literal_plus=True)
    if canonical != literal:
        raise ValueError('release_public_literal_plus_invalid')

active = subprocess.run(['systemctl', 'is-active', '--quiet',
                         'submerge.service'], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=8)
if active.returncode:
    raise ValueError('release_service_not_active')
print('public_release=ok ordinary=16 trial=1 mihomo_syntax=17 '
      'five_visible_groups=yes routes_per_ordinary=27 '
      'test_date_label_fixed=yes literal_plus={} no_store=yes '
      'age_absent=yes service_active=yes secrets_hidden=yes'.format(len(plus)))

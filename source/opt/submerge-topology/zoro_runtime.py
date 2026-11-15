"""Build private runtime candidates. Does not install or start a service."""
import argparse
import copy
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat

ZORO_SERVER = '218.208.109.3'
DMIT_SERVER = '179.255.136.79'
METHOD = 'chacha20-ietf-poly1305'
BT_TAG = 'violation-bt-quarantine'
TRANSPORT_PATH = Path('/etc/submerge-topology/zorocloud-transport.json')
TAIWAN_TRANSPORT_PATH = Path(os.environ.get('TOPOLOGY_TAIWAN_TRANSPORT',
                                         '/etc/submerge-topology/taiwan-transport.json'))
TAIWAN_SERVER = '2001:b030:112d:711:11b0::'
SOURCE_PATH = Path('/run/dmit-direct-staging/config.json')


def protected_json(path):
    info = Path(path).stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('private file permissions invalid')
    return json.loads(Path(path).read_text())


def private_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + '.candidate')
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(data, stream, ensure_ascii=False, separators=(',', ':'))
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def validate_transport(transport):
    if (not isinstance(transport, dict) or transport.get('schema') != 1 or
            transport.get('server') != ZORO_SERVER or transport.get('server_port') != 2448 or
            transport.get('method') != METHOD or
            not isinstance(transport.get('password'), str) or len(transport['password']) < 32):
        raise ValueError('unexpected Zoro transport')
    return transport


def ensure_transport(path=TRANSPORT_PATH):
    path = Path(path)
    if path.exists():
        return validate_transport(protected_json(path))
    value = {'schema': 1, 'server': ZORO_SERVER, 'server_port': 2448,
             'method': METHOD, 'password': secrets.token_urlsafe(48),
             'created_at': datetime.now(timezone.utc).isoformat()}
    private_write(path, value)
    return value


def build_zoro_config(transport):
    validate_transport(transport)
    # Only the known DMIT first hop may forward through this authenticated exit.
    allowed = str(ipaddress.ip_network(DMIT_SERVER + '/32', strict=True))
    return {
        'log': {'level': 'info', 'timestamp': True},
        'inbounds': [{'type': 'shadowsocks', 'tag': 'zoro-dmit-ss',
                      'listen': '0.0.0.0', 'listen_port': transport['server_port'],
                      'method': transport['method'], 'password': transport['password']}],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}],
        'route': {'rules': [
            {'inbound': ['zoro-dmit-ss'], 'source_ip_cidr': [allowed],
             'action': 'route', 'outbound': 'direct'},
            {'action': 'reject'},
        ], 'final': 'direct'},
    }


def validate_taiwan_transport(transport):
    if (not isinstance(transport, dict) or transport.get('schema') != 1 or
            transport.get('server') != TAIWAN_SERVER or transport.get('server_port') != 2448 or
            transport.get('method') != METHOD or
            not isinstance(transport.get('password'), str) or len(transport['password']) < 32):
        raise ValueError('unexpected Taiwan transport')
    if (str(ipaddress.ip_address(transport.get('source_ipv6', ''))) !=
            '2605:52c0:2:6f85:be24:11ff:fea8:a90c' or
            transport.get('egress_interface') != 'eth1'):
        raise ValueError('unexpected Taiwan source or egress interface')
    return transport


def build_taiwan_config(transport):
    validate_taiwan_transport(transport)
    allowed=transport['source_ipv6']+'/128'
    match={'inbound':['taiwan-dmit-ss'],'source_ip_cidr':[allowed]}
    return {'log':{'level':'info','timestamp':True},
        'dns':{'servers':[{'type':'udp','tag':'taiwan-ipv4-dns','server':'1.1.1.1'}],
               'strategy':'ipv4_only'},
        'inbounds':[{'type':'shadowsocks','tag':'taiwan-dmit-ss','listen':'::',
                     'listen_port':2448,'method':transport['method'],'password':transport['password']}],
        'outbounds':[{'type':'direct','tag':'direct','bind_interface':'eth1',
            'domain_resolver':{'server':'taiwan-ipv4-dns','strategy':'ipv4_only'}}],
        'route':{'rules':[
            {**match,'action':'resolve','server':'taiwan-ipv4-dns','strategy':'ipv4_only'},
            {**match,'ip_version':6,'action':'reject'},
            {**match,'action':'route','outbound':'direct'},
            {'action':'reject'}],
            'default_domain_resolver':{'server':'taiwan-ipv4-dns','strategy':'ipv4_only'},'final':'direct'}}


def build_dmit_config(source, transport, *, direct_port=31117, zoro_port=29513,
                      direct_listen='127.0.0.1', zoro_listen='0.0.0.0',
                      clash_port=None, api_port=None, event_secret=None,
                      taiwan_transport=None, taiwan_port=29514):
    validate_transport(transport)
    if not isinstance(source, dict):
        raise ValueError('source config invalid')
    origins = [item for item in source.get('inbounds', [])
               if item.get('type') == 'anytls' and item.get('tag') == 'dmit-direct-stage']
    if len(origins) != 1:
        raise ValueError('source direct inbound identity changed')
    template = origins[0]
    tls = template.get('tls')
    users = template.get('users')
    if not isinstance(tls, dict) or tls.get('enabled') is not True:
        raise ValueError('source TLS is not enabled')
    if not isinstance(users, list) or not users:
        raise ValueError('source user cohort missing')
    names = [item.get('name') for item in users if isinstance(item, dict)]
    passwords = [item.get('password') for item in users if isinstance(item, dict)]
    if (len(names) != len(users) or len(set(names)) != len(users) or
            len(set(passwords)) != len(users) or
            any(not isinstance(value, str) or not value for value in names + passwords)):
        raise ValueError('source user cohort invalid')
    if any(type(port) is not int or not 1 <= port <= 65535
           for port in (direct_port, zoro_port)) or direct_port == zoro_port:
        raise ValueError('invalid listener ports')
    direct = copy.deepcopy(template)
    direct.update(listen=direct_listen, listen_port=direct_port)
    zoro = copy.deepcopy(template)
    zoro.update(tag='dmit-zorocloud', listen=zoro_listen, listen_port=zoro_port)
    quarantine = [item for item in source.get('outbounds', []) if item.get('tag') == BT_TAG]
    if len(quarantine) != 1 or quarantine[0].get('server') != '127.0.0.1' or quarantine[0].get('server_port') != 18115:
        raise ValueError('audited loopback BT quarantine is required')
    direct_out = [item for item in source.get('outbounds', [])
                  if item.get('tag') == 'direct' and item.get('type') == 'direct']
    if len(direct_out) != 1:
        raise ValueError('audited direct outbound is required')
    config = copy.deepcopy(source)
    config['inbounds'] = [direct, zoro]
    config['outbounds'] = [copy.deepcopy(direct_out[0]),
        {'type': 'shadowsocks', 'tag': 'zorocloud', 'server': transport['server'],
         'server_port': transport['server_port'], 'method': transport['method'],
         'password': transport['password'], 'connect_timeout': '8s'},
        copy.deepcopy(quarantine[0])]
    config['route'] = {'rules': [
        {'action': 'sniff'},
        {'protocol': ['bittorrent'], 'action': 'route', 'outbound': BT_TAG},
        {'protocol': ['bittorrent'], 'action': 'reject'},
        {'inbound': ['dmit-direct-stage', 'dmit-zorocloud'], 'network': ['udp'], 'action': 'reject'},
        {'inbound': ['dmit-direct-stage'], 'action': 'route', 'outbound': 'direct'},
        {'inbound': ['dmit-zorocloud'], 'action': 'route', 'outbound': 'zorocloud'},
        {'action': 'reject'},
    ], 'final': 'direct'}
    if taiwan_transport is not None:
        validate_taiwan_transport(taiwan_transport)
        if type(taiwan_port) is not int or not 1 <= taiwan_port <= 65535 or taiwan_port in (direct_port,zoro_port):
            raise ValueError('invalid Taiwan listener port')
        taiwan=copy.deepcopy(template)
        taiwan.update(tag='dmit-taiwan',listen=zoro_listen,listen_port=taiwan_port)
        config['inbounds'].append(taiwan)
        config['outbounds'].insert(-1,{'type':'shadowsocks','tag':'bytevirt-taiwan',
            'server':taiwan_transport['server'],'server_port':taiwan_transport['server_port'],
            'method':taiwan_transport['method'],'password':taiwan_transport['password'],
            'inet6_bind_address':taiwan_transport['source_ipv6'],'connect_timeout':'8s'})
        config['route']['rules'][3]['inbound'].append('dmit-taiwan')
        config['route']['rules'].insert(-1,{'inbound':['dmit-taiwan'],'action':'route','outbound':'bytevirt-taiwan'})
    clash = config.setdefault('experimental', {}).get('clash_api')
    if not isinstance(clash, dict) or not isinstance(clash.get('secret'), str) or len(clash['secret']) < 24:
        raise ValueError('existing authenticated Clash API is required')
    if clash_port is not None:
        if type(clash_port) is not int or not 1 <= clash_port <= 65535:
            raise ValueError('invalid Clash API port')
        clash['external_controller'] = '127.0.0.1:' + str(clash_port)
    services = config.get('services', [])
    api_services = [item for item in services if item.get('type') == 'api']
    if api_port is not None:
        if type(api_port) is not int or not 1 <= api_port <= 65535:
            raise ValueError('invalid native API port')
        if len(api_services) > 1:
            raise ValueError('ambiguous native API service')
        if api_services:
            api_services[0].update(listen='127.0.0.1', listen_port=api_port)
        else:
            if not isinstance(event_secret, str) or len(event_secret) < 32:
                raise ValueError('native API secret required')
            services.append({'type': 'api', 'tag': 'zoro-traffic-events',
                'listen': '127.0.0.1', 'listen_port': api_port, 'secret': event_secret})
            config['services'] = services
    return config


def main(args):
    if os.geteuid() != 0:
        raise SystemExit('root required')
    source = protected_json(args.source)
    transport = ensure_transport(args.transport)
    event_secret = None
    if args.event_secret:
        path = Path(args.event_secret)
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('native API secret file permissions invalid')
        event_secret = path.read_text().strip()
    candidate = build_dmit_config(source, transport, direct_port=args.direct_port,
        zoro_port=args.zoro_port, direct_listen=args.direct_listen,
        zoro_listen=args.zoro_listen, clash_port=args.clash_port,
        api_port=args.api_port, event_secret=event_secret,
        taiwan_transport=(protected_json(args.taiwan_transport)
                          if Path(args.taiwan_transport).exists() else None))
    private_write(args.dmit_output, candidate)
    private_write(args.zoro_output, build_zoro_config(transport))
    print(json.dumps({'candidates_written': True,
        'users': len(candidate['inbounds'][0]['users']),
        'direct_port': args.direct_port, 'zoro_port': args.zoro_port,
        'bt_quarantine_preserved': True, 'secrets': 'hidden'}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', default=str(SOURCE_PATH))
    parser.add_argument('--transport', default=str(TRANSPORT_PATH))
    parser.add_argument('--taiwan-transport', default=str(TAIWAN_TRANSPORT_PATH))
    parser.add_argument('--dmit-output', default='/root/topology-20261105/dmit-config.json')
    parser.add_argument('--zoro-output', default='/root/topology-20261105/zorocloud-config.json')
    parser.add_argument('--direct-port', type=int, default=31117)
    parser.add_argument('--zoro-port', type=int, default=29513)
    parser.add_argument('--direct-listen', default='127.0.0.1')
    parser.add_argument('--zoro-listen', default='0.0.0.0')
    parser.add_argument('--clash-port', type=int)
    parser.add_argument('--api-port', type=int)
    parser.add_argument('--event-secret')
    try:
        main(parser.parse_args())
    except Exception as error:
        raise SystemExit('zoro runtime preparation failed: ' + type(error).__name__)

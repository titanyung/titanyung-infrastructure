"""Last-good server-side Paoluz provider cache, without exposing source URLs.

``PaoluzCache(...).get(refresh=True, authorized=None)`` attempts a refresh at
most once per guard period. ``authorized=False`` never performs a network
request. Without an explicit authorization clock, a successful, usable upstream
response is the authority; rejected/expired responses keep the last good copy.

An injected fetcher accepts ``(url, timeout)`` and returns text/bytes, or a
``(text_or_bytes, final_url)`` pair. A validator accepts ``{'proxies': [...]}``
and raises (or returns False) when the client cannot use the materialized nodes.
No exception text, credentials or source URL is printed by this module.
"""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import threading
import time
import urllib.parse
import urllib.request

import yaml

MAX_BYTES = 10 * 1024 * 1024
MAX_PROVIDERS = 16
MAX_NODES = 5000
SUPPORTED_TYPES = frozenset({
    'ss', 'ssr', 'vmess', 'vless', 'trojan', 'snell', 'hysteria', 'hysteria2',
    'tuic', 'wireguard', 'anytls', 'http', 'socks5', 'socks', 'ssh', 'shadowtls',
    'mieru',
})
_STATES = {}
_STATES_LOCK = threading.Lock()


class CacheUnavailable(RuntimeError):
    pass


def _state(path):
    with _STATES_LOCK:
        return _STATES.setdefault(str(path.resolve()), {
            'lock': threading.Lock(), 'document': None, 'sha256': None,
            'last_attempt': None, 'last_success': None,
        })


def _atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + '.new-' + str(os.getpid()) + '-' + str(threading.get_ident()))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(temporary), flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(str(temporary), 0o600)
        os.replace(str(temporary), str(path))
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class PaoluzCache:
    def __init__(self, upstream_url, cache_file='/var/lib/submerge/paoluz-provider.yaml',
                 metadata_file=None, seed_file='/var/lib/submerge/paoluz.yaml',
                 fetcher=None, validator=None, refresh_guard=5, timeout=5,
                 clock=None, resolver=None):
        if not isinstance(upstream_url, str) or not upstream_url:
            raise ValueError('upstream URL required')
        self.upstream_url = upstream_url
        self.cache_file = Path(cache_file)
        self.metadata_file = Path(metadata_file or str(self.cache_file) + '.metadata.json')
        self.seed_file = Path(seed_file) if seed_file else None
        self.fetcher = fetcher
        self.validator = validator
        self.refresh_guard = max(0, float(refresh_guard))
        self.timeout = min(15, max(0.1, float(timeout)))
        self.clock = clock or time.time
        self.resolver = resolver or self._resolve
        self._state = _state(self.cache_file)
        self.last_error = None
        self.last_refresh_succeeded = False

    @property
    def content_sha256(self):
        return self._state['sha256']

    @property
    def last_success_at(self):
        return self._state['last_success']

    @staticmethod
    def _resolve(host, port):
        return {entry[4][0] for entry in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}

    def _public_url(self, value):
        if not isinstance(value, str):
            raise ValueError('provider URL invalid')
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.fragment:
            raise ValueError('provider URL invalid')
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        try:
            addresses = {str(ipaddress.ip_address(parsed.hostname))}
        except ValueError:
            addresses = self.resolver(parsed.hostname, port)
        if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
            raise ValueError('non-public provider URL')
        return value

    def _default_fetch(self, url, timeout):
        owner = self

        class SafeRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, message, headers, newurl):
                owner._public_url(newurl)
                return super().redirect_request(request, fp, code, message, headers, newurl)

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), SafeRedirect())
        request = urllib.request.Request(url, headers={
            'User-Agent': 'Clash.Meta', 'Accept': 'application/yaml,text/yaml,text/plain',
        })
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ValueError('provider response too large')
            return body, response.geturl()

    def _fetch(self, url, context):
        self._public_url(url)
        remaining = context['deadline'] - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('provider refresh budget exhausted')
        result = (self.fetcher or self._default_fetch)(url, min(self.timeout, remaining))
        if isinstance(result, tuple) and len(result) == 2:
            body, final_url = result
        else:
            body, final_url = result, url
        self._public_url(final_url)
        if isinstance(body, str):
            body = body.encode('utf-8')
        if not isinstance(body, bytes):
            raise ValueError('provider response must be text')
        context['bytes'] += len(body)
        if context['bytes'] > MAX_BYTES:
            raise ValueError('provider refresh too large')
        document = yaml.safe_load(body)
        if not isinstance(document, dict):
            raise ValueError('provider response is not YAML configuration')
        return document, final_url

    def _nodes(self, document, context, allow_fetch):
        if not isinstance(document, dict):
            raise ValueError('provider document must be an object')
        nodes = document.get('proxies') or []
        if not isinstance(nodes, list):
            raise ValueError('provider proxies must be a list')
        result = list(nodes)
        providers = document.get('proxy-providers') or {}
        if not isinstance(providers, dict):
            raise ValueError('provider definitions must be an object')
        for provider in providers.values():
            context['providers'] += 1
            if context['providers'] > MAX_PROVIDERS or not isinstance(provider, dict):
                raise ValueError('too many or invalid provider definitions')
            if provider.get('type') == 'inline':
                child = {'proxies': provider.get('payload')}
            else:
                if provider.get('type') != 'http' or not allow_fetch:
                    raise ValueError('provider cannot be materialized without authorization')
                url = provider.get('url')
                if url in context['visited']:
                    raise ValueError('provider cycle or duplicate source')
                context['visited'].add(url)
                child, unused_final = self._fetch(url, context)
            result.extend(self._nodes(child, context, allow_fetch))
            if len(result) > MAX_NODES:
                raise ValueError('too many provider nodes')
        return result

    def _validated(self, nodes):
        if not nodes or len(nodes) > MAX_NODES:
            raise ValueError('provider contains no usable nodes')
        names = {}
        for node in nodes:
            if not isinstance(node, dict):
                raise ValueError('provider node must be an object')
            name, kind = node.get('name'), str(node.get('type', '')).lower()
            if not isinstance(name, str) or not name.strip() or kind not in SUPPORTED_TYPES:
                raise ValueError('provider node identity or type invalid')
            if kind == 'wireguard' and node.get('peers'):
                if not isinstance(node['peers'], list):
                    raise ValueError('wireguard peers invalid')
            elif (not isinstance(node.get('server'), str) or not node['server'] or
                  type(node.get('port')) is not int or not 1 <= node['port'] <= 65535):
                raise ValueError('provider endpoint invalid')
            if name in names and names[name] != node:
                raise ValueError('conflicting provider node names')
            names[name] = copy.deepcopy(node)
        for node in names.values():
            if node.get('dialer-proxy', 'DIRECT') not in set(names) | {'DIRECT'}:
                raise ValueError('provider dialer target is unavailable')
        result = {'proxies': list(names.values())}
        if self.validator is not None and self.validator(copy.deepcopy(result)) is False:
            raise ValueError('provider validation rejected')
        return result

    @staticmethod
    def _serialize(document):
        return yaml.safe_dump(document, allow_unicode=True, sort_keys=True).encode('utf-8')

    def _remember(self, document, last_success=None):
        self._state['document'] = document
        self._state['sha256'] = hashlib.sha256(self._serialize(document)).hexdigest()
        self._state['last_success'] = last_success

    def _load_existing(self):
        if self._state['document'] is not None:
            return
        if self.cache_file.is_file():
            raw = self.cache_file.read_bytes()
            if len(raw) > MAX_BYTES:
                raise ValueError('stored provider too large')
            loaded = yaml.safe_load(raw)
            if not isinstance(loaded, dict) or set(loaded) != {'proxies'}:
                raise ValueError('stored provider is not materialized')
            document = self._validated(loaded['proxies'])
            success = None
            if self.metadata_file.is_file():
                try:
                    metadata = json.loads(self.metadata_file.read_text(encoding='utf-8'))
                    if metadata.get('content_sha256') == hashlib.sha256(self._serialize(document)).hexdigest():
                        success = metadata.get('last_success_at')
                except (ValueError, OSError):
                    pass
            self._remember(document, success)
            return
        if self.seed_file is not None and self.seed_file.is_file():
            raw = self.seed_file.read_bytes()
            if len(raw) > MAX_BYTES:
                raise ValueError('seed provider too large')
            document = self._validated(self._nodes(yaml.safe_load(raw), {
                'providers': 0, 'visited': set(), 'bytes': len(raw),
                'deadline': time.monotonic(),
            }, allow_fetch=False))
            _atomic(self.cache_file, self._serialize(document))
            self._remember(document)

    def get(self, refresh=True, authorized=None):
        state = self._state
        # Other client updates can use the immutable last-good object while a
        # single refresher waits for the upstream. They do not queue behind it.
        acquired = state['lock'].acquire(blocking=False)
        if not acquired:
            if state['document'] is not None:
                return copy.deepcopy(state['document'])
            acquired = state['lock'].acquire(timeout=self.timeout + 0.5)
            if not acquired:
                raise CacheUnavailable('Paoluz cache unavailable')
        try:
            self.last_refresh_succeeded = False
            try:
                self._load_existing()
            except Exception as error:
                self.last_error = type(error).__name__
            now = self.clock()
            due = (state['last_attempt'] is None or now - state['last_attempt'] >= self.refresh_guard)
            if refresh and authorized is not False and due:
                state['last_attempt'] = now
                try:
                    context = {'providers': 0, 'visited': {self.upstream_url},
                               'bytes': 0, 'deadline': time.monotonic() + self.timeout}
                    source, final_url = self._fetch(self.upstream_url, context)
                    document = self._validated(self._nodes(source, context, allow_fetch=True))
                    serialized = self._serialize(document)
                    digest = hashlib.sha256(serialized).hexdigest()
                    metadata = {'schema': 1, 'latest_resolved_upstream_url': final_url,
                                'last_success_at': now, 'content_sha256': digest}
                    _atomic(self.cache_file, serialized)
                    _atomic(self.metadata_file, json.dumps(metadata, sort_keys=True).encode('utf-8'))
                    self._remember(document, now)
                    self.last_error = None
                    self.last_refresh_succeeded = True
                except Exception as error:
                    self.last_error = type(error).__name__
            if state['document'] is None:
                raise CacheUnavailable('Paoluz cache unavailable')
            return copy.deepcopy(state['document'])
        finally:
            state['lock'].release()

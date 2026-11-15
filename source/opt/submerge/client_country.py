"""Bounded country lookup for a trusted subscription request source IP.

Only the loopback merger's Nginx-generated X-Real-IP is considered. The
country is display metadata; lookup failure must never fail a subscription.
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
import urllib.request
from collections import OrderedDict
from typing import Optional


_SUCCESS_TTL = 24 * 60 * 60
_FAILURE_TTL = 60
_MAX_ENTRIES = 4096
_LOOKUP_TIMEOUT = 1.0
_lock = threading.Lock()
_cache = OrderedDict()
_inflight = {}
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _query_country(ip_text: str) -> Optional[str]:
    request = urllib.request.Request(
        "https://api.country.is/" + ip_text,
        headers={"Accept": "application/json", "User-Agent": "submerge-country/1"},
    )
    with _opener.open(request, timeout=_LOOKUP_TIMEOUT) as response:
        if response.status != 200 or response.geturl() != request.full_url:
            return None
        payload = response.read(129)
    if len(payload) > 128:
        return None
    result = json.loads(payload)
    if not isinstance(result, dict):
        return None
    country = result.get("country")
    if result.get("ip") != ip_text or not isinstance(country, str):
        return None
    country = country.upper()
    return country if re.fullmatch(r"[A-Z]{2}", country) else None


def country_from_request(peer_ip: str, real_ip_header: Optional[str]) -> Optional[str]:
    """Return ISO country only for an Nginx-authenticated public peer.

    X-Forwarded-For is deliberately ignored. A direct request to the private
    merger listener with a spoofed header has no public network path.
    """
    try:
        if not ipaddress.ip_address(peer_ip).is_loopback:
            return None
        if not isinstance(real_ip_header, str) or not real_ip_header:
            return None
        if real_ip_header != real_ip_header.strip():
            return None
        address = ipaddress.ip_address(real_ip_header)
        if not address.is_global:
            return None
        ip_text = str(address)
    except (ValueError, TypeError):
        return None

    now = time.monotonic()
    with _lock:
        cached = _cache.get(ip_text)
        if cached and cached[0] > now:
            _cache.move_to_end(ip_text)
            return cached[1]
        waiter = _inflight.get(ip_text)
        owner = waiter is None
        if owner:
            waiter = threading.Event()
            _inflight[ip_text] = waiter

    if not owner:
        if not waiter.wait(_LOOKUP_TIMEOUT + 0.3):
            return None
        with _lock:
            cached = _cache.get(ip_text)
            return cached[1] if cached and cached[0] > time.monotonic() else None

    country = None
    try:
        country = _query_country(ip_text)
    except Exception:
        # A failed optional icon lookup must not turn /sub into HTTP 502.
        pass
    finally:
        with _lock:
            expiry = time.monotonic() + (
                _SUCCESS_TTL if country else _FAILURE_TTL)
            _cache[ip_text] = (expiry, country)
            _cache.move_to_end(ip_text)
            while len(_cache) > _MAX_ENTRIES:
                _cache.popitem(last=False)
            _inflight.pop(ip_text, None)
            waiter.set()
    return country

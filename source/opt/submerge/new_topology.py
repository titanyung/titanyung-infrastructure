"""Pure renderer for verified routes and DMIT-cached Paoluz.

This module provisions no server and fetches no subscription. The caller must
verify each supplied route and enforce upstream authorization/cache rules.
"""
from __future__ import annotations

import copy
from datetime import datetime
import ipaddress
from typing import Optional
from urllib.parse import urlsplit

from five_group_stage import (
    ALL, AUTO, GOOGLE, HK, STREAMING, VPS, OTHER, CHINA, GLOBAL,
    AI_DOMAIN_SUFFIXES, GOOGLE_DOMAIN_SUFFIXES, NETFLIX_DOMAIN_SUFFIXES,
    DISNEY_PLUS_DOMAIN_SUFFIXES, OTHER_STREAMING_GEOCATEGORIES,
    LEGACY_RULE_TARGETS, SINGAPORE_TZ, ROUTE_NAMES, _label, _safe_dns,
    _target_index, direct_label_for_country,
)

DMIT = "🔷 🇺🇸 DMIT"
BYTEVIRT = "🔷 📡 🇬🇧 🇭🇰 DMIT→Bytevirt iCable静态家宽"
ZORO = "🔷 🌀 DMIT→zorocloud"
TAIWAN = "🔷 📶 🇹🇼 DMIT→ByteVirt 台湾动态家宽"
PAOLUZ = "✈️ 机场paoluz"
AIRPORT_FAST = "⚡ paoluz最低延迟"
AIRPORT_AUTO = "🧭 自动选择（机场优先）"
HEALTH_URL = "https://www.gstatic.com/generate_204"
HEALTH_INTERVAL = 60
HEALTH_TIMEOUT = 5000
ZORO_EMERGENCY_PROVIDER = "zoro-emergency"
DNS_OVERSEAS = "DNS-Overseas"
DNS_GOOGLE = "DNS-GoogleAI"
UDP_FALLBACK_GUARD = "NETWORK,UDP,REJECT"
BUILTINS = frozenset({"DIRECT", "REJECT", "REJECT-DROP", "PASS"})
PROVIDER_HOSTS = frozenset({"node.titanyung.click", "dnode.titanyung.click"})


def _unique(items):
    return list(dict.fromkeys(items))


def prioritize_provider(document, preferred_name=None, preferred_type=None):
    """Move a verified preference first without editing any node or raw cache.

    No probing, sorting, or automatic latency selection occurs. If a preferred
    name disappeared, use the first declared preferred protocol (AnyTLS by
    default). Every other source node retains its original relative order.
    Without a preference the deep copy preserves the complete original order.
    """
    if not isinstance(document, dict) or not isinstance(document.get('proxies'), list):
        raise ValueError('provider document invalid')
    for value in (preferred_name, preferred_type):
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError('provider preference invalid')
    output = copy.deepcopy(document)
    if preferred_name is None and preferred_type is None:
        return output
    nodes = output['proxies']
    if any(not isinstance(node, dict) or not isinstance(node.get('name'), str) or
           not isinstance(node.get('type'), str) for node in nodes):
        raise ValueError('provider node identity invalid')
    protocol = (preferred_type or 'anytls').lower()
    selected = next((index for index, node in enumerate(nodes)
        if preferred_name is not None and node['name'] == preferred_name and
        (preferred_type is None or node['type'].lower() == protocol)), None)
    if selected is None:
        selected = next((index for index, node in enumerate(nodes)
                         if node['type'].lower() == protocol), None)
    if selected not in (None, 0):
        nodes.insert(0, nodes.pop(selected))
    return output


def _source_node(node):
    if not isinstance(node, dict):
        raise ValueError("verified route must be an object")
    if (not isinstance(node.get("name"), str) or not node["name"] or
            not isinstance(node.get("type"), str) or node["type"] == "direct" or
            not isinstance(node.get("server"), str) or not node["server"] or
            type(node.get("port")) is not int or not 1 <= node["port"] <= 65535):
        raise ValueError("verified route is missing its name or endpoint")
    return copy.deepcopy(node)


def _provider(url, dmit_server):
    if not isinstance(url, str):
        raise ValueError("Paoluz provider URL is required")
    parsed = urlsplit(url)
    host = parsed.hostname
    if (parsed.scheme not in {"http", "https"} or not host or not parsed.path or
            parsed.username is not None or parsed.password is not None or parsed.fragment):
        raise ValueError("invalid DMIT provider URL")
    if host not in PROVIDER_HOSTS | {dmit_server}:
        raise ValueError("Paoluz must use the DMIT cache endpoint")
    # No upstream credentials or source provider definitions are copied.
    provider = {"type": "http", "url": url, "path": "./providers/paoluz.yaml",
                "proxy": "DIRECT", "health-check": {
                    "enable": True, "url": HEALTH_URL, "interval": HEALTH_INTERVAL,
                    "timeout": HEALTH_TIMEOUT, "lazy": False, "expected-status": 204}}
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        bootstrap_rule = "DOMAIN,{},DIRECT".format(host)
    else:
        kind = "IP-CIDR6" if address.version == 6 else "IP-CIDR"
        bootstrap_rule = "{},{}/{},DIRECT,no-resolve".format(kind, host,
                                                            address.max_prefixlen)
    return provider, host, bootstrap_rule


def _route_nodes(base, dmit_node, bytevirt_node, zoro_node, taiwan_node=None):
    roots_supplied = [dmit_node, bytevirt_node, zoro_node]
    if taiwan_node is not None:
        roots_supplied.append(taiwan_node)
    supplied = [_source_node(node) for node in roots_supplied]
    if len({node["name"] for node in supplied}) != len(supplied):
        raise ValueError("verified route identities must be unique")
    if supplied[0].get("dialer-proxy", "DIRECT") != "DIRECT":
        raise ValueError("DMIT direct route has an unexpected prior hop")
    zoro_name = supplied[2]["name"]
    if not zoro_name.replace(" ", "").endswith("DMIT→zorocloud"):
        zoro_name = ZORO
    names = [DMIT, BYTEVIRT, zoro_name] + ([TAIWAN] if taiwan_node is not None else [])
    if len(set(names)) != len(names):
        raise ValueError("route display names collide")
    original = {}
    for node in base.get("proxies") or []:
        if not isinstance(node, dict) or not isinstance(node.get("name"), str):
            raise ValueError("invalid source proxy")
        if node["name"] in original:
            raise ValueError("duplicate source proxy")
        original[node["name"]] = copy.deepcopy(node)
    rename = {node["name"]: name for node, name in zip(supplied, names)}
    roots = {}
    for node, name in zip(supplied, names):
        original[node["name"]] = node
        roots[name] = node["name"]
    generated, visiting, done = [], set(), set()

    def include(original_name):
        name = rename.get(original_name, original_name)
        if name in visiting:
            raise ValueError("dialer dependency cycle")
        if name in done:
            return
        if original_name not in original:
            raise ValueError("verified route has a missing dialer ancestor")
        if name in names and roots.get(name) != original_name:
            raise ValueError("dialer ancestor collides with a route")
        node = copy.deepcopy(original[original_name])
        visiting.add(name)
        dialer = node.get("dialer-proxy")
        if dialer and dialer != "DIRECT":
            include(dialer)
            node["dialer-proxy"] = rename.get(dialer, dialer)
        visiting.remove(name)
        node["name"] = name
        generated.append(node)
        done.add(name)

    for node in supplied:
        include(node["name"])
    # Only supplied verified roots are user-selectable. Ancestors remain exact technical
    # proxies, retaining their credentials and protocol options unchanged.
    nodes = {node["name"]: node for node in generated}
    generated = [nodes[name] for name in names] + [node for node in generated
                                                if node["name"] not in names]
    return generated, rename, set(original), names


def _rules(source, rename, source_names, semantic_names, bootstrap_rule):
    if not isinstance(source, list):
        raise ValueError("source rules must be a list")
    allowed = set(semantic_names) | {ALL, AUTO, GOOGLE, HK, STREAMING, VPS,
                                   OTHER, CHINA, GLOBAL} | BUILTINS
    aliases = dict(LEGACY_RULE_TARGETS)
    aliases.update({name: OTHER for name in (
        "paoluz", "Paoluz-All", "🦊 PAOLUZ", "🦊 机场paoluz", "机场paoluz", PAOLUZ)})
    # Known old generated node names may no longer be present in the raw base.
    old_nodes = set(ROUTE_NAMES.values()) | {_label(key) for key in ROUTE_NAMES}
    retired = (source_names | old_nodes) - set(rename) - allowed
    rewritten = []
    for rule in source:
        if not isinstance(rule, str):
            raise ValueError("all rules must be strings")
        parts = rule.split(",")
        index = _target_index(parts)
        target = parts[index]
        if parts[0] == "RULE-SET":
            raise ValueError("rule provider must be materialized before topology replacement")
        if target in rename:
            target = rename[target]
        elif target in aliases:
            target = aliases[target]
        elif target in retired:
            # The user explicitly removed the old routes and their provider
            # access targets. Never remap those destinations to a guessed hop.
            continue
        if target not in allowed:
            raise ValueError("unresolved rule target after topology replacement")
        parts[index] = target
        if len(parts) > 2 and parts[0] == "GEOSITE" and parts[1] in {"disney", "bamtech"}:
            continue
        if len(parts) > 2 and parts[0] == "GEOSITE" and parts[1] == "category-ai-cn":
            parts[index] = "DIRECT"
        elif len(parts) > 2 and ((parts[0] == "GEOSITE" and parts[1] == "netflix") or
                                (parts[0] == "DOMAIN-SUFFIX" and parts[1] in NETFLIX_DOMAIN_SUFFIXES)):
            parts[index] = HK
        elif len(parts) > 2 and ((parts[0] == "DOMAIN-SUFFIX" and parts[1] in DISNEY_PLUS_DOMAIN_SUFFIXES) or
                                (parts[0] == "GEOSITE" and parts[1] in OTHER_STREAMING_GEOCATEGORIES)):
            parts[index] = STREAMING
        elif len(parts) > 2 and ((parts[0] == "GEOSITE" and parts[1] in {"youtube", "google"}) or
                                (parts[0] == "DOMAIN-SUFFIX" and parts[1] in GOOGLE_DOMAIN_SUFFIXES)):
            parts[index] = GOOGLE
        rewritten.append(",".join(parts))
    explicit_google = ["GEOSITE,youtube," + GOOGLE, "GEOSITE,google," + GOOGLE,
                       "GEOSITE,category-ai-!cn," + GOOGLE] + [
        "DOMAIN-SUFFIX,{},{}".format(domain, GOOGLE)
        for domain in GOOGLE_DOMAIN_SUFFIXES + AI_DOMAIN_SUFFIXES]
    explicit_streaming = ["DOMAIN-SUFFIX,{},{}".format(domain, HK)
                          for domain in NETFLIX_DOMAIN_SUFFIXES] + ["GEOSITE,netflix," + HK] + [
        "DOMAIN-SUFFIX,{},{}".format(domain, STREAMING) for domain in DISNEY_PLUS_DOMAIN_SUFFIXES]
    forced = set(explicit_google + explicit_streaming)
    forced.update({"GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT", "MATCH," + ALL,
                   "GEOSITE,category-entertainment," + STREAMING})
    rewritten = [rule for rule in rewritten if rule not in forced and
                 rule != UDP_FALLBACK_GUARD and not rule.startswith("MATCH,")]
    hk_specific = [rule for rule in rewritten if not rule.startswith("GEOIP,") and
                   rule.split(",")[_target_index(rule.split(","))] == HK]
    rewritten = [rule for rule in rewritten if rule not in hk_specific]
    first_geoip = next((i for i, rule in enumerate(rewritten) if rule.startswith("GEOIP,")), len(rewritten))
    rewritten[first_geoip:first_geoip] = hk_specific + ["GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT",
        "GEOSITE,category-entertainment," + STREAMING]
    if not any(rule.startswith("GEOIP,HK,") for rule in rewritten):
        rewritten.append("GEOIP,HK," + HK)
    # Mihomo skips a matched policy whose selected leaf cannot carry UDP.
    # Without this last guard, exhausting MATCH falls back to DIRECT. Keep
    # explicit domestic/LAN DIRECT rules and UDP-capable proxy choices first.
    return _unique([bootstrap_rule] + explicit_google + explicit_streaming + rewritten +
                   ["MATCH," + ALL, UDP_FALLBACK_GUARD])


def build_new_topology(base: dict, *, dmit_node: dict, bytevirt_node: dict,
                       zoro_node: dict, paoluz_provider_url: str,
                       taiwan_node: Optional[dict] = None,
                       direct_country: Optional[str] = None,
                       now: Optional[datetime] = None) -> dict:
    if not isinstance(base, dict):
        raise ValueError("base configuration must be an object")
    if now is None:
        now = datetime.now(SINGAPORE_TZ)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("refresh time must be timezone-aware")
    generated, rename, source_names, names = _route_nodes(
        base, dmit_node, bytevirt_node, zoro_node, taiwan_node=taiwan_node)
    dmit, bytevirt, zoro = names[:3]
    after_zoro = names[3:]
    provider, host, bootstrap_rule = _provider(paoluz_provider_url, dmit_node["server"])
    direct = direct_label_for_country(direct_country) + "\n" + now.astimezone(SINGAPORE_TZ).strftime("%Y.%m.%d %H:%M:%S")
    if direct in {node["name"] for node in generated}:
        raise ValueError("direct outbound name collision")
    output = copy.deepcopy(base)
    output["proxies"] = generated + [{"name": direct, "type": "direct", "udp": True}]
    output["proxy-providers"] = {"paoluz": provider}
    # The fallback checks every airport leaf before this last provider. This
    # guards against a stale failed health result on the URL-test wrapper when
    # another airport leaf is already known alive. The original Zoro proxy is
    # still independently selectable in either visible group.
    output["proxy-providers"][ZORO_EMERGENCY_PROVIDER] = {
        "type": "inline", "payload": [copy.deepcopy(next(
            node for node in generated if node['name'] == zoro))],
        "health-check": copy.deepcopy(provider['health-check'])}
    output.pop("rule-providers", None)
    output["proxy-groups"] = [
        {"name": GLOBAL, "type": "select", "proxies": [GOOGLE, HK, STREAMING, VPS, CHINA, OTHER],
         "default-selected": GOOGLE, "hidden": True},
        {"name": ALL, "type": "select", "proxies": [AUTO, GOOGLE, HK, STREAMING, VPS, OTHER]},
        {"name": GOOGLE, "type": "select", "proxies": [zoro, *after_zoro, dmit], "default-selected": zoro},
        {"name": HK, "type": "select", "proxies": [bytevirt], "default-selected": bytevirt},
        {"name": STREAMING, "type": "select", "proxies": [AIRPORT_AUTO, zoro, *after_zoro],
         "use": ["paoluz"], "default-selected": AIRPORT_AUTO, "empty-fallback": "REJECT"},
        {"name": VPS, "type": "select", "proxies": [dmit, bytevirt, zoro, *after_zoro], "default-selected": dmit},
        {"name": OTHER, "type": "select", "proxies": [AIRPORT_AUTO, zoro, *after_zoro],
         "use": ["paoluz"], "default-selected": AIRPORT_AUTO, "empty-fallback": "REJECT"},
        {"name": CHINA, "type": "select", "proxies": [direct], "default-selected": direct, "hidden": True},
        {"name": AUTO, "type": "select", "proxies": [OTHER], "hidden": True},
        {"name": AIRPORT_FAST, "type": "url-test", "use": ["paoluz"],
         "url": HEALTH_URL, "interval": HEALTH_INTERVAL, "timeout": HEALTH_TIMEOUT,
         "expected-status": 204,
         "tolerance": 0, "lazy": False, "max-failed-times": 1,
         "empty-fallback": "REJECT", "hidden": True},
        {"name": AIRPORT_AUTO, "type": "fallback", "proxies": [AIRPORT_FAST],
         "use": ["paoluz", ZORO_EMERGENCY_PROVIDER],
         "url": HEALTH_URL, "interval": HEALTH_INTERVAL, "timeout": HEALTH_TIMEOUT,
         "expected-status": 204,
         "lazy": False, "max-failed-times": 1, "empty-fallback": "REJECT", "hidden": True},
        {"name": DNS_OVERSEAS, "type": "select", "proxies": [AIRPORT_AUTO], "hidden": True},
        {"name": DNS_GOOGLE, "type": "select", "proxies": [GOOGLE], "hidden": True},
    ]
    output["rules"] = _rules(base.get("rules") or [], rename, source_names, names, bootstrap_rule)
    output["mode"] = "rule"
    output["ipv6"] = False
    output["dns"] = _safe_dns(base.get("dns"))
    # Mihomo splits the DNS URL fragment at '&' before resolving a proxy name.
    # Visible group labels contain '&', so use unambiguous internal aliases.
    # Foreign DNS stays inside a proxy; AI DNS follows the actual AI selection.
    output["dns"]["nameserver"] = [
        "https://1.1.1.1/dns-query#" + DNS_OVERSEAS,
        "https://1.0.0.1/dns-query#" + DNS_OVERSEAS]
    output["dns"]["nameserver-policy"]["geosite:google,youtube,category-ai-!cn"] = [
        "https://1.1.1.1/dns-query#" + DNS_GOOGLE,
        "https://1.0.0.1/dns-query#" + DNS_GOOGLE]
    # Provider download must bootstrap even before airport nodes are loaded.
    policy = output["dns"].get("nameserver-policy") or {}
    output["dns"]["nameserver-policy"] = {host: ["https://223.5.5.5/dns-query#DIRECT",
                                                 "https://223.6.6.6/dns-query#DIRECT"], **policy}
    tun = output.get("tun")
    if isinstance(tun, dict) and tun.get("enable"):
        hijack = tun.get("dns-hijack")
        if not isinstance(hijack, list) or not all(isinstance(item, str) for item in hijack):
            raise ValueError("enabled TUN requires an explicit DNS hijack list")
        for item in ("any:53", "tcp://any:53"):
            if item not in hijack:
                hijack.append(item)
    return output


# November 6 plan. Keep the earlier renderer above intact for rollback and for
# callers which have not yet opted into the six independently verified routes.
PLAN_GOOGLE = "🤖 chatgpt、claude、google（不含youtube）"
PLAN_TVB = "🇭🇰 TVB、viu tv"
PLAN_HK_OTHER = "🇭🇰 HK其他"
PLAN_STREAMING = "🎬 非CN&HK流媒体的流媒体"
PLAN_BINANCE = "🪙 币安"
PLAN_PAOLUZ = "✈️ 断线备用"
PLAN_ROUTE_KEYS = ("dmit", "bytevirt_hk", "bytevirt_tw", "lazycat_sg", "lazycat_hkt", "uzuma_sg")
PLAN_ROUTE_NAMES = {
    "dmit": DMIT,
    "bytevirt_hk": "🔷 📡 🇬🇧 🇭🇰 DMIT→Bytevirt HK ISP",
    "bytevirt_tw": "🔷 📶 🇹🇼 DMIT→Bytevirt HINET NAT",
    "lazycat_sg": "🔷 🐈 🇸🇬 DMIT→Lazycat starhub",
    "lazycat_hkt": "🔷 🐈 🇬🇧 🇭🇰 DMIT→Lazycat HKT",
    "uzuma_sg": "🔷 📱 🇸🇬 DMIT→uzuma SG-Singtel1",
}
PLAN_VISIBLE_GROUPS = (ALL, AUTO, PLAN_GOOGLE, PLAN_TVB, PLAN_HK_OTHER,
                       VPS, OTHER, PLAN_PAOLUZ)
PLAN_ALL_MEMBERS = (AUTO, PLAN_GOOGLE, PLAN_TVB, PLAN_HK_OTHER,
                    VPS, OTHER, PLAN_PAOLUZ)
PLAN_YOUTUBE_SUFFIXES = (
    "youtube.com", "youtu.be", "youtube-nocookie.com", "googlevideo.com",
    "ytimg.com", "youtube.googleapis.com", "youtubei.googleapis.com",
    "youtubemusic.com", "yt.be",
)
PLAN_TVB_SUFFIXES = ("tvb.com", "tvb.com.au", "mytvsuper.com", "tvbanywhere.com",
                     "tvbanywhereplus.com", "viu.tv", "viutv.hk", "viu.com")
PLAN_BINANCE_SUFFIXES = ("binance.com", "binance.me", "binance.info", "binancefuture.com",
                         "binance.cloud", "bnbstatic.com", "bnappzh.com")
PLAN_WECHAT_SUFFIXES = ("weixin.qq.com", "wechat.com", "weixinbridge.com",
                        "qpic.cn", "qlogo.cn", "wx.qq.com")
PLAN_DNS_HK = "DNS-PlanHK"
PLAN_DNS_TVB = "DNS-PlanTVB"
PLAN_DNS_BINANCE = "DNS-PlanBinance"
PLAN_VERSION = "six-server-20261106"


def _plan_nodes(base, routes):
    if not isinstance(routes, dict) or set(routes) != set(PLAN_ROUTE_KEYS):
        raise ValueError("six verified plan routes are required")
    supplied = {key: _source_node(routes[key]) for key in PLAN_ROUTE_KEYS}
    originals = [node["name"] for node in supplied.values()]
    if len(set(originals)) != len(originals):
        raise ValueError("verified route identities must be unique")
    if supplied["dmit"].get("dialer-proxy", "DIRECT") != "DIRECT":
        raise ValueError("DMIT direct route has an unexpected prior hop")
    source = {}
    for node in base.get("proxies") or []:
        if not isinstance(node, dict) or not isinstance(node.get("name"), str):
            raise ValueError("invalid source proxy")
        if node["name"] in source:
            raise ValueError("duplicate source proxy")
        source[node["name"]] = copy.deepcopy(node)
    rename = {supplied[key]["name"]: PLAN_ROUTE_NAMES[key] for key in PLAN_ROUTE_KEYS}
    roots = {PLAN_ROUTE_NAMES[key]: supplied[key]["name"] for key in PLAN_ROUTE_KEYS}
    source.update({node["name"]: node for node in supplied.values()})
    generated, visiting, done = [], set(), set()

    def include(original):
        name = rename.get(original, original)
        if name in visiting:
            raise ValueError("dialer dependency cycle")
        if name in done:
            return
        if original not in source:
            raise ValueError("verified route has a missing dialer ancestor")
        if name in roots and roots[name] != original:
            raise ValueError("dialer ancestor collides with a route")
        node = copy.deepcopy(source[original])
        visiting.add(name)
        dialer = node.get("dialer-proxy")
        if dialer and dialer != "DIRECT":
            include(dialer)
            node["dialer-proxy"] = rename.get(dialer, dialer)
        visiting.remove(name)
        node["name"] = name
        generated.append(node)
        done.add(name)

    for key in PLAN_ROUTE_KEYS:
        include(supplied[key]["name"])
    names = set(PLAN_ROUTE_NAMES.values())
    indexed = {node["name"]: node for node in generated}
    ordered = [indexed[PLAN_ROUTE_NAMES[key]] for key in PLAN_ROUTE_KEYS]
    ordered.extend(node for node in generated if node["name"] not in names)
    return ordered, rename, set(source)


def _plan_rules(source, rename, source_names, bootstrap_rule):
    if not isinstance(source, list):
        raise ValueError("source rules must be a list")
    names = set(PLAN_ROUTE_NAMES.values())
    allowed = names | set(PLAN_VISIBLE_GROUPS) | {CHINA, GLOBAL} | BUILTINS
    aliases = dict(LEGACY_RULE_TARGETS)
    aliases.update({GOOGLE: PLAN_GOOGLE, HK: PLAN_HK_OTHER, STREAMING: OTHER,
                    PLAN_STREAMING: OTHER,
                    PAOLUZ: PLAN_PAOLUZ, "paoluz": PLAN_PAOLUZ, "Paoluz": PLAN_PAOLUZ,
                    "✈️ paoluz": PLAN_PAOLUZ,
                    "Paoluz-All": PLAN_PAOLUZ, "🦊 PAOLUZ": PLAN_PAOLUZ,
                    "🦊 机场paoluz": PLAN_PAOLUZ, "机场paoluz": PLAN_PAOLUZ,
                    "断线备用": PLAN_PAOLUZ, "币安": OTHER, PLAN_BINANCE: OTHER,
                    "🤖 谷歌全系（不含流媒体）与AI": PLAN_GOOGLE,
                    "谷歌全系（不含流媒体）与AI": PLAN_GOOGLE,
                    "🇭🇰 TVB&viu tv": PLAN_TVB, "📺 TVB&viu tv": PLAN_TVB,
                    "TVB&viu tv": PLAN_TVB, "HK其他": PLAN_HK_OTHER,
                    "非CN&HK流媒体的流媒体": OTHER,
                    "google（不含youtube）、chatgpt、claude": PLAN_GOOGLE,
                    "🤖 google（不含youtube）、chatgpt、claude": PLAN_GOOGLE,
                    "chatgpt、claude、google（不含youtube）": PLAN_GOOGLE,
                    "TVB、viu tv": PLAN_TVB})
    # Normalize both raw historical aliases and their old emoji targets.
    aliases = {key: aliases.get(value, value) for key, value in aliases.items()}
    aliases.update({"大陆-TVB→解锁TVB": PLAN_TVB, "大陆-TVB": PLAN_TVB})
    retired = (source_names | set(ROUTE_NAMES.values()) |
               {_label(key) for key in ROUTE_NAMES} | {ZORO, TAIWAN}) - set(rename) - allowed
    inherited = []
    for rule in source:
        if not isinstance(rule, str):
            raise ValueError("all rules must be strings")
        parts = rule.split(",")
        index = _target_index(parts)
        if parts[0] == "RULE-SET":
            raise ValueError("rule provider must be materialized before topology replacement")
        if parts[0] == "MATCH" or rule == UDP_FALLBACK_GUARD:
            continue
        target = parts[index]
        if target in rename:
            target = rename[target]
        elif target in aliases:
            target = aliases[target]
        elif target in retired or ("DMIT→zorocloud" in target):
            continue
        if target not in allowed:
            raise ValueError("unresolved rule target after network plan replacement")
        # Explicit rules below are authoritative for these categories. Remove
        # inherited category rules so stale Google/HK labels cannot win first.
        if parts[0] == "GEOSITE" and parts[1] in {
                "google", "youtube", "category-ai-!cn", "netflix", "disney", "bamtech",
                *OTHER_STREAMING_GEOCATEGORIES}:
            continue
        if parts[0] == "GEOSITE" and parts[1] == "category-ai-cn":
            target = "DIRECT"
        elif parts[0] == "GEOIP" and parts[1].upper() == "HK":
            target = PLAN_HK_OTHER
        parts[index] = target
        inherited.append(",".join(parts))
    # Direct DMIT bootstrap must precede its proxy-server IP service rule.
    # Existing LAN, WeChat and remote-control DIRECT rules remain available;
    # specific foreign services precede broad CN and entertainment categories.
    critical = [bootstrap_rule]
    critical += ["DOMAIN-SUFFIX,{},DIRECT".format(domain) for domain in PLAN_WECHAT_SUFFIXES]
    critical += ["PROCESS-NAME,{},DIRECT".format(name) for name in
                 ("Weixin.exe", "WeChat.exe", "WeChatAppEx.exe", "SunloginClient.exe", "SunloginClient")]
    tvb = ["DOMAIN-SUFFIX,{},{}".format(domain, PLAN_TVB) for domain in PLAN_TVB_SUFFIXES]
    netflix = ["DOMAIN-SUFFIX,{},{}".format(domain, PLAN_HK_OTHER) for domain in NETFLIX_DOMAIN_SUFFIXES]
    netflix.append("GEOSITE,netflix," + PLAN_HK_OTHER)
    binance = ["DOMAIN-SUFFIX,{},{}".format(domain, OTHER) for domain in PLAN_BINANCE_SUFFIXES]
    youtube = ["DOMAIN-SUFFIX,{},{}".format(domain, OTHER) for domain in PLAN_YOUTUBE_SUFFIXES]
    youtube.append("GEOSITE,youtube," + OTHER)
    google = ["DOMAIN-SUFFIX,{},{}".format(domain, PLAN_GOOGLE) for domain in
              GOOGLE_DOMAIN_SUFFIXES + AI_DOMAIN_SUFFIXES if domain not in PLAN_YOUTUBE_SUFFIXES]
    google += ["GEOSITE,google," + PLAN_GOOGLE, "GEOSITE,category-ai-!cn," + PLAN_GOOGLE]
    streaming = ["DOMAIN-SUFFIX,{},{}".format(domain, OTHER) for domain in DISNEY_PLUS_DOMAIN_SUFFIXES]
    # Do not let stale explicit service rules override the category's new home.
    forced_suffixes = set(PLAN_TVB_SUFFIXES + NETFLIX_DOMAIN_SUFFIXES + PLAN_BINANCE_SUFFIXES +
                          PLAN_YOUTUBE_SUFFIXES + GOOGLE_DOMAIN_SUFFIXES + AI_DOMAIN_SUFFIXES +
                          DISNEY_PLUS_DOMAIN_SUFFIXES + PLAN_WECHAT_SUFFIXES)
    inherited = [rule for rule in inherited if not (
        rule.startswith("DOMAIN-SUFFIX,") and rule.split(",")[1] in forced_suffixes)]
    inherited = [rule for rule in inherited if rule not in {"GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT"}]
    nonglobal = [rule for rule in inherited if not rule.startswith("GEOIP,")]
    broad = [rule for rule in inherited if rule.startswith("GEOIP,") and not rule.startswith("GEOIP,HK,")]
    provider = ["DOMAIN,dmit.io," + PLAN_ROUTE_NAMES["dmit"],
                "DOMAIN,www.dmit.io," + PLAN_ROUTE_NAMES["dmit"],
                "DOMAIN,bytevirt.com," + PLAN_ROUTE_NAMES["bytevirt_hk"],
                "DOMAIN,www.bytevirt.com," + PLAN_ROUTE_NAMES["bytevirt_hk"],
                "DOMAIN,dash.lazycat.wiki," + PLAN_ROUTE_NAMES["lazycat_sg"],
                "DOMAIN,uzuma.ru," + PLAN_ROUTE_NAMES["uzuma_sg"]]
    categories = ["GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT"] + [
        "GEOSITE,{},{}".format(category, OTHER)
        for category in sorted(OTHER_STREAMING_GEOCATEGORIES)]
    return _unique(critical + provider + tvb + netflix + binance + youtube + google + streaming +
                   nonglobal + categories + ["GEOIP,HK," + PLAN_HK_OTHER] + broad +
                   ["MATCH," + ALL, UDP_FALLBACK_GUARD])


def build_network_plan(base: dict, *, routes: dict, paoluz_provider_url: str,
                       client_kind: str = "desktop", direct_country: Optional[str] = None,
                       now: Optional[datetime] = None, server_policy: bool = False) -> dict:
    """Render the six-server plan only from caller-verified route objects.

    ``mobile`` makes Singtel the first AI member; ``desktop`` and
    ``router`` make StarHub first. Mihomo's actual initial choice is the first
    member, so behavior does not depend on a UI understanding default metadata.
    Existing client-persisted manual choices remain under client control.
    """
    if not isinstance(base, dict):
        raise ValueError("base configuration must be an object")
    if client_kind not in {"mobile", "desktop", "router"}:
        raise ValueError("client kind must be mobile, desktop or router")
    if type(server_policy) is not bool:
        raise ValueError("server policy flag must be boolean")
    if now is None:
        now = datetime.now(SINGAPORE_TZ)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("refresh time must be timezone-aware")
    generated, rename, source_names = _plan_nodes(base, routes)
    provider, host, bootstrap_rule = _provider(paoluz_provider_url, routes["dmit"]["server"])
    labels = PLAN_ROUTE_NAMES
    sg = [labels["uzuma_sg"], labels["lazycat_sg"]]
    if client_kind != "mobile":
        sg.reverse()
    direct = direct_label_for_country(direct_country) + "\n" + now.astimezone(SINGAPORE_TZ).strftime("%Y.%m.%d %H:%M:%S")
    reserved = set(PLAN_VISIBLE_GROUPS) | {GLOBAL, CHINA, AIRPORT_FAST, DNS_OVERSEAS,
        DNS_GOOGLE, PLAN_DNS_HK, PLAN_DNS_TVB} | BUILTINS
    if ({node["name"] for node in generated}.intersection(reserved) or direct in reserved or
            direct in {node["name"] for node in generated}):
        raise ValueError("plan proxy name collision")
    output = copy.deepcopy(base)
    output["x-submerge-plan"] = PLAN_VERSION
    output["x-submerge-client-kind"] = client_kind
    output.pop("x-submerge-server-policy", None)
    if server_policy:
        output["x-submerge-server-policy"] = "dmit-domain-routing-20261106"
    output["proxies"] = generated + [{"name": direct, "type": "direct", "udp": True}]
    output["proxy-providers"] = {"paoluz": provider}
    output.pop("rule-providers", None)
    output["proxy-groups"] = [
        {"name": GLOBAL, "type": "select", "proxies": [PLAN_GOOGLE, PLAN_TVB, PLAN_HK_OTHER,
            VPS, CHINA, OTHER, PLAN_PAOLUZ],
         "default-selected": PLAN_GOOGLE, "hidden": True},
        {"name": ALL, "type": "select", "proxies": list(PLAN_ALL_MEMBERS)},
        {"name": AUTO, "type": "select", "proxies": [OTHER], "desc": "按目标分流；中国大陆直连"},
        {"name": PLAN_GOOGLE, "type": "select", "proxies": sg.copy(), "default-selected": sg[0]},
        {"name": PLAN_TVB, "type": "select", "proxies": [labels["bytevirt_hk"]]},
        {"name": PLAN_HK_OTHER, "type": "select", "proxies": [labels["lazycat_hkt"]]},
        {"name": VPS, "type": "select", "proxies": [labels[key] for key in PLAN_ROUTE_KEYS]},
        {"name": OTHER, "type": "select", "proxies": [labels["bytevirt_tw"]]},
        {"name": PLAN_PAOLUZ, "type": "select", "proxies": [AIRPORT_FAST], "use": ["paoluz"],
         "desc": "断线备用：paoluz 全部节点；自动最低延迟或手动选择", "empty-fallback": "REJECT"},
        {"name": CHINA, "type": "select", "proxies": [direct], "hidden": True},
        {"name": AIRPORT_FAST, "type": "url-test", "use": ["paoluz"], "url": HEALTH_URL,
         "interval": HEALTH_INTERVAL, "timeout": HEALTH_TIMEOUT, "expected-status": 204,
         "tolerance": 0, "lazy": False, "max-failed-times": 1, "empty-fallback": "REJECT", "hidden": True},
        {"name": DNS_OVERSEAS, "type": "select", "proxies": [OTHER], "hidden": True},
        {"name": DNS_GOOGLE, "type": "select", "proxies": [PLAN_GOOGLE], "hidden": True},
        {"name": PLAN_DNS_HK, "type": "select", "proxies": [PLAN_HK_OTHER], "hidden": True},
        {"name": PLAN_DNS_TVB, "type": "select", "proxies": [PLAN_TVB], "hidden": True},
    ]
    output["rules"] = _plan_rules(base.get("rules") or [], rename, source_names, bootstrap_rule)
    output["mode"] = "rule"
    output["ipv6"] = False
    output["dns"] = _safe_dns(base.get("dns"))
    def doh(group):
        return ["https://1.1.1.1/dns-query#" + group, "https://1.0.0.1/dns-query#" + group]
    output["dns"]["nameserver"] = doh(DNS_OVERSEAS)
    policy = {host: ["https://223.5.5.5/dns-query#DIRECT", "https://223.6.6.6/dns-query#DIRECT"]}
    for domain in PLAN_WECHAT_SUFFIXES:
        policy["+." + domain] = ["https://223.5.5.5/dns-query#DIRECT", "https://223.6.6.6/dns-query#DIRECT"]
    for domain in PLAN_TVB_SUFFIXES:
        policy["+." + domain] = doh(PLAN_DNS_TVB)
    for domain in PLAN_BINANCE_SUFFIXES:
        policy["+." + domain] = doh(DNS_OVERSEAS)
    for domain in PLAN_YOUTUBE_SUFFIXES:
        policy["+." + domain] = doh(DNS_OVERSEAS)
    policy.update({"geosite:youtube": doh(DNS_OVERSEAS),
                   "geosite:netflix": doh(PLAN_DNS_HK),
                   "geosite:google,category-ai-!cn": doh(DNS_GOOGLE),
                   "geosite:cn": ["https://223.5.5.5/dns-query#DIRECT", "https://223.6.6.6/dns-query#DIRECT"]})
    output["dns"]["nameserver-policy"] = policy
    tun = output.get("tun")
    if isinstance(tun, dict) and tun.get("enable"):
        hijack = tun.get("dns-hijack")
        if not isinstance(hijack, list) or not all(isinstance(item, str) for item in hijack):
            raise ValueError("enabled TUN requires an explicit DNS hijack list")
        for item in ("any:53", "tcp://any:53"):
            if item not in hijack:
                hijack.append(item)
    return output


def validate_network_profile(document, provider_document=None):
    if isinstance(document, dict) and 'x-submerge-client-policy' in document:
        from client_policy import validate_profile
        return validate_profile(document, provider_document)
    return _validate_network_profile_legacy(document, provider_document)


def _validate_network_profile_legacy(document, provider_document=None):
    """Validate either a provider-backed or fully materialized plan profile.

    This checks its declared contract independently of the renderer. It does
    not contact an upstream, infer a route, or mark an unprobed route usable.
    Stable errors deliberately exclude node credentials and subscription URLs.
    """
    def require(condition, reason):
        if not condition:
            raise ValueError("network_plan_" + reason)

    require(isinstance(document, dict), "object_required")
    require(document.get("x-submerge-plan") == PLAN_VERSION, "version_invalid")
    kind = document.get("x-submerge-client-kind")
    require(isinstance(kind, str) and kind in {"mobile", "desktop", "router"}, "client_kind_invalid")
    rows, nodes = document.get("proxy-groups"), document.get("proxies")
    require(isinstance(rows, list) and isinstance(nodes, list), "inventory_missing")
    require(all(isinstance(row, dict) and isinstance(row.get("name"), str) for row in rows), "group_invalid")
    require(all(isinstance(node, dict) and isinstance(node.get("name"), str) for node in nodes), "node_invalid")
    groups = {row["name"]: row for row in rows}
    indexed = {node["name"]: node for node in nodes}
    require(len(groups) == len(rows) and len(indexed) == len(nodes), "duplicate_identity")
    expected_order = [GLOBAL, *PLAN_VISIBLE_GROUPS, CHINA, AIRPORT_FAST, DNS_OVERSEAS,
                      DNS_GOOGLE, PLAN_DNS_HK, PLAN_DNS_TVB]
    require([row["name"] for row in rows] == expected_order, "group_order_invalid")
    require([row["name"] for row in rows if not row.get("hidden")] == list(PLAN_VISIBLE_GROUPS), "visibility_invalid")
    labels = PLAN_ROUTE_NAMES
    wanted = set(labels.values())
    require(wanted.issubset(indexed), "route_missing")
    for name in wanted:
        _source_node(indexed[name])
    if "x-submerge-server-policy" in document:
        require(document["x-submerge-server-policy"] == "dmit-domain-routing-20261106",
                "server_policy_invalid")
        ports = {"dmit": 31117, "bytevirt_hk": 29518, "bytevirt_tw": 29514,
                 "lazycat_sg": 29515, "lazycat_hkt": 29516, "uzuma_sg": 29517}
        if kind == "mobile":
            ports = {key: (29611 if key == "dmit" else port + 100) for key, port in ports.items()}
        password = indexed[labels["dmit"]].get("password")
        require(isinstance(password, str) and len(password) >= 24, "server_policy_credential_invalid")
        for key, port in ports.items():
            node = indexed[labels[key]]
            require(node.get("type") == "anytls" and node.get("server") == "179.255.136.79"
                    and node.get("port") == port and node.get("password") == password
                    and node.get("dialer-proxy", "DIRECT") == "DIRECT" and node.get("udp") is False,
                    "server_policy_front_invalid")
    require(indexed[labels["dmit"]].get("dialer-proxy", "DIRECT") == "DIRECT", "first_hop_invalid")
    sg = [labels["uzuma_sg"], labels["lazycat_sg"]] if kind == "mobile" else [labels["lazycat_sg"], labels["uzuma_sg"]]
    direct_names = groups[CHINA].get("proxies")
    require(isinstance(direct_names, list) and len(direct_names) == 1 and direct_names[0] in indexed,
            "direct_identity_invalid")
    require(indexed[direct_names[0]].get("type") == "direct" and indexed[direct_names[0]].get("udp") is True,
            "direct_identity_invalid")
    expected_members = {
        GLOBAL: [PLAN_GOOGLE, PLAN_TVB, PLAN_HK_OTHER, VPS, CHINA, OTHER, PLAN_PAOLUZ],
        ALL: list(PLAN_ALL_MEMBERS), AUTO: [OTHER], PLAN_GOOGLE: sg, PLAN_TVB: [labels["bytevirt_hk"]],
        PLAN_HK_OTHER: [labels["lazycat_hkt"]],
        VPS: [labels[key] for key in PLAN_ROUTE_KEYS], OTHER: [labels["bytevirt_tw"]],
        CHINA: direct_names, DNS_OVERSEAS: [OTHER], DNS_GOOGLE: [PLAN_GOOGLE],
        PLAN_DNS_HK: [PLAN_HK_OTHER], PLAN_DNS_TVB: [PLAN_TVB],
    }
    for name, members in expected_members.items():
        group = groups[name]
        require(group.get("type") == "select" and group.get("proxies") == members and not group.get("use"),
                "members_invalid")
        if "default-selected" in group:
            require(group["default-selected"] == members[0], "default_invalid")
    backup, fastest = groups[PLAN_PAOLUZ], groups[AIRPORT_FAST]
    require(backup.get("type") == "select" and backup.get("empty-fallback") == "REJECT", "backup_invalid")
    require(fastest.get("type") == "url-test" and fastest.get("use") == ["paoluz"] and
            not fastest.get("proxies") and fastest.get("empty-fallback") == "REJECT" and
            fastest.get("url") == HEALTH_URL and fastest.get("tolerance") == 0 and
            fastest.get("interval") == HEALTH_INTERVAL and fastest.get("timeout") == HEALTH_TIMEOUT and
            fastest.get("expected-status") == 204 and fastest.get("lazy") is False, "fastest_invalid")
    providers = document.get("proxy-providers")
    require(isinstance(providers, dict) and set(providers) == {"paoluz"}, "providers_invalid")
    provider = providers["paoluz"]
    require(isinstance(provider, dict) and provider.get("proxy") == "DIRECT", "provider_bootstrap_invalid")
    expected_provider, host, _ = _provider(provider.get("url"), indexed[labels["dmit"]]["server"])
    require(provider == expected_provider, "provider_settings_invalid")
    require(not document.get("rule-providers"), "rule_providers_forbidden")
    supplied_airport = None
    if provider_document is not None:
        require(isinstance(provider_document, dict) and isinstance(provider_document.get("proxies"), list),
                "provider_document_invalid")
        supplied_airport = provider_document["proxies"]
        require(all(isinstance(node, dict) and isinstance(node.get("name"), str) and node["name"] and
                    isinstance(node.get("type"), str) for node in supplied_airport), "airport_identity_invalid")
        airport_names = [node["name"] for node in supplied_airport]
        require(len(set(airport_names)) == len(airport_names), "airport_duplicate_identity")
    elif backup.get("use") == ["paoluz"]:
        airport_names = []
    else:
        members = backup.get("proxies")
        require(isinstance(members, list) and members and members[0] == AIRPORT_FAST, "backup_members_invalid")
        airport_names = members[1:]
        require(len(set(airport_names)) == len(airport_names), "airport_duplicate_identity")
    reserved = set(groups) | wanted | set(direct_names) | BUILTINS
    require(not reserved.intersection(airport_names), "airport_collision")
    if backup.get("use") == ["paoluz"]:
        require(backup.get("proxies") == [AIRPORT_FAST], "backup_members_invalid")
        materialized = False
    else:
        require(not backup.get("use") and backup.get("proxies") == [AIRPORT_FAST, *airport_names],
                "backup_members_invalid")
        require(all(name in indexed for name in airport_names), "airport_nodes_missing")
        materialized = True
        if supplied_airport is not None:
            require(all(indexed[node["name"]] == node for node in supplied_airport), "airport_payload_changed")
    # Only an explicit verified root's recursively required dialers may remain
    # outside the six user-facing routes, direct node, and materialized airport.
    own, visiting = set(), set()
    def visit(name):
        require(name not in visiting and name in indexed and name not in airport_names, "dialer_invalid")
        if name in own:
            return
        visiting.add(name)
        dialer = indexed[name].get("dialer-proxy")
        if dialer and dialer != "DIRECT":
            visit(dialer)
        visiting.remove(name)
        own.add(name)
    for name in wanted:
        visit(name)
    require(set(indexed) == own | set(direct_names) | (set(airport_names) if materialized else set()), "extra_nodes_forbidden")
    require(document.get("mode") == "rule" and document.get("ipv6") is False, "mode_invalid")
    rules = document.get("rules")
    require(isinstance(rules, list) and all(isinstance(rule, str) for rule in rules), "rules_invalid")
    require(rules[-2:] == ["MATCH," + ALL, UDP_FALLBACK_GUARD], "udp_guard_invalid")
    require(rules.count(UDP_FALLBACK_GUARD) == 1 and rules.count("MATCH," + ALL) == 1, "terminal_rules_invalid")
    require(not any(rule.startswith("NETWORK,UDP,") and rule != UDP_FALLBACK_GUARD for rule in rules),
            "udp_bypass_forbidden")
    allowed_targets = reserved
    for rule in rules:
        parts = rule.split(",")
        require(parts[_target_index(parts)] in allowed_targets and parts[0] != "RULE-SET", "rule_target_invalid")
    required_rules = ["GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT", "GEOIP,HK," + PLAN_HK_OTHER,
        "GEOSITE,youtube," + OTHER, "GEOSITE,google," + PLAN_GOOGLE,
        "GEOSITE,category-ai-!cn," + PLAN_GOOGLE, "GEOSITE,netflix," + PLAN_HK_OTHER]
    for suffixes, target in ((PLAN_TVB_SUFFIXES, PLAN_TVB), (NETFLIX_DOMAIN_SUFFIXES, PLAN_HK_OTHER),
        (PLAN_BINANCE_SUFFIXES, OTHER), (PLAN_YOUTUBE_SUFFIXES, OTHER),
        (PLAN_WECHAT_SUFFIXES, "DIRECT")):
        required_rules.extend("DOMAIN-SUFFIX,{},{}".format(suffix, target) for suffix in suffixes)
    require(all(rule in rules for rule in required_rules), "required_rules_missing")
    require(rules.index("GEOSITE,youtube," + OTHER) < rules.index("GEOSITE,google," + PLAN_GOOGLE),
            "youtube_precedence_invalid")
    dns = document.get("dns")
    require(isinstance(dns, dict) and dns.get("enable") is True and dns.get("ipv6") is False and
            dns.get("enhanced-mode") == "fake-ip" and dns.get("respect-rules") is False and
            not dns.get("fallback"), "dns_invalid")
    def doh(group):
        return ["https://1.1.1.1/dns-query#" + group, "https://1.0.0.1/dns-query#" + group]
    require(dns.get("nameserver") == doh(DNS_OVERSEAS), "dns_foreign_invalid")
    policy = dns.get("nameserver-policy")
    require(isinstance(policy, dict) and policy.get("geosite:youtube") == doh(DNS_OVERSEAS) and
            policy.get("geosite:google,category-ai-!cn") == doh(DNS_GOOGLE) and
            policy.get("geosite:netflix") == doh(PLAN_DNS_HK), "dns_category_invalid")
    domestic_dns = ["https://223.5.5.5/dns-query#DIRECT", "https://223.6.6.6/dns-query#DIRECT"]
    require(policy.get(host) == domestic_dns and policy.get("geosite:cn") == domestic_dns, "dns_bootstrap_invalid")
    for suffixes, group in ((PLAN_TVB_SUFFIXES, PLAN_DNS_TVB), (PLAN_BINANCE_SUFFIXES, DNS_OVERSEAS),
                            (PLAN_YOUTUBE_SUFFIXES, DNS_OVERSEAS)):
        require(all(policy.get("+." + domain) == doh(group) for domain in suffixes), "dns_service_invalid")
    require(all(policy.get("+." + domain) == domestic_dns for domain in PLAN_WECHAT_SUFFIXES), "dns_wechat_invalid")
    tun = document.get("tun")
    if isinstance(tun, dict) and tun.get("enable"):
        require(isinstance(tun.get("dns-hijack"), list) and
                {"any:53", "tcp://any:53"}.issubset(tun["dns-hijack"]), "tun_dns_invalid")
    return True

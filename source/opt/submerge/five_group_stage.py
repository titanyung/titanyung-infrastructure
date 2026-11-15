"""Staging-only, fail-closed layout for the requested subscription groups.

This is a post-processor for an already generated per-user Clash document. It
does not provision a relay, infer a path from its name, or modify production.
The caller must bind every required route key to an existing, independently
verified per-user node. Apply this after the merger's test-account isolation
and DNS setup, immediately before YAML serialization.

"自动" is a selector, not a latency test. Global rules handle destination
classes; when no earlier rule matches, MATCH -> 全部节点 -> 自动 reaches the
non-mainland group. Choosing another 全部节点 entry changes only traffic that
falls through to 全部节点, not higher-priority Google/HK/provider rules.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping, Optional, Sequence, Tuple

from expiry_policy import (SERVICE_EXPIRY_DATES, SINGAPORE_TZ, expired_services,
                           service_expires_at)


ALL = "🌐 全部节点"
AUTO = "🧭 自动"
GOOGLE = "🤖 谷歌全系 & AI"
HK = "🇭🇰 HK&HK流媒体"
STREAMING = "🎬 非中国大陆&HK流媒体的流媒体"
VPS = "🖥️ VPS访问"
OTHER = "🌍 非中国大陆的其他"
CHINA = "🇨🇳 中国大陆"
GLOBAL = "GLOBAL"


# These are semantic route IDs, not guessed substrings of emitted node names.
GOOGLE_KEYS = (
    "nex_dmit", "ip2_dmit", "sg_dmit", "kk_dmit", "ph_dmit",
    "nex_bwh", "ip2_bwh", "sg_bwh", "kk_bwh", "ph_bwh",
    "vps_dmit", "vps_bwh",
)
HK_KEYS = (
    "bv_dmit", "hkt_dmit", "bv_bwh", "hkt_bwh",
)
STREAMING_KEYS = (
    "bv_bwh", "bv_dmit", "vps_bwh", "vps_dmit",
)
VPS_KEYS = (
    "vps_dmit", "vps_bwh", "bv_dmit", "bv_bwh",
    "nex_dmit", "nex_bwh", "ip2_dmit", "ip2_bwh",
    "sg_dmit", "sg_bwh", "hkt_dmit", "hkt_bwh",
    "ph_dmit", "ph_bwh", "kk_dmit", "kk_bwh",
)
OTHER_KEYS = (
    "bv_dmit", "hkt_dmit", "bv_bwh", "hkt_bwh", "vps_bwh",
    "nex_dmit", "ip2_dmit", "sg_dmit", "kk_dmit", "ph_dmit",
    "nex_bwh", "ip2_bwh", "sg_bwh", "kk_bwh", "ph_bwh",
    "vps_dmit",
)
ALL_KEYS = frozenset(GOOGLE_KEYS + HK_KEYS + STREAMING_KEYS +
                     VPS_KEYS + OTHER_KEYS)

ROUTE_NAMES = {
    "nex_dmit": "DMIT→NexIP SG静态住宅IP",
    "nex_bwh": "BWH→NexIP SG静态住宅IP",
    "ip2_dmit": "DMIT→ip2up.com静态住宅IP",
    "ip2_bwh": "BWH→ip2up.com静态住宅IP",
    "sg_dmit": "DMIT→LazyCat SG动态家宽",
    "sg_bwh": "BWH→LazyCat SG动态家宽",
    "ph_dmit": "DMIT→proxyhive.io静态住宅IP",
    "ph_bwh": "BWH→proxyhive.io静态住宅IP",
    "kk_dmit": "DMIT→kookey静态住宅IP",
    "kk_bwh": "BWH→kookey静态住宅IP",
    "hkt_dmit": "DMIT→LazyCat HKT动态家宽",
    "hkt_bwh": "BWH→LazyCat HKT动态家宽",
    "vps_dmit": "DMIT",
    "vps_bwh": "BWH",
    "bv_dmit": "DMIT→Bytevirt iCable静态家宽",
    "bv_bwh": "BWH→Bytevirt iCable静态家宽",
}

# Client node names are plain text: use distinct Unicode emoji for each real
# hop, then the country of the observed final egress. British Hong Kong has no
# separate Unicode flag emoji; the UK and Hong Kong pair conveys the requested
# historic/current distinction without relying on unsupported custom images.
INGRESS_ICONS = {"dmit": "🔷", "bwh": "🧱"}
EGRESS_ICONS = {
    "bytevirt": "📡", "lazycat": "🐈", "nexip": "🧩",
    "ip2up": "🆙", "proxyhive": "🐝", "kookey": "🔑",
}
EXIT_FLAGS = {"us": "🇺🇸", "sg": "🇸🇬", "hk": "🇬🇧 🇭🇰"}

ROUTE_ICON_PARTS = {
    "nex_dmit": ("dmit", "nexip", "sg"),
    "nex_bwh": ("bwh", "nexip", "sg"),
    "ip2_dmit": ("dmit", "ip2up", "sg"),
    "ip2_bwh": ("bwh", "ip2up", "sg"),
    "sg_dmit": ("dmit", "lazycat", "sg"),
    "sg_bwh": ("bwh", "lazycat", "sg"),
    "ph_dmit": ("dmit", "proxyhive", "sg"),
    "ph_bwh": ("bwh", "proxyhive", "sg"),
    "kk_dmit": ("dmit", "kookey", "sg"),
    "kk_bwh": ("bwh", "kookey", "sg"),
    "hkt_dmit": ("dmit", "lazycat", "hk"),
    "hkt_bwh": ("bwh", "lazycat", "hk"),
    "vps_dmit": ("dmit", None, "us"),
    "vps_bwh": ("bwh", None, "us"),
    "bv_dmit": ("dmit", "bytevirt", "hk"),
    "bv_bwh": ("bwh", "bytevirt", "hk"),
}

if set(ROUTE_ICON_PARTS) != set(ROUTE_NAMES):
    raise RuntimeError("route icon map must cover every published route")

ROUTE_ICONS = {
    key: " ".join(part for part in (
        INGRESS_ICONS[ingress], EGRESS_ICONS[egress] if egress else None,
        EXIT_FLAGS[country],
    ) if part)
    for key, (ingress, egress, country) in ROUTE_ICON_PARTS.items()
}

DIRECT_ICON = "🛣️"
DIRECT_LABEL = DIRECT_ICON + " 🌐 🌐 直连"


def direct_label_for_country(country_code: Optional[str]) -> str:
    """Label a direct route at profile creation, if client country is known.

    A generated Mihomo profile cannot change this text when the client's IP
    changes later; callers must refresh the profile with a trusted country.
    """
    if country_code is None:
        return DIRECT_LABEL
    country = country_code.upper()
    if not re.fullmatch(r"[A-Z]{2}", country):
        raise ValueError("direct country must be an ISO two-letter code")
    flags = EXIT_FLAGS.get(country.lower())
    if flags is None:
        flags = "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in country)
    return "{} {} 🌐 直连".format(DIRECT_ICON, flags)

ROUTE_SERVICES = {
    "nex_dmit": frozenset(),
    "nex_bwh": frozenset({"bwh"}),
    "ip2_dmit": frozenset({"ip2up"}),
    "ip2_bwh": frozenset({"bwh", "ip2up"}),
    "sg_dmit": frozenset({"lazycat_sg"}),
    "sg_bwh": frozenset({"bwh", "lazycat_sg"}),
    "ph_dmit": frozenset({"proxyhive"}),
    "ph_bwh": frozenset({"bwh", "proxyhive"}),
    "kk_dmit": frozenset({"kookey"}),
    "kk_bwh": frozenset({"bwh", "kookey"}),
    "hkt_dmit": frozenset({"lazycat_hkt"}),
    "hkt_bwh": frozenset({"bwh", "lazycat_hkt"}),
    "vps_dmit": frozenset(),
    "vps_bwh": frozenset({"bwh"}),
    "bv_dmit": frozenset(),
    "bv_bwh": frozenset({"bwh"}),
}

PROVIDER_DEFAULT_KEYS = {
    "dmit": ("vps_dmit",),
    "bwh": ("vps_bwh",),
    "bytevirt": ("bv_dmit", "bv_bwh"),
    "nexip": ("nex_dmit", "nex_bwh"),
    "ip2up": ("ip2_dmit", "ip2_bwh"),
    "lazycat_sg": ("sg_bwh", "sg_dmit"),
    "lazycat_hkt": ("hkt_dmit", "hkt_bwh"),
    "proxyhive": ("ph_bwh",),
    "kookey": ("kk_dmit", "kk_bwh"),
}

GROUP_DEFAULT_KEYS = {
    GOOGLE: ("nex_dmit", "sg_dmit", "kk_dmit", "sg_bwh"),
    HK: ("bv_dmit", "bv_bwh"),
    STREAMING: ("bv_bwh", "bv_dmit"),
    VPS: ("vps_dmit",),
    OTHER: ("bv_bwh", "nex_dmit", "sg_dmit", "kk_dmit", "ph_dmit"),
}

# Only these suffixes have an existing locally audited provider rule. Other
# providers use exact DOMAIN entries until their actual portals are checked;
# a guessed suffix can capture unrelated traffic before CN DIRECT rules.
APPROVED_PROVIDER_SUFFIXES = {
    "bwh": frozenset({"bandwagonhost.com", "64clouds.com"}),
}

LEGACY_RULE_TARGETS = {
    "全部节点": ALL,
    "自动": AUTO,
    "google全系 & AI": GOOGLE,
    "谷歌全系 & AI": GOOGLE,
    "HK&HK流媒体": HK,
    "非中国大陆&HK流媒体的流媒体": STREAMING,
    "VPS访问": VPS,
    "非中国大陆的其他": OTHER,
    "AI工具": GOOGLE,
    "DMIT→kookey（2027-01-15 01:42到期）": GOOGLE,
    "大陆-TVB→解锁TVB": HK,
    "大陆-TVB": HK,
    "HK": HK,
    "HK-Optimized": HK,
}

# Explicit hosts complement GEOSITE,google and GEOSITE,youtube. In particular,
# music.youtube.com is covered by youtube.com, while media often loads from
# googlevideo.com and ytimg.com rather than the page's own hostname.
GOOGLE_DOMAIN_SUFFIXES = (
    "youtube.com", "youtu.be", "youtube-nocookie.com",
    "googlevideo.com", "ytimg.com", "youtube.googleapis.com",
    "google.com", "googleapis.com", "gstatic.com",
    "googleusercontent.com", "ggpht.com", "gvt1.com", "gvt2.com",
)

# Confirmed non-mainland AI service domains from the active 16-user merger.
# The generic AI geosite category is retained, but these explicit suffixes
# protect common services if a client's geodata is older than the server's.
AI_DOMAIN_SUFFIXES = (
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "anthropic.com", "claude.ai", "claudeusercontent.com",
    "perplexity.ai", "generativelanguage.googleapis.com",
)

# The upstream domain-list-community has a broad disney category that also
# includes unrelated properties and a mainland-China Disney site. Disney+
# gets only the specifically identified login/playback suffixes here, so the
# general mainland DIRECT rules are not preempted by that broad category.
NETFLIX_DOMAIN_SUFFIXES = (
    "netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net",
    "nflxso.net", "nflxext.com",
)
DISNEY_PLUS_DOMAIN_SUFFIXES = (
    "disneyplus.com", "disneystreaming.com", "dssott.com",
    "bamgrid.com", "bamtech.net", "dmed.technology",
    "disney-plus.net", "disneyaccount.com", "disneysubscription.com",
    "streamingdisney.net",
)
OTHER_STREAMING_GEOCATEGORIES = frozenset({
    "primevideo", "apple-tvplus", "spotify", "twitch", "hbo",
    "category-entertainment",
})


@dataclass(frozen=True)
class RouteBinding:
    source_name: str
    # Evidence is supplied by external hop, egress and reachability checks.
    # This module cannot verify a real tunnel from a YAML object alone.
    evidence: str


@dataclass(frozen=True)
class ProviderMatch:
    rule_type: str
    value: str

    def render(self, target: str, *, provider: str) -> str:
        if self.rule_type not in {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR"}:
            raise ValueError("unsupported provider match type")
        if not self.value or "," in self.value:
            raise ValueError("invalid provider match value")
        if self.rule_type == "IP-CIDR":
            network = ipaddress.ip_network(self.value, strict=True)
            if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 32:
                raise ValueError("provider IP match must be one exact IPv4 address")
            if not network.is_global:
                raise ValueError("provider IP match must be public")
            return "IP-CIDR,{},{},no-resolve".format(self.value, target)
        labels = self.value.split(".")
        if (len(self.value) > 253 or len(labels) < 2 or
                any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in labels) or
                not re.fullmatch(r"[a-z]{2,24}", labels[-1])):
            raise ValueError("provider domain must be an exact ASCII DNS name")
        if (self.rule_type == "DOMAIN-SUFFIX" and
                self.value not in APPROVED_PROVIDER_SUFFIXES.get(provider, frozenset())):
            raise ValueError("unapproved provider suffix")
        return "{},{},{}".format(self.rule_type, self.value, target)


def _label(key: str) -> str:
    services = ROUTE_SERVICES[key].intersection(SERVICE_EXPIRY_DATES)
    prefix = ROUTE_ICONS[key] + " "
    if not services:
        return prefix + ROUTE_NAMES[key]
    earliest = min(service_expires_at(service) for service in services)
    display = (earliest.strftime("%Y-%m-%d %H:%M:%S")
               if any((earliest.hour, earliest.minute, earliest.second))
               else earliest.date().isoformat())
    return "{}{}（{}到期）".format(prefix, ROUTE_NAMES[key], display)


def _prioritized_keys(candidates: Sequence[str], active: set[str]) -> list[str]:
    """Earliest expiring marked default wins; user list order breaks ties."""
    live = [key for key in candidates if key in active]
    return sorted(live, key=lambda key: (
        min((service_expires_at(service) for service in ROUTE_SERVICES[key]
             if service in SERVICE_EXPIRY_DATES),
            default=datetime.max.replace(tzinfo=SINGAPORE_TZ)),
        candidates.index(key),
    ))


def _target_index(parts) -> int:
    if len(parts) < 2:
        raise ValueError("invalid Clash rule")
    if parts[0] == "MATCH":
        return 1
    if parts[-1] == "no-resolve":
        if len(parts) < 3:
            raise ValueError("invalid Clash rule")
        return len(parts) - 2
    return len(parts) - 1


def _rewrite_legacy_rules(rules):
    rewritten = []
    for rule in rules:
        if not isinstance(rule, str):
            raise ValueError("all Clash rules must be strings")
        parts = rule.split(",")
        index = _target_index(parts)
        target = parts[index]
        if (len(parts) > 2 and parts[0] == "GEOSITE" and
                parts[1] in {"disney", "bamtech"}):
            # The source has GEOSITE,bamtech before CN DIRECT. Its category
            # is broader than the requested Disney+ service. Keep the
            # narrower explicit suffixes, but drop the category entirely.
            continue
        if len(parts) > 2 and parts[0] == "GEOSITE" and parts[1] == "category-ai-cn":
            # Mainland AI sites remain DIRECT. The legacy target was a
            # Singapore test route and must not override CN classification.
            parts[index] = "DIRECT"
            rewritten.append(",".join(parts))
            continue
        if (len(parts) > 2 and
                ((parts[0] == "GEOSITE" and parts[1] == "netflix") or
                 (parts[0] == "DOMAIN-SUFFIX" and
                  parts[1] in NETFLIX_DOMAIN_SUFFIXES))):
            parts[index] = HK
        elif (len(parts) > 2 and parts[0] == "DOMAIN-SUFFIX" and
              parts[1] in DISNEY_PLUS_DOMAIN_SUFFIXES):
            parts[index] = STREAMING
        elif (len(parts) > 2 and parts[0] == "GEOSITE" and
              parts[1] in OTHER_STREAMING_GEOCATEGORIES):
            parts[index] = STREAMING
        elif (len(parts) > 2 and
              ((parts[0] == "GEOSITE" and parts[1] in {"youtube", "google"}) or
               (parts[0] == "DOMAIN-SUFFIX" and
                parts[1] in GOOGLE_DOMAIN_SUFFIXES))):
            parts[index] = GOOGLE
        elif target in LEGACY_RULE_TARGETS:
            parts[index] = LEGACY_RULE_TARGETS[target]
        elif target not in {ALL, GOOGLE, HK, STREAMING, VPS, OTHER,
                            "DIRECT", "REJECT", "REJECT-DROP", "PASS"}:
            raise ValueError("unmapped existing rule target: {}".format(target))
        rewritten.append(",".join(parts))
    if "MATCH,{}".format(ALL) not in rewritten:
        raise ValueError("MATCH must continue to use 全部节点")
    if "GEOSITE,cn,DIRECT" not in rewritten or "GEOIP,CN,DIRECT" not in rewritten:
        raise ValueError("mainland direct rules are missing")
    if "GEOSITE,youtube,{}".format(GOOGLE) not in rewritten:
        raise ValueError("existing YouTube rule is missing")
    return rewritten


def _safe_dns(existing):
    dns = copy.deepcopy(existing if isinstance(existing, dict) else {})
    # Application DNS stays on the previously used ByteVirt egress even though
    # the general non-mainland OTHER group now defaults to LazyCat SG. Direct
    # and bootstrap resolvers remain for direct traffic and proxy setup only.
    dns["default-nameserver"] = ["https://223.5.5.5/dns-query"]
    dns["nameserver"] = [
        "https://1.1.1.1/dns-query#" + STREAMING,
        "https://1.0.0.1/dns-query#" + STREAMING,
    ]
    dns["direct-nameserver"] = ["https://223.5.5.5/dns-query"]
    dns["proxy-server-nameserver"] = ["https://223.5.5.5/dns-query"]
    dns["respect-rules"] = False
    dns["ipv6"] = False
    dns["enable"] = True
    dns["enhanced-mode"] = "fake-ip"
    dns.pop("fallback", None)
    dns.pop("fallback-filter", None)
    # Resolve mainland names locally before the foreign default DNS
    # path. direct-nameserver alone applies only after DIRECT is selected;
    # applications asking for real IPs must not depend on the proxy to obtain
    # mainland answers. Pin encrypted resolvers by IP to avoid bootstrap loops.
    dns["nameserver-policy"] = {
        # Preserve the routing precedence for foreign services which overlap
        # a mainland suffix (for example google.cn). YAML key order matters.
        "geosite:google,youtube,category-ai-!cn": list(dns["nameserver"]),
        "geosite:cn": [
            "https://223.5.5.5/dns-query#DIRECT",
            "https://223.6.6.6/dns-query#DIRECT",
        ],
    }
    return dns


def build_five_group_stage(
    merged: dict,
    *,
    bindings: Mapping[str, RouteBinding],
    provider_matches: Mapping[str, Sequence[ProviderMatch]],
    now: Optional[datetime] = None,
    trial_account: bool = False,
    direct_country: Optional[str] = None,
) -> dict:
    """Build a staging candidate; reject missing/unverified active routes.

    For the isolated ``test`` account, pass ``trial_account=True`` *after*
    the existing merger's trial-only filtering. It returns an unchanged copy;
    the 16 ordinary users are checked at the /test/sub/ staging endpoint.
    """

    if not isinstance(merged, dict):
        raise ValueError("merged must be a dictionary")
    if trial_account:
        return copy.deepcopy(merged)
    if now is None:
        now = datetime.now(SINGAPORE_TZ)
    expired = expired_services(now)
    active = {key for key in ALL_KEYS if not ROUTE_SERVICES[key].intersection(expired)}
    missing = active.difference(bindings)
    if missing:
        raise ValueError("unbound active routes: {}".format(", ".join(sorted(missing))))

    source_nodes = {}
    for proxy in merged.get("proxies") or []:
        if not isinstance(proxy, dict) or not isinstance(proxy.get("name"), str):
            raise ValueError("every source proxy needs a string name")
        if proxy["name"] in source_nodes:
            raise ValueError("duplicate source proxy name")
        source_nodes[proxy["name"]] = proxy

    for key in sorted(active):
        binding = bindings[key]
        if not isinstance(binding, RouteBinding) or not binding.source_name or not binding.evidence:
            raise ValueError("unverified route: {}".format(key))
        if binding.source_name not in source_nodes:
            raise ValueError("source node unavailable for route: {}".format(key))

    # A source may be reused only through an explicit route-key binding. The
    # generated aliases are independently named and never parsed for service
    # dependencies; expiry is decided solely by ROUTE_SERVICES.
    generated = []
    for key in sorted(active):
        node = copy.deepcopy(source_nodes[bindings[key].source_name])
        node["name"] = _label(key)
        generated.append(node)

    # Preserve exact source ancestors for any Mihomo dialer-proxy chains.
    # They are technical nodes, not members of the user-facing groups.
    pending = list(generated)
    included_names = {node["name"] for node in generated}
    while pending:
        node = pending.pop()
        dialer = node.get("dialer-proxy")
        if not dialer or dialer in {"DIRECT", "REJECT"} or dialer in included_names:
            continue
        if dialer not in source_nodes:
            raise ValueError("missing dialer ancestor: {}".format(dialer))
        ancestor = copy.deepcopy(source_nodes[dialer])
        if ancestor["name"] in included_names:
            continue
        included_names.add(ancestor["name"])
        generated.append(ancestor)
        pending.append(ancestor)

    def members(keys: Tuple[str, ...]):
        return [_label(key) for key in keys if key in active]

    group_members = {
        GOOGLE: members(GOOGLE_KEYS),
        HK: members(HK_KEYS),
        STREAMING: members(STREAMING_KEYS),
        VPS: members(VPS_KEYS),
        OTHER: members(OTHER_KEYS),
    }
    if any(not candidates for candidates in group_members.values()):
        raise ValueError("expiry would leave a requested group empty")
    for group_name, defaults in GROUP_DEFAULT_KEYS.items():
        if not any(key in active for key in defaults):
            raise ValueError("requested default route is unavailable: {}".format(group_name))
    # Preserve the user's exact displayed route order. A Mihomo select group
    # supports a separate default-selected member, so expiry can switch the
    # preferred default without shuffling the displayed alternatives.
    selected = {name: _label(_prioritized_keys(defaults, active)[0])
                for name, defaults in GROUP_DEFAULT_KEYS.items()}

    output = copy.deepcopy(merged)
    # This is an actual direct outbound for the China choice in Mihomo's
    # GLOBAL selector. Rule-mode mainland rules still use built-in DIRECT.
    # FlClash has no profile-controlled description field. Its normal node
    # cards display two name lines, so put the refresh timestamp on line two.
    # Keep the China group identity stable so GLOBAL's direct selection can
    # survive later subscription refreshes even as this timestamp changes.
    refreshed_at = now.astimezone(SINGAPORE_TZ).strftime("%Y.%m.%d %H:%M:%S")
    direct_name = direct_label_for_country(direct_country) + "\n" + refreshed_at
    if direct_name in included_names:
        raise ValueError("direct outbound name collides with an existing route")
    generated.append({"name": direct_name, "type": "direct", "udp": True})
    output["proxies"] = generated
    output["proxy-groups"] = [
        # An explicitly defined GLOBAL follows this list's order in FlClash.
        {"name": GLOBAL, "type": "select",
         "proxies": [GOOGLE, HK, STREAMING, VPS, CHINA, OTHER],
         "default-selected": GOOGLE, "hidden": True},
        {"name": ALL, "type": "select",
         "proxies": [AUTO, GOOGLE, HK, STREAMING, VPS, OTHER]},
        {"name": GOOGLE, "type": "select", "proxies": group_members[GOOGLE],
         "default-selected": selected[GOOGLE]},
        {"name": HK, "type": "select", "proxies": group_members[HK],
         "default-selected": selected[HK]},
        {"name": STREAMING, "type": "select", "proxies": group_members[STREAMING],
         "default-selected": selected[STREAMING]},
        {"name": VPS, "type": "select", "proxies": group_members[VPS],
         "default-selected": selected[VPS]},
        {"name": OTHER, "type": "select", "proxies": group_members[OTHER],
         "default-selected": selected[OTHER]},
        {"name": CHINA, "type": "select", "proxies": [direct_name],
         "default-selected": direct_name, "hidden": True},
        # Mihomo supports hidden helper groups; a particular frontend may
        # still render this seventh technical group, so PC UI acceptance is
        # required before claiming the requested six visible groups.
        {"name": AUTO, "type": "select", "proxies": [OTHER], "hidden": True},
    ]

    # A provider's destination rules choose its own default path. The single
    # VPS selector cannot provide nine simultaneous per-destination defaults.
    provider_rules = []
    for provider, candidates in PROVIDER_DEFAULT_KEYS.items():
        preferred = _prioritized_keys(candidates, active)
        if not preferred:
            continue
        matches = provider_matches.get(provider)
        if not matches:
            raise ValueError("missing exact destination rules for provider: {}".format(provider))
        for match in matches:
            if not isinstance(match, ProviderMatch):
                raise ValueError("provider matches must be ProviderMatch objects")
            provider_rules.append(match.render(_label(preferred[0]), provider=provider))

    legacy_rules = _rewrite_legacy_rules(merged.get("rules") or [])
    # YouTube and Google must precede *all* broad entertainment/HK legacy
    # rules, not just GEOIP,HK. A GEOSITE,category-entertainment rule can
    # otherwise capture YouTube before its later service-specific rule.
    explicit_google = ["GEOSITE,youtube," + GOOGLE,
                       "GEOSITE,google," + GOOGLE,
                       "GEOSITE,category-ai-!cn," + GOOGLE] + [
        "DOMAIN-SUFFIX,{},{}".format(domain, GOOGLE)
        for domain in GOOGLE_DOMAIN_SUFFIXES + AI_DOMAIN_SUFFIXES
    ]
    legacy_rules = [rule for rule in legacy_rules if rule not in explicit_google]
    # Service-specific choices must precede the legacy HK and entertainment
    # rules. Otherwise Disney+ could be sent to HK merely because a service
    # address geolocates there. Keep Netflix in the HK group.
    streaming_rules = [
        "DOMAIN-SUFFIX,{},{}".format(domain, HK)
        for domain in NETFLIX_DOMAIN_SUFFIXES
    ] + ["GEOSITE,netflix," + HK] + [
        "DOMAIN-SUFFIX,{},{}".format(domain, STREAMING)
        for domain in DISNEY_PLUS_DOMAIN_SUFFIXES
    ]
    # The old category-entertainment rule covers more than HK services. Keep
    # explicit HK service rules and mainland DIRECT ahead of it. Place it
    # before broad GEOIP rules: a foreign streaming service can otherwise be
    # captured by GEOIP,HK merely because its CDN happens to be in Hong Kong.
    # The real raw merger may omit this category entirely. Emit one canonical
    # rule regardless of source presence, collapsing any legacy duplicates.
    broad_entertainment = ["GEOSITE,category-entertainment," + STREAMING]
    legacy_rules = [rule for rule in legacy_rules
                    if rule not in broad_entertainment]
    # An existing source can put an HK-specific rule after GEOIP. Pull those
    # narrow matches before the first GEOIP without changing their own order.
    # Do not move a GEOIP rule, even if its target is the HK selector.
    hk_specific = [rule for rule in legacy_rules
                   if not rule.startswith("GEOIP,") and
                   rule.split(",")[_target_index(rule.split(","))] == HK]
    legacy_rules = [rule for rule in legacy_rules if rule not in hk_specific]
    # Keep narrow HK service/domain matches, then mainland domain and IP
    # DIRECT, then foreign entertainment, and only then broad GEOIP. A
    # mainland hostname must not be captured by GEOIP,HK.
    cn_direct = ("GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT")
    legacy_rules = [rule for rule in legacy_rules if rule not in cn_direct]
    first_geoip = next((index for index, rule in enumerate(legacy_rules)
                        if rule.startswith("GEOIP,")), None)
    if first_geoip is None:
        first_geoip = legacy_rules.index("MATCH," + ALL)
    legacy_rules[first_geoip:first_geoip] = (
        hk_specific + list(cn_direct) + broad_entertainment)
    output["rules"] = explicit_google + streaming_rules + provider_rules + legacy_rules
    output["mode"] = "rule"
    output["ipv6"] = False
    output["dns"] = _safe_dns(merged.get("dns"))
    tun = output.get("tun")
    if isinstance(tun, dict) and tun.get("enable"):
        hijack = tun.get("dns-hijack")
        if not isinstance(hijack, list) or not all(isinstance(item, str)
                                                  for item in hijack):
            raise ValueError("enabled TUN needs an explicit DNS hijack list")
        if "any:53" not in hijack:
            hijack.append("any:53")
        if "tcp://any:53" not in hijack:
            hijack.append("tcp://any:53")
    return output

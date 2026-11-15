"""Exact-host destination correction after sniff and before resolve.

sing-box 1.14.3 sniff only supplies domain metadata for an IP destination.
These rules deliberately repeat a known *complete hostname* as override_address.
They do not rewrite arbitrary subdomains to a parent and do not claim to fix
unknown hosts, hidden SNI/ECH, or traffic without a sniffable hostname.
"""
import copy
import re


EXACT_SERVICE_DOMAINS = (
    "chatgpt.com", "www.chatgpt.com", "chat.openai.com", "api.openai.com",
    "auth.openai.com", "platform.openai.com",
    "claude.ai", "www.claude.ai", "api.anthropic.com", "console.anthropic.com",
    "www.google.com", "google.com", "accounts.google.com",
    "gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
    "www.youtube.com", "youtube.com", "m.youtube.com", "music.youtube.com",
    "youtubei.googleapis.com", "www.netflix.com", "netflix.com", "api.netflix.com",
    "www.disneyplus.com", "disneyplus.com",
    "www.mytvsuper.com", "mytvsuper.com", "www.tvb.com", "tvb.com",
    "www.viu.com", "viu.com", "www.viu.tv", "viu.tv",
    "www.binance.com", "binance.com", "accounts.binance.com", "api.binance.com",
)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _domains(domains):
    if isinstance(domains, (str, bytes)):
        raise ValueError("exact domains must be a list of complete hostnames")
    result = list(domains)
    if not result or len(result) != len(set(result)):
        raise ValueError("exact domains must be nonempty and unique")
    for name in result:
        if not isinstance(name, str) or len(name) > 253:
            raise ValueError("invalid exact service hostname")
        labels = name.split(".")
        if len(labels) < 2 or not all(_LABEL.fullmatch(label) for label in labels):
            raise ValueError("exact service hostname must be normalized DNS name")
        if all(label.isdigit() for label in labels):
            raise ValueError("IP literals cannot be exact service hostnames")
    return result


def _inbounds(inbounds):
    if inbounds is None:
        return None
    if isinstance(inbounds, (str, bytes)):
        raise ValueError("inbound scope must be a list of tags")
    result = list(inbounds)
    if not result or len(result) != len(set(result)):
        raise ValueError("inbound scope must be nonempty and unique")
    if any(not isinstance(tag, str) or not tag.strip() for tag in result):
        raise ValueError("invalid inbound tag")
    return result


def build_exact_domain_overrides(inbounds=None, domains=EXACT_SERVICE_DOMAINS):
    """Build non-final correction actions; caller places them after sniff.

    Scope to managed public inbounds in production. This helper does not add
    resolving, final routing, protocol rejection, or any DNS/outbound endpoint.
    """
    names, scope = _domains(domains), _inbounds(inbounds)
    result = []
    for name in names:
        rule = {"domain": [name], "action": "route-options", "override_address": name}
        if scope is not None:
            rule["inbound"] = list(scope)
        result.append(rule)
    return result


def validate_exact_domain_overrides(rules, inbounds=None, domains=EXACT_SERVICE_DOMAINS):
    """Require exactly the generated allowlist; reject broadened matching."""
    if rules != build_exact_domain_overrides(inbounds=inbounds, domains=domains):
        raise ValueError("exact-host destination overrides differ from approved allowlist")
    return True


def inject_exact_domain_overrides(rules, inbounds, domains=EXACT_SERVICE_DOMAINS):
    """Copy rules and insert immediately after one sniff, before first resolve.

    This intentionally fails on an ambiguous policy rather than moving guards
    or rewriting an existing action. Root integration may instead use build().
    """
    if not isinstance(rules, list):
        raise ValueError("route rules must be a list")
    sniff = [index for index, item in enumerate(rules) if item.get("action") == "sniff"]
    resolves = [index for index, item in enumerate(rules) if item.get("action") == "resolve"]
    if len(sniff) != 1 or not resolves or sniff[0] >= resolves[0]:
        raise ValueError("one sniff action must precede the first resolve action")
    if any("override_address" in item for item in rules[sniff[0] + 1:resolves[0]]):
        raise ValueError("destination correction already present before resolve")
    output = copy.deepcopy(rules)
    output[sniff[0] + 1:sniff[0] + 1] = build_exact_domain_overrides(inbounds, domains)
    return output

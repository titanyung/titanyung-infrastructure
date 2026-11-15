"""Apply dated service retirement to a generated Clash subscription.

The caller supplies explicit dependencies for the nodes, groups, and rules it
creates. Names are opaque identifiers: a service name appearing in a user's
own node name never makes that node eligible for deletion.

This module does not change any server, service, or dashboard history. Call it
on every subscription generation so the boundary takes effect at the first
request on or after its Asia/Singapore cutoff, without a timer or cached YAML.
"""

from __future__ import annotations

import copy
from datetime import date, datetime, time, timedelta, timezone
from typing import Dict, FrozenSet, Iterable, Mapping, Optional, Set


# Singapore has no daylight-saving transition at any of these expiry dates.
# A named fixed-offset tzinfo also works on the server's Python 3.8 runtime.
SINGAPORE_TZ = timezone(timedelta(hours=8), "Asia/Singapore")

SERVICE_EXPIRY_DATES = {
    "gomami": date(2026, 10, 22),
    "bwh": date(2026, 11, 24),
    "proxyhive": datetime(2026, 10, 28, 22, 27, 54, tzinfo=SINGAPORE_TZ),
    "lazycat_hkt": date(2026, 11, 17),
    "kookey": date(2027, 1, 15),
    "ip2up": datetime(2026, 11, 23, 7, 28, 51, tzinfo=SINGAPORE_TZ),
    # Provider's Hong Kong ordinary-optimized VPS was retired early after
    # the user's refund registration; the old contract date no longer applies.
    "nosla": date(2026, 10, 22),
}

# SG remains a known dependency even though it no longer has an expiry.
PERMANENT_SERVICES = frozenset({"lazycat_sg"})

BUILTIN_TARGETS = frozenset({"DIRECT", "REJECT", "REJECT-DROP", "PASS"})


def service_expires_at(service: str) -> datetime:
    """Normalize a date or precise aware instant to a Singapore cutoff."""
    value = SERVICE_EXPIRY_DATES[service]
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("service expiry datetime must be timezone-aware")
        return value.astimezone(SINGAPORE_TZ)
    if type(value) is not date:
        raise ValueError("service expiry must be a date or aware datetime")
    return datetime.combine(value, time.min, SINGAPORE_TZ)


def expired_services(now: Optional[datetime] = None) -> FrozenSet[str]:
    """Return services past their Singapore-local cutoff.

    Inject ``now`` for tests. A supplied naive datetime is rejected rather
    than silently interpreted in the host's timezone.
    """

    if now is None:
        now = datetime.now(SINGAPORE_TZ)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    local_now = now.astimezone(SINGAPORE_TZ)
    return frozenset(
        service
        for service in SERVICE_EXPIRY_DATES
        if local_now >= service_expires_at(service)
    )


def _dependency_map(
    dependencies: Optional[Mapping[str, Iterable[str]]], label: str
) -> Dict[str, FrozenSet[str]]:
    result = {}
    for name, services in (dependencies or {}).items():
        if not isinstance(name, str) or not name:
            raise ValueError("{} keys must be nonempty strings".format(label))
        if isinstance(services, str):
            raise ValueError("{} for {!r} must be a collection".format(label, name))
        required = frozenset(services)
        unknown = required.difference(SERVICE_EXPIRY_DATES).difference(PERMANENT_SERVICES)
        if unknown:
            raise ValueError("{} for {!r} has unknown services: {}".format(
                label, name, ", ".join(sorted(unknown))
            ))
        result[name] = required
    return result


def _rule_target_index(parts):
    if len(parts) < 2:
        raise ValueError("invalid Clash rule")
    if parts[0] == "MATCH":
        return 1
    if parts[-1] == "no-resolve":
        if len(parts) < 3:
            raise ValueError("invalid Clash rule with no-resolve")
        return len(parts) - 2
    return len(parts) - 1


def apply_expiry_policy(
    config: dict,
    *,
    node_dependencies: Mapping[str, Iterable[str]],
    group_dependencies: Optional[Mapping[str, Iterable[str]]] = None,
    rule_dependencies: Optional[Mapping[str, Iterable[str]]] = None,
    rule_fallbacks: Optional[Mapping[str, str]] = None,
    now: Optional[datetime] = None,
) -> dict:
    """Return a retired-service-filtered copy of a generated Clash config.

    ``node_dependencies`` and ``group_dependencies`` map exact emitted names
    to every service in their real path. For example, a DMIT -> NoSLA -> HKT
    node declares ``{"nosla"}``; a BWH -> NoSLA node declares both ``{"bwh",
    "nosla"}``. The caller must register all managed paths; this function
    never guesses from names or addresses. Nodes using an expired dialer are
    additionally removed transitively.

    ``rule_dependencies`` maps exact emitted rule strings to services; such a
    rule is removed at expiry unless ``rule_fallbacks`` supplies an exact rule
    to surviving target mapping. Rules targeting a removed node/group without
    an explicit fallback cause an error, never a silent traffic reroute.

    A non-expiring group that would become empty also causes an error. This
    makes the caller provide stable defaults before publishing the result.
    Existing unrelated nodes and groups, including user-chosen names that
    happen to contain a service's name, are preserved.
    """

    if not isinstance(config, dict):
        raise ValueError("config must be a dictionary")
    node_deps = _dependency_map(node_dependencies, "node_dependencies")
    group_deps = _dependency_map(group_dependencies, "group_dependencies")
    rule_deps = _dependency_map(rule_dependencies, "rule_dependencies")
    fallbacks = dict(rule_fallbacks or {})
    if any(not isinstance(key, str) or not isinstance(value, str) or not value
           for key, value in fallbacks.items()):
        raise ValueError("rule_fallbacks must map exact rules to nonempty targets")

    expired = expired_services(now)
    result = copy.deepcopy(config)
    nodes = result.get("proxies", [])
    groups = result.get("proxy-groups", [])
    rules = result.get("rules", [])
    if not isinstance(nodes, list) or not isinstance(groups, list) or not isinstance(rules, list):
        raise ValueError("proxies, proxy-groups, and rules must be lists")

    removed_nodes: Set[str] = {
        name for name, services in node_deps.items() if services.intersection(expired)
    }
    removed_groups: Set[str] = {
        name for name, services in group_deps.items() if services.intersection(expired)
    }

    # A proxy whose dialer was retired cannot safely remain selectable. This
    # also handles indirect chains even when their names do not mention the
    # retired service.
    changed = True
    while changed:
        changed = False
        for node in nodes:
            if not isinstance(node, dict) or not isinstance(node.get("name"), str):
                raise ValueError("each proxy must have a string name")
            name = node["name"]
            if name not in removed_nodes and node.get("dialer-proxy") in (
                removed_nodes | removed_groups
            ):
                removed_nodes.add(name)
                changed = True
    result["proxies"] = [node for node in nodes if node["name"] not in removed_nodes]

    retained_groups = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("name"), str):
            raise ValueError("each proxy group must have a string name")
        if group["name"] in removed_groups:
            continue
        members = group.get("proxies")
        if members is not None:
            if not isinstance(members, list):
                raise ValueError("group proxies must be a list")
            group["proxies"] = [
                member for member in members
                if member not in removed_nodes and member not in removed_groups
            ]
            if members and not group["proxies"] and not group.get("use"):
                raise ValueError("expiry would empty group: {}".format(group["name"]))
        retained_groups.append(group)
    result["proxy-groups"] = retained_groups

    surviving_targets = (
        {node["name"] for node in result["proxies"]}
        | {group["name"] for group in retained_groups}
        | BUILTIN_TARGETS
    )
    retained_rules = []
    for rule in rules:
        if not isinstance(rule, str):
            raise ValueError("each Clash rule must be a string")
        retired_rule = bool(rule_deps.get(rule, frozenset()).intersection(expired))
        parts = rule.split(",")
        target_index = _rule_target_index(parts)
        target = parts[target_index]
        fallback = fallbacks.get(rule)
        if retired_rule or target in removed_nodes or target in removed_groups:
            if fallback is None:
                if retired_rule:
                    continue
                raise ValueError("rule targets retired node/group without fallback: {}".format(rule))
            if fallback not in surviving_targets:
                raise ValueError("rule fallback is unavailable: {}".format(fallback))
            parts[target_index] = fallback
            rule = ",".join(parts)
        retained_rules.append(rule)
    result["rules"] = retained_rules
    return result

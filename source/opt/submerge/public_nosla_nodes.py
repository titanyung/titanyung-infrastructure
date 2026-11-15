"""Pure production-candidate nodes for direct and chained NoSLA routes.

No service is changed by importing this module. The caller must separately
verify public first-hop services, load private maps as root, and bind these
source names to the three matching five-group semantic route keys.
"""

from __future__ import annotations

import hmac
from typing import Mapping


PUBLIC_IP = "216.23.117.226"
PUBLIC_PORT = 2450
TLS_SERVER_NAME = "nosla-hk.internal"
TLS_FINGERPRINT = (
    "83:3B:63:CD:42:88:BB:E3:19:30:FF:ED:DD:B9:C5:D5:"
    "82:36:6A:1D:0B:6A:83:62:D3:3F:F7:85:76:32:1F:12"
)
SOURCE_NAMES = {
    "vps_nosla": "__PUB-NoSLA-direct",
    "vps_dmit_nosla": "__PUB-DMIT-to-NoSLA-direct",
    "vps_bwh_nosla": "__PUB-BWH-to-NoSLA-direct",
}
FIRST_HOPS = {
    "vps_dmit_nosla": ("dmit", "179.255.136.79", 31117),
    "vps_bwh_nosla": ("bwh", "45.78.70.23", 31107),
}


def _cohort_password(service: str, sub_secret: str,
                     maps: Mapping[str, Mapping[str, str]],
                     ordinary: frozenset[str]) -> str:
    values = maps.get(service)
    if (not isinstance(values, Mapping) or sub_secret not in ordinary or
            not isinstance(values.get(sub_secret), str) or
            len(values[sub_secret]) < 24 or
            any(other != sub_secret and
                values.get(other) == values[sub_secret]
                for other in ordinary)):
        raise ValueError(service + "_credential_cohort_invalid")
    return values[sub_secret]


def build_public_nosla_sources(
    *, sub_secret: str, ordinary_sub_secrets: frozenset[str],
    credential_maps: Mapping[str, Mapping[str, str]],
    first_hop_nodes: Mapping[str, dict], active_keys: frozenset[str],
) -> dict[str, dict]:
    """Return only the active three NoSLA source nodes for one subscriber.

    `first_hop_nodes` keys are `dmit` and `bwh` when the corresponding chain
    is active. Those nodes must be *direct* public AnyTLS first hops, never a
    ByteVirt, HKT or proxy-routed legacy endpoint. Expired NoSLA routes may
    omit its credential map entirely: expiry removes subscription nodes only.
    """
    if not active_keys.issubset(SOURCE_NAMES):
        raise ValueError("unexpected_nosla_route_key")
    if not active_keys:
        return {}
    if (not isinstance(sub_secret, str) or not sub_secret or
            not isinstance(ordinary_sub_secrets, frozenset) or
            sub_secret not in ordinary_sub_secrets):
        raise ValueError("subscriber_not_in_ordinary_cohort")
    nosla_password = _cohort_password("nosla", sub_secret, credential_maps,
                                      ordinary_sub_secrets)
    result = {}
    for key in sorted(active_keys):
        node = {
            "name": SOURCE_NAMES[key], "type": "anytls",
            "server": PUBLIC_IP, "port": PUBLIC_PORT,
            "password": nosla_password, "sni": TLS_SERVER_NAME,
            "fingerprint": TLS_FINGERPRINT,
            "skip-cert-verify": True, "udp": False,
        }
        if key in FIRST_HOPS:
            service, expected_ip, expected_port = FIRST_HOPS[key]
            first = first_hop_nodes.get(service)
            first_password = _cohort_password(service, sub_secret,
                                              credential_maps,
                                              ordinary_sub_secrets)
            if (not isinstance(first, dict) or
                    first.get("type") != "anytls" or
                    first.get("server") != expected_ip or
                    first.get("port") != expected_port or
                    first.get("dialer-proxy") not in (None, "DIRECT") or
                    not isinstance(first.get("name"), str) or
                    not first["name"] or
                    not isinstance(first.get("password"), str) or
                    not hmac.compare_digest(first["password"], first_password)):
                raise ValueError(service + "_public_direct_first_hop_unverified")
            if hmac.compare_digest(first_password, nosla_password):
                raise ValueError("first_hop_reuses_nosla_credential")
            node["dialer-proxy"] = first["name"]
        result[key] = node
    return result

#!/usr/bin/env python3

import copy
import json
import os
import re
import ssl
import sys
import time
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

from client_country import country_from_request
from public_five_group_hook import apply_public_five_group


# ============================================================
# 配置
# ============================================================

SUI_URL_TEMPLATE = os.environ.get(
    "SUI_URL_TEMPLATE",
    "",
).strip()

BWH_TITANYUNG_URL = os.environ.get(
    "BWH_TITANYUNG_URL",
    "https://node.titanyungty.top:31878/sub/titanyung?format=clash",
).strip()

PAOLUZ_URL = os.environ.get(
    "PAOLUZ_URL",
    "",
).strip()

LISTEN_HOST = os.environ.get(
    "LISTEN_HOST",
    "127.0.0.1",
)

LISTEN_PORT = int(
    os.environ.get(
        "LISTEN_PORT",
        "18080",
    )
)


CACHE_DIR = "/var/lib/submerge"
HKT_USER_KEYS_FILE = os.environ.get(
    "HKT_USER_KEYS_FILE", "/etc/submerge/hkt-public-users.json"
)

PAOLUZ_CACHE_FILE = os.path.join(
    CACHE_DIR,
    "paoluz.yaml",
)

PAOLUZ_CACHE_TIME_FILE = os.path.join(
    CACHE_DIR,
    "paoluz.timestamp",
)


# 多台设备连续点更新时，
# 5秒内不重复轰Paoluz接口。
PAOLUZ_REFRESH_GUARD = 5

# 只有订阅所有者本人可以看到奶昔 / Paoluz 上游节点。
# Nginx 会先把 /sub/<用户名> 映射成 S-UI 的订阅 ID，
# 所以这里同时接受用户名和 titanyung 当前的订阅 ID。
PAOLUZ_ALLOWED_SUBIDS = {
    item.strip()
    for item in os.environ.get(
        "PAOLUZ_ALLOWED_SUBIDS",
        "titanyung,4ee2afda-32fb-42d9-9d71-986be785194b",
    ).split(",")
    if item.strip()
}

paoluz_lock = threading.Lock()


# ============================================================
# 基础工具
# ============================================================

def uniq(items):
    result = []
    seen = set()

    for item in items:
        if not item:
            continue

        if item in seen:
            continue

        seen.add(item)
        result.append(item)

    return result


def request_text(url, timeout=30):
    parsed_url = urllib.parse.urlparse(url)
    is_local_https = (
        parsed_url.scheme == "https"
        and parsed_url.hostname in {"127.0.0.1", "::1", "localhost"}
    )

    headers = {
        # 尽量让订阅服务返回Clash/Mihomo格式
        "User-Agent": "ClashMetaForAndroid/2.11.14.Meta",
        "Accept": "*/*",
        "Accept-Encoding": "identity",
    }

    if is_local_https:
        headers["Host"] = "dsub.titanyung.click"

    request = urllib.request.Request(
        url,
        headers=headers,
    )

    with urllib.request.urlopen(
        request,
        timeout=timeout,
        context=(
            ssl._create_unverified_context()
            if is_local_https
            else None
        ),
    ) as response:
        raw = response.read()

    return raw.decode(
        "utf-8",
        errors="replace",
    )


def parse_yaml(text, name):
    try:
        data = yaml.safe_load(text)
    except Exception as exc:
        raise RuntimeError(
            f"{name} YAML解析失败: {exc}"
        )

    if not isinstance(data, dict):
        raise RuntimeError(
            f"{name}不是Clash YAML配置"
        )

    return data


def atomic_write(path, content):
    temp_path = path + ".tmp"

    with open(
        temp_path,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(content)

    os.replace(
        temp_path,
        path,
    )


def read_timestamp(path):
    try:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:
            return float(
                file.read().strip()
            )
    except Exception:
        return 0.0


# ============================================================
# Paoluz更新
#
# 每次客户端请求merge订阅时：
#
# 1. 尝试更新Paoluz
# 2. 成功就用最新版本
# 3. 更新失败就使用最后一次成功缓存
#
# 所以以后：
#
# 登录Paoluz后台
# ↓
# FlClash/OpenClash点击更新订阅
# ↓
# 搬瓦工立即尝试同步Paoluz
# ============================================================

def get_paoluz_config(force=False):

    os.makedirs(
        CACHE_DIR,
        exist_ok=True,
    )

    with paoluz_lock:

        now = time.time()

        last_refresh = read_timestamp(
            PAOLUZ_CACHE_TIME_FILE
        )

        cache_exists = os.path.exists(
            PAOLUZ_CACHE_FILE
        )

        should_refresh = (
            force
            or not cache_exists
            or (
                now - last_refresh
                >= PAOLUZ_REFRESH_GUARD
            )
        )

        if should_refresh:

            try:
                text = request_text(
                    PAOLUZ_URL,
                    timeout=30,
                )

                config = parse_yaml(
                    text,
                    "Paoluz订阅",
                )

                proxies = (
                    config.get("proxies")
                    or []
                )

                groups = (
                    config.get(
                        "proxy-groups"
                    )
                    or []
                )

                providers = (
                    config.get(
                        "proxy-providers"
                    )
                    or {}
                )

                # 防止Paoluz授权失败时返回了一个
                # HTML错误页/空配置，却覆盖好缓存。
                if (
                    len(proxies) == 0
                    and len(groups) == 0
                    and len(providers) == 0
                ):
                    raise RuntimeError(
                        "Paoluz返回配置中没有任何节点或分组"
                    )

                atomic_write(
                    PAOLUZ_CACHE_FILE,
                    text,
                )

                atomic_write(
                    PAOLUZ_CACHE_TIME_FILE,
                    str(now),
                )

                print(
                    "[Paoluz] 在线更新成功",
                    file=sys.stderr,
                )

                return config

            except Exception as exc:

                print(
                    f"[Paoluz] 在线更新失败: {exc}",
                    file=sys.stderr,
                )

                if not cache_exists:
                    raise RuntimeError(
                        "Paoluz更新失败且没有可用缓存"
                    )

        # 使用最近一次成功缓存
        with open(
            PAOLUZ_CACHE_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            text = file.read()

        return parse_yaml(
            text,
            "Paoluz缓存",
        )


# ============================================================
# 名称
# ============================================================

BUILTIN_NAMES = {
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "COMPATIBLE",
}


def allocate_name(
    original,
    used_names,
    prefix="PAOLUZ | ",
):
    if original not in used_names:
        used_names.add(original)
        return original

    base = prefix + original

    candidate = base
    index = 2

    while candidate in used_names:
        candidate = (
            f"{base} #{index}"
        )
        index += 1

    used_names.add(candidate)

    return candidate


def safe_file_name(name):
    return re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        name,
    )


# ============================================================
# 保证S-UI自己的Proxy / Auto存在
#
# 注意：
# 这里只使用S-UI自己的节点，
# 不会把Paoluz节点混进Proxy。
#
# Proxy仍然代表：
#
# 客户端
# → 搬瓦工AnyTLS
# → S-UI
# → residential-out
# → 静态住宅IP
# ============================================================

def ensure_sui_groups(config):

    proxies = (
        config.get("proxies")
        or []
    )

    groups = (
        config.get("proxy-groups")
        or []
    )

    sui_proxy_names = [
        proxy.get("name")
        for proxy in proxies
        if (
            isinstance(proxy, dict)
            and proxy.get("name")
        )
    ]

    existing_group_names = {
        group.get("name")
        for group in groups
        if (
            isinstance(group, dict)
            and group.get("name")
        )
    }


    if (
        "Auto"
        not in existing_group_names
        and sui_proxy_names
    ):
        groups.append(
            {
                "name": "Auto",
                "type": "url-test",
                "proxies": sui_proxy_names,
                "url":
                    "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
            }
        )


    existing_group_names = {
        group.get("name")
        for group in groups
        if (
            isinstance(group, dict)
            and group.get("name")
        )
    }


    if "Proxy" not in existing_group_names:

        members = []

        if "Auto" in existing_group_names:
            members.append("Auto")

        members.extend(
            sui_proxy_names
        )

        if not members:
            members = ["DIRECT"]

        groups.append(
            {
                "name": "Proxy",
                "type": "select",
                "proxies": uniq(members),
            }
        )


    config["proxy-groups"] = groups


# ============================================================
# 合并
# ============================================================


# ============================================================
# SUBMERGE_ROUTE_ADMIN_LOADER
#
# 图形化分流后台规则
# ============================================================

ROUTE_RULE_FILE = "/var/lib/submerge/route_rules.json"


def load_route_admin_rules(target_aliases=None):

    target_aliases = target_aliases or {}

    try:

        with open(
            ROUTE_RULE_FILE,
            "r",
            encoding="utf-8",
        ) as f:
            data = json.load(f)

    except Exception as exc:

        print(
            "[route-admin] 读取失败:",
            exc,
            file=sys.stderr,
        )

        return []


    rules = data.get("rules", [])

    if not isinstance(rules, list):
        return []


    enabled = [
        r
        for r in rules
        if (
            isinstance(r, dict)
            and r.get("enabled", True)
        )
    ]


    enabled.sort(
        key=lambda r: int(
            r.get("priority", 9999)
        )
    )


    result = []


    for r in enabled:

        rule_type = str(
            r.get("type", "")
        ).strip()

        value = str(
            r.get("value", "")
        ).strip()

        target = str(
            r.get("target", "")
        ).strip()

        target = target_aliases.get(
            target,
            target,
        )

        extra = str(
            r.get("extra", "")
        ).strip()


        if not rule_type:
            continue

        if not target:
            continue


        # MATCH特殊格式
        if rule_type == "MATCH":

            result.append(
                f"MATCH,{target}"
            )

            continue


        if not value:
            continue


        rule = (
            f"{rule_type},"
            f"{value},"
            f"{target}"
        )


        if extra:

            rule += (
                ","
                + extra
            )


        result.append(rule)


    return result


def merge_configs(
    sui_config,
    paoluz_config,
    include_paoluz=True,
    bwh_config=None,
    hkt_public_password=None,
):
    # ========================================================
    # 核心：
    # Paoluz完整原配置作为底座。
    #
    # 不再人工修改：
    # - Paoluz节点参数
    # - dialer-proxy
    # - DNS
    # - hosts
    # - proxy-server-nameserver
    #
    # 从而让合并后的Paoluz尽量与单独使用Paoluz完全一致。
    # ========================================================

    if include_paoluz:
        output = copy.deepcopy(paoluz_config)
    else:
        # 其他用户只保留自己 S-UI 订阅里的通用设置，
        # 节点和策略组在下方重新生成，避免夹带任何上游内容。
        output = copy.deepcopy(sui_config)
        output["proxies"] = []
        output["proxy-groups"] = []
        output["rules"] = []

    if not isinstance(output.get("proxies"), list):
        output["proxies"] = []

    if not isinstance(output.get("proxy-groups"), list):
        output["proxy-groups"] = []


    # ========================================================
    # S-UI自己的搬瓦工节点
    # ========================================================

    sui_proxies = sui_config.get("proxies") or []

    existing_names = {
        p.get("name")
        for p in output["proxies"]
        if isinstance(p, dict) and p.get("name")
    }

    # 这里的 sui_config 来自 DMIT 上的 S-UI。
    # 保留变量分离，避免把新加坡节点误标成搬瓦工。
    bwh_nodes = []
    trial_node_name = "DMIT→proxyhive.io（测试）"
    lazycat_node_name = "DMIT→LAZYCAT（测试）"
    hkt_node_name = "DMIT→LazyCat HKT"
    old_group_name = "DMIT→kookey（2027-01-15 01:42到期）"
    trial_nodes = []
    lazycat_nodes = []
    hkt_nodes = []

    for proxy in sui_proxies:
        if not isinstance(proxy, dict):
            continue

        old_name = proxy.get("name")

        if not old_name:
            continue

        if str(proxy.get("type", "")).lower() == "anytls" and str(proxy.get("port")) == "29504":
            if lazycat_nodes or lazycat_node_name in existing_names:
                raise ValueError("Duplicate Lazycat trial node")
            lazycat_proxy = copy.deepcopy(proxy)
            lazycat_proxy["name"] = lazycat_node_name
            lazycat_proxy["dialer-proxy"] = "DIRECT"
            lazycat_proxy["udp"] = True
            output["proxies"].append(lazycat_proxy)
            existing_names.add(lazycat_node_name)
            lazycat_nodes.append(lazycat_node_name)
            continue

        if str(proxy.get("type", "")).lower() == "anytls" and str(proxy.get("port")) == "29505":
            if hkt_nodes or hkt_node_name in existing_names:
                raise ValueError("Duplicate HKT node")
            hkt_proxy = copy.deepcopy(proxy)
            hkt_proxy["name"] = hkt_node_name
            hkt_proxy["dialer-proxy"] = "DIRECT"
            hkt_proxy["udp"] = True
            output["proxies"].append(hkt_proxy)
            existing_names.add(hkt_node_name)
            hkt_nodes.append(hkt_node_name)
            continue

        # A separate AnyTLS listener is required: renaming the ordinary DMIT
        # node would still select the old residential-out on the server.
        if str(proxy.get("type", "")).lower() == "anytls" and str(proxy.get("port")) == "29503":
            if trial_nodes or trial_node_name in existing_names:
                raise ValueError("Duplicate Singapore static-IP trial node")
            trial_proxy = copy.deepcopy(proxy)
            trial_proxy["name"] = trial_node_name
            trial_proxy["dialer-proxy"] = "DIRECT"
            # The upstream static-IP service is HTTP CONNECT and cannot relay UDP.
            trial_proxy["udp"] = False
            output["proxies"].append(trial_proxy)
            existing_names.add(trial_node_name)
            trial_nodes.append(trial_node_name)
            continue

        new_name = (
            old_group_name + "-节点"
            if not bwh_nodes
            else f"{old_group_name}-节点-{len(bwh_nodes) + 1}"
        )

        new_proxy = copy.deepcopy(proxy)
        new_proxy["name"] = new_name

        # ====================================================
        # S-UI / 搬瓦工节点必须直接建立连接
        #
        # 客户端
        # → DIRECT连接搬瓦工AnyTLS
        # → 搬瓦工S-UI
        # → residential-out
        # → 静态住宅IP
        #
        # 这里只影响BWH节点，不影响Paoluz。
        # ====================================================

        new_proxy["dialer-proxy"] = "DIRECT"

        output["proxies"].append(new_proxy)

        existing_names.add(new_name)
        bwh_nodes.append(new_name)

    if not bwh_nodes:
        bwh_nodes = ["DIRECT"]

    # Keep the expiring Singapore VPS selectable after node/sub DNS moves to
    # DMIT. All nine current users have the same AnyTLS password on both VPSes.
    # Pin the former server by IP, retaining its TLS name so DNS cutover cannot
    # silently turn this choice back into a DMIT connection.
    gomami_node_name = "GoMami-新加坡-10.22到期"
    gomami_source = next(
        (p for p in sui_proxies if isinstance(p, dict)
         and str(p.get("type", "")).lower() == "anytls"
         and str(p.get("port")) not in ("29503", "29504", "29505")), None
    )
    if gomami_source is None:
        gomami_source = next(
            (p for p in sui_proxies if isinstance(p, dict)
             and str(p.get("type", "")).lower() == "anytls"), None
        )
    if gomami_source is None:
        raise ValueError("GoMami fallback requires an AnyTLS source node")
    gomami_proxy = copy.deepcopy(gomami_source)
    gomami_proxy.update({
        "name": gomami_node_name,
        "server": "103.26.8.100",
        "port": 443,
        "sni": "node.titanyung.click",
        "skip-cert-verify": False,
        "dialer-proxy": "DIRECT",
    })
    output["proxies"] = [
        p for p in output["proxies"]
        if not (isinstance(p, dict) and p.get("name") == gomami_node_name)
    ]
    output["proxies"].append(gomami_proxy)

    # DMIT's server routes Hong Kong destinations directly to ByteVirt HK ISP.
    dmit_hk_node_name = "DMIT→ByteVirt香港ISP"
    dmit_hk_proxy = copy.deepcopy(gomami_source)
    dmit_hk_proxy["name"] = dmit_hk_node_name
    dmit_hk_proxy["dialer-proxy"] = "DIRECT"
    output["proxies"] = [
        p for p in output["proxies"]
        if not (isinstance(p, dict) and p.get("name") == dmit_hk_node_name)
    ]
    output["proxies"].append(dmit_hk_proxy)

    # 搬瓦工 LA 仅作为所有用户都能手动选择的备用节点。
    # 认证参数直接来自搬瓦工自身订阅，不参与任何自动分流。
    bwhla_nodes = []
    for proxy in (bwh_config or {}).get("proxies", []):
        if not isinstance(proxy, dict):
            continue
        old_name = proxy.get("name")
        if not old_name:
            continue
        new_name = (
            "备用-LA"
            if not bwhla_nodes
            else f"备用-LA-{len(bwhla_nodes) + 1}"
        )
        new_proxy = copy.deepcopy(proxy)
        new_proxy["name"] = new_name
        new_proxy["dialer-proxy"] = "DIRECT"
        output["proxies"].append(new_proxy)
        bwhla_nodes.append(new_name)


    # ========================================================
    # ByteVirt香港ISP节点（经NoSLA香港中转）
    #
    # 复用当前订阅用户自己的AnyTLS认证信息，只替换连接入口。
    # 实际链路：客户端 -> NoSLA香港 -> ByteVirt香港ISP。
    # ========================================================

    hk_isp_node_name = "NoSLA→ByteVirt香港ISP"
    bwh_hk_node_name = "BWH→ByteVirt香港ISP（11.22到期）"
    gomami_hk_node_name = "GoMami→ByteVirt香港ISP（10.22到期）"
    dmit_nosla_bytevirt_node_name = "DMIT→NoSLA→ByteVirt香港ISP"
    bwh_nosla_bytevirt_node_name = "BWH→NoSLA→ByteVirt香港ISP"
    gomami_nosla_bytevirt_node_name = "GoMami→NoSLA→ByteVirt香港ISP"
    hk_isp_proxy = None

    for proxy in sui_proxies:
        if (
            isinstance(proxy, dict)
            and str(proxy.get("type", "")).lower() == "anytls"
        ):
            hk_isp_proxy = copy.deepcopy(proxy)
            break

    if hk_isp_proxy is not None:
        hk_isp_proxy["name"] = hk_isp_node_name
        hk_isp_proxy["server"] = "216.23.117.226"
        hk_isp_proxy["port"] = 2443
        hk_isp_proxy["tls"] = True
        hk_isp_proxy["sni"] = "hk.titanyung.internal"
        hk_isp_proxy["skip-cert-verify"] = True
        hk_isp_proxy["dialer-proxy"] = "DIRECT"

        output["proxies"] = [
            p
            for p in output["proxies"]
            if not (
                isinstance(p, dict)
                and p.get("name") == hk_isp_node_name
            )
        ]
        output["proxies"].append(hk_isp_proxy)

        bwh_hk_proxy = copy.deepcopy(hk_isp_proxy)
        bwh_hk_proxy["name"] = bwh_hk_node_name
        bwh_hk_proxy["server"] = "45.78.70.23"
        bwh_hk_proxy["port"] = 2445
        output["proxies"] = [
            p for p in output["proxies"]
            if not (isinstance(p, dict) and p.get("name") == bwh_hk_node_name)
        ]
        output["proxies"].append(bwh_hk_proxy)

        # Mihomo dials ByteVirt through the already authenticated GoMami
        # AnyTLS node. This is a real two-hop chain, without a new listener
        # or redirect on the expiring GoMami server.
        gomami_hk_proxy = copy.deepcopy(hk_isp_proxy)
        gomami_hk_proxy["name"] = gomami_hk_node_name
        gomami_hk_proxy["server"] = "61.15.36.199"
        gomami_hk_proxy["port"] = 2443
        gomami_hk_proxy["dialer-proxy"] = gomami_node_name
        output["proxies"] = [
            p for p in output["proxies"]
            if not (isinstance(p, dict) and p.get("name") == gomami_hk_node_name)
        ]
        output["proxies"].append(gomami_hk_proxy)

        # These point at NoSLA itself. DMIT's dedicated TCP socket relay
        # avoids the existing DMIT HK listener, which first visits ByteVirt.
        for name, server, port, dialer in ((
            (dmit_nosla_bytevirt_node_name, "179.255.136.79", 31103, "DIRECT"),
            (bwh_nosla_bytevirt_node_name, "45.78.70.23", 31105, "DIRECT"),
            (gomami_nosla_bytevirt_node_name, "216.23.117.226", 2443,
             gomami_node_name),
        ) if hkt_public_password else ()):
            relay = copy.deepcopy(hk_isp_proxy)
            relay.update({"name": name, "server": server, "port": port,
                          "dialer-proxy": dialer})
            output["proxies"] = [p for p in output["proxies"]
                                 if not (isinstance(p, dict) and p.get("name") == name)]
            output["proxies"].append(relay)

    if hk_isp_proxy is None:
        raise ValueError("Hong Kong relay node is unavailable; refusing a direct fallback")

    # Separate, per-user HKT public ingress. The existing DMIT private tunnel
    # uses a different listener/key, so publishing these nodes cannot disclose
    # its server-side transport credential.
    gomami_hkt_node_name = "GoMami→LazyCat HKT"
    bwh_hkt_node_name = "BWH→LazyCat HKT"
    nosla_hkt_node_name = "NoSLA→LazyCat HKT"
    gomami_nosla_hkt_node_name = "GoMami→NoSLA→LazyCat HKT"
    bwh_nosla_hkt_node_name = "BWH→NoSLA→LazyCat HKT"
    dmit_nosla_hkt_node_name = "DMIT→NoSLA→LazyCat HKT"
    dmit_bytevirt_nosla_hkt_node_name = "DMIT→ByteVirt→NoSLA→LazyCat HKT"
    bwh_bytevirt_nosla_hkt_node_name = "BWH→ByteVirt→NoSLA→LazyCat HKT"
    if hkt_public_password:
        hkt_base = {
            "type": "ss",
            "server": "149.104.4.71",
            "port": 31101,
            "cipher": "2022-blake3-aes-128-gcm",
            "password": hkt_public_password,
            "udp": False,
        }
        hkt_choices = (
            (gomami_hkt_node_name, "149.104.4.71", 31101, gomami_node_name),
            (bwh_hkt_node_name, "45.78.70.23", 31104, "DIRECT"),
            (nosla_hkt_node_name, "216.23.117.226", 2446, "DIRECT"),
            (gomami_nosla_hkt_node_name, "216.23.117.226", 2446, gomami_node_name),
            (bwh_nosla_hkt_node_name, "45.78.70.23", 31106, "DIRECT"),
            (dmit_nosla_hkt_node_name, "179.255.136.79", 31102, "DIRECT"),
            # Source counters prove these existing HK first hops reach NoSLA
            # via ByteVirt. Keep the extra hop visible in their labels.
            (dmit_bytevirt_nosla_hkt_node_name, "216.23.117.226", 2446, dmit_hk_node_name),
            (bwh_bytevirt_nosla_hkt_node_name, "216.23.117.226", 2446, bwh_hk_node_name),
        )
        output["proxies"] = [p for p in output["proxies"]
                             if not (isinstance(p, dict) and p.get("name") in
                                     {choice[0] for choice in hkt_choices})]
        for name, server, port, dialer in hkt_choices:
            hkt_proxy = copy.deepcopy(hkt_base)
            hkt_proxy.update({"name": name, "server": server, "port": port,
                              "dialer-proxy": dialer})
            output["proxies"].append(hkt_proxy)
    output["proxies"] = [
        p for p in output["proxies"]
        if not (isinstance(p, dict) and p.get("name") in {
            "大陆-TVB-节点", "秋天的第一只小鸡 - bytevir的香港ISP",
            "搬瓦工→ByteVirt香港ISP（测试）",
        })
    ]


    # ========================================================
    # 删除我们自己以前创建的同名组
    # Paoluz自己的其他原始组全部保留
    # ========================================================

    output["proxy-groups"] = [
        g
        for g in output["proxy-groups"]
        if (
            not isinstance(g, dict)
            or g.get("name") not in {
                "Proxy",
                "Auto",
                "HK",
                "HK-Optimized",
                "Paoluz-HK",
                "Paoluz-All",
                "全部节点",
                "DMIT-静态IP",
                "DMIT→kookey（2027-01-15 01:42到期）",
                "gomamiSG",
                "BWH",
                "AI工具",
                "ByteVirt新加坡机房",
                "香港三网优化",
                "ByteVirt香港ISP",
                "大陆-TVB",
                "解锁TVB",
                "大陆-TVB→解锁TVB",
                "BWHLA",
                "备用-BWHLA",
                "美新就近",
                "奶昔全部节点",
                "Paoluz全部节点",
            }
        )
    ]


    # ========================================================
    # 搬瓦工 Auto / Proxy
    # ========================================================

    auto_group = {
        "name": "Auto",
        "type": "url-test",
        "proxies": bwh_nodes,
        "url": "https://www.gstatic.com/generate_204",
        "interval": 300,
        "tolerance": 50,
    }

    proxy_group = {
        "name": "Proxy",
        "type": "select",
        "proxies": ["Auto"] + bwh_nodes,
    }

    hk_isp_group = {
        "name": "HK",
        "type": "select",
        "proxies": ["大陆-TVB→解锁TVB"],
    }

    nosla_hk_group = {
        "name": "HK-Optimized",
        "type": "select",
        "proxies": ["大陆-TVB→解锁TVB"],
    }


    # ========================================================
    # Paoluz香港节点
    # 直接引用Paoluz原始节点，不复制、不改参数
    # ========================================================

    hk_regex = re.compile(
        r"香港|"
        r"\bHK\b|"
        r"Hong\s*Kong|"
        r"HongKong",
        re.IGNORECASE,
    )

    hk_nodes = []
    paoluz_nodes = []

    for proxy in paoluz_config.get("proxies", []):
        if not isinstance(proxy, dict):
            continue

        name = proxy.get("name")

        if not name:
            continue

        paoluz_nodes.append(name)

        if hk_regex.search(name):
            hk_nodes.append(name)

    hk_nodes = uniq(hk_nodes)
    paoluz_nodes = uniq(paoluz_nodes)

    hk_group = {
        "name": "Paoluz-HK",
        "type": "select",
        "proxies": hk_nodes if hk_nodes else ["DIRECT"],
    }

    all_group = {
        "name": "Paoluz-All",
        "type": "select",
        "proxies": paoluz_nodes if paoluz_nodes else ["DIRECT"],
    }

    # ========================================================
    # 用户可见的总入口
    #
    # 全部节点
    # ├─ DMIT→kookey（2027-01-15 01:42到期）
    # ├─ DMIT→proxyhive.io（测试，手动选择）
    # ├─ GoMami-新加坡-10.22到期（原服务器 IP 直连，手动备用）
    # ├─ 备用-BWHLA（手动备用，不参与自动分流）
    # ├─ 四条香港入口（NoSLA 为默认，其余可手选）
    # ├─ 大陆-TVB（兼容旧组名，同样经 NoSLA 中转）
    # ├─ 奶昔全部节点（上游原生总组）
    # └─ Paoluz全部节点（原始节点全集）
    # ========================================================

    existing_upstream_groups = {
        g.get("name")
        for g in output["proxy-groups"]
        if isinstance(g, dict) and g.get("name")
    }
    milkshake_source = (
        "🦊 PAOLUZ"
        if "🦊 PAOLUZ" in existing_upstream_groups
        else "Paoluz-All"
    )

    bwh_visible_group = {
        "name": "备用-BWHLA",
        "type": "select",
        "proxies": bwhla_nodes or ["DIRECT"],
    }
    dmit_static_group = {
        "name": old_group_name,
        "type": "select",
        "proxies": bwh_nodes,
    }
    bwh_choice_group = {
        "name": "BWH",
        "type": "select",
        "proxies": bwhla_nodes,
    }
    ai_group = {
        "name": "AI工具",
        "type": "select",
        # AI follows the client's overall non-CN/non-HK choice, including trial.
        "proxies": ["全部节点"],
    }
    nosla_visible_group = {
        "name": "大陆-TVB",
        "type": "select",
        "proxies": ["HK-Optimized"],
    }
    hk_isp_visible_group = {
        "name": "大陆-TVB→解锁TVB",
        "type": "select",
        "proxies": (
            [hkt_node_name, dmit_hk_node_name, hk_isp_node_name,
             bwh_hk_node_name, gomami_hk_node_name,
            *([gomami_hkt_node_name, bwh_hkt_node_name, nosla_hkt_node_name,
                gomami_nosla_hkt_node_name,
                bwh_nosla_hkt_node_name,
                dmit_nosla_hkt_node_name,
                dmit_nosla_bytevirt_node_name,
                bwh_nosla_bytevirt_node_name,
                gomami_nosla_bytevirt_node_name,
                dmit_bytevirt_nosla_hkt_node_name,
                bwh_bytevirt_nosla_hkt_node_name]
               if hkt_public_password else [])]
            if hkt_nodes else
            [hk_isp_node_name, dmit_hk_node_name,
             bwh_hk_node_name, gomami_hk_node_name,
             *([gomami_hkt_node_name, bwh_hkt_node_name, nosla_hkt_node_name,
                gomami_nosla_hkt_node_name,
                bwh_nosla_hkt_node_name,
                dmit_nosla_hkt_node_name,
                dmit_nosla_bytevirt_node_name,
                bwh_nosla_bytevirt_node_name,
                gomami_nosla_bytevirt_node_name,
                dmit_bytevirt_nosla_hkt_node_name,
                bwh_bytevirt_nosla_hkt_node_name]
               if hkt_public_password else [])]
        ),
    }
    optional_upstream_groups = []
    optional_upstream_entries = []

    if include_paoluz:
        optional_upstream_groups = [
            {
                "name": "奶昔",
                "type": "select",
                "proxies": [milkshake_source],
            },
            {
                "name": "paoluz",
                "type": "select",
                "proxies": ["Paoluz-All"],
            },
        ]
        optional_upstream_entries = [
            "奶昔",
            "paoluz",
        ]

    all_nodes_group = {
        "name": "全部节点",
        "type": "select",
        "proxies": [
            *lazycat_nodes,
            old_group_name,
            *trial_nodes,
            gomami_node_name,
            *(["备用-BWHLA"] if bwhla_nodes else []),
            *hkt_nodes,
            hk_isp_node_name,
            dmit_hk_node_name,
            bwh_hk_node_name,
            gomami_hk_node_name,
            "大陆-TVB→解锁TVB",
            "大陆-TVB",
            *optional_upstream_entries,
        ],
    }


    # ========================================================
    # 策略组
    # ========================================================

    output["proxy-groups"] = [
        all_nodes_group,
        ai_group,
        dmit_static_group,
        *([bwh_choice_group] if bwhla_nodes else []),
        *([bwh_visible_group] if bwhla_nodes else []),
        hk_isp_visible_group,
        nosla_visible_group,
        *optional_upstream_groups,
        auto_group,
        proxy_group,
        nosla_hk_group,
        hk_isp_group,
        *([hk_group, all_group] if include_paoluz else []),
        *output["proxy-groups"],
    ]


    # ========================================================
    # 分流
    # ========================================================

    output["mode"] = "rule"
    output["ipv6"] = False

    rule_target_aliases = {
        "Paoluz-HK": "大陆-TVB→解锁TVB",
        "HK": "大陆-TVB→解锁TVB",
        "HK-Optimized": "大陆-TVB",
        "欧美线路": "全部节点",
        "Proxy": "全部节点",
        "IP测试-新加坡": "全部节点",
        "IP测试-国际B": "全部节点",
        "BWHLA": "全部节点",
        "备用-BWHLA": "全部节点",
        "美新就近": "全部节点",
        "解锁TVB": "大陆-TVB→解锁TVB",
        "ByteVirt新加坡机房": "全部节点",
        "DMIT-静态IP": old_group_name,
        "GoMami新加坡机房": old_group_name,
        "gomamiSG": old_group_name,
    }

    if not include_paoluz:
        # 这些策略组来自奶昔 / Paoluz 上游。普通用户看不到上游组时，
        # 必须把规则目标换成现有的自建线路，否则 Clash 会拒绝加载配置。
        # 普通用户不包含搬瓦工、奶昔或 Paoluz；所有旧目标都映射
        # 到仍然存在的自建策略组，保证配置可被客户端加载。
        rule_target_aliases.update({
            "奶昔": "全部节点",
            "paoluz": "全部节点",
        })

    output["rules"] = load_route_admin_rules(
        target_aliases=rule_target_aliases,
    )

    return output


class MergeHandler(
    BaseHTTPRequestHandler
):

    def do_GET(self):

        parsed = urllib.parse.urlparse(
            self.path
        )

        path = parsed.path


        if not path.startswith(
            "/merge/"
        ):
            self.send_error(
                404,
                "Not Found",
            )
            return


        subid = urllib.parse.unquote(
            path[
                len("/merge/"):
            ].strip("/")
        )


        # 兼容常见UUID、字母数字、
        # 下划线、短横线、等号等subid
        if not re.fullmatch(
            r"[A-Za-z0-9._~+=-]+",
            subid,
        ):
            self.send_error(
                400,
                "Invalid subid",
            )
            return


        query = urllib.parse.parse_qs(
            parsed.query
        )


        force_paoluz = (
            query.get(
                "force",
                ["0"],
            )[0]
            == "1"
        )


        try:

            # =================================================
            # S-UI用户自己的Clash配置
            # =================================================

            encoded_subid = (
                urllib.parse.quote(
                    subid,
                    safe="",
                )
            )


            sui_url = (
                SUI_URL_TEMPLATE.replace(
                    "{subid}",
                    encoded_subid,
                )
            )


            sui_text = request_text(
                sui_url,
                timeout=30,
            )


            sui_config = parse_yaml(
                sui_text,
                "S-UI订阅",
            )


            include_paoluz = (
                subid in PAOLUZ_ALLOWED_SUBIDS
            )

            # 只有 titanyung 本人需要获取并合并上游订阅。
            # 其他用户从源头跳过拉取，避免节点或组名泄漏到客户端。
            paoluz_config = (
                get_paoluz_config(
                    force=force_paoluz
                )
                if include_paoluz
                else {}
            )

            bwh_config = {}
            if BWH_TITANYUNG_URL:
                bwh_text = request_text(
                    BWH_TITANYUNG_URL,
                    timeout=30,
                )
                bwh_config = parse_yaml(
                    bwh_text,
                    "BWHLA订阅",
                )


            # =================================================
            # 合并
            # =================================================

            merged = merge_configs(
                sui_config,
                paoluz_config,
                include_paoluz=include_paoluz,
                bwh_config=bwh_config,
                hkt_public_password=(
                    json.load(open(HKT_USER_KEYS_FILE, encoding="utf-8")).get(subid)
                    if os.path.exists(HKT_USER_KEYS_FILE) else None
                ),
            )

            # Trial-only accounts have no ordinary DMIT/GoMami authorization.
            # Keep only verified test paths; ordinary production users are untouched.
            trial_anytls = [p for p in sui_config.get("proxies", [])
                            if isinstance(p, dict) and str(p.get("type", "")).lower() == "anytls"]
            trial_ports = {str(p.get("port")) for p in trial_anytls}
            if trial_anytls and "29504" in trial_ports and trial_ports <= {"29503", "29504", "29505"}:
                invalid_nodes = {
                    "DMIT→ByteVirt香港ISP",
                    "GoMami→ByteVirt香港ISP（10.22到期）",
                    "GoMami-新加坡-10.22到期",
                }
                invalid_groups = {"DMIT→kookey（2027-01-15 01:42到期）"}
                removed = invalid_nodes | invalid_groups
                merged["proxies"] = [p for p in merged["proxies"]
                                     if p.get("name") not in invalid_nodes]
                merged["proxy-groups"] = [g for g in merged["proxy-groups"]
                                          if g.get("name") not in invalid_groups]
                for group in merged["proxy-groups"]:
                    members = [name for name in group.get("proxies", []) if name not in removed]
                    if group.get("name") == "全部节点":
                        trial_name = "DMIT→LAZYCAT（测试）"
                        if trial_name not in members:
                            raise ValueError("Lazycat trial absent from trial-only selector")
                        members = [trial_name] + [name for name in members if name != trial_name]
                    if not members:
                        raise ValueError("empty trial-only group: " + str(group.get("name")))
                    group["proxies"] = members
                remap = {
                    "DMIT→kookey（2027-01-15 01:42到期）": "全部节点",
                    "GoMami-新加坡-10.22到期": "全部节点",
                    "DMIT→ByteVirt香港ISP": "大陆-TVB→解锁TVB",
                    "GoMami→ByteVirt香港ISP（10.22到期）": "大陆-TVB→解锁TVB",
                }
                revised_rules = []
                for rule in merged["rules"]:
                    parts = rule.split(",")
                    target_index = 1 if parts[0] == "MATCH" else 2
                    if len(parts) > target_index and parts[target_index] in remap:
                        parts[target_index] = remap[parts[target_index]]
                    revised_rules.append(",".join(parts))
                merged["rules"] = revised_rules

            # Route non-direct DNS through the subscriber's selected proxy.
            # Direct traffic and proxy bootstrap use a dedicated resolver.
            dns_config = copy.deepcopy(merged.get("dns") or {})
            dns_config["default-nameserver"] = [
                "https://223.5.5.5/dns-query",
            ]
            dns_config["nameserver"] = [
                "https://1.1.1.1/dns-query#全部节点",
                "https://1.0.0.1/dns-query#全部节点",
            ]
            dns_config["proxy-server-nameserver"] = [
                "https://223.5.5.5/dns-query",
            ]
            dns_config["direct-nameserver"] = [
                "https://223.5.5.5/dns-query",
            ]
            dns_config["respect-rules"] = False
            dns_config.pop("fallback", None)
            merged["dns"] = dns_config


            # Nginx overwrites X-Real-IP with the connection's peer address;
            # ignore X-Forwarded-For and any duplicated header. The optional
            # bounded GeoIP lookup changes only the direct node's flag.
            real_ip_headers = self.headers.get_all("X-Real-IP") or []
            client_country = country_from_request(
                self.client_address[0],
                real_ip_headers[0] if len(real_ip_headers) == 1 else None,
            )
            merged = apply_public_five_group(
                merged, subid, direct_country=client_country,
            )

            # =================================================
            # 输出
            # =================================================

            output_text = yaml.safe_dump(
                merged,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                width=4096,
            )


            body = output_text.encode(
                "utf-8"
            )


            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/yaml; charset=utf-8",
            )

            self.send_header(
                "Cache-Control",
                "no-store, no-cache, must-revalidate",
            )

            self.send_header(
                "Pragma",
                "no-cache",
            )

            self.send_header(
                "Content-Disposition",
                'inline; filename="merged-clash.yaml"',
            )

            self.send_header(
                "Content-Length",
                str(len(body)),
            )

            self.end_headers()

            self.wfile.write(
                body
            )


        except Exception as exc:

            message = (
                "merge failed: "
                + str(exc)
                + "\n"
            )

            body = message.encode(
                "utf-8"
            )


            self.send_response(502)

            self.send_header(
                "Content-Type",
                "text/plain; charset=utf-8",
            )

            self.send_header(
                "Content-Length",
                str(len(body)),
            )

            self.end_headers()

            self.wfile.write(
                body
            )


    def log_message(
        self,
        fmt,
        *args,
    ):
        print(
            (
                "%s - %s"
                % (
                    self.address_string(),
                    fmt % args,
                )
            ),
            flush=True,
        )


# ============================================================
# Main
# ============================================================

def main():

    if not SUI_URL_TEMPLATE:
        raise RuntimeError(
            "SUI_URL_TEMPLATE没有配置"
        )


    if "{subid}" not in SUI_URL_TEMPLATE:
        raise RuntimeError(
            "SUI_URL_TEMPLATE必须包含{subid}"
        )


    if not PAOLUZ_URL:
        raise RuntimeError(
            "PAOLUZ_URL没有配置"
        )


    os.makedirs(
        CACHE_DIR,
        exist_ok=True,
    )


    server = ThreadingHTTPServer(
        (
            LISTEN_HOST,
            LISTEN_PORT,
        ),
        MergeHandler,
    )


    print(
        (
            "submerge listening on "
            f"{LISTEN_HOST}:"
            f"{LISTEN_PORT}"
        ),
        flush=True,
    )


    server.serve_forever()


if __name__ == "__main__":
    main()

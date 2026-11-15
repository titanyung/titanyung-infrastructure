#!/usr/bin/env python3

# Existing control readers share these owned dependencies in the web process.
# Worker CLI path setup is not executed when its read functions are imported.
import sys as _security_owned_sys
from pathlib import Path as _SecurityOwnedPath
_security_owned_paths = ('/opt/submerge-security-center', '/opt/submerge-topology', '/opt/submerge-edge', '/opt/submerge-routing', '/opt/submerge-user-access', '/opt/submerge-client-policy', '/opt/submerge')
_security_owned_sys.path[:] = list(_security_owned_paths) + [p for p in _security_owned_sys.path if p not in _security_owned_paths]
import network_runtime as _security_owned_network
if _SecurityOwnedPath(_security_owned_network.__file__).resolve() != _SecurityOwnedPath('/opt/submerge-topology/network_runtime.py'):
    raise RuntimeError('security_owned_network_reader_required')


import base64
import gzip
import glob
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import struct
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import qrcode
import qrcode.image.svg
import yaml

from flask import (
    Flask,
    Response,
    jsonify,
    request,
)


APP = Flask(__name__)


# ============================================================
# 基础配置
# ============================================================

VIEW_HASH_FILE = (
    "/etc/submerge-view-key.sha256"
)

SECURITY_CONFIG_FILE = (
    "/etc/submerge-security.json"
)

TOTP_CONFIG_FILE = (
    "/etc/submerge-totp.json"
)

ADMIN_AUTH_FILE = (
    "/etc/nginx/.submerge-admin-gomami"
)

HK_ADMIN_AUTH_FILE = (
    "/etc/nginx/.shared-admin.htpasswd"
)

HK_AUTH_SSH = [
    "ssh",
    "-i", "/root/.ssh/hk-submerge-transfer",
    "-p", "8586",
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes",
    "root@61.15.36.199",
]

HK_AUTH_REMOTE = r'''import base64,os,shutil,sys,time
path="/etc/nginx/.shared-admin.htpasswd"
data=base64.b64decode(sys.stdin.buffer.read())
if not data.startswith(b"admin:$apr1$") or not data.endswith(b"\n"):
    raise SystemExit("invalid auth payload")
st=os.stat(path)
backup=path+".bak-ui-"+time.strftime("%Y%m%d-%H%M%S",time.gmtime())
shutil.copy2(path,backup)
tmp=path+".new"
with open(tmp,"wb") as f:
    f.write(data)
os.chown(tmp,st.st_uid,st.st_gid)
os.chmod(tmp,st.st_mode & 0o777)
os.replace(tmp,path)
print("ok")
'''

SUB_ACCESS_LOG = (
    "/var/log/nginx/subscription_access.log"
)

MERGE_URL = (
    "http://127.0.0.1:18080/merge/{subid}"
)

PUBLIC_SUB_URL = (
    "https://sgnode.titanyungty.top:31877/"
    "sub/{subid}?format=clash"
)

TZ = ZoneInfo(
    "Asia/Shanghai"
)


# ============================================================
# 允许查看的服务器配置文件
#
# 不允许通过参数直接输入任意路径。
# 防止 ../../etc/shadow 之类路径穿越。
# ============================================================

SENSITIVE_FILES = {

    "merge_sub.py":
        "/opt/submerge/merge_sub.py",

    "rule_admin.py":
        "/opt/submerge/rule_admin.py",

    "security_admin.py":
        "/opt/submerge/security_admin.py",

    "route_rules.json":
        "/var/lib/submerge/route_rules.json",

    "submerge.env":
        "/etc/submerge.env",

    "nginx-bwh-sub":
        "/etc/nginx/sites-available/bwh-sub",

    "nginx-sub-compat":
        "/etc/nginx/sites-available/"
        "sui-sub-compat",
}


# ============================================================
# 通用工具
# ============================================================

def load_json_file(path, default):

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as f:

            return json.load(f)

    except Exception:

        return default


def security_config():

    return load_json_file(
        SECURITY_CONFIG_FILE,
        {
            "daily_request_warn": 100,
            "daily_bytes_warn":
                50 * 1024 * 1024,
            "unique_ip_warn": 5,
        }
    )


def totp_config():

    return load_json_file(
        TOTP_CONFIG_FILE,
        {},
    )


def totp_enabled():

    cfg = totp_config()
    return bool(
        cfg.get("enabled")
        and cfg.get("secret")
    )


def totp_value(secret, counter):

    padding = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(
        secret + padding,
        casefold=True,
    )
    digest = hmac.new(
        key,
        struct.pack(">Q", counter),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    value = (
        struct.unpack(">I", digest[offset:offset + 4])[0]
        & 0x7FFFFFFF
    ) % 1000000
    return f"{value:06d}"


def verify_totp(code, secret=None):

    code = re.sub(r"\s+", "", str(code or ""))
    if not re.fullmatch(r"\d{6}", code):
        return False

    if secret is None:
        secret = str(totp_config().get("secret", ""))
    if not secret:
        return False

    counter = int(time.time()) // 30
    for drift in (-1, 0, 1):
        try:
            expected = totp_value(secret, counter + drift)
        except Exception:
            return False
        if hmac.compare_digest(code, expected):
            return True
    return False


def same_origin_request():

    origin = request.headers.get("Origin", "")
    if not origin:
        return True
    parsed = urllib.parse.urlparse(origin)
    request_hostname = request.host.split(":", 1)[0].lower()
    return (
        parsed.scheme == "https"
        and (parsed.hostname or "").lower() == request_hostname
    )


def admin_request():

    auth = request.authorization
    return bool(auth and auth.username == "admin")


# ============================================================
# 二次密钥验证
# ============================================================

def verify_view_key():

    if totp_enabled():
        return verify_totp(
            request.headers.get("X-TOTP-Code", "")
        )

    supplied = request.headers.get(
        "X-View-Key",
        "",
    )

    if not supplied:
        return False


    try:

        with open(
            VIEW_HASH_FILE,
            "r",
            encoding="utf-8",
        ) as f:

            expected = (
                f.read()
                .strip()
                .lower()
            )

    except Exception:

        return False


    actual = hashlib.sha256(
        supplied.encode("utf-8")
    ).hexdigest()


    return hmac.compare_digest(
        actual,
        expected,
    )


def key_required():

    if verify_view_key():
        return None

    return jsonify({
        "error":
            "敏感信息查看密钥错误"
    }), 403


# ============================================================
# 订阅流量统计
# ============================================================

def subscription_stats():

    cfg = security_config()

    result = {}


    if not os.path.exists(
        SUB_ACCESS_LOG
    ):
        return []


    today = datetime.now(
        TZ
    ).date()


    try:

        f = open(
            SUB_ACCESS_LOG,
            "r",
            encoding="utf-8",
            errors="replace",
        )

    except Exception:

        return []


    with f:

        for line in f:

            try:

                row = json.loads(
                    line
                )

            except Exception:

                continue


            uri = str(
                row.get(
                    "uri",
                    ""
                )
            )


            match = re.search(
                r"/(?:sub|merge)/"
                r"([^/?]+)",
                uri,
            )

            if not match:
                continue


            subid = urllib.parse.unquote(
                match.group(1)
            )


            try:

                dt = datetime.fromisoformat(
                    row.get("time")
                )

                local_dt = dt.astimezone(
                    TZ
                )

            except Exception:

                continue


            if local_dt.date() != today:
                continue


            item = result.setdefault(
                subid,
                {
                    "subid": subid,
                    "requests": 0,
                    "bytes": 0,
                    "ips": set(),
                    "last_time": None,
                },
            )


            item["requests"] += 1


            try:

                item["bytes"] += int(
                    row.get(
                        "bytes",
                        0
                    )
                )

            except Exception:

                pass


            ip = str(
                row.get(
                    "ip",
                    ""
                )
            ).strip()

            if ip:
                item["ips"].add(ip)


            item["last_time"] = (
                local_dt.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )


    output = []


    for item in result.values():

        unique_ips = len(
            item["ips"]
        )

        alerts = []


        if item["requests"] >= int(
            cfg.get(
                "daily_request_warn",
                100
            )
        ):

            alerts.append(
                "请求次数异常"
            )


        if item["bytes"] >= int(
            cfg.get(
                "daily_bytes_warn",
                50 * 1024 * 1024
            )
        ):

            alerts.append(
                "下载流量异常"
            )


        if unique_ips >= int(
            cfg.get(
                "unique_ip_warn",
                5
            )
        ):

            alerts.append(
                "来源IP数量异常"
            )


        output.append({

            "subid":
                item["subid"],

            "requests":
                item["requests"],

            "bytes":
                item["bytes"],

            "mb":
                round(
                    item["bytes"]
                    / 1024
                    / 1024,
                    2,
                ),

            "unique_ips":
                unique_ips,

            "last_time":
                item["last_time"],

            "alert":
                bool(alerts),

            "alerts":
                alerts,
        })


    output.sort(
        key=lambda x: (
            not x["alert"],
            -x["requests"],
        )
    )


    return output


# ============================================================
# QR
# ============================================================

def make_qr_svg(text):

    img = qrcode.make(
        text,
        image_factory=
            qrcode.image.svg.SvgPathImage,
    )

    buffer = io.BytesIO()

    img.save(buffer)

    return buffer.getvalue().decode(
        "utf-8"
    )


# ============================================================
# 获取某用户合并后的配置
# ============================================================

SUBID_RE = re.compile(
    r"^[A-Za-z0-9._~+=-]+$"
)


def load_merged_config(subid):

    if not SUBID_RE.fullmatch(
        subid
    ):

        raise ValueError(
            "非法 subid"
        )


    url = MERGE_URL.format(
        subid=urllib.parse.quote(
            subid,
            safe="",
        )
    )


    req = urllib.request.Request(
        url,
        headers={
            "User-Agent":
                "Submerge-Security/1.0"
        }
    )


    with urllib.request.urlopen(
        req,
        timeout=30,
    ) as resp:

        raw = resp.read()


    data = yaml.safe_load(
        raw.decode(
            "utf-8",
            errors="replace",
        )
    )


    if not isinstance(
        data,
        dict,
    ):

        raise ValueError(
            "合并配置格式错误"
        )


    return data


# ============================================================
# 节点 URI
#
# 当前支持：
# - Shadowsocks
# - AnyTLS
#
# 其他协议可后续继续增加。
# ============================================================

def uri_host(host):

    host = str(host)

    try:

        ip = ipaddress.ip_address(
            host
        )

        if ip.version == 6:
            return "[" + host + "]"

    except Exception:
        pass


    return host


def node_share_uri(node):

    node_type = str(
        node.get(
            "type",
            ""
        )
    ).lower()


    name = urllib.parse.quote(
        str(
            node.get(
                "name",
                ""
            )
        ),
        safe="",
    )


    server = uri_host(
        node.get(
            "server",
            ""
        )
    )


    port = node.get(
        "port"
    )


    # ========================================================
    # Shadowsocks SIP002
    # ========================================================

    if node_type == "ss":

        method = str(
            node.get(
                "cipher",
                ""
            )
        )

        password = str(
            node.get(
                "password",
                ""
            )
        )


        if method.startswith(
            "2022-"
        ):

            # AEAD-2022:
            # userinfo不能使用Base64URL
            userinfo = (
                urllib.parse.quote(
                    method,
                    safe="",
                )
                + ":"
                + urllib.parse.quote(
                    password,
                    safe="",
                )
            )

        else:

            raw = (
                method
                + ":"
                + password
            ).encode(
                "utf-8"
            )

            userinfo = (
                base64.urlsafe_b64encode(
                    raw
                )
                .decode()
                .rstrip("=")
            )


        return (
            f"ss://{userinfo}"
            f"@{server}:{port}"
            f"#{name}"
        )


    # ========================================================
    # AnyTLS
    # ========================================================

    if node_type == "anytls":

        password = urllib.parse.quote(
            str(
                node.get(
                    "password",
                    ""
                )
            ),
            safe="",
        )


        params = {}


        sni = node.get(
            "sni"
        )

        if sni:
            params["sni"] = sni


        if node.get(
            "skip-cert-verify",
            False
        ):

            params[
                "insecure"
            ] = "1"


        query = urllib.parse.urlencode(
            params
        )


        suffix = (
            "?"
            + query
            if query
            else ""
        )


        return (
            f"anytls://{password}"
            f"@{server}:{port}/"
            f"{suffix}"
            f"#{name}"
        )


    return None



# ============================================================
# SUBMERGE_DETAILED_SUBSCRIPTION_HISTORY
#
# 订阅拉取日志 + 流量历史
# ============================================================

SUBSCRIPTION_LOG_GLOB = (
    "/var/log/nginx/"
    "subscription_access.log*"
)


def _open_subscription_log(
    path
):

    if path.endswith(".gz"):

        return gzip.open(
            path,
            "rt",
            encoding="utf-8",
            errors="replace",
        )

    return open(
        path,
        "r",
        encoding="utf-8",
        errors="replace",
    )


def _subid_from_uri(
    uri
):

    match = re.search(
        r"/(?:sub|merge)/"
        r"([^/?]+)",
        str(uri),
    )


    if not match:
        return None


    return urllib.parse.unquote(
        match.group(1)
    )


def read_subscription_records(
    days=30,
    subid=None,
    limit=None,
):

    days = max(
        1,
        min(
            int(days),
            90,
        )
    )


    now = datetime.now(TZ)

    cutoff = (
        now
        - timedelta(
            days=days
        )
    )


    records = []


    for path in glob.glob(
        SUBSCRIPTION_LOG_GLOB
    ):

        try:

            f = _open_subscription_log(
                path
            )

        except Exception:

            continue


        with f:

            for line in f:

                try:

                    row = json.loads(
                        line
                    )

                except Exception:

                    continue


                current_subid = (
                    _subid_from_uri(
                        row.get(
                            "uri",
                            ""
                        )
                    )
                )


                if not current_subid:
                    continue


                if (
                    subid is not None
                    and current_subid
                    != subid
                ):
                    continue


                try:

                    dt = (
                        datetime
                        .fromisoformat(
                            row.get(
                                "time",
                                ""
                            )
                        )
                        .astimezone(TZ)
                    )

                except Exception:

                    continue


                if dt < cutoff:
                    continue


                try:

                    body_bytes = int(
                        row.get(
                            "bytes",
                            0
                        )
                    )

                except Exception:

                    body_bytes = 0


                try:

                    status = int(
                        row.get(
                            "status",
                            0
                        )
                    )

                except Exception:

                    status = 0


                try:

                    request_time = float(
                        row.get(
                            "request_time",
                            0
                        )
                    )

                except Exception:

                    request_time = 0.0


                records.append({

                    "dt":
                        dt,

                    "time":
                        dt.strftime(
                            "%Y-%m-%d "
                            "%H:%M:%S"
                        ),

                    "subid":
                        current_subid,

                    "ip":
                        str(
                            row.get(
                                "ip",
                                ""
                            )
                        ),

                    "xff":
                        str(
                            row.get(
                                "xff",
                                ""
                            )
                        ),

                    "method":
                        str(
                            row.get(
                                "method",
                                ""
                            )
                        ),

                    "uri":
                        str(
                            row.get(
                                "uri",
                                ""
                            )
                        ),

                    "status":
                        status,

                    "bytes":
                        body_bytes,

                    "request_time":
                        round(
                            request_time,
                            3,
                        ),

                    "ua":
                        str(
                            row.get(
                                "ua",
                                ""
                            )
                        ),

                    "referer":
                        str(
                            row.get(
                                "referer",
                                ""
                            )
                        ),
                })


    records.sort(
        key=lambda x:
            x["dt"],
        reverse=True,
    )


    if limit is not None:

        limit = max(
            1,
            min(
                int(limit),
                1000,
            )
        )

        records = records[
            :limit
        ]


    return records


def detailed_subscription_summary():

    records = (
        read_subscription_records(
            days=30
        )
    )


    now = datetime.now(TZ)

    today = now.date()

    seven_cutoff = (
        now
        - timedelta(
            days=7
        )
    )


    result = {}


    for record in records:

        subid = record["subid"]


        item = result.setdefault(
            subid,
            {
                "subid":
                    subid,

                "today_requests":
                    0,

                "today_bytes":
                    0,

                "today_ips":
                    set(),

                "d7_requests":
                    0,

                "d7_bytes":
                    0,

                "d30_requests":
                    0,

                "d30_bytes":
                    0,

                "ips":
                    set(),

                "success":
                    0,

                "errors":
                    0,

                "last_time":
                    None,

                "_last_dt":
                    None,
            },
        )


        item["d30_requests"] += 1

        item["d30_bytes"] += (
            record["bytes"]
        )


        if record["ip"]:

            item["ips"].add(
                record["ip"]
            )


        if (
            200
            <= record["status"]
            < 400
        ):

            item["success"] += 1

        else:

            item["errors"] += 1


        if record["dt"] >= seven_cutoff:

            item["d7_requests"] += 1

            item["d7_bytes"] += (
                record["bytes"]
            )


        if record["dt"].date() == today:

            item["today_requests"] += 1

            item["today_bytes"] += (
                record["bytes"]
            )

            if record["ip"]:

                item["today_ips"].add(
                    record["ip"]
                )


        if (
            item["_last_dt"] is None
            or record["dt"]
            > item["_last_dt"]
        ):

            item["_last_dt"] = (
                record["dt"]
            )

            item["last_time"] = (
                record["time"]
            )


    cfg = security_config()

    output = []


    for item in result.values():

        alerts = []


        if (
            item["today_requests"]
            >= int(
                cfg.get(
                    "daily_request_warn",
                    100
                )
            )
        ):

            alerts.append(
                "今日请求次数异常"
            )


        if (
            item["today_bytes"]
            >= int(
                cfg.get(
                    "daily_bytes_warn",
                    50 * 1024 * 1024
                )
            )
        ):

            alerts.append(
                "今日订阅流量异常"
            )


        if (
            len(item["today_ips"])
            >= int(
                cfg.get(
                    "unique_ip_warn",
                    5
                )
            )
        ):

            alerts.append(
                "今日来源IP异常"
            )


        output.append({

            "subid":
                item["subid"],

            "today_requests":
                item[
                    "today_requests"
                ],

            "today_bytes":
                item[
                    "today_bytes"
                ],

            "d7_requests":
                item[
                    "d7_requests"
                ],

            "d7_bytes":
                item[
                    "d7_bytes"
                ],

            "d30_requests":
                item[
                    "d30_requests"
                ],

            "d30_bytes":
                item[
                    "d30_bytes"
                ],

            "today_unique_ips":
                len(
                    item[
                        "today_ips"
                    ]
                ),

            "unique_ips":
                len(
                    item["ips"]
                ),

            "success":
                item["success"],

            "errors":
                item["errors"],

            "last_time":
                item["last_time"],

            "alert":
                bool(alerts),

            "alerts":
                alerts,
        })


    output.sort(
        key=lambda x: (
            not x["alert"],
            -x["today_requests"],
            x["subid"],
        )
    )


    return output


def subscription_daily_traffic(
    subid,
    days=30,
):

    days = max(
        1,
        min(
            int(days),
            90,
        )
    )


    records = (
        read_subscription_records(
            days=days,
            subid=subid,
        )
    )


    now = datetime.now(TZ)

    start_date = (
        now.date()
        - timedelta(
            days=days - 1
        )
    )


    daily = {}


    for i in range(days):

        day = (
            start_date
            + timedelta(days=i)
        )

        key = day.isoformat()

        daily[key] = {
            "date":
                key,

            "requests":
                0,

            "bytes":
                0,

            "ips":
                set(),

            "errors":
                0,
        }


    for record in records:

        key = (
            record["dt"]
            .date()
            .isoformat()
        )


        if key not in daily:
            continue


        item = daily[key]

        item["requests"] += 1

        item["bytes"] += (
            record["bytes"]
        )


        if record["ip"]:

            item["ips"].add(
                record["ip"]
            )


        if not (
            200
            <= record["status"]
            < 400
        ):

            item["errors"] += 1


    result = []


    for item in daily.values():

        result.append({

            "date":
                item["date"],

            "requests":
                item["requests"],

            "bytes":
                item["bytes"],

            "unique_ips":
                len(
                    item["ips"]
                ),

            "errors":
                item["errors"],
        })


    return result



# ============================================================
# SUBMERGE_MINUTE_TRAFFIC
#
# 精确到分钟的订阅拉取流量统计
# ============================================================

def subscription_minute_traffic(
    subid,
    minutes=1440,
):

    try:
        minutes = int(minutes)

    except Exception:
        minutes = 1440


    # 最少看 1 分钟
    # 最多看最近 7 天
    minutes = max(
        1,
        min(
            minutes,
            10080,
        )
    )


    now = datetime.now(TZ)

    cutoff = (
        now
        - timedelta(
            minutes=minutes
        )
    )


    records = (
        read_subscription_records(
            days=max(
                1,
                int(
                    minutes / 1440
                ) + 1
            ),
            subid=subid,
        )
    )


    buckets = {}


    for record in records:

        dt = record["dt"]

        if dt < cutoff:
            continue


        # 精确到分钟
        minute_dt = dt.replace(
            second=0,
            microsecond=0,
        )


        key = minute_dt.strftime(
            "%Y-%m-%d %H:%M"
        )


        item = buckets.setdefault(
            key,
            {
                "minute":
                    key,

                "requests":
                    0,

                "bytes":
                    0,

                "ips":
                    set(),

                "success":
                    0,

                "errors":
                    0,

                "total_request_time":
                    0.0,

                "max_request_time":
                    0.0,
            },
        )


        item["requests"] += 1

        item["bytes"] += int(
            record.get(
                "bytes",
                0
            )
        )


        ip = record.get(
            "ip",
            ""
        )

        if ip:
            item["ips"].add(ip)


        status = int(
            record.get(
                "status",
                0
            )
        )


        if (
            200
            <= status
            < 400
        ):

            item["success"] += 1

        else:

            item["errors"] += 1


        rt = float(
            record.get(
                "request_time",
                0
            )
        )


        item[
            "total_request_time"
        ] += rt


        item[
            "max_request_time"
        ] = max(
            item[
                "max_request_time"
            ],
            rt,
        )


    result = []


    for item in buckets.values():

        requests = item["requests"]


        avg_time = (
            item[
                "total_request_time"
            ]
            / requests
            if requests
            else 0
        )


        result.append({

            "minute":
                item["minute"],

            "requests":
                requests,

            "bytes":
                item["bytes"],

            "unique_ips":
                len(
                    item["ips"]
                ),

            "success":
                item["success"],

            "errors":
                item["errors"],

            "avg_request_time":
                round(
                    avg_time,
                    3,
                ),

            "max_request_time":
                round(
                    item[
                        "max_request_time"
                    ],
                    3,
                ),
        })


    result.sort(
        key=lambda x:
            x["minute"]
    )


    return result



# ============================================================
# API
# ============================================================

# ============================================================
# 二次查看密钥验证
#
# 只用于后台“查看敏感内容”。
# 不参与 /sub/ 客户端订阅下载。
# ============================================================

@APP.get("/api/verify")
def api_verify():

    denied = key_required()

    if denied:
        return denied

    return jsonify({
        "ok": True
    })



@APP.get("/api/stats")
def api_stats():

    return jsonify({
        "thresholds":
            security_config(),

        "links":
            subscription_stats(),
    })



# ============================================================
# SUBMERGE_SUBSCRIPTION_HISTORY_API
# ============================================================

@APP.get(
    "/api/subscriptions/summary"
)
def api_subscription_summary():

    return jsonify({

        "links":
            detailed_subscription_summary(),

        "retention_days":
            30,
    })


@APP.get(
    "/api/subscriptions/"
    "<subid>/logs"
)
def api_subscription_logs(
    subid
):

    try:

        limit = int(
            request.args.get(
                "limit",
                "200"
            )
        )

    except Exception:

        limit = 200


    records = (
        read_subscription_records(
            days=30,
            subid=subid,
            limit=limit,
        )
    )


    output = []


    for record in records:

        output.append({

            key: value
            for key, value
            in record.items()
            if key != "dt"
        })


    return jsonify({

        "subid":
            subid,

        "logs":
            output,
    })


@APP.get(
    "/api/subscriptions/"
    "<subid>/traffic"
)
def api_subscription_traffic(
    subid
):

    try:

        days = int(
            request.args.get(
                "days",
                "30"
            )
        )

    except Exception:

        days = 30


    return jsonify({

        "subid":
            subid,

        "days":
            days,

        "traffic":
            subscription_daily_traffic(
                subid,
                days,
            ),
    })




@APP.get(
    "/api/subscriptions/"
    "<subid>/minute-traffic"
)
def api_subscription_minute_traffic(
    subid
):

    try:

        minutes = int(
            request.args.get(
                "minutes",
                "1440"
            )
        )

    except Exception:

        minutes = 1440


    return jsonify({

        "subid":
            subid,

        "minutes":
            minutes,

        "traffic":
            subscription_minute_traffic(
                subid,
                minutes,
            ),
    })




# ============================================================
# SUBMERGE_ACCESS_HISTORY_API
#
# 每个用户最近7天访问记录
# ============================================================

ACCESS_HISTORY_GLOB = (
    "/var/log/submerge-access/*.jsonl"
)


def read_access_history(
    user=None,
    limit=500,
):

    records = []

    files = sorted(
        glob.glob(
            ACCESS_HISTORY_GLOB
        ),
        reverse=True,
    )

    for path in files:

        try:

            with open(
                path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as f:

                for line in f:

                    try:
                        row = json.loads(line)

                    except Exception:
                        continue

                    if (
                        user
                        and row.get("user")
                        != user
                    ):
                        continue

                    records.append(row)

        except Exception:
            continue


    records.sort(
        key=lambda x:
            x.get("time", ""),
        reverse=True,
    )


    try:
        limit = int(limit)

    except Exception:
        limit = 500


    limit = max(
        1,
        min(
            limit,
            5000,
        )
    )


    return records[:limit]


@APP.get("/api/access/users")
def api_access_users():

    records = read_access_history(
        limit=5000
    )

    users = {}

    for row in records:

        user = str(
            row.get(
                "user",
                "unknown",
            )
        )

        item = users.setdefault(
            user,
            {
                "user":
                    user,

                "requests":
                    0,

                "hosts":
                    set(),

                "last_time":
                    None,
            },
        )

        item["requests"] += 1

        host = str(
            row.get(
                "host",
                "",
            )
        )

        if host:
            item["hosts"].add(host)

        current_time = str(
            row.get(
                "time",
                "",
            )
        )

        if (
            not item["last_time"]
            or current_time
            > item["last_time"]
        ):
            item["last_time"] = (
                current_time
            )


    result = []

    for item in users.values():

        result.append({
            "user":
                item["user"],

            "requests":
                item["requests"],

            "unique_hosts":
                len(
                    item["hosts"]
                ),

            "last_time":
                item["last_time"],
        })


    result.sort(
        key=lambda x:
            -x["requests"]
    )


    return jsonify({
        "retention_days":
            7,

        "users":
            result,
    })


@APP.get("/api/access/logs")
def api_access_logs():

    user = request.args.get(
        "user",
        "",
    ).strip()


    try:
        limit = int(
            request.args.get(
                "limit",
                "500",
            )
        )

    except Exception:
        limit = 500


    return jsonify({
        "retention_days":
            7,

        "user":
            user,

        "records":
            read_access_history(
                user=user or None,
                limit=limit,
            ),
    })



@APP.get("/api/sensitive/files")
def api_sensitive_files():

    denied = key_required()

    if denied:
        return denied


    return jsonify({

        "files": [
            {
                "id": key,
                "path": path,
            }
            for key, path
            in SENSITIVE_FILES.items()
            if os.path.exists(path)
        ]
    })


@APP.get(
    "/api/sensitive/file/<file_id>"
)
def api_sensitive_file(file_id):

    denied = key_required()

    if denied:
        return denied


    path = SENSITIVE_FILES.get(
        file_id
    )


    if not path:
        return jsonify({
            "error":
                "文件不在允许列表"
        }), 404


    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as f:

            content = f.read()

    except Exception as exc:

        return jsonify({
            "error":
                str(exc)
        }), 500


    return jsonify({
        "id":
            file_id,

        "path":
            path,

        "content":
            content,
    })


@APP.get(
    "/api/sensitive/subscription/<subid>"
)
def api_subscription(subid):

    denied = key_required()

    if denied:
        return denied


    if not SUBID_RE.fullmatch(
        subid
    ):

        return jsonify({
            "error":
                "非法subid"
        }), 400


    url = PUBLIC_SUB_URL.format(
        subid=urllib.parse.quote(
            subid,
            safe="",
        )
    )


    return jsonify({
        "subid":
            subid,

        "url":
            url,

        "qr_svg":
            make_qr_svg(url),
    })


@APP.get(
    "/api/sensitive/nodes/<subid>"
)
def api_nodes(subid):

    denied = key_required()

    if denied:
        return denied


    try:

        config = load_merged_config(
            subid
        )

    except Exception as exc:

        return jsonify({
            "error":
                str(exc)
        }), 500


    nodes = []


    for index, node in enumerate(
        config.get(
            "proxies",
            []
        )
    ):

        if not isinstance(
            node,
            dict,
        ):
            continue


        nodes.append({

            "index":
                index,

            "name":
                node.get(
                    "name"
                ),

            "type":
                node.get(
                    "type"
                ),
        })


    return jsonify({
        "subid":
            subid,

        "nodes":
            nodes,
    })


@APP.get(
    "/api/sensitive/node/"
    "<subid>/<int:index>"
)
def api_node(subid, index):

    denied = key_required()

    if denied:
        return denied


    try:

        config = load_merged_config(
            subid
        )

        nodes = config.get(
            "proxies",
            []
        )


        if (
            index < 0
            or index >= len(nodes)
        ):

            raise ValueError(
                "节点不存在"
            )


        node = nodes[index]


        uri = node_share_uri(
            node
        )


        if not uri:

            return jsonify({

                "name":
                    node.get(
                        "name"
                    ),

                "type":
                    node.get(
                        "type"
                    ),

                "error":
                    "暂不支持生成此协议的分享链接"
            }), 400


    except Exception as exc:

        return jsonify({
            "error":
                str(exc)
        }), 500


    return jsonify({

        "name":
            node.get(
                "name"
        ),

        "type":
            node.get(
                "type"
        ),

        "uri":
            uri,

        "qr_svg":
            make_qr_svg(uri),
    })


# ============================================================
# 页面
# ============================================================

HTML = r'''
<!doctype html>
<html lang="zh-CN">

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1">

<title>Submerge 安全中心</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: #0f1115;
  color: #e8e8ea;
  font-family:
    Inter,
    "PingFang SC",
    "Microsoft YaHei",
    sans-serif;
}

main {
  max-width: 1400px;
  margin: auto;
  padding: 24px;
}

h1 {
  margin: 0 0 6px;
}

.muted {
  color: #8f96a3;
}

.cards {
  display: grid;
  grid-template-columns:
    repeat(3, minmax(0,1fr));
  gap: 12px;
  margin: 22px 0;
}

.card,
.panel {
  background: #181b21;
  border: 1px solid #2b3039;
  border-radius: 14px;
  padding: 16px;
}

.card strong {
  font-size: 24px;
  display: block;
  margin-top: 6px;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th,
td {
  text-align: left;
  padding: 11px 10px;
  border-bottom: 1px solid #292e36;
}

.alert {
  color: #ff7070;
  font-weight: 700;
}

.ok {
  color: #55d98b;
}

button,
input,
select {
  min-height: 42px;
  border-radius: 9px;
  border: 1px solid #343946;
  background: #20242c;
  color: #eee;
  padding: 0 12px;
}

button {
  cursor: pointer;
}

.actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: #101216;
  border-radius: 10px;
  padding: 14px;
  max-height: 520px;
  overflow: auto;
}

#qr svg {
  max-width: 320px;
  width: 100%;
  height: auto;
  background: white;
  padding: 10px;
}



/* SUBMERGE_SUB_HISTORY_STYLE */

.subscription-detail-grid {
  display: grid;
  grid-template-columns:
    repeat(2, minmax(0,1fr));
  gap: 14px;
  margin-top: 16px;
}

.subscription-scroll {
  overflow-x: auto;
}

.subscription-scroll table {
  min-width: 760px;
}

.mono {
  font-family:
    ui-monospace,
    SFMono-Regular,
    Menlo,
    Consolas,
    monospace;
}

.small {
  font-size: 12px;
}

@media(max-width:900px) {

  .subscription-detail-grid {
    grid-template-columns:
      1fr;
  }
}




/* SUBMERGE_ACCESS_HISTORY_STYLE */

.access-summary {
  display: grid;
  grid-template-columns:
    repeat(3,minmax(0,1fr));
  gap: 12px;
  margin: 14px 0;
}

.access-summary-card {
  background: #20242c;
  border: 1px solid #303642;
  border-radius: 11px;
  padding: 13px;
}

.access-summary-card strong {
  display: block;
  margin-top: 5px;
  font-size: 22px;
}

.access-toolbar {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin: 14px 0;
}

.access-toolbar select {
  min-width: 180px;
}

.access-log-wrap {
  max-height: 560px;
  overflow: auto;
}

.access-host {
  font-family:
    ui-monospace,
    SFMono-Regular,
    Menlo,
    Consolas,
    monospace;
}

@media(max-width:800px) {

  .access-summary {
    grid-template-columns: 1fr;
  }
}


@media(max-width:800px) {

  .cards {
    grid-template-columns: 1fr;
  }

  .table-wrap {
    overflow-x: auto;
  }

  table {
    min-width: 800px;
  }
}



/* SUBMERGE_SPLIT_LOG_TRAFFIC_TABLES_V2 */

.subscription-detail-grid {
    display: block !important;
    width: 100%;
}

.subscription-table-section {
    width: 100%;
    display: block;
}

.subscription-table-section + .subscription-table-section {
    margin-top: 32px;
    padding-top: 28px;
    border-top: 1px solid #303642;
}

.subscription-table-title {
    margin:
        0
        0
        14px
        0;
}

.subscription-table-card {
    width: 100%;
}

.subscription-table-scroll {
    width: 100%;
    overflow-x: auto;
}

.subscription-table-scroll table {
    width: 100%;
    min-width: 900px;
}

.subscription-table-pagination {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;

    margin-top: 14px;
}

.subscription-table-pagination button {
    min-width: 78px;
}

.subscription-table-pagination button:disabled {
    opacity: .42;
    cursor: not-allowed;
}

.subscription-table-page-info {
    min-width: 110px;
    text-align: center;
    color: #a8adb7;
}

.subscription-table-count {
    color: #8f96a3;
    font-size: 13px;
    margin-right: 4px;
}

@media(max-width:800px) {

    .subscription-table-pagination {
        justify-content: center;
    }

}



/* ==========================================================
   SUBMERGE_UI_CLEAN_SCROLL_V6

   Chrome 风格深色滚动条
   ========================================================== */


/* Firefox */

* {
    scrollbar-width: thin;
    scrollbar-color:
        #5f6368
        transparent;
}


/* Chrome / Edge / Chromium */

*::-webkit-scrollbar {
    width: 11px;
    height: 11px;
}


*::-webkit-scrollbar-track {
    background:
        transparent;
}


*::-webkit-scrollbar-thumb {

    background-color:
        #5f6368;

    border-radius:
        999px;

    border:
        3px solid transparent;

    background-clip:
        content-box;
}


*::-webkit-scrollbar-thumb:hover {

    background-color:
        #80868b;
}


*::-webkit-scrollbar-thumb:active {

    background-color:
        #9aa0a6;
}


*::-webkit-scrollbar-corner {

    background:
        transparent;
}


/* ==========================================================
   弹窗滚动条稍微再细一点
   ========================================================== */

.submerge-modal-body::-webkit-scrollbar,
.access-log-wrap::-webkit-scrollbar {

    width: 10px;
    height: 10px;
}


.submerge-modal-body::-webkit-scrollbar-thumb,
.access-log-wrap::-webkit-scrollbar-thumb {

    background-color:
        #5f6368;

    border-radius:
        999px;

    border:
        2px solid transparent;

    background-clip:
        content-box;
}


.submerge-modal-body::-webkit-scrollbar-thumb:hover,
.access-log-wrap::-webkit-scrollbar-thumb:hover {

    background-color:
        #80868b;
}


/* ==========================================================
   弹窗本身禁止出现难看的外部横向滚动条
   ========================================================== */

.submerge-modal {

    overflow:
        hidden;
}


.submerge-modal-body {

    overflow-y:
        auto;

    overflow-x:
        auto;
}


/* ==========================================================
   操作列不要被撑得太宽
   ========================================================== */

.submerge-action-buttons {

    display:
        flex;

    gap:
        8px;

    align-items:
        center;

    white-space:
        nowrap;
}


</style>

</head>

<body>

<main>

<h1>🛡️ Submerge 安全中心</h1>

<div class="muted">
反爬虫 · 订阅流量警报 · 敏感信息二次密钥
</div>


<div class="cards">

  <div class="card">
    今日订阅链接
    <strong id="linkCount">0</strong>
  </div>

  <div class="card">
    今日请求
    <strong id="requestCount">0</strong>
  </div>

  <div class="card">
    异常链接
    <strong id="alertCount">0</strong>
  </div>

</div>


<div class="panel" style="margin-top:16px">
  <h2>🔑 后台登录密码</h2>
  <p class="muted">
    同时修改分流规则、安全中心和香港流量后台的 admin 密码。
  </p>
  <div class="actions">
    <input id="newAdminPassword"
           type="password"
           autocomplete="new-password"
           placeholder="新密码（至少12位）">
    <input id="confirmAdminPassword"
           type="password"
           autocomplete="new-password"
           placeholder="再次输入新密码">
    <button type="button" id="changeAdminPassword">
      修改三个后台密码
    </button>
  </div>
  <div id="adminPasswordStatus" class="muted" style="margin-top:10px"></div>
</div>


<div class="panel" style="margin-top:16px">
  <h2>🔐 Google Authenticator 二次验证</h2>
  <p class="muted">
    绑定后，查看订阅链接、二维码和节点敏感信息时需要输入6位动态码。
  </p>
  <div class="actions">
    <strong id="totpState">正在读取状态……</strong>
    <button type="button" id="startTotpSetup">绑定验证器</button>
    <button type="button" id="showTotpUnbind" style="display:none">解绑验证器</button>
  </div>

  <div id="totpSetupBox" style="display:none;margin-top:18px">
    <div id="totpQr" style="background:#fff;display:inline-block;padding:12px;border-radius:10px"></div>
    <p class="muted">无法扫码时，手动输入下面的密钥：</p>
    <pre id="totpSecret" style="user-select:all"></pre>
    <div class="actions">
      <input id="totpBindCode"
             inputmode="numeric"
             maxlength="6"
             autocomplete="one-time-code"
             placeholder="输入验证器显示的6位动态码">
      <button type="button" id="confirmTotpBind">确认绑定</button>
    </div>
  </div>

  <div id="totpUnbindBox" style="display:none;margin-top:18px">
    <div class="actions">
      <input id="totpUnbindCode"
             inputmode="numeric"
             maxlength="6"
             autocomplete="one-time-code"
             placeholder="输入当前6位动态码">
      <button type="button" id="confirmTotpUnbind">确认解绑</button>
    </div>
  </div>
  <div id="totpStatus" class="muted" style="margin-top:10px"></div>
</div>


<div class="panel">

<h2>订阅链接流量警报</h2>

<div class="table-wrap">

<table>

<thead>
<tr>
<th>SubID</th>
<th>请求</th>
<th>流量</th>
<th>来源IP</th>
<th>最后访问</th>
<th>状态</th>
</tr>
</thead>

<tbody id="statsRows">
</tbody>

</table>

</div>

</div>




<!-- SUBMERGE_SUBSCRIPTION_HISTORY_PANEL -->

<div
  class="panel"
  style="margin-top:16px">

<h2>📥 订阅拉取记录</h2>

<p class="muted">
记录每条订阅链接的请求时间、来源 IP、
客户端、HTTP 状态、响应大小和下载流量。
保留最近 30 天。
</p>


<div class="table-wrap">

<table>

<thead>

<tr>
<th>SubID</th>
<th>今日请求</th>
<th>今日流量</th>
<th>7天流量</th>
<th>30天流量</th>
<th>今日IP</th>
<th>成功 / 失败</th>
<th>最后拉取</th>
<th>操作</th>
</tr>

</thead>

<tbody id="subSummaryRows">
</tbody>

</table>

</div>


<!-- SUBMERGE_SPLIT_LOG_TRAFFIC_TABLES_V2 -->

<div class="subscription-detail-grid">


    <!-- =====================================================
         表一：拉取日志
         ===================================================== -->

    <div class="subscription-table-section">

        <h3
          id="subLogTitle"
          class="subscription-table-title">
          📄 拉取日志
        </h3>


        <div class="subscription-table-card">

            <div class="subscription-table-scroll">

                <table>

                    <thead>

                        <tr>
                            <th>时间</th>
                            <th>来源 IP</th>
                            <th>状态</th>
                            <th>大小</th>
                            <th>耗时</th>
                            <th>客户端</th>
                        </tr>

                    </thead>


                    <tbody id="subLogRows">
                    </tbody>

                </table>

            </div>


            <div class="subscription-table-pagination">

                <span
                  id="subLogCount"
                  class="subscription-table-count">
                  共 0 条
                </span>


                <button
                  type="button"
                  id="subLogPrev">
                  上一页
                </button>


                <span
                  id="subLogPageInfo"
                  class="subscription-table-page-info">
                  第 1 / 1 页
                </span>


                <button
                  type="button"
                  id="subLogNext">
                  下一页
                </button>

            </div>

        </div>

    </div>



    <!-- =====================================================
         表二：分钟流量
         ===================================================== -->

    <div class="subscription-table-section">

        <h3
          id="subTrafficTitle"
          class="subscription-table-title">
          📊 分钟流量
        </h3>


        <div class="subscription-table-card">

            <div class="subscription-table-scroll">

                <table>

                    <thead>

                        <tr>
                            <th>分钟</th>
                            <th>请求</th>
                            <th>流量</th>
                            <th>来源 IP</th>
                            <th>成功</th>
                            <th>失败</th>
                            <th>平均耗时</th>
                        </tr>

                    </thead>


                    <tbody id="subTrafficRows">
                    </tbody>

                </table>

            </div>


            <div class="subscription-table-pagination">

                <span
                  id="subTrafficCount"
                  class="subscription-table-count">
                  共 0 条
                </span>


                <button
                  type="button"
                  id="subTrafficPrev">
                  上一页
                </button>


                <span
                  id="subTrafficPageInfo"
                  class="subscription-table-page-info">
                  第 1 / 1 页
                </span>


                <button
                  type="button"
                  id="subTrafficNext">
                  下一页
                </button>

            </div>

        </div>

    </div>


</div>


<div
  class="panel"
  style="margin-top:16px">

<h2>🌐 用户访问记录</h2>

<p class="muted">
记录用户通过搬瓦工访问的目标域名/IP和端口。
仅保留最近7天。
HTTPS不会解密网页内容，因此不会记录具体页面路径。
</p>


<div class="access-summary">

  <div class="access-summary-card">
    用户数
    <strong id="accessUserCount">
      0
    </strong>
  </div>

  <div class="access-summary-card">
    记录数
    <strong id="accessRequestCount">
      0
    </strong>
  </div>

  <div class="access-summary-card">
    保留
    <strong>
      7天
    </strong>
  </div>

</div>


<div class="access-toolbar">

<select id="accessUserFilter">

<option value="">
全部用户
</option>

</select>


<button
  type="button"
  id="refreshAccess">
刷新
</button>

</div>


<div class="access-log-wrap">

<table>

<thead>

<tr>
<th>时间</th>
<th>用户</th>
<th>目标域名 / IP</th>
<th>端口</th>
<th>入站</th>
<th>协议</th>
</tr>

</thead>

<tbody id="accessRows">
</tbody>

</table>

</div>

</div>


<div class="panel"
     style="margin-top:16px">

<h2>🔐 敏感信息查看</h2>

<p class="muted">
每次查看都会重新要求输入独立查看密钥。
浏览器不会保存该密钥。
</p>


<div class="actions">

<select id="fileSelect">
<option value="">
选择配置文件
</option>
</select>

<button type="button"
        id="viewFile">
查看配置文件
</button>

</div>


<hr style="border-color:#292e36;margin:20px 0">


<div class="actions">

<input
 id="subid"
 placeholder="输入 subid，例如 wrt">

<button type="button"
        id="viewSub">
查看订阅链接 / QR
</button>

<button type="button"
        id="loadNodes">
加载节点
</button>

</div>


<div class="actions"
     style="margin-top:10px">

<select id="nodeSelect">
<option value="">
先加载节点
</option>
</select>

<button type="button"
        id="viewNode">
查看节点链接 / QR
</button>

</div>


<pre id="sensitiveOutput">
敏感内容将在这里显示
</pre>

<div id="qr">
</div>

</div>

</main>


<script>

const changeAdminPasswordButton = document.getElementById(
  "changeAdminPassword"
);

changeAdminPasswordButton.addEventListener("click", async () => {
  const password = document.getElementById("newAdminPassword").value;
  const confirmPassword = document.getElementById("confirmAdminPassword").value;
  const status = document.getElementById("adminPasswordStatus");

  if (password.length < 12) {
    status.textContent = "新密码至少需要12位。";
    return;
  }
  if (password !== confirmPassword) {
    status.textContent = "两次输入的密码不一致。";
    return;
  }

  changeAdminPasswordButton.disabled = true;
  status.textContent = "正在同步三个后台……";

  try {
    const response = await fetch("./api/admin-password", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({password}),
      cache: "no-store"
    });
    const result = await response.json();
    if (!response.ok || !result.ok) {
      throw new Error(result.error || "修改失败");
    }
    document.getElementById("newAdminPassword").value = "";
    document.getElementById("confirmAdminPassword").value = "";
    status.textContent = "修改成功。请关闭三个后台页面，再使用新密码登录。";
    alert("三个后台密码已修改。请关闭旧页面后使用新密码重新登录。");
  } catch (error) {
    status.textContent = "修改失败：" + error.message;
  } finally {
    changeAdminPasswordButton.disabled = false;
  }
});

let sensitiveMode = "view_key";
let pendingTotpSecret = "";

async function refreshTotpStatus() {
  const response = await fetch("./api/totp/status", {cache: "no-store"});
  const result = await response.json();
  sensitiveMode = result.bound ? "totp" : "view_key";
  document.getElementById("totpState").textContent =
    result.bound ? "状态：已绑定" : "状态：未绑定";
  document.getElementById("startTotpSetup").style.display =
    result.bound ? "none" : "inline-block";
  document.getElementById("showTotpUnbind").style.display =
    result.bound ? "inline-block" : "none";
  document.getElementById("totpSetupBox").style.display = "none";
  document.getElementById("totpUnbindBox").style.display = "none";
}

document.getElementById("startTotpSetup").addEventListener("click", async () => {
  const status = document.getElementById("totpStatus");
  status.textContent = "正在生成二维码……";
  try {
    const response = await fetch("./api/totp/setup", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: "{}",
      cache: "no-store"
    });
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || "生成失败");
    pendingTotpSecret = result.secret;
    document.getElementById("totpQr").innerHTML = result.qr_svg;
    document.getElementById("totpSecret").textContent = result.secret;
    document.getElementById("totpSetupBox").style.display = "block";
    status.textContent = "请扫码后输入验证器显示的6位动态码。";
  } catch (error) {
    status.textContent = "生成失败：" + error.message;
  }
});

document.getElementById("confirmTotpBind").addEventListener("click", async () => {
  const code = document.getElementById("totpBindCode").value.trim();
  const status = document.getElementById("totpStatus");
  try {
    const response = await fetch("./api/totp/bind", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({secret: pendingTotpSecret, code}),
      cache: "no-store"
    });
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || "绑定失败");
    pendingTotpSecret = "";
    document.getElementById("totpBindCode").value = "";
    status.textContent = "绑定成功。敏感信息现在使用6位动态码验证。";
    await refreshTotpStatus();
  } catch (error) {
    status.textContent = "绑定失败：" + error.message;
  }
});

document.getElementById("showTotpUnbind").addEventListener("click", () => {
  document.getElementById("totpUnbindBox").style.display = "block";
  document.getElementById("totpStatus").textContent =
    "请输入当前动态码确认解绑。解绑后恢复使用原 View Key。";
});

document.getElementById("confirmTotpUnbind").addEventListener("click", async () => {
  const code = document.getElementById("totpUnbindCode").value.trim();
  const status = document.getElementById("totpStatus");
  try {
    const response = await fetch("./api/totp/unbind", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({code}),
      cache: "no-store"
    });
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || "解绑失败");
    document.getElementById("totpUnbindCode").value = "";
    status.textContent = "已解绑。敏感信息恢复使用原 View Key。";
    await refreshTotpStatus();
  } catch (error) {
    status.textContent = "解绑失败：" + error.message;
  }
});

refreshTotpStatus().catch(() => {
  document.getElementById("totpState").textContent = "状态读取失败";
});

const SUB_PAGE_SIZE = 100;

const output =
  document.getElementById(
    "sensitiveOutput"
  );

const qr =
  document.getElementById(
    "qr"
  );


function askKey() {

  return prompt(
    sensitiveMode === "totp"
      ? "请输入 Google Authenticator 的6位动态码"
      : "请输入敏感信息查看密钥"
  );
}


async function secureFetch(url) {

  const key =
    askKey();

  if (!key) {
    throw new Error(
      "已取消"
    );
  }


  const res =
    await fetch(
      url,
      {
        headers: sensitiveMode === "totp"
          ? {"X-TOTP-Code": key}
          : {"X-View-Key": key}
      }
    );


  const data =
    await res.json();


  if (!res.ok) {

    throw new Error(
      data.error
      || "请求失败"
    );
  }


  return data;
}


async function loadStats() {

  const res =
    await fetch(
      "./api/stats"
    );

  const data =
    await res.json();

  const links =
    data.links || [];


  linkCount.textContent =
    links.length;


  requestCount.textContent =
    links.reduce(
      (n,x) =>
        n + x.requests,
      0
    );


  alertCount.textContent =
    links.filter(
      x => x.alert
    ).length;


  statsRows.innerHTML = "";


  for (const item of links) {

    const tr =
      document.createElement(
        "tr"
      );


    tr.innerHTML = `

      <td>${item.subid}</td>

      <td>${item.requests}</td>

      <td>${item.mb} MB</td>

      <td>${item.unique_ips}</td>

      <td>${item.last_time || "-"}</td>

      <td class="${
        item.alert
          ? "alert"
          : "ok"
      }">

      ${
        item.alert
        ? "⚠ "
          + item.alerts.join(" / ")
        : "正常"
      }

      </td>
    `;


    statsRows.appendChild(
      tr
    );
  }
}




// SUBMERGE_SUBSCRIPTION_HISTORY_JS

function formatBytes(
  bytes
) {

  let value =
    Number(bytes || 0);


  if (value < 1024) {
    return value + " B";
  }


  if (
    value
    < 1024 * 1024
  ) {

    return (
      value / 1024
    ).toFixed(1)
      + " KB";
  }


  if (
    value
    < 1024 * 1024 * 1024
  ) {

    return (
      value
      / 1024
      / 1024
    ).toFixed(2)
      + " MB";
  }


  return (
    value
    / 1024
    / 1024
    / 1024
  ).toFixed(2)
    + " GB";
}


function addTextCell(
  tr,
  text,
  className
) {

  const td =
    document.createElement(
      "td"
    );

  td.textContent =
    text == null
      ? ""
      : String(text);


  if (className) {
    td.className =
      className;
  }


  tr.appendChild(td);

  return td;
}


async function loadSubscriptionSummary() {

  try {

    const res =
      await fetch(
        "./api/subscriptions/summary",
        {
          cache:
            "no-store"
        }
      );


    const data =
      await res.json();


    const rows =
      document.getElementById(
        "subSummaryRows"
      );


    if (!rows) {
      return;
    }


    rows.innerHTML = "";


    for (
      const item
      of data.links || []
    ) {

      const tr =
        document.createElement(
          "tr"
        );


      addTextCell(
        tr,
        item.subid,
        "mono"
      );


      addTextCell(
        tr,
        item.today_requests
      );


      addTextCell(
        tr,
        formatBytes(
          item.today_bytes
        )
      );


      addTextCell(
        tr,
        formatBytes(
          item.d7_bytes
        )
      );


      addTextCell(
        tr,
        formatBytes(
          item.d30_bytes
        )
      );


      addTextCell(
        tr,
        item.today_unique_ips
      );


      addTextCell(
        tr,
        item.success
        + " / "
        + item.errors,
        item.errors
          ? "alert"
          : "ok"
      );


      addTextCell(
        tr,
        item.last_time || "-"
      );


      const td =
        document.createElement(
          "td"
        );


      const button =
        document.createElement(
          "button"
        );

      button.type =
        "button";

      button.textContent =
        item.alert
        ? "⚠ 查看"
        : "查看";


      button.addEventListener(
        "click",
        () => {

          loadSubscriptionDetail(
            item.subid
          );
        }
      );


      td.appendChild(
        button
      );

      tr.appendChild(
        td
      );


      if (item.alert) {
        tr.classList.add(
          "alert-row"
        );
      }


      rows.appendChild(
        tr
      );
    }


  } catch(e) {

    console.error(
      "subscription summary:",
      e
    );
  }
}


async function loadSubscriptionDetail(
  subid
) {

  const logTitle =
    document.getElementById(
      "subLogTitle"
    );

  const trafficTitle =
    document.getElementById(
      "subTrafficTitle"
    );


  logTitle.textContent =
    "拉取日志 · "
    + subid;

  trafficTitle.textContent =
    "分钟流量 · "
    + subid;


  try {

    const [
      logsRes,
      trafficRes
    ] =
      await Promise.all([

        fetch(
          "./api/subscriptions/"
          + encodeURIComponent(
              subid
            )
          + "/logs?limit=200",
          {
            cache:
              "no-store"
          }
        ),

        fetch(
          "./api/subscriptions/"
          + encodeURIComponent(
              subid
            )
          + "/minute-traffic?minutes=1440",
          {
            cache:
              "no-store"
          }
        )

      ]);


    const logs =
      await logsRes.json();

    const traffic =
      await trafficRes.json();


    const logRows =
      document.getElementById(
        "subLogRows"
      );

    logRows.innerHTML = "";


    for (
      const item
      of logs.logs || []
    ) {

      const tr =
        document.createElement(
          "tr"
        );


      addTextCell(
        tr,
        item.time
      );


      addTextCell(
        tr,
        item.ip,
        "mono"
      );


      addTextCell(
        tr,
        item.status,
        (
          item.status >= 400
          ? "alert"
          : "ok"
        )
      );


      addTextCell(
        tr,
        formatBytes(
          item.bytes
        )
      );


      addTextCell(
        tr,
        item.request_time
        + "s"
      );


      addTextCell(
        tr,
        item.ua,
        "small"
      );


      logRows.appendChild(
        tr
      );
    }


    const trafficRows =
      document.getElementById(
        "subTrafficRows"
      );

    trafficRows.innerHTML = "";


    for (
      const item
      of traffic.traffic || []
    ) {

      const tr =
        document.createElement(
          "tr"
        );


      addTextCell(
        tr,
        item.minute
      );


      addTextCell(
        tr,
        item.requests
      );


      addTextCell(
        tr,
        formatBytes(
          item.bytes
        )
      );


      addTextCell(
        tr,
        item.unique_ips
      );


      addTextCell(
        tr,
        item.success,
        "ok"
      );


      addTextCell(
        tr,
        item.errors,
        item.errors
          ? "alert"
          : "ok"
      );


      addTextCell(
        tr,
        item.avg_request_time
        + "s"
      );


      trafficRows.appendChild(
        tr
      );
    }


  } catch(e) {

    console.error(
      "subscription detail:",
      e
    );
  }
}




// SUBMERGE_ACCESS_HISTORY_JS

async function loadAccessUsers() {

  try {

    const res =
      await fetch(
        "./api/access/users",
        {
          cache:
            "no-store"
        }
      );


    const data =
      await res.json();


    const select =
      document.getElementById(
        "accessUserFilter"
      );


    const oldValue =
      select.value;


    select.innerHTML =
      '<option value="">全部用户</option>';


    for (
      const item
      of data.users || []
    ) {

      const option =
        document.createElement(
          "option"
        );

      option.value =
        item.user;

      option.textContent =
        item.user
        + " · "
        + item.requests
        + "条";


      select.appendChild(
        option
      );
    }


    select.value =
      oldValue;


    accessUserCount.textContent =
      (data.users || []).length;


  } catch(e) {

    console.error(
      "load access users:",
      e
    );
  }
}


async function loadAccessLogs() {

  const user =
    document
      .getElementById(
        "accessUserFilter"
      )
      .value;


  let url =
    "./api/access/logs?limit=1000";


  if (user) {

    url += (
      "&user="
      + encodeURIComponent(user)
    );
  }


  try {

    const res =
      await fetch(
        url,
        {
          cache:
            "no-store"
        }
      );


    const data =
      await res.json();


    const records =
      data.records || [];


    accessRequestCount.textContent =
      records.length;


    const rows =
      document.getElementById(
        "accessRows"
      );


    rows.innerHTML = "";


    for (
      const item
      of records
    ) {

      const tr =
        document.createElement(
          "tr"
        );


      const values = [

        item.time || "-",

        item.user || "-",

        item.host
          || item.target
          || "-",

        item.port == null
          ? "-"
          : item.port,

        item.inbound || "-",

        item.inbound_protocol
          || "-",

      ];


      values.forEach(
        (value,index) => {

          const td =
            document.createElement(
              "td"
            );

          td.textContent =
            value;


          if (index === 2) {

            td.className =
              "access-host";
          }


          tr.appendChild(
            td
          );
        }
      );


      rows.appendChild(
        tr
      );
    }


  } catch(e) {

    console.error(
      "load access logs:",
      e
    );
  }
}


async function refreshAccessHistory() {

  await loadAccessUsers();

  await loadAccessLogs();
}


accessUserFilter.addEventListener(
  "change",
  loadAccessLogs
);


refreshAccess.addEventListener(
  "click",
  refreshAccessHistory
);


viewFile.addEventListener(
  "click",
  async () => {

    const id =
      fileSelect.value;

    if (!id) return;


    try {

      const data =
        await secureFetch(
          "./api/sensitive/file/"
          + encodeURIComponent(id)
        );

      output.textContent =
        data.path
        + "\n\n"
        + data.content;

      qr.innerHTML = "";

    } catch(e) {

      output.textContent =
        e.message;
    }
  }
);


viewSub.addEventListener(
  "click",
  async () => {

    const id =
      subid.value.trim();

    if (!id) return;


    try {

      const data =
        await secureFetch(
          "./api/sensitive/subscription/"
          + encodeURIComponent(id)
        );

      output.textContent =
        data.url;

      qr.innerHTML =
        data.qr_svg;

    } catch(e) {

      output.textContent =
        e.message;
    }
  }
);


loadNodes.addEventListener(
  "click",
  async () => {

    const id =
      subid.value.trim();

    if (!id) return;


    try {

      const data =
        await secureFetch(
          "./api/sensitive/nodes/"
          + encodeURIComponent(id)
        );


      nodeSelect.innerHTML =
        '<option value="">'
        + '选择节点'
        + '</option>';


      for (
        const node
        of data.nodes
      ) {

        const option =
          document.createElement(
            "option"
          );

        option.value =
          node.index;

        option.textContent =
          node.name
          + " ["
          + node.type
          + "]";

        nodeSelect.appendChild(
          option
        );
      }


      output.textContent =
        "已加载 "
        + data.nodes.length
        + " 个节点";

      qr.innerHTML = "";

    } catch(e) {

      output.textContent =
        e.message;
    }
  }
);


viewNode.addEventListener(
  "click",
  async () => {

    const id =
      subid.value.trim();

    const index =
      nodeSelect.value;


    if (
      !id
      || index === ""
    ) {
      return;
    }


    try {

      const data =
        await secureFetch(
          "./api/sensitive/node/"
          + encodeURIComponent(id)
          + "/"
          + index
        );


      output.textContent =
        data.name
        + "\n\n"
        + data.uri;

      qr.innerHTML =
        data.qr_svg;

    } catch(e) {

      output.textContent =
        e.message;

      qr.innerHTML = "";
    }
  }
);


async function loadFiles() {

  try {

    const data =
      await secureFetch(
        "./api/sensitive/files"
      );


    for (
      const f of data.files
    ) {

      const option =
        document.createElement(
          "option"
        );

      option.value =
        f.id;

      option.textContent =
        f.id;

      fileSelect.appendChild(
        option
      );
    }

  } catch(e) {

    output.textContent =
      "配置文件列表未解锁";
  }
}


loadStats();

refreshAccessHistory();

loadSubscriptionSummary();

setInterval(
  loadStats,
  60000
);




setInterval(
  loadSubscriptionSummary,
  60000
);




setInterval(
  refreshAccessHistory,
  60000
);


// 文件列表也属于敏感内容。
// 用户主动点击配置查看时再解锁。
// 页面打开时不主动要求密钥。

fileSelect.addEventListener(
  "mousedown",
  async function once() {

    if (
      fileSelect.options.length
      > 1
    ) {
      return;
    }

    await loadFiles();
  }
);



// ============================================================
// SUBMERGE_TABLE_PAGINATION_HOTFIX_V3
//
// 不再修改旧函数。
// 直接在脚本最后覆盖现有函数。
// ============================================================

const SUBMERGE_PAGE_SIZE_V3 = 100;

let submergeLogRowsV3 = [];
let submergeTrafficRowsV3 = [];

let submergeLogPageV3 = 1;
let submergeTrafficPageV3 = 1;


// ============================================================
// GMT+8 显示
// ============================================================

function submergeGMT8V3(value) {

  if (!value) {
    return "-";
  }


  // 已经是后端格式化好的 GMT+8
  if (
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/
      .test(String(value))
  ) {
    return String(value);
  }


  const date =
    new Date(value);


  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return String(value);
  }


  const parts =
    new Intl.DateTimeFormat(
      "zh-CN",
      {
        timeZone:
          "Asia/Shanghai",

        year:
          "numeric",

        month:
          "2-digit",

        day:
          "2-digit",

        hour:
          "2-digit",

        minute:
          "2-digit",

        second:
          "2-digit",

        hour12:
          false,
      }
    )
    .formatToParts(date);


  const map = {};

  for (const p of parts) {
    map[p.type] = p.value;
  }


  return (
    map.year
    + "-"
    + map.month
    + "-"
    + map.day
    + " "
    + map.hour
    + ":"
    + map.minute
    + ":"
    + map.second
  );
}


// ============================================================
// 格式化流量
// ============================================================

function submergeBytesV3(bytes) {

  let n =
    Number(bytes || 0);


  if (n < 1024) {
    return n + " B";
  }


  if (
    n < 1024 * 1024
  ) {
    return (
      n / 1024
    ).toFixed(1)
      + " KB";
  }


  if (
    n < 1024 * 1024 * 1024
  ) {
    return (
      n
      / 1024
      / 1024
    ).toFixed(2)
      + " MB";
  }


  return (
    n
    / 1024
    / 1024
    / 1024
  ).toFixed(2)
    + " GB";
}


// ============================================================
// 安全插入 td
// ============================================================

function submergeCellV3(
  tr,
  value,
  className
) {

  const td =
    document.createElement(
      "td"
    );


  td.textContent =
    value == null
      ? ""
      : String(value);


  if (className) {
    td.className =
      className;
  }


  tr.appendChild(td);

  return td;
}


// ============================================================
// 拉取日志分页
// ============================================================

function submergeRenderLogsV3() {

  const tbody =
    document.getElementById(
      "subLogRows"
    );

  const count =
    document.getElementById(
      "subLogCount"
    );

  const pageInfo =
    document.getElementById(
      "subLogPageInfo"
    );

  const prev =
    document.getElementById(
      "subLogPrev"
    );

  const next =
    document.getElementById(
      "subLogNext"
    );


  if (
    !tbody
    || !count
    || !pageInfo
    || !prev
    || !next
  ) {
    return;
  }


  const total =
    submergeLogRowsV3.length;


  const pages =
    Math.max(
      1,
      Math.ceil(
        total
        / SUBMERGE_PAGE_SIZE_V3
      )
    );


  submergeLogPageV3 =
    Math.max(
      1,
      Math.min(
        submergeLogPageV3,
        pages
      )
    );


  const start =
    (
      submergeLogPageV3 - 1
    )
    * SUBMERGE_PAGE_SIZE_V3;


  const rows =
    submergeLogRowsV3.slice(
      start,
      start
      + SUBMERGE_PAGE_SIZE_V3
    );


  tbody.innerHTML = "";


  for (
    const item
    of rows
  ) {

    const tr =
      document.createElement(
        "tr"
      );


    submergeCellV3(
      tr,
      submergeGMT8V3(
        item.time
      )
    );


    submergeCellV3(
      tr,
      item.ip || "-",
      "mono"
    );


    submergeCellV3(
      tr,
      item.status ?? "-",
      (
        Number(
          item.status
        ) >= 400
          ? "alert"
          : "ok"
      )
    );


    submergeCellV3(
      tr,
      submergeBytesV3(
        item.bytes
      )
    );


    const rt =
      Number(
        item.request_time || 0
      );


    submergeCellV3(
      tr,
      (
        Math.round(
          rt * 1000
        ) / 1000
      )
      + "s"
    );


    submergeCellV3(
      tr,
      item.ua || "-",
      "small"
    );


    tbody.appendChild(
      tr
    );
  }


  count.textContent =
    "共 "
    + total
    + " 条";


  pageInfo.textContent =
    "第 "
    + submergeLogPageV3
    + " / "
    + pages
    + " 页";


  prev.disabled =
    submergeLogPageV3 <= 1;


  next.disabled =
    submergeLogPageV3 >= pages;
}


// ============================================================
// 分钟流量分页
// ============================================================

function submergeRenderTrafficV3() {

  const tbody =
    document.getElementById(
      "subTrafficRows"
    );

  const count =
    document.getElementById(
      "subTrafficCount"
    );

  const pageInfo =
    document.getElementById(
      "subTrafficPageInfo"
    );

  const prev =
    document.getElementById(
      "subTrafficPrev"
    );

  const next =
    document.getElementById(
      "subTrafficNext"
    );


  if (
    !tbody
    || !count
    || !pageInfo
    || !prev
    || !next
  ) {
    return;
  }


  const total =
    submergeTrafficRowsV3.length;


  const pages =
    Math.max(
      1,
      Math.ceil(
        total
        / SUBMERGE_PAGE_SIZE_V3
      )
    );


  submergeTrafficPageV3 =
    Math.max(
      1,
      Math.min(
        submergeTrafficPageV3,
        pages
      )
    );


  const start =
    (
      submergeTrafficPageV3 - 1
    )
    * SUBMERGE_PAGE_SIZE_V3;


  const rows =
    submergeTrafficRowsV3.slice(
      start,
      start
      + SUBMERGE_PAGE_SIZE_V3
    );


  tbody.innerHTML = "";


  for (
    const item
    of rows
  ) {

    const tr =
      document.createElement(
        "tr"
      );


    submergeCellV3(
      tr,
      item.minute || "-"
    );


    submergeCellV3(
      tr,
      item.requests || 0
    );


    submergeCellV3(
      tr,
      submergeBytesV3(
        item.bytes
      )
    );


    submergeCellV3(
      tr,
      item.unique_ips || 0
    );


    submergeCellV3(
      tr,
      item.success || 0,
      "ok"
    );


    submergeCellV3(
      tr,
      item.errors || 0,
      (
        item.errors
          ? "alert"
          : "ok"
      )
    );


    const avg =
      Number(
        item.avg_request_time
        || 0
      );


    submergeCellV3(
      tr,
      (
        Math.round(
          avg * 1000
        ) / 1000
      )
      + "s"
    );


    tbody.appendChild(
      tr
    );
  }


  count.textContent =
    "共 "
    + total
    + " 条";


  pageInfo.textContent =
    "第 "
    + submergeTrafficPageV3
    + " / "
    + pages
    + " 页";


  prev.disabled =
    submergeTrafficPageV3 <= 1;


  next.disabled =
    submergeTrafficPageV3 >= pages;
}


// ============================================================
// 完整重新加载某个订阅详情
// ============================================================

loadSubscriptionDetail =
async function(
  subid
) {

  const logTitle =
    document.getElementById(
      "subLogTitle"
    );

  const trafficTitle =
    document.getElementById(
      "subTrafficTitle"
    );


  if (logTitle) {
    logTitle.textContent =
      "拉取日志 · "
      + subid;
  }


  if (trafficTitle) {
    trafficTitle.textContent =
      "分钟流量 · "
      + subid;
  }


  try {

    const [
      logResponse,
      trafficResponse
    ] =
      await Promise.all([

        fetch(
          "./api/subscriptions/"
          + encodeURIComponent(
              subid
            )
          + "/logs?limit=5000",
          {
            cache:
              "no-store"
          }
        ),

        fetch(
          "./api/subscriptions/"
          + encodeURIComponent(
              subid
            )
          + "/minute-traffic"
          + "?minutes=10080",
          {
            cache:
              "no-store"
          }
        )

      ]);


    const logs =
      await logResponse.json();


    const traffic =
      await trafficResponse.json();


    submergeLogRowsV3 =
      Array.isArray(
        logs.logs
      )
        ? logs.logs
        : [];


    submergeTrafficRowsV3 =
      Array.isArray(
        traffic.traffic
      )
        ? traffic.traffic
        : [];


    // 最新分钟排在前面
    submergeTrafficRowsV3.sort(
      (a,b) =>
        String(
          b.minute || ""
        ).localeCompare(
          String(
            a.minute || ""
          )
        )
    );


    submergeLogPageV3 = 1;

    submergeTrafficPageV3 = 1;


    submergeRenderLogsV3();

    submergeRenderTrafficV3();


  } catch(error) {

    console.error(
      "V3 subscription detail:",
      error
    );
  }
};


// ============================================================
// 分页按钮
// 用 onclick 覆盖旧事件，避免重复 listener 干扰
// ============================================================

const _logPrev =
  document.getElementById(
    "subLogPrev"
  );

const _logNext =
  document.getElementById(
    "subLogNext"
  );

const _trafficPrev =
  document.getElementById(
    "subTrafficPrev"
  );

const _trafficNext =
  document.getElementById(
    "subTrafficNext"
  );


if (_logPrev) {

  _logPrev.onclick =
    () => {

      if (
        submergeLogPageV3 > 1
      ) {

        submergeLogPageV3 -= 1;

        submergeRenderLogsV3();
      }
    };
}


if (_logNext) {

  _logNext.onclick =
    () => {

      const pages =
        Math.max(
          1,
          Math.ceil(
            submergeLogRowsV3.length
            / SUBMERGE_PAGE_SIZE_V3
          )
        );


      if (
        submergeLogPageV3
        < pages
      ) {

        submergeLogPageV3 += 1;

        submergeRenderLogsV3();
      }
    };
}


if (_trafficPrev) {

  _trafficPrev.onclick =
    () => {

      if (
        submergeTrafficPageV3 > 1
      ) {

        submergeTrafficPageV3 -= 1;

        submergeRenderTrafficV3();
      }
    };
}


if (_trafficNext) {

  _trafficNext.onclick =
    () => {

      const pages =
        Math.max(
          1,
          Math.ceil(
            submergeTrafficRowsV3.length
            / SUBMERGE_PAGE_SIZE_V3
          )
        );


      if (
        submergeTrafficPageV3
        < pages
      ) {

        submergeTrafficPageV3 += 1;

        submergeRenderTrafficV3();
      }
    };
}


// ============================================================
// 用户访问记录 GMT+8
//
// 监听 tbody 更新，自动把旧 +00:00 时间转换。
// ============================================================

function submergeFixAccessTimesV3() {

  const tbody =
    document.getElementById(
      "accessRows"
    );


  if (!tbody) {
    return;
  }


  for (
    const row
    of tbody.rows
  ) {

    if (
      !row.cells
      || row.cells.length < 1
    ) {
      continue;
    }


    const cell =
      row.cells[0];


    const raw =
      cell.textContent.trim();


    if (
      raw.includes("T")
      || raw.endsWith("Z")
      || /[+-]\d\d:\d\d$/.test(raw)
    ) {

      cell.textContent =
        submergeGMT8V3(raw);
    }
  }
}


submergeFixAccessTimesV3();


const _accessBody =
  document.getElementById(
    "accessRows"
  );


if (_accessBody) {

  new MutationObserver(
    submergeFixAccessTimesV3
  ).observe(
    _accessBody,
    {
      childList:
        true,

      subtree:
        true
    }
  );
}




// ============================================================
// SUBMERGE_SUB_MODAL_HOTFIX_V5
// 订阅表两个按钮：查订阅 / 查流量
// 使用弹窗显示，每页100条
// ============================================================
(function () {
  if (window.__SUBMERGE_SUB_MODAL_HOTFIX_V5__) return;
  window.__SUBMERGE_SUB_MODAL_HOTFIX_V5__ = true;

  const PAGE_SIZE = 100;

  function addStyle() {
    if (document.getElementById("submerge-modal-style-v5")) return;
    const s = document.createElement("style");
    s.id = "submerge-modal-style-v5";
    s.textContent = `
      .submerge-mini-btn{
        display:inline-flex;
        align-items:center;
        justify-content:center;
        min-width:72px;
        padding:8px 12px;
        margin:0 6px 6px 0;
        border:1px solid rgba(255,255,255,.12);
        border-radius:12px;
        background:#151c2c;
        color:#fff;
        cursor:pointer;
        font-size:13px;
      }
      .submerge-mini-btn:hover{background:#1b2440}
      .submerge-modal-mask{
        position:fixed; inset:0; z-index:99999;
        background:rgba(0,0,0,.58);
        display:none; align-items:center; justify-content:center;
        padding:24px;
      }
      .submerge-modal{
        width:min(1400px,96vw);
        height:min(86vh,900px);
        background:#0f1726;
        border:1px solid rgba(255,255,255,.10);
        border-radius:18px;
        box-shadow:0 20px 60px rgba(0,0,0,.45);
        display:flex; flex-direction:column;
        overflow:hidden;
      }
      .submerge-modal-header{
        display:flex; align-items:center; justify-content:space-between;
        padding:16px 20px;
        border-bottom:1px solid rgba(255,255,255,.08);
      }
      .submerge-modal-title{
        font-size:20px; font-weight:700; color:#fff;
      }
      .submerge-modal-close{
        border:none; background:transparent; color:#fff;
        font-size:26px; cursor:pointer; line-height:1;
      }
      .submerge-modal-desc{
        padding:0 20px 12px 20px;
        color:rgba(255,255,255,.72);
        font-size:13px;
      }
      .submerge-modal-body{
        flex:1; overflow:auto; padding:0 20px 20px 20px;
      }
      .submerge-modal-table{
        width:100%;
        border-collapse:collapse;
      }
      .submerge-modal-table th,
      .submerge-modal-table td{
        padding:12px 10px;
        border-bottom:1px solid rgba(255,255,255,.06);
        text-align:left;
        font-size:13px;
        white-space:nowrap;
      }
      .submerge-modal-table th{
        position:sticky; top:0;
        background:#0f1726;
        z-index:2;
      }
      .submerge-modal-foot{
        display:flex; align-items:center; justify-content:flex-end;
        gap:14px;
        padding:14px 20px;
        border-top:1px solid rgba(255,255,255,.08);
      }
      .submerge-page-btn{
        min-width:82px;
        padding:10px 16px;
        border:1px solid rgba(255,255,255,.12);
        border-radius:12px;
        background:#151c2c;
        color:#fff;
        cursor:pointer;
      }
      .submerge-page-btn:disabled{
        opacity:.45; cursor:not-allowed;
      }
      .submerge-page-info,
      .submerge-page-count{
        color:#fff;
        font-size:13px;
      }
      .submerge-ok{color:#39d98a}
      .submerge-bad{color:#ff6b6b}
      .submerge-small{font-size:12px; color:rgba(255,255,255,.78)}
      .submerge-mono{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace}
    `;
    document.head.appendChild(s);
  }

  function fmtBytes(n) {
    n = Number(n || 0);
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(2) + " MB";
    return (n / 1024 / 1024 / 1024).toFixed(2) + " GB";
  }

  function fmtTime(v) {
    if (!v) return "-";
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(String(v))) return String(v);
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return String(v);
    const parts = new Intl.DateTimeFormat("zh-CN", {
      timeZone: "Asia/Shanghai",
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: false
    }).formatToParts(d);
    const m = {};
    for (const p of parts) m[p.type] = p.value;
    return `${m.year}-${m.month}-${m.day} ${m.hour}:${m.minute}:${m.second}`;
  }

  function esc(v) {
    return String(v ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function ensureModal() {
    if (document.getElementById("submergeModalMask")) return;
    const wrap = document.createElement("div");
    wrap.id = "submergeModalMask";
    wrap.className = "submerge-modal-mask";
    wrap.innerHTML = `
      <div class="submerge-modal">
        <div class="submerge-modal-header">
          <div class="submerge-modal-title" id="submergeModalTitle">详情</div>
          <button class="submerge-modal-close" id="submergeModalClose">×</button>
        </div>
        <div class="submerge-modal-desc" id="submergeModalDesc"></div>
        <div class="submerge-modal-body" id="submergeModalBody"></div>
        <div class="submerge-modal-foot">
          <span class="submerge-page-count" id="submergeModalCount">共 0 条</span>
          <button class="submerge-page-btn" id="submergeModalPrev">上一页</button>
          <span class="submerge-page-info" id="submergeModalPageInfo">第 1 / 1 页</span>
          <button class="submerge-page-btn" id="submergeModalNext">下一页</button>
        </div>
      </div>
    `;
    document.body.appendChild(wrap);

    document.getElementById("submergeModalClose").onclick = closeModal;
    wrap.addEventListener("click", function (e) {
      if (e.target === wrap) closeModal();
    });
  }

  const state = {
    title: "",
    desc: "",
    rows: [],
    page: 1,
    kind: "logs"
  };

  function closeModal() {
    const mask = document.getElementById("submergeModalMask");
    if (mask) mask.style.display = "none";
  }

  function openModal() {
    ensureModal();
    const mask = document.getElementById("submergeModalMask");
    mask.style.display = "flex";
    renderModal();
  }

  function renderLogsRows(rows) {
    return rows.map(item => `
      <tr>
        <td>${esc(fmtTime(item.time))}</td>
        <td class="submerge-mono">${esc(item.ip || "-")}</td>
        <td class="${Number(item.status || 0) >= 400 ? "submerge-bad" : "submerge-ok"}">${esc(item.status ?? "-")}</td>
        <td>${esc(fmtBytes(item.bytes))}</td>
        <td>${esc((Math.round(Number(item.request_time || 0) * 1000) / 1000) + "s")}</td>
        <td class="submerge-small">${esc(item.ua || "-")}</td>
      </tr>
    `).join("");
  }

  function renderTrafficRows(rows) {
    return rows.map(item => `
      <tr>
        <td>${esc(item.minute || "-")}</td>
        <td>${esc(item.requests || 0)}</td>
        <td>${esc(fmtBytes(item.bytes))}</td>
        <td>${esc(item.unique_ips || 0)}</td>
        <td class="submerge-ok">${esc(item.success || 0)}</td>
        <td class="${Number(item.errors || 0) > 0 ? "submerge-bad" : "submerge-ok"}">${esc(item.errors || 0)}</td>
        <td>${esc((Math.round(Number(item.avg_request_time || 0) * 1000) / 1000) + "s")}</td>
      </tr>
    `).join("");
  }

  function renderModal() {
    const total = state.rows.length;
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    state.page = Math.max(1, Math.min(state.page, pages));

    const start = (state.page - 1) * PAGE_SIZE;
    const view = state.rows.slice(start, start + PAGE_SIZE);

    document.getElementById("submergeModalTitle").textContent = state.title;
    document.getElementById("submergeModalDesc").textContent = state.desc;
    document.getElementById("submergeModalCount").textContent = `共 ${total} 条`;
    document.getElementById("submergeModalPageInfo").textContent = `第 ${state.page} / ${pages} 页`;

    const prev = document.getElementById("submergeModalPrev");
    const next = document.getElementById("submergeModalNext");

    prev.disabled = state.page <= 1;
    next.disabled = state.page >= pages;

    prev.onclick = function () {
      if (state.page > 1) {
        state.page -= 1;
        renderModal();
      }
    };
    next.onclick = function () {
      if (state.page < pages) {
        state.page += 1;
        renderModal();
      }
    };

    let thead = "";
    let tbody = "";

    if (state.kind === "logs") {
      thead = `
        <tr>
          <th>时间</th>
          <th>来源IP</th>
          <th>状态</th>
          <th>大小</th>
          <th>耗时</th>
          <th>客户端</th>
        </tr>
      `;
      tbody = renderLogsRows(view);
    } else {
      thead = `
        <tr>
          <th>分钟</th>
          <th>请求</th>
          <th>流量</th>
          <th>来源IP</th>
          <th>成功</th>
          <th>失败</th>
          <th>平均耗时</th>
        </tr>
      `;
      tbody = renderTrafficRows(view);
    }

    document.getElementById("submergeModalBody").innerHTML = `
      <table class="submerge-modal-table">
        <thead>${thead}</thead>
        <tbody>${tbody}</tbody>
      </table>
    `;
  }

  async function openLogs(subid) {
    const res = await fetch(`./api/subscriptions/${encodeURIComponent(subid)}/logs?limit=20000`, { cache: "no-store" });
    const data = await res.json();
    const rows = Array.isArray(data.logs) ? data.logs : [];
    rows.sort((a, b) => String(b.time || "").localeCompare(String(a.time || "")));

    state.title = `订阅拉取日志 · ${subid}`;
    state.desc = "仅显示最近 7 天。每页 100 条。";
    state.rows = rows;
    state.page = 1;
    state.kind = "logs";
    openModal();
  }

  async function openTraffic(subid) {
    const res = await fetch(`./api/subscriptions/${encodeURIComponent(subid)}/minute-traffic?minutes=10080`, { cache: "no-store" });
    const data = await res.json();
    const rows = Array.isArray(data.traffic) ? data.traffic : [];
    rows.sort((a, b) => String(b.minute || "").localeCompare(String(a.minute || "")));

    state.title = `分钟流量 · ${subid}`;
    state.desc = "仅显示最近 7 天。每页 100 条。";
    state.rows = rows;
    state.page = 1;
    state.kind = "traffic";
    openModal();
  }

  function patchRetentionText(root) {
    if (!root) return;
    root.querySelectorAll("p,div,span").forEach(el => {
      if (el.children.length > 0) return;
      if (typeof el.textContent === "string" && el.textContent.includes("30天")) {
        el.textContent = el.textContent.replaceAll("30天", "7天");
      }
    });
  }

  function installButtons() {
    const titles = [...document.querySelectorAll("h1,h2,h3,h4")];
    const title = titles.find(x => (x.textContent || "").includes("订阅拉取记录"));
    if (!title) return;

    const box = title.closest("section,div");
    if (!box) return;

    patchRetentionText(box);

    const table = box.querySelector("table");
    if (!table) return;

    const tbody = table.querySelector("tbody");
    if (!tbody) return;

    [...tbody.querySelectorAll("tr")].forEach(tr => {
      const tds = tr.querySelectorAll("td");
      if (tds.length < 2) return;

      const subid = (tds[0].textContent || "").trim();
      if (!subid) return;

      const actionTd = tds[tds.length - 1];
      if (actionTd.dataset.submergeModalV5 === "1") return;

      actionTd.dataset.submergeModalV5 = "1";
      actionTd.innerHTML = "";

      const b1 = document.createElement("button");
      b1.className = "submerge-mini-btn";
      b1.textContent = "查订阅";
      b1.onclick = () => openLogs(subid);

      const b2 = document.createElement("button");
      b2.className = "submerge-mini-btn";
      b2.textContent = "查流量";
      b2.onclick = () => openTraffic(subid);

      actionTd.appendChild(b1);
      actionTd.appendChild(b2);
    });
  }

  addStyle();
  ensureModal();

  document.addEventListener("DOMContentLoaded", installButtons);
  setTimeout(installButtons, 600);
  setTimeout(installButtons, 1800);
  setInterval(installButtons, 2000);
})();



// ============================================================
// SUBMERGE_UI_CLEAN_SCROLL_V6
//
// 订阅详情已经全部使用弹窗。
// 主页面不再保留重复的拉取日志 / 分钟流量表。
// ============================================================

(function () {

    if (
        window.__SUBMERGE_UI_CLEAN_SCROLL_V6__
    ) {
        return;
    }


    window.__SUBMERGE_UI_CLEAN_SCROLL_V6__ =
        true;


    function hideOldInlineSubscriptionTables() {

        const ids = [
            "subLogTitle",
            "subTrafficTitle"
        ];


        for (
            const id
            of ids
        ) {

            const title =
                document.getElementById(
                    id
                );


            if (!title) {
                continue;
            }


            /*
             * 弹窗标题使用的是：
             *
             * submergeModalTitle
             *
             * 因此这里不会误伤弹窗。
             */


            let container =
                title.closest(
                    ".subscription-table-section"
                );


            /*
             * 兼容更早版本结构。
             */

            if (!container) {

                container =
                    title.parentElement;
            }


            if (
                container
                && !container.closest(
                    ".submerge-modal"
                )
            ) {

                container.style.display =
                    "none";
            }
        }


        /*
         * 如果 subscription-detail-grid
         * 里面两个旧表全隐藏了，
         * 整个空壳也一起隐藏。
         */

        const grid =
            document.querySelector(
                ".subscription-detail-grid"
            );


        if (grid) {

            const visibleChildren =
                [...grid.children]
                .filter(
                    element => {

                        return (
                            element.style.display
                            !== "none"
                        );
                    }
                );


            if (
                visibleChildren.length
                === 0
            ) {

                grid.style.display =
                    "none";
            }
        }
    }


    // ========================================================
    // 操作列按钮整理
    // ========================================================

    function beautifyActionButtons() {

        const tables =
            document.querySelectorAll(
                "table"
            );


        for (
            const table
            of tables
        ) {

            const headers =
                [
                    ...table.querySelectorAll(
                        "thead th"
                    )
                ];


            const actionIndex =
                headers.findIndex(
                    th =>
                        (
                            th.textContent
                            || ""
                        )
                        .trim()
                        === "操作"
                );


            if (
                actionIndex < 0
            ) {
                continue;
            }


            const rows =
                table.querySelectorAll(
                    "tbody tr"
                );


            for (
                const row
                of rows
            ) {

                const cells =
                    row.querySelectorAll(
                        "td"
                    );


                if (
                    !cells[
                        actionIndex
                    ]
                ) {
                    continue;
                }


                cells[
                    actionIndex
                ].classList.add(
                    "submerge-action-buttons"
                );
            }
        }
    }


    function applyV6() {

        hideOldInlineSubscriptionTables();

        beautifyActionButtons();
    }


    applyV6();


    /*
     * 页面数据是异步加载的，
     * 所以监听 DOM 变化。
     */

    const observer =
        new MutationObserver(
            applyV6
        );


    observer.observe(
        document.body,
        {
            childList:
                true,

            subtree:
                true
        }
    );


    /*
     * 再做几次兜底。
     */

    setTimeout(
        applyV6,
        500
    );

    setTimeout(
        applyV6,
        1500
    );

})();


</script>

</body>
</html>
'''


@APP.get("/")
def index():

    return Response(
        HTML,
        mimetype="text/html",
    )



# ============================================================
# View Key compatibility API for S-UI-X Delivery gate
# ============================================================

BWH_VIEW_KEY_FILE = "/etc/submerge-view-key.sha256"


def bwh_verify_view_key(value):

    if not value:
        return False

    try:
        with open(
            BWH_VIEW_KEY_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            expected = f.read().strip()

    except Exception:
        return False

    actual = hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()

    return hmac.compare_digest(
        actual,
        expected
    )


@APP.route("/api/view-key/verify", methods=["GET", "POST"])
def bwh_view_key_verify():

    if request.method == "GET":
        return jsonify({
            "ok": True,
            "mode": "totp" if totp_enabled() else "view_key",
        })

    payload = request.get_json(
        silent=True
    ) or {}

    key = str(
        payload.get(
            "key",
            ""
        )
    )

    ok = (
        verify_totp(key)
        if totp_enabled()
        else bwh_verify_view_key(key)
    )

    return jsonify({
        "ok": ok
    }), (
        200 if ok else 403
    )


def atomic_auth_write(path, data):

    st = os.stat(path)
    tmp = path + ".new"

    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

    os.chown(tmp, st.st_uid, st.st_gid)
    os.chmod(tmp, st.st_mode & 0o777)
    os.replace(tmp, path)


def write_totp_config(payload):

    tmp = TOTP_CONFIG_FILE + ".new"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chown(tmp, 0, 0)
    os.chmod(tmp, 0o600)
    os.replace(tmp, TOTP_CONFIG_FILE)


def totp_admin_guard():

    if not admin_request():
        return jsonify({
            "ok": False,
            "error": "当前登录身份无权管理二次验证",
        }), 403
    if not same_origin_request():
        return jsonify({
            "ok": False,
            "error": "请求来源无效",
        }), 403
    return None


@APP.get("/api/totp/status")
def api_totp_status():

    denied = totp_admin_guard()
    if denied:
        return denied
    return jsonify({
        "ok": True,
        "bound": totp_enabled(),
    })


@APP.post("/api/totp/setup")
def api_totp_setup():

    denied = totp_admin_guard()
    if denied:
        return denied
    if totp_enabled():
        return jsonify({
            "ok": False,
            "error": "验证器已经绑定",
        }), 409

    secret = base64.b32encode(
        secrets.token_bytes(20)
    ).decode("ascii").rstrip("=")
    issuer = "Titanyung"
    account = "security-center"
    label = urllib.parse.quote(f"{issuer}:{account}", safe="")
    uri = (
        f"otpauth://totp/{label}"
        f"?secret={secret}"
        f"&issuer={urllib.parse.quote(issuer, safe='')}"
        "&algorithm=SHA1&digits=6&period=30"
    )
    return jsonify({
        "ok": True,
        "secret": secret,
        "qr_svg": make_qr_svg(uri),
    })


@APP.post("/api/totp/bind")
def api_totp_bind():

    denied = totp_admin_guard()
    if denied:
        return denied
    if totp_enabled():
        return jsonify({
            "ok": False,
            "error": "验证器已经绑定",
        }), 409

    payload = request.get_json(silent=True) or {}
    secret = str(payload.get("secret", "")).strip().upper()
    code = str(payload.get("code", "")).strip()
    if not re.fullmatch(r"[A-Z2-7]{32}", secret):
        return jsonify({
            "ok": False,
            "error": "绑定密钥无效，请重新生成二维码",
        }), 400
    if not verify_totp(code, secret):
        return jsonify({
            "ok": False,
            "error": "动态码错误，请检查手机时间后重试",
        }), 403

    if os.path.exists(TOTP_CONFIG_FILE):
        shutil.copy2(
            TOTP_CONFIG_FILE,
            TOTP_CONFIG_FILE + ".bak-" + time.strftime(
                "%Y%m%d-%H%M%S", time.gmtime()
            ),
        )
    write_totp_config({
        "enabled": True,
        "secret": secret,
        "issuer": "Titanyung",
        "account": "security-center",
        "bound_at": int(time.time()),
    })
    return jsonify({"ok": True})


@APP.post("/api/totp/unbind")
def api_totp_unbind():

    denied = totp_admin_guard()
    if denied:
        return denied
    if not totp_enabled():
        return jsonify({
            "ok": True,
            "bound": False,
        })

    payload = request.get_json(silent=True) or {}
    code = str(payload.get("code", "")).strip()
    if not verify_totp(code):
        return jsonify({
            "ok": False,
            "error": "动态码错误",
        }), 403

    shutil.copy2(
        TOTP_CONFIG_FILE,
        TOTP_CONFIG_FILE + ".bak-" + time.strftime(
            "%Y%m%d-%H%M%S", time.gmtime()
        ),
    )
    write_totp_config({
        "enabled": False,
        "unbound_at": int(time.time()),
    })
    return jsonify({
        "ok": True,
        "bound": False,
    })


@APP.post("/api/admin-password")
def change_admin_password():

    auth = request.authorization
    if not auth or auth.username != "admin":
        return jsonify({
            "ok": False,
            "error": "当前登录身份无权修改密码",
        }), 403

    origin = request.headers.get("Origin", "")
    if origin:
        parsed = urllib.parse.urlparse(origin)
        request_hostname = request.host.split(":", 1)[0].lower()
        if (
            parsed.scheme != "https"
            or (parsed.hostname or "").lower() != request_hostname
        ):
            return jsonify({
                "ok": False,
                "error": "请求来源无效",
            }), 403

    payload = request.get_json(silent=True) or {}
    password = str(payload.get("password", ""))

    if len(password) < 12 or len(password) > 128:
        return jsonify({
            "ok": False,
            "error": "密码长度必须为12至128位",
        }), 400

    if any(ord(ch) < 33 or ord(ch) > 126 for ch in password):
        return jsonify({
            "ok": False,
            "error": "密码只能使用英文半角可见字符，不能包含空格",
        }), 400

    try:
        generated = subprocess.run(
            ["openssl", "passwd", "-apr1", "-stdin"],
            input=password,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=True,
        ).stdout.strip()

        if not generated.startswith("$apr1$"):
            raise RuntimeError("密码哈希生成失败")

        new_data = ("admin:" + generated + "\n").encode("ascii")
        old_data = open(ADMIN_AUTH_FILE, "rb").read()
        backup = (
            ADMIN_AUTH_FILE
            + ".bak-ui-"
            + time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        )
        shutil.copy2(ADMIN_AUTH_FILE, backup)
        atomic_auth_write(ADMIN_AUTH_FILE, new_data)

        encoded = base64.b64encode(new_data).decode("ascii")
        command = "python3 -c " + shlex.quote(HK_AUTH_REMOTE)
        synced = subprocess.run(
            HK_AUTH_SSH + [command],
            input=encoded,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )

        if synced.returncode != 0 or synced.stdout.strip() != "ok":
            atomic_auth_write(ADMIN_AUTH_FILE, old_data)
            raise RuntimeError("香港后台同步失败，已恢复旧密码")

    except Exception as exc:
        APP.logger.exception("admin password update failed")
        return jsonify({
            "ok": False,
            "error": str(exc),
        }), 500

    return jsonify({
        "ok": True,
    })



# Protected violation-mail extension; no changes to existing auth or TOTP.
import sys as _violation_sys
_violation_sys.path.insert(0, "/opt/security-mail-alerts")
from violation_mail_plugin import register as _register_violation_mail
_register_violation_mail(APP, admin_request, same_origin_request, verify_view_key)


# Dedicated user access lifecycle; audit history has no traffic retention.
import sys
sys.path.insert(0, '/opt/submerge-user-access')
from admin_registration import install as install_user_access
from control_backend import ControlBackend
install_user_access(APP, admin_request, same_origin_request, verify_view_key,
    totp_enabled, backend=ControlBackend(), allowed_origins=('https://dnode.titanyung.click:31880', 'https://node.titanyung.click:31880', 'https://node.titanyung.click:9443', 'https://sub.titanyung.click:9443', 'https://dsub.titanyung.click:9443', 'https://sgnode.titanyungty.top:9443'))

# Seven security pages; existing authenticated APIs remain authoritative.
import os as _center_os
import sys as _center_sys
_center_sys.path.insert(0,_center_os.environ.get('SECURITY_CENTER_MODULE_DIR','/opt/submerge-security-center'))
from center_plugin import register as _register_security_center
_register_security_center(APP,HTML,admin_request,same_origin_request,verify_view_key,totp_enabled,ControlBackend())

if __name__ == "__main__":

    APP.run(
        host="127.0.0.1",
        port=int(_center_os.environ.get('SECURITY_CENTER_PORT','18082')),
        debug=False,
    )

#!/usr/bin/env python3

import ipaddress
import json
import re
import subprocess
import time

from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo


LOG_DIR = Path("/var/log/submerge-access")

RETENTION_DAYS = 7

TZ = ZoneInfo("Asia/Shanghai")


LOG_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# S-UI / sing-box 实际日志格式
#
# INFO - inbound/anytls[anytls-main] [wrt]
# inbound connection to www.google.com:443
# ============================================================

CONN_RE = re.compile(
    r"""
    (?:INFO|DEBUG|TRACE)
    \s*-\s*
    inbound/
    (?P<proto>[^\[]+)
    \[
        (?P<inbound>[^\]]+)
    \]
    \s*
    \[
        (?P<user>[^\]]+)
    \]
    \s*
    inbound\s+connection\s+to\s+
    (?P<target>\S+)
    """,
    re.X,
)


# ============================================================
# 不记录这些内部流量
# ============================================================

IGNORE_HOSTS = {
    "sgnode.titanyungty.top",
    "103.26.8.100",
    "179.255.136.79",
    "localhost",
    "127.0.0.1",
}


def split_target(target):

    target = str(
        target
    ).strip()


    # IPv6
    if target.startswith("["):

        match = re.match(
            r"^\[(.+)\]:(\d+)$",
            target,
        )

        if match:

            return (
                match.group(1),
                int(match.group(2)),
            )


    # 域名 / IPv4
    if ":" in target:

        host, port = target.rsplit(
            ":",
            1,
        )

        try:

            return (
                host,
                int(port),
            )

        except Exception:

            pass


    return (
        target,
        None,
    )


def should_ignore_record(record):

    host = str(
        record.get(
            "host",
            "",
        )
    ).strip().lower()


    port = record.get(
        "port"
    )


    # 自己服务器
    if host in IGNORE_HOSTS:

        return True


    # DNS 查询
    if port == 53:

        return True


    # 私网 / 回环 / 链路本地
    try:

        ip = ipaddress.ip_address(
            host
        )


        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
        ):

            return True


    except Exception:

        pass


    return False


# ============================================================
# 严格只保留 7 个自然日
#
# 今天 + 前6天
# ============================================================

def cleanup_old_logs():

    cutoff = (
        datetime.now(TZ).date()
        - timedelta(
            days=RETENTION_DAYS - 1
        )
    )


    for path in LOG_DIR.glob(
        "*.jsonl"
    ):

        try:

            file_date = datetime.strptime(
                path.stem,
                "%Y-%m-%d",
            ).date()


        except Exception:

            continue


        if file_date < cutoff:

            try:

                path.unlink()

                print(
                    "[cleanup] deleted:",
                    path,
                    flush=True,
                )


            except Exception as exc:

                print(
                    "[cleanup] failed:",
                    path,
                    exc,
                    flush=True,
                )


def write_record(record):

    if should_ignore_record(
        record
    ):

        return


    now = datetime.now(TZ)


    path = (
        LOG_DIR
        / (
            now.strftime(
                "%Y-%m-%d"
            )
            + ".jsonl"
        )
    )


    with path.open(
        "a",
        encoding="utf-8",
    ) as file:

        file.write(
            json.dumps(
                record,
                ensure_ascii=False,
            )
            + "\n"
        )


def parse_line(line):

    match = CONN_RE.search(
        line
    )


    if not match:

        return None


    host, port = split_target(
        match.group(
            "target"
        )
    )


    return {

        "time":
            datetime.now(TZ)
            .isoformat(
                timespec="seconds"
            ),

        "user":
            match.group(
                "user"
            )
            or "unknown",

        "inbound":
            match.group(
                "inbound"
            ),

        "inbound_protocol":
            match.group(
                "proto"
            ).strip(),

        "target":
            match.group(
                "target"
            ),

        "host":
            host,

        "port":
            port,
    }


def main():

    cleanup_old_logs()


    print(
        "[access] collector started",
        flush=True,
    )


    proc = subprocess.Popen(
        [
            "journalctl",
            "-u",
            "s-ui.service",
            "-f",
            "-n",
            "0",
            "-o",
            "cat",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )


    if proc.stdout is None:

        raise RuntimeError(
            "journalctl stdout unavailable"
        )


    last_cleanup = time.time()


    for line in proc.stdout:

        record = parse_line(
            line
        )


        if record:

            write_record(
                record
            )


        # 每小时清理
        if (
            time.time()
            - last_cleanup
            >= 3600
        ):

            cleanup_old_logs()

            last_cleanup = time.time()


if __name__ == "__main__":

    main()

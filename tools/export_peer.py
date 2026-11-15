#!/usr/bin/env python3
"""Read-only custom-source snapshot for audited peer hosts.

Execute from stdin over pinned SSH, e.g. ``python3 - manifest --profile
lazycat-sg``. The archive stream is private until source review. It does not
include any /etc config, database, key, log, backup or runtime state.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile


PROFILES = {
    "lazycat-sg": ("/usr/local/lib/lazycat-edge",),
    "bytevirt-hk": ("/opt/hk-traffic-dashboard",),
}
SUFFIXES = frozenset((".py", ".js", ".css", ".html", ".md", ".sh",
                      ".service", ".timer", ".conf"))
SKIP_DIRS = frozenset((".git", ".private", ".venv", "venv", "node_modules",
                       "__pycache__", "data", "db", "database", "logs", "log",
                       "backups", "backup", "cache", "state", "tmp", "temp"))
SKIP_NAME = re.compile(
    r"(?i)(?:^\.|\.(?:bak|backup|old|orig|tmp|log|db|sqlite|sqlite3|pem|key|"
    r"p12|pfx|crt|cer|pub|sock|sent)(?:$|-)|secret|credential|password|token|"
    r"known.host|private.key)"
)
RISK = {
    "private_key_block": re.compile(rb"-----BEGIN (?:RSA |OPENSSH |EC |)PRIVATE KEY-----"),
    "credential_url": re.compile(rb"https?://[^\s:@/]+:[^\s@/]+@"),
    "credential_prefix": re.compile(rb"(?:ghp_|xoxb-|sk-[A-Za-z0-9]{20})"),
    "literal_secret_assignment": re.compile(
        rb"(?im)^\s*[A-Z][A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)"
        rb"[A-Z0-9_]*\s*=\s*['\"](?!/)[^'\"\r\n]{8,}['\"]"
    ),
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def eligible(root, path):
    if path.is_symlink() or not path.is_file():
        return False
    parts = path.relative_to(root).parts
    if any(part in SKIP_DIRS or part.startswith(".") for part in parts[:-1]):
        return False
    if SKIP_NAME.search(path.name):
        return False
    return path.suffix.lower() in SUFFIXES or path.name == "requirements.txt"


def collect(profile):
    files = []
    blobs = {}
    for name in PROFILES[profile]:
        root = Path(name)
        if not root.is_dir() or root.is_symlink() or root.resolve() != root:
            raise RuntimeError("source_root_missing_or_changed")
        for path in sorted(root.rglob("*")):
            if not eligible(root, path):
                continue
            if path.stat().st_size > 2 * 1024 * 1024:
                raise RuntimeError("source_file_too_large")
            raw = path.read_bytes()
            relative = path.relative_to("/").as_posix()
            files.append({
                "path": relative,
                "bytes": len(raw),
                "sha256": digest(raw),
                "mode": oct(stat.S_IMODE(path.stat().st_mode)),
                "risk_flags": [label for label, rx in RISK.items() if rx.search(raw)],
            })
            blobs[relative] = raw
    files.sort(key=lambda row: row["path"])
    manifest = {
        "schema": 1,
        "origin": profile,
        "roots": list(PROFILES[profile]),
        "file_count": len(files),
        "total_bytes": sum(row["bytes"] for row in files),
        "files": files,
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["manifest_sha256"] = digest(canonical)
    return manifest, blobs


def archive(manifest, blobs, approved):
    if approved != manifest["manifest_sha256"]:
        raise RuntimeError("reviewed_manifest_hash_required")
    if any(row["risk_flags"] for row in manifest["files"]):
        raise RuntimeError("source_risk_flags_require_manual_review")
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as tar:
        body = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
        entry = tarfile.TarInfo("MANIFEST.json")
        entry.size, entry.mode = len(body), 0o600
        entry.uid = entry.gid = entry.mtime = 0
        tar.addfile(entry, io.BytesIO(body))
        for row in manifest["files"]:
            raw = blobs[row["path"]]
            if digest(raw) != row["sha256"]:
                raise RuntimeError("source_changed_during_snapshot")
            entry = tarfile.TarInfo(row["path"])
            entry.size = len(raw)
            entry.mode = int(row["mode"], 8)
            entry.uid = entry.gid = entry.mtime = 0
            tar.addfile(entry, io.BytesIO(raw))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("manifest", "archive"))
    parser.add_argument("--profile", choices=tuple(PROFILES), required=True)
    parser.add_argument("--approve-sha256", default="")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise RuntimeError("run_on_audited_peer_as_root")
    manifest, blobs = collect(args.profile)
    if args.mode == "manifest":
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
    else:
        archive(manifest, blobs, args.approve_sha256)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("snapshot_refused=" + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)

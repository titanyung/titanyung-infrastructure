#!/usr/bin/env python3
"""Read-only, allowlisted DMIT source snapshot; never reads runtime data.

Run this *on DMIT* after reviewing this file. ``manifest`` prints only file
metadata. ``archive`` needs the reviewed manifest hash and streams a tar to
stdout; the caller is responsible for storing it outside the production host.
No credentials, databases, logs or generated state are intentionally included.
An archive is still private until a human has reviewed the source contents.
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


ROOTS = (
    "/opt/submerge",
    "/opt/submerge-topology",
    "/opt/submerge-routing",
    "/opt/submerge-client-policy",
    "/opt/submerge-user-access",
    "/opt/submerge-edge",
    "/opt/submerge-security-center",
    "/opt/submerge-staging",
    "/opt/sg-traffic-dashboard",
    "/opt/sg-traffic-dashboard-expiry-prod",
    "/opt/static-connection-events",
    "/opt/user-daily-traffic",
    "/opt/security-mail-alerts",
    "/opt/paoluz-pools",
    "/opt/ledger-system",
    "/usr/local/lib/lazycat-edge",
)
SOURCE_SUFFIXES = frozenset({
    ".py", ".js", ".css", ".html", ".md", ".service", ".timer", ".conf",
})
SKIP_DIRS = frozenset({
    ".git", ".private", ".venv", "venv", "node_modules", "__pycache__",
    "data", "db", "database", "logs", "log", "backups", "backup", "cache",
    "state", "tmp", "temp", "tests-output", "qa-output",
})
SKIP_NAME = re.compile(
    r"(?i)(?:^\.|(?:\.bak|\.backup|\.old|\.orig|\.tmp|\.log|\.db|\.sqlite|"
    r"\.sqlite3|\.pem|\.key|\.p12|\.pfx|\.crt|\.cer|\.pub|\.sock|\.sent)$|"
    r"(?:secret|credential|password|token|known.host|private.key))"
)
RISK_PATTERNS = {
    "private_key_block": re.compile(rb"-----BEGIN (?:RSA |OPENSSH |EC |)PRIVATE KEY-----"),
    "credential_url": re.compile(rb"https?://[^\s:@/]+:[^\s@/]+@"),
    "credential_prefix": re.compile(rb"(?:ghp_|xoxb-|sk-[A-Za-z0-9]{20})"),
    "literal_secret_assignment": re.compile(
        rb"(?im)^\s*[A-Z][A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)"
        rb"[A-Z0-9_]*\s*=\s*['\"](?!/)[^'\"\r\n]{8,}['\"]"
    ),
}
REDACT_NATIVE_SECRET_DEFAULT = re.compile(
    rb"(?m)(\bnative_secret\s*=\s*['\"])/[^'\"\r\n]+(['\"])"
)
REDACTION_SOURCE_SHA256 = {
    "opt/submerge-user-access/production_adapter.py":
        "f813bfb021db7f42059c855ee1232258061cc15c8aedb31b8dd35bfab82aaff6",
    "opt/submerge-routing/client_bootstrap.py":
        "613f7530e97bfbb8e74a6ce6a898e9985ba75158fd75100a330369e52405c429",
    "opt/submerge-user-access/purge_codecs.py":
        "c3bfc0766987b83f38b93b541e2771e59f91a3f0fe45cd5085730a5e51511169",
}
REDACT_OFFLINE_FIXTURE_PASSWORD = re.compile(
    rb"(?m)('password'\s*:\s*')[^'\r\n]+(')"
)
REDACT_BLOCKED_NODE_PASSWORD = re.compile(
    rb"(?m)('password'\s*:\s*')[^'\r\n]+(')"
)
REDACT_BLOCKED_URI_USERINFO = re.compile(
    rb"(?m)^BLOCKED_URI='ss://'\+base64\.urlsafe_b64encode\(b'[^'\r\n]+'\)"
    rb"\.decode\(\)\.rstrip\('='\)\+'@127\.0\.0\.1:9#'"
    rb"\+urllib\.parse\.quote\(BLOCKED_NAME,safe=''\)(?=\r?$)"
)


def redact_once(raw, pattern, replacement, failure):
    changed, count = pattern.subn(replacement, raw)
    if count != 1:
        raise RuntimeError(failure)
    return changed


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def eligible(root, path):
    if path.is_symlink() or not path.is_file():
        return False
    relative = path.relative_to(root)
    if any(part in SKIP_DIRS or part.startswith(".") for part in relative.parts[:-1]):
        return False
    if SKIP_NAME.search(path.name):
        return False
    if path.suffix.lower() in SOURCE_SUFFIXES:
        return True
    if path.name == "requirements.txt":
        return True
    if path.name == "manifest.webmanifest" and "static" in relative.parts:
        return True
    if path.suffix.lower() == ".png" and "static" in relative.parts and re.search(
        r"(?i)(?:pwa|icon|logo)[-_a-z0-9]*\.png$", path.name
    ):
        return True
    return False


def collect():
    files = []
    blobs = {}
    for name in ROOTS:
        root = Path(name)
        if not root.is_dir() or root.is_symlink() or root.resolve() != root:
            raise RuntimeError("allowlisted_root_missing_or_changed")
        for path in sorted(root.rglob("*")):
            if not eligible(root, path):
                continue
            if path.stat().st_size > 2 * 1024 * 1024:
                raise RuntimeError("allowlisted_source_file_too_large")
            source = path.read_bytes()
            raw = source
            redacted = []
            relative = path.relative_to("/").as_posix()
            if relative == "opt/ledger-system/tests/test_app.py":
                continue  # Test fixtures contain many literal sample passwords.
            if relative in REDACTION_SOURCE_SHA256 and (
                sha256(source) != REDACTION_SOURCE_SHA256[relative]
            ):
                raise RuntimeError("redaction_source_changed")
            if relative == "opt/submerge-user-access/production_adapter.py":
                raw = redact_once(
                    raw, REDACT_NATIVE_SECRET_DEFAULT,
                    rb"\g<1>/etc/REPLACE_AT_DEPLOY/native-secret\g<2>",
                    "native_secret_default_changed",
                )
                redacted.append("native_secret_default_path")
            elif relative == "opt/submerge-routing/client_bootstrap.py":
                raw = redact_once(
                    raw, REDACT_OFFLINE_FIXTURE_PASSWORD,
                    rb"\g<1>REPLACE_OFFLINE_FIXTURE_PASSWORD\g<2>",
                    "offline_fixture_password_changed",
                )
                redacted.append("offline_fixture_password")
            elif relative == "opt/submerge-user-access/purge_codecs.py":
                raw = redact_once(
                    raw, REDACT_BLOCKED_NODE_PASSWORD,
                    rb"\g<1>REPLACE_BLOCKED_NODE_PASSWORD\g<2>",
                    "blocked_node_placeholder_password_changed",
                )
                redacted.append("blocked_node_placeholder_password")
                raw = redact_once(
                    raw, REDACT_BLOCKED_URI_USERINFO,
                    rb"BLOCKED_URI='ss://REPLACE_BLOCKED_URI_USERINFO@127.0.0.1:9#'"
                    rb"+urllib.parse.quote(BLOCKED_NAME,safe='')",
                    "blocked_node_uri_userinfo_changed",
                )
                redacted.append("blocked_node_uri_userinfo")
            risk = [label for label, pattern in RISK_PATTERNS.items() if pattern.search(raw)]
            files.append({
                "path": relative,
                "bytes": len(raw),
                "sha256": sha256(raw),
                "source_bytes": len(source),
                "source_sha256": sha256(source),
                "mode": oct(stat.S_IMODE(path.stat().st_mode)),
                "redacted_fields": redacted,
                "risk_flags": risk,
            })
            blobs[relative] = raw
    files.sort(key=lambda item: item["path"])
    manifest = {
        "schema": 1,
        "origin": "DMIT source snapshot, not a deployment bundle",
        "roots": list(ROOTS),
        "file_count": len(files),
        "total_bytes": sum(item["bytes"] for item in files),
        "files": files,
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["manifest_sha256"] = sha256(canonical)
    return manifest, blobs


def archive(manifest, blobs, approved):
    if approved != manifest["manifest_sha256"]:
        raise RuntimeError("reviewed_manifest_hash_required")
    if any(item["risk_flags"] for item in manifest["files"]):
        raise RuntimeError("source_risk_flags_require_manual_review")
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as stream:
        manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
        entry = tarfile.TarInfo("MANIFEST.json")
        entry.size = len(manifest_bytes)
        entry.mode = 0o600
        entry.uid = entry.gid = entry.mtime = 0
        stream.addfile(entry, io.BytesIO(manifest_bytes))
        for item in manifest["files"]:
            raw = blobs[item["path"]]
            if sha256(raw) != item["sha256"]:
                raise RuntimeError("source_changed_during_snapshot")
            entry = tarfile.TarInfo(item["path"])
            entry.size = len(raw)
            entry.mode = int(item["mode"], 8)
            entry.uid = entry.gid = entry.mtime = 0
            stream.addfile(entry, io.BytesIO(raw))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("manifest", "archive"))
    parser.add_argument("--approve-sha256", default="")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise RuntimeError("run_on_dmit_as_root")
    manifest, blobs = collect()
    if args.mode == "manifest":
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
    else:
        archive(manifest, blobs, args.approve_sha256)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never print source bytes or exception paths to an operator transcript.
        print("snapshot_refused=" + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)

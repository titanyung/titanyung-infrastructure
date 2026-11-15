#!/usr/bin/env python3
"""Check a staged source directory before it is uploaded.

Usage:
    python verify_package.py DIRECTORY [--manifest MANIFEST.json]

If DIRECTORY/MANIFEST.json exists, it is used automatically. The supported
manifest is a JSON object with a ``files`` list of ``path`` and ``sha256``
entries. The DMIT exporter schema also includes ``bytes``, ``risk_flags``,
``file_count``, ``total_bytes`` and ``manifest_sha256``; all are verified.

This command reports only relative paths, issue names and counts. It never
prints file contents, credential candidates or hash values. A clean scan
exits 0; any issue or unreadable input exits 1.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple


MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_MANIFEST_BYTES = 10 * 1024 * 1024
MAX_PRINTED_ISSUES = 100

BLOCKED_DIRS = {
    ".private", ".ssh", ".git", ".hg", ".svn", ".work",
    ".codex-attachments", ".codex-remote-attachments", "sources",
    "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".venv", "venv", "env", "test-results",
    "playwright-report", "logs", "backups", "snapshots", "dumps",
    ".aws", ".azure", ".docker", ".gnupg", ".kube",
    "private", "secrets", "credentials", "certs", "certificates",
    "keys", "ssh", "runtime-data",
}
BLOCKED_SUFFIXES = {
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
    ".env", ".db", ".sqlite", ".sqlite3", ".jsonl", ".log",
    ".tar", ".tgz", ".gz", ".zip", ".7z", ".bak", ".old",
    ".backup", ".secret", ".pyc", ".pyo", ".kdbx",
    ".ovpn", ".mobileconfig", ".age", ".gpg", ".asc",
}
BLOCKED_NAMES = {
    ".npmrc", ".pypirc", ".netrc", ".htpasswd", "htpasswd",
    "authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa",
    "id_dsa", "credentials", "credentials.json", "token.json",
    ".envrc",
}
HASH_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
PREFIX_RE = re.compile(r"[A-Za-z]:|//")

# Search bytes so that an undecodable file cannot bypass credential checks.
# Each expression is deliberately conservative: a false positive blocks an
# upload for review; it never causes a credential value to be printed.
CONTENT_PATTERNS = {
    "private_key": re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "pgp_private_key": re.compile(rb"-----BEGIN PGP " rb"PRIVATE KEY BLOCK-----"),
    "bearer_or_basic": re.compile(
        rb"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"
    ),
    "authorization_header": re.compile(
        rb"(?i)(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?"
        rb"(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"
    ),
    "credential_assignment": re.compile(
        rb"(?i)(?<![/\-])\b(?:[a-z0-9]+[_-])*(?:password|passwd|pwd|token|secret|api[_-]?key|"
        rb"access[_-]?key|client[_-]?secret|private[_-]?key|"
        rb"auth[_-]?token|credentials?)\b[\"']?\s*[:=]\s*"
        rb"(?:[\"'][^\"'\r\n]{8,}[\"']|[A-Za-z0-9_+./=-]{12,})"
    ),
    "url_credentials": re.compile(
        rb"(?i)[a-z][a-z0-9+.-]*://[^/\s:@]{1,128}:[^@/\s]{4,}@"
    ),
    "query_credential": re.compile(
        rb"(?i)[?&](?:token|secret|password|passwd|api[_-]?key|"
        rb"access[_-]?key|auth)=([^&\s]{8,})"
    ),
    "credential_prefix": re.compile(
        rb"(?:ghp_[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9-]{20,}|"
        rb"sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})"
    ),
    "password_hash": re.compile(
        rb"(?m)^[^:\s]{1,64}:\$(?:apr1|2[aby]|y)\$"
    ),
}
NATIVE_SECRET_PLACEHOLDER = re.compile(
    rb"(?i)native_secret\s*=\s*['\"]/etc/REPLACE_AT_DEPLOY/native-secret['\"]\Z"
)
APPROVED_REDACTIONS = {
    "opt/submerge-user-access/production_adapter.py": (
        "native_secret_default_path",
    ),
    "opt/submerge-routing/client_bootstrap.py": (
        "offline_fixture_password",
    ),
    "opt/submerge-user-access/purge_codecs.py": (
        "blocked_node_placeholder_password",
        "blocked_node_uri_userinfo",
    ),
}
REDACTION_MARKERS = {
    "native_secret_default_path": b"/etc/REPLACE_AT_DEPLOY/native-secret",
    "offline_fixture_password": b"REPLACE_OFFLINE_FIXTURE_PASSWORD",
    "blocked_node_placeholder_password": b"REPLACE_BLOCKED_NODE_PASSWORD",
    "blocked_node_uri_userinfo": b"REPLACE_BLOCKED_URI_USERINFO",
}
FETCH_CREDENTIALS_MODE = re.compile(
    rb"(?i)credentials[\"']?\s*[:=]\s*[\"'](?:include|same-origin|omit)[\"']\Z"
)
SOURCE_EXTENSIONS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}


def is_reparse(path: Path) -> bool:
    """Treat Windows junctions and other reparse points like symlinks."""
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


def valid_relative(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    if value.startswith("/") or PREFIX_RE.match(value):
        return False
    if any(ord(char) < 32 for char in value):
        return False
    return all(
        part not in ("", ".", "..") and ":" not in part
        for part in value.split("/")
    )


def blocked_dir(name: str) -> bool:
    lower = name.casefold()
    return (
        lower in BLOCKED_DIRS
        or lower.startswith("backup-")
        or lower.startswith("snapshot-")
        or lower.endswith("-private")
    )


def blocked_file(name: str) -> bool:
    lower = name.casefold()
    if lower in BLOCKED_NAMES:
        return True
    if lower.startswith(".env.") or lower.startswith("known_hosts"):
        return True
    if lower.startswith("known-hosts") or lower.endswith("known-hosts"):
        return True
    if lower.endswith((".db-wal", ".db-shm", ".sqlite-wal", ".sqlite-shm",
                       ".sqlite3-wal", ".sqlite3-shm")):
        return True
    return Path(lower).suffix in BLOCKED_SUFFIXES


def safe_label(value: str) -> str:
    """Keep a malicious filename from adding terminal control lines."""
    return json.dumps(value, ensure_ascii=False)


def unique_json(pairs: List[Tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def parse_manifest(path: Path, issues: List[Tuple[str, str]],
                   pinned_hash: Optional[str] = None) -> Optional[Dict[str, dict]]:
    try:
        if is_reparse(path) or not path.is_file():
            raise ValueError("manifest_not_regular_file")
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValueError("manifest_too_large")
        with path.open("r", encoding="utf-8") as source:
            manifest = json.load(source, object_pairs_hook=unique_json)
        if not isinstance(manifest, dict):
            raise ValueError("manifest_not_object")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        issues.append(("MANIFEST.json", "invalid_manifest:" + type(error).__name__))
        return None

    if manifest.get("schema") != 1:
        issues.append(("MANIFEST.json", "unsupported_manifest_schema"))
    expected_self_hash = manifest.get("manifest_sha256")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    actual_self_hash = hashlib.sha256(canonical).hexdigest()
    if not isinstance(expected_self_hash, str) or not HASH_RE.fullmatch(expected_self_hash):
        issues.append(("MANIFEST.json", "invalid_manifest_hash"))
    elif actual_self_hash != expected_self_hash.lower():
        issues.append(("MANIFEST.json", "manifest_hash_mismatch"))
    if pinned_hash is not None and actual_self_hash != pinned_hash.lower():
        issues.append(("MANIFEST.json", "pinned_manifest_hash_mismatch"))

    entries = manifest.get("files")
    if not isinstance(entries, list):
        issues.append(("MANIFEST.json", "manifest_files_not_list"))
        return None
    if "file_count" in manifest and (
        type(manifest["file_count"]) is not int or manifest["file_count"] != len(entries)
    ):
        issues.append(("MANIFEST.json", "manifest_file_count_mismatch"))

    expected: Dict[str, dict] = {}
    casefolded = set()
    size_total = 0
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            issues.append(("MANIFEST.json", "invalid_manifest_entry"))
            continue
        relative = item.get("path")
        digest = item.get("sha256")
        if not valid_relative(relative):
            issues.append(("MANIFEST.json", "invalid_manifest_path"))
            continue
        if not isinstance(digest, str) or not HASH_RE.fullmatch(digest):
            issues.append((relative, "invalid_file_hash"))
            continue
        folded = relative.casefold()
        if relative in expected or folded in casefolded:
            issues.append((relative, "duplicate_manifest_path"))
            continue
        expected[relative] = item
        casefolded.add(folded)
        if "bytes" in item:
            if type(item["bytes"]) is not int or item["bytes"] < 0:
                issues.append((relative, "invalid_manifest_size"))
            else:
                size_total += item["bytes"]
        if "risk_flags" in item and not isinstance(item["risk_flags"], list):
            issues.append((relative, "invalid_risk_metadata"))
        elif item.get("risk_flags"):
            issues.append((relative, "manifest_risk_flag"))
        redacted = item.get("redacted_fields", [])
        if not isinstance(redacted, list) or any(not isinstance(x, str) for x in redacted):
            issues.append((relative, "invalid_redaction_metadata"))
            continue
        source_hash = item.get("source_sha256")
        source_bytes = item.get("source_bytes")
        if source_hash is not None and (
            not isinstance(source_hash, str) or not HASH_RE.fullmatch(source_hash)
        ):
            issues.append((relative, "invalid_source_hash"))
        if source_bytes is not None and (type(source_bytes) is not int or source_bytes < 0):
            issues.append((relative, "invalid_source_size"))
        if redacted:
            if (
                tuple(redacted) != APPROVED_REDACTIONS.get(relative)
                or not isinstance(source_hash, str)
                or not HASH_RE.fullmatch(source_hash)
                or source_hash.lower() == digest.lower()
                or type(source_bytes) is not int
            ):
                issues.append((relative, "unapproved_redaction"))
        elif isinstance(source_hash, str) and source_hash.lower() != digest.lower():
            issues.append((relative, "unrecorded_source_difference"))
        if not redacted and source_bytes is not None and item.get("bytes") != source_bytes:
            issues.append((relative, "unrecorded_size_difference"))
    if "total_bytes" in manifest and manifest["total_bytes"] != size_total:
        issues.append(("MANIFEST.json", "manifest_total_bytes_mismatch"))
    return expected


def python_concat_spans(data: bytes) -> List[Tuple[int, int]]:
    """Locate Python string tokens whose value is assembled dynamically."""
    try:
        tree = ast.parse(data.decode("utf-8"))
    except (SyntaxError, UnicodeError):
        return []
    starts = [0]
    for line in data.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    spans = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if not hasattr(node, "end_lineno"):
            continue
        if not isinstance(parents.get(node), (ast.BinOp, ast.JoinedStr)):
            continue
        spans.append((
            starts[node.lineno - 1] + node.col_offset,
            starts[node.end_lineno - 1] + node.end_col_offset,
        ))
    return spans


def scan_content(data: bytes, suffix: str,
                 allowed_redactions: Tuple[str, ...] = ()) -> List[str]:
    findings = []
    concat_spans = python_concat_spans(data) if suffix == ".py" else []
    for name, pattern in CONTENT_PATTERNS.items():
        matches = list(pattern.finditer(data))
        if name == "credential_assignment":
            kept = []
            for match in matches:
                raw = match.group(0)
                split = re.search(rb"[:=]", raw)
                right = raw[split.end():].strip() if split else b""
                if ("native_secret_default_path" in allowed_redactions
                        and NATIVE_SECRET_PLACEHOLDER.fullmatch(raw)):
                    continue
                if ("offline_fixture_password" in allowed_redactions
                        and b"REPLACE_OFFLINE_FIXTURE_PASSWORD" in raw):
                    continue
                if ("blocked_node_placeholder_password" in allowed_redactions
                        and b"REPLACE_BLOCKED_NODE_PASSWORD" in raw):
                    continue
                if FETCH_CREDENTIALS_MODE.fullmatch(raw):
                    continue
                if right[:1] not in (b"\"", b"'") and suffix in SOURCE_EXTENSIONS:
                    # A bare identifier/expression in source code is a reference.
                    # Markdown, JSON and config text still scan bare literals.
                    continue
                if suffix == ".py" and any(
                    start <= match.start() < end < match.end()
                    for start, end in concat_spans
                ):
                    # An assignment assembled across source string tokens is
                    # not a quoted literal present in the emitted content.
                    continue
                if (suffix in SOURCE_EXTENSIONS and b"fixture" in right.lower()) or (
                    b"REDACTED" in right or b"PLACEHOLDER" in right
                ):
                    continue
                kept.append(match)
            matches = kept
        elif name == "query_credential":
            matches = [match for match in matches if not re.search(
                rb"=[{][a-zA-Z_][a-zA-Z0-9_]*[}][\"']?\Z",
                match.group(0),
            )]
        elif name == "url_credentials" and "blocked_node_uri_userinfo" in allowed_redactions:
            matches = [match for match in matches if
                       b"REPLACE_BLOCKED_URI_USERINFO" not in match.group(0)]
        if matches:
            findings.append(name)
    if suffix == ".png":
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            findings.append("invalid_png")
    else:
        try:
            data.decode("utf-8")
        except UnicodeError:
            findings.append("non_utf8_or_binary")
        if b"\x00" in data:
            findings.append("binary_content")
    return findings


def walk_package(root: Path, manifest_path: Optional[Path],
                 expected: Optional[Dict[str, dict]],
                 issues: List[Tuple[str, str]]) -> Dict[str, Tuple[int, str]]:
    found: Dict[str, Tuple[int, str]] = {}
    folded = set()

    def visit(directory: Path, prefix: str) -> None:
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError:
            issues.append((prefix or ".", "unreadable_directory"))
            return
        for child in children:
            relative = prefix + "/" + child.name if prefix else child.name
            path = Path(child.path)
            try:
                info = path.lstat()
            except OSError:
                issues.append((relative, "unreadable_entry"))
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                issues.append((relative, "symlink_or_reparse_point"))
                continue
            if stat.S_ISDIR(info.st_mode):
                if blocked_dir(child.name):
                    issues.append((relative, "blocked_directory"))
                else:
                    visit(path, relative)
                continue
            if not stat.S_ISREG(info.st_mode):
                issues.append((relative, "non_regular_file"))
                continue
            if manifest_path is not None and path.absolute() == manifest_path.absolute():
                continue
            if blocked_file(child.name):
                issues.append((relative, "blocked_filename"))
                continue
            if relative.casefold() in folded:
                issues.append((relative, "case_colliding_path"))
                continue
            folded.add(relative.casefold())
            if info.st_size > MAX_FILE_BYTES:
                issues.append((relative, "file_too_large"))
                continue
            try:
                with path.open("rb") as source:
                    data = source.read(MAX_FILE_BYTES + 1)
                after = path.lstat()
                if is_reparse(path) or (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    issues.append((relative, "file_changed_during_scan"))
                    continue
            except OSError:
                issues.append((relative, "unreadable_file"))
                continue
            if len(data) > MAX_FILE_BYTES:
                issues.append((relative, "file_too_large"))
                continue
            suffix = path.suffix.casefold()
            if suffix == ".png" and (
                "static" not in [part.casefold() for part in Path(relative).parts]
                or not re.fullmatch(r"(?i)(?:pwa|icon|logo)[-_a-z0-9]*\.png", path.name)
            ):
                issues.append((relative, "unapproved_binary_asset"))
            manifest_item = expected.get(relative) if expected is not None else None
            allowed_redactions: Tuple[str, ...] = ()
            recorded_redactions = manifest_item.get("redacted_fields", ()) if manifest_item else ()
            if (
                manifest_item is not None
                and isinstance(recorded_redactions, (list, tuple))
                and tuple(recorded_redactions) == APPROVED_REDACTIONS.get(relative)
                and isinstance(manifest_item.get("source_sha256"), str)
                and HASH_RE.fullmatch(manifest_item["source_sha256"])
                and manifest_item["source_sha256"].lower() != manifest_item["sha256"].lower()
            ):
                allowed_redactions = tuple(manifest_item["redacted_fields"])
                for field in allowed_redactions:
                    if REDACTION_MARKERS[field] not in data:
                        issues.append((relative, "missing_redaction_marker"))
            for finding in scan_content(data, suffix, allowed_redactions):
                issues.append((relative, finding))
            found[relative.replace("\\", "/")] = (len(data), hashlib.sha256(data).hexdigest())

    visit(root, "")
    return found


def verify(root: Path, manifest_path: Optional[Path], require_manifest: bool,
           pinned_hash: Optional[str] = None) -> Tuple[int, List[Tuple[str, str]]]:
    issues: List[Tuple[str, str]] = []
    if ".." in root.parts:
        return 0, [(".", "path_traversal")]
    try:
        if is_reparse(root) or not root.is_dir():
            return 0, [(".", "invalid_or_linked_root")]
    except OSError:
        return 0, [(".", "unreadable_root")]
    auto_manifest = root / "MANIFEST.json"
    selected = manifest_path if manifest_path is not None else (
        auto_manifest if auto_manifest.exists() or auto_manifest.is_symlink() else None
    )
    if (require_manifest or pinned_hash is not None) and selected is None:
        issues.append(("MANIFEST.json", "manifest_required"))
    expected = parse_manifest(selected, issues, pinned_hash) if selected is not None else None
    found = walk_package(root, selected, expected, issues)
    if expected is not None:
        for relative, item in expected.items():
            if relative not in found:
                issues.append((relative, "missing_from_directory"))
                continue
            size, digest = found[relative]
            if digest != item["sha256"].lower():
                issues.append((relative, "sha256_mismatch"))
            if "bytes" in item and size != item["bytes"]:
                issues.append((relative, "size_mismatch"))
        for relative in found.keys() - expected.keys():
            issues.append((relative, "missing_from_manifest"))
    return len(found), issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="staged source directory")
    parser.add_argument("--manifest", type=Path, help="JSON manifest; defaults to DIRECTORY/MANIFEST.json")
    parser.add_argument("--require-manifest", action="store_true", help="fail if no JSON manifest is available")
    parser.add_argument("--expected-manifest-sha256", help="previously reviewed manifest digest")
    args = parser.parse_args()
    if args.expected_manifest_sha256 is not None and not HASH_RE.fullmatch(args.expected_manifest_sha256):
        parser.error("--expected-manifest-sha256 requires 64 hexadecimal characters")
    count, issues = verify(
        args.directory, args.manifest, args.require_manifest,
        args.expected_manifest_sha256,
    )
    ordered = sorted(set(issues), key=lambda issue: (issue[0].casefold(), issue[1]))
    for relative, kind in ordered[:MAX_PRINTED_ISSUES]:
        print(safe_label(relative) + " " + kind)
    if len(ordered) > MAX_PRINTED_ISSUES:
        print("additional_issues=" + str(len(ordered) - MAX_PRINTED_ISSUES))
    categories = Counter(kind for _, kind in ordered)
    print("files_scanned=" + str(count) + " issues=" + str(len(ordered)))
    if categories:
        print("issue_counts=" + ",".join(
            name + ":" + str(categories[name]) for name in sorted(categories)
        ))
    return 1 if ordered else 0


if __name__ == "__main__":
    sys.exit(main())

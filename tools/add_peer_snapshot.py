#!/usr/bin/env python3
"""Add a verified read-only peer source tar to the assembled local repository."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def safe_path(raw):
    parts = PurePosixPath(raw).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise RuntimeError("unsafe_archive_path")
    return Path(*parts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--peer", choices=("lazycat-sg", "bytevirt-hk", "starhub", "lazycat-hkt"), required=True)
    args = parser.parse_args()
    destination = args.repo / "peers" / args.peer
    if destination.exists():
        raise RuntimeError("peer_destination_already_exists")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest.get("origin") != args.peer:
        raise RuntimeError("peer_origin_mismatch")
    expected = {item["path"]: item for item in manifest["files"]}
    if len(expected) != manifest["file_count"] or any(item["risk_flags"] for item in expected.values()):
        raise RuntimeError("peer_manifest_rejected")
    with tarfile.open(args.archive, "r:") as tar:
        members = tar.getmembers()
        embedded = json.load(tar.extractfile(members[0])) if members and members[0].name == "MANIFEST.json" else None
        if embedded != manifest:
            raise RuntimeError("peer_manifest_mismatch")
        if len(members) - 1 != len(expected) or {m.name for m in members[1:]} != set(expected):
            raise RuntimeError("peer_member_set_mismatch")
        destination.mkdir(parents=True)
        for member in members[1:]:
            if not member.isfile():
                raise RuntimeError("peer_non_file_member")
            raw = tar.extractfile(member).read()
            item = expected[member.name]
            if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise RuntimeError("peer_file_mismatch")
            target = destination / "source" / safe_path(member.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    (destination / "source-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"peer_added=ok origin={args.peer} files={len(expected)}")


if __name__ == "__main__":
    main()

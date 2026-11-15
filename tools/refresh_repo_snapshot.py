#!/usr/bin/env python3
"""Replace an uncommitted DMIT snapshot with a newly verified redacted one."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def checked_path(root: Path, raw: str) -> Path:
    parts = PurePosixPath(raw).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise RuntimeError("unsafe_relative_path")
    return root.joinpath(*parts)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    root = args.repo / "source"
    old = json.loads((args.repo / "source-manifest.json").read_text(encoding="utf-8"))
    new = json.loads(args.manifest.read_text(encoding="utf-8"))
    old_files = {item["path"]: item for item in old["files"]}
    new_files = {item["path"]: item for item in new["files"]}
    if len(new_files) != new["file_count"] or any(row["risk_flags"] for row in new_files.values()):
        raise RuntimeError("new_manifest_rejected")
    removed = set(old_files) - set(new_files)
    if removed not in (set(), {"opt/ledger-system/tests/test_app.py"}):
        raise RuntimeError("unexpected_removed_file")
    if set(new_files) - set(old_files):
        raise RuntimeError("unexpected_added_file")
    for path, item in old_files.items():
        original = checked_path(root, path)
        if not original.is_file() or sha(original.read_bytes()) != item["sha256"]:
            raise RuntimeError("existing_snapshot_changed")
    with tarfile.open(args.archive, "r:") as archive:
        members = archive.getmembers()
        embedded = json.load(archive.extractfile(members[0])) if members and members[0].name == "MANIFEST.json" else None
        if embedded != new or {m.name for m in members[1:]} != set(new_files):
            raise RuntimeError("new_archive_mismatch")
        for member in members[1:]:
            if not member.isfile():
                raise RuntimeError("new_archive_nonfile")
            raw = archive.extractfile(member).read()
            item = new_files[member.name]
            if len(raw) != item["bytes"] or sha(raw) != item["sha256"]:
                raise RuntimeError("new_archive_file_mismatch")
            checked_path(root, member.name).write_bytes(raw)
    for path in removed:
        checked_path(root, path).unlink()
    (args.repo / "source-manifest.json").write_text(
        json.dumps(new, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"snapshot_refreshed=ok files={new['file_count']} manifest_sha256={new['manifest_sha256']}")


if __name__ == "__main__":
    main()

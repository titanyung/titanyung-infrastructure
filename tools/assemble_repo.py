#!/usr/bin/env python3
"""Assemble a new, private working tree from the verified source tar.

The source project mirror is never modified. This tool refuses to write into
an existing destination and accepts only paths already in the reviewed
manifest. No credentials or runtime data are intentionally copied.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile


LOCAL_DOCS = {
    "ops/cloud-handoff-20261115/live-services.json": "docs/live-services.json",
    "ops/cloud-handoff-20261115/live-services.md": "docs/live-services.md",
    "ops/routing-adjust-20261112/STATUS.md": "docs/routing-adjust-20261112-status.md",
    "ops/x-ai-route-20261114/README.md": "docs/x-ai-route-20261114.md",
    "ops/x-ai-route-20261114/release/README.md": "docs/x-ai-route-release.md",
    "ops/ledger-system/README.md": "docs/ledger-system.md",
    "ops/unified-admin/README.md": "docs/unified-admin.md",
    "ops/user-daily-traffic/README.md": "docs/user-daily-traffic.md",
    "ops/pwa-install/README.md": "docs/pwa-install.md",
}
LOCAL_CODE = {
    "ops/x-ai-route-20261114/test_x_ai_route.py": "release/x-ai-route/test_x_ai_route.py",
    "ops/x-ai-route-20261114/release/release.py": "release/x-ai-route/release.py",
}


def safe_relative(raw: str) -> Path:
    parts = PurePosixPath(raw).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise RuntimeError("unsafe_path")
    return Path(*parts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    if args.destination.exists():
        raise RuntimeError("destination_already_exists")

    with tarfile.open(args.archive, "r:") as archive:
        members = archive.getmembers()
        if not members or members[0].name != "MANIFEST.json":
            raise RuntimeError("manifest_missing")
        manifest = json.load(archive.extractfile(members[0]))
        expected = {item["path"]: item for item in manifest["files"]}
        if any(item["risk_flags"] for item in expected.values()):
            raise RuntimeError("risk_flags_present")
        actual = {member.name for member in members[1:]}
        if actual != set(expected) or len(actual) != len(members) - 1:
            raise RuntimeError("archive_member_set_mismatch")
        args.destination.mkdir(parents=True)
        for member in members[1:]:
            if not member.isfile():
                raise RuntimeError("non_file_archive_member")
            path = safe_relative(member.name)
            raw = archive.extractfile(member).read()
            item = expected[member.name]
            if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise RuntimeError("archive_content_mismatch")
            target = args.destination / "source" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        (args.destination / "source-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    for source, target in {**LOCAL_DOCS, **LOCAL_CODE}.items():
        original = args.project / safe_relative(source)
        if not original.is_file() or original.is_symlink():
            raise RuntimeError("reference_file_missing")
        final = args.destination / safe_relative(target)
        final.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, final)
    draft = args.project / "ops/cloud-handoff-20261115/docs-draft"
    shutil.copyfile(draft / "README.md", args.destination / "README.md")
    shutil.copyfile(draft / "CLOUD-HANDOFF.md", args.destination / "CLOUD-HANDOFF.md")
    tools = args.destination / "tools"
    tools.mkdir()
    for name in (
        "export_live.py", "export_peer.py", "pull_snapshot.py",
        "assemble_repo.py", "add_peer_snapshot.py", "verify_package.py",
    ):
        source = args.project / "ops/cloud-handoff-20261115" / name
        if source.is_file():
            shutil.copyfile(source, tools / name)
    print(f"repository_assembled=ok live_files={len(expected)} local_docs={len(LOCAL_DOCS)} local_code={len(LOCAL_CODE)}")
    print(f"destination={args.destination}")


if __name__ == "__main__":
    main()

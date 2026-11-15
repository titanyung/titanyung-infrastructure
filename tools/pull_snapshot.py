#!/usr/bin/env python3
"""Stream a reviewed DMIT source snapshot into a local tar file.

Only metadata is printed. The private SSH key is used by OpenSSH and never
copied into the export. The production server is read-only during this step.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh", type=Path, required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--exporter", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    approved = manifest["manifest_sha256"]
    expected = {item["path"]: item for item in manifest["files"]}
    if not approved or any(item["risk_flags"] for item in expected.values()):
        raise RuntimeError("manifest_not_approved")
    if args.output.exists():
        raise RuntimeError("output_already_exists")

    command = [
        str(args.ssh), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={args.known_hosts}",
        "-i", str(args.identity), args.host, "python3", "-", "archive",
        "--approve-sha256", approved,
    ]
    with args.exporter.open("rb") as source, args.output.open("xb") as output:
        result = subprocess.run(command, stdin=source, stdout=output, stderr=subprocess.PIPE)
    if result.returncode:
        args.output.unlink(missing_ok=True)
        print("snapshot_transfer_failed=" + str(result.returncode), file=sys.stderr)
        return 1

    with tarfile.open(args.output, "r:") as archive:
        members = archive.getmembers()
        if not members or members[0].name != "MANIFEST.json":
            raise RuntimeError("archive_manifest_missing")
        embedded = json.load(archive.extractfile(members[0]))
        if embedded != manifest:
            raise RuntimeError("archive_manifest_mismatch")
        found = {}
        for member in members[1:]:
            if not member.isfile() or member.name not in expected or member.name in found:
                raise RuntimeError("archive_unexpected_member")
            raw = archive.extractfile(member).read()
            digest = hashlib.sha256(raw).hexdigest()
            if len(raw) != expected[member.name]["bytes"] or digest != expected[member.name]["sha256"]:
                raise RuntimeError("archive_content_mismatch")
            found[member.name] = digest
        if set(found) != set(expected):
            raise RuntimeError("archive_missing_member")
    print(f"snapshot_verified=ok files={len(found)} manifest_sha256={approved}")
    print(f"archive={args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print("snapshot_refused=" + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)

"""Create a consistent SQLite snapshot of the independent ledger database."""

import os
import sqlite3
from datetime import datetime


def main():
    source = os.environ.get("LEDGER_DATABASE", "/var/lib/ledger-system/ledger.db")
    if not os.path.isfile(source):
        raise SystemExit("ledger database not found")
    directory = os.path.join(os.path.dirname(source), "backups")
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = os.path.join(directory, "ledger-" + stamp + ".sqlite")
    temporary = target + ".tmp"
    if os.path.exists(target) or os.path.exists(temporary):
        raise SystemExit("backup filename already exists")
    source_db = sqlite3.connect("file:" + source + "?mode=ro", uri=True)
    backup_db = sqlite3.connect(temporary)
    try:
        source_db.backup(backup_db)
        if backup_db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("backup integrity check failed")
        backup_db.close()
        source_db.close()
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        print("Ledger backup created:", target)
    finally:
        source_db.close()
        backup_db.close()
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    main()

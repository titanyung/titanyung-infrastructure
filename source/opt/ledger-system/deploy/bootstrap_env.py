"""One-time server setup: write independent ledger secrets without printing them."""

import os
import secrets


TARGET = "/etc/ledger-system/ledger.env"


def main():
    if os.geteuid() != 0:
        raise SystemExit("run as root")
    os.makedirs(os.path.dirname(TARGET), mode=0o700, exist_ok=True)
    try:
        fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print("Ledger secrets already exist; preserved.")
        return
    try:
        data = (
            "LEDGER_SECRET_KEY=" + secrets.token_hex(48) + "\n"
            "LEDGER_SETUP_TOKEN=" + secrets.token_urlsafe(36) + "\n"
            "LEDGER_DATABASE=/var/lib/ledger-system/ledger.db\n"
            "TZ=Asia/Shanghai\n"
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
        os.chmod(TARGET, 0o600)
        print("Ledger secrets created (not displayed).")
    except Exception:
        os.unlink(TARGET)
        raise


if __name__ == "__main__":
    main()

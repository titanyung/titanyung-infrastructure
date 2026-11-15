"""SSH-only ledger ingestion. Reads one JSON object from stdin; never exposes an HTTP write route."""

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from datetime import date, datetime

from app import billing_cycle_month, parse_amount, unique_tags


DEFAULT_DATABASE = "/var/lib/ledger-system/ledger.db"


def category_rows(conn):
    return conn.execute("SELECT id,parent_id,name FROM categories ORDER BY name COLLATE NOCASE,id").fetchall()


def resolve_category(conn, payload):
    category_id = payload.get("category_id")
    path = payload.get("category_path")
    if (category_id is None) == (path is None):
        raise ValueError("必须且只能提供 category_id 或 category_path")
    if category_id is not None:
        if type(category_id) is not int or category_id <= 0:
            raise ValueError("category_id 必须是正整数")
        row = conn.execute("SELECT id FROM categories WHERE id=?", (category_id,)).fetchone()
        if row is None:
            raise ValueError("消费项目不存在")
        return row[0]
    if not isinstance(path, list) or not path or len(path) > 20:
        raise ValueError("category_path 必须是非空的项目名称数组")
    parent = None
    for name in path:
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
            raise ValueError("category_path 包含无效名称")
        row = conn.execute(
            "SELECT id FROM categories WHERE parent_id IS ? AND name=? COLLATE NOCASE",
            (parent, name.strip()),
        ).fetchone()
        if row is None:
            raise ValueError("消费项目不存在：" + " / ".join(path))
        parent = row[0]
    return parent


def validate_payload(conn, payload):
    if not isinstance(payload, dict):
        raise ValueError("流水必须是 JSON 对象")
    source_id = payload.get("source_id")
    if not isinstance(source_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{8,160}", source_id):
        raise ValueError("source_id 必须是 8–160 位稳定流水编号")
    occurred = payload.get("occurred_at")
    if not isinstance(occurred, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}", occurred):
        raise ValueError("occurred_at 格式应为 YYYY-MM-DD HH:MM（北京时间）")
    try:
        when = datetime.strptime(occurred.replace("T", " "), "%Y-%m-%d %H:%M")
    except ValueError as exc:
        raise ValueError("消费时间无效") from exc
    amount = parse_amount(payload.get("amount"), allow_negative=True, zero=False)
    category_id = resolve_category(conn, payload)
    note = payload.get("note", "")
    if not isinstance(note, str) or len(note.strip()) > 2000:
        raise ValueError("备注必须是最多 2000 字的文本")
    tags = payload.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(item, str) for item in tags):
        raise ValueError("tags 必须是标签名称数组")
    names = unique_tags("\n".join(tags))
    return {
        "source_id": source_id,
        "occurred_at": when.strftime("%Y-%m-%d %H:%M:00"),
        "amount_cents": amount,
        "category_id": category_id,
        "note": note.strip(),
        "tags": names,
    }


def add(conn, payload):
    data = validate_payload(conn, payload)
    digest = hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True,
                                       separators=(",", ":")).encode("utf-8")).hexdigest()
    conn.execute("BEGIN IMMEDIATE")
    try:
        previous = conn.execute("SELECT payload_sha256,bill_id FROM ingest_requests WHERE source_id=?",
                                (data["source_id"],)).fetchone()
        if previous:
            if previous[0] != digest:
                raise ValueError("同一 source_id 已关联不同流水；未写入")
            if conn.execute("SELECT 1 FROM bills WHERE id=?", (previous[1],)).fetchone() is None:
                raise ValueError("该流水曾入账但账单已被删除；请人工核对")
            result = {"status": "already_exists", "bill_id": previous[1]}
        else:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor = conn.execute(
                "INSERT INTO bills(occurred_at,amount_cents,category_id,note,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?)",
                (data["occurred_at"], data["amount_cents"], data["category_id"], data["note"], now, now),
            )
            bill_id = cursor.lastrowid
            for name in data["tags"]:
                normalized = name.casefold()
                conn.execute("INSERT OR IGNORE INTO tags(name,normalized) VALUES(?,?)", (name, normalized))
                tag_id = conn.execute("SELECT id FROM tags WHERE normalized=?", (normalized,)).fetchone()[0]
                conn.execute("INSERT INTO bill_tags(bill_id,tag_id) VALUES(?,?)", (bill_id, tag_id))
            conn.execute("INSERT INTO ingest_requests(source_id,payload_sha256,bill_id,created_at) VALUES(?,?,?,?)",
                         (data["source_id"], digest, bill_id, now))
            result = {"status": "created", "bill_id": bill_id}
        conn.commit()
        result["cycle"] = billing_cycle_month(date.fromisoformat(data["occurred_at"][:10]))
        return result
    except Exception:
        conn.rollback()
        raise


def main():
    parser = argparse.ArgumentParser(description="Ledger SSH-only ingestion")
    parser.add_argument("command", choices=("categories", "add"))
    parser.add_argument("--database", default=DEFAULT_DATABASE)
    args = parser.parse_args()
    try:
        conn = sqlite3.connect("file:" + args.database + "?mode=rw", uri=True, timeout=15)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        if args.command == "categories":
            result = {"categories": [dict(zip(("id", "parent_id", "name"), row))
                                     for row in category_rows(conn)]}
        else:
            result = add(conn, json.load(sys.stdin))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    finally:
        if "conn" in locals():
            conn.close()


if __name__ == "__main__":
    sys.exit(main())

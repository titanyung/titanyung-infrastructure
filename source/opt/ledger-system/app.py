"""Independent, single-user household ledger. All amounts are integer cents."""

import base64
import calendar
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import struct
import time
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from urllib.parse import quote, urlsplit

from flask import Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from itsdangerous import BadSignature, URLSafeTimedSerializer


TRUST_COOKIE_NAME = "ledger_trusted_device"
TRUST_COOKIE_MAX_AGE = 365 * 24 * 60 * 60


def bytes_to_base64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def base64url_to_bytes(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


SCHEMA = """
CREATE TABLE IF NOT EXISTS auth_state (
  id INTEGER PRIMARY KEY CHECK(id=1), totp_secret TEXT, password_hash TEXT,
  pending_secret TEXT, failed_passwords INTEGER NOT NULL DEFAULT 0,
  last_totp_step INTEGER NOT NULL DEFAULT -1, version INTEGER NOT NULL DEFAULT 1
);
INSERT OR IGNORE INTO auth_state(id) VALUES(1);
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK(id=1), started_at TEXT NOT NULL
);
INSERT OR IGNORE INTO settings(id,started_at) VALUES(1,datetime('now','localtime'));
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES categories(id) ON DELETE RESTRICT,
  name TEXT NOT NULL COLLATE NOCASE, created_at TEXT NOT NULL,
  UNIQUE(parent_id,name)
);
CREATE UNIQUE INDEX IF NOT EXISTS root_category_name ON categories(name) WHERE parent_id IS NULL;
CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, normalized TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS bills (
  id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents != 0),
  category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE RESTRICT,
  note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS bills_time ON bills(occurred_at);
CREATE INDEX IF NOT EXISTS bills_category ON bills(category_id);
CREATE TABLE IF NOT EXISTS bill_tags (
  bill_id INTEGER NOT NULL REFERENCES bills(id) ON DELETE CASCADE,
  tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE RESTRICT,
  PRIMARY KEY(bill_id,tag_id)
);
CREATE TABLE IF NOT EXISTS ingest_requests (
  source_id TEXT PRIMARY KEY, payload_sha256 TEXT NOT NULL,
  bill_id INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS budget_rules (
  category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
  effective_month TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents >= 0),
  PRIMARY KEY(category_id,effective_month)
);
CREATE TABLE IF NOT EXISTS rate_attempts (ip_hash TEXT NOT NULL, at_epoch INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS rate_attempts_by_ip ON rate_attempts(ip_hash,at_epoch);
CREATE TABLE IF NOT EXISTS passkeys (
  credential_id TEXT PRIMARY KEY, public_key TEXT NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
"""


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("LEDGER_SECRET_KEY", ""),
        DATABASE=os.environ.get("LEDGER_DATABASE", os.path.join(os.path.dirname(__file__), "ledger.db")),
        SETUP_TOKEN=os.environ.get("LEDGER_SETUP_TOKEN", ""),
        SESSION_COOKIE_NAME="ledger_session",
        SESSION_COOKIE_DOMAIN=None,
        SESSION_COOKIE_PATH="/",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=True,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"] or not app.config["SETUP_TOKEN"]:
        raise RuntimeError("LEDGER_SECRET_KEY and LEDGER_SETUP_TOKEN must be set")
    if len(app.config["SECRET_KEY"]) < 32 or len(app.config["SETUP_TOKEN"]) < 24:
        raise RuntimeError("Ledger secrets are too short")
    trust_signer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="ledger-trusted-device-v1")

    def safe_return_to(value):
        value = (value or "").strip()
        parsed = urlsplit(value)
        if not value.startswith("/") or value.startswith("//") or "\\" in value or parsed.scheme or parsed.netloc:
            return url_for("dashboard")
        if len(value) > 2048 or any(ord(char) < 32 for char in value):
            return url_for("dashboard")
        return value

    def db():
        if "db" not in g:
            path = app.config["DATABASE"]
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            conn = sqlite3.connect(path, timeout=15)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=15000")
            g.db = conn
        return g.db

    def init_db():
        conn = db()
        conn.executescript(SCHEMA)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.commit()

    @app.teardown_appcontext
    def close_db(_error):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    with app.app_context():
        init_db()

    @app.after_request
    def prevent_private_page_caching(response):
        if request.endpoint not in ("static", "manifest", "service_worker"):
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Pragma"] = "no-cache"
        return response

    def auth_state():
        return db().execute("SELECT * FROM auth_state WHERE id=1").fetchone()

    def trusted_device(state):
        token = request.cookies.get(TRUST_COOKIE_NAME, "")
        if not token or len(token) > 512:
            return False
        try:
            payload = trust_signer.loads(token, max_age=TRUST_COOKIE_MAX_AGE)
        except BadSignature:
            return False
        return isinstance(payload, dict) and payload.get("auth_version") == state["version"]

    def remember_device(response, state):
        token = trust_signer.dumps({
            "auth_version": state["version"],
            "nonce": secrets.token_urlsafe(16),
        })
        response.set_cookie(
            TRUST_COOKIE_NAME, token, max_age=TRUST_COOKIE_MAX_AGE,
            secure=app.config["SESSION_COOKIE_SECURE"], httponly=True,
            samesite="Lax", path="/",
        )
        return response

    def csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf
    app.jinja_env.filters["money"] = money

    @app.context_processor
    def quick_add_context():
        if session.get("auth_version") and not session.get("locked"):
            return {"quick_categories": category_tree(),
                    "quick_tags": db().execute("SELECT name FROM tags ORDER BY name").fetchall()}
        return {}

    @app.before_request
    def guard():
        # A previously opened login form can be submitted after another tab has
        # already logged in.  The successful login rotates the CSRF token, so
        # send the authenticated browser home before checking that stale form.
        if request.endpoint == "login" and session.get("auth_version") == auth_state()["version"] and not session.get("locked"):
            return redirect(url_for("dashboard"), code=303 if request.method == "POST" else 302)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf_token", "")
            if not hmac.compare_digest(sent, session.get("csrf", "")) or not sent:
                if request.endpoint == "login":
                    if not request.cookies.get(app.config["SESSION_COOKIE_NAME"]):
                        flash("浏览器未发送本站登录 Cookie，请允许 ledger.titanyung.top 使用 Cookie 后重试", "error")
                        return render_template("login.html", trusted_device=trusted_device(auth_state()))
                    flash("登录页面已过期，请刷新页面后重试", "error")
                    return redirect(url_for("login"), code=303)
                abort(400, "表单已过期，请刷新页面后重试")
        if request.endpoint in ("static", "health", "favicon", "manifest", "service_worker"):
            return None
        state = auth_state()
        if state["password_hash"] is None:
            if request.endpoint not in ("setup", "setup_finish"):
                return redirect(url_for("setup"))
            return None
        if request.endpoint in ("login", "recover", "recover_action", "logout", "passkey_auth_options", "passkey_auth_verify"):
            return None
        if session.get("auth_version") != state["version"]:
            if "auth_version" in session:
                session.clear()
            return redirect(url_for("login"))
        if request.endpoint == "lock":
            return None
        now_epoch = int(time.time())
        if session.get("locked") or now_epoch - session.get("last_active", now_epoch) >= 60:
            session["locked"] = True
            if request.method == "GET" and request.endpoint not in ("lock", "activity"):
                session["return_to"] = safe_return_to(request.full_path.rstrip("?"))
            return redirect(url_for("login"), code=303 if request.method != "GET" else 302)
        session["last_active"] = now_epoch
        session.permanent = True
        return None

    @app.route("/health")
    def health():
        try:
            db().execute("SELECT 1").fetchone()
            return "ok\n", 200, {"Content-Type": "text/plain; charset=utf-8"}
        except sqlite3.Error:
            return "unavailable\n", 503

    @app.route("/favicon.ico")
    def favicon():
        return "", 204

    @app.route("/manifest.webmanifest")
    def manifest():
        response = app.send_static_file("manifest.webmanifest")
        response.mimetype = "application/manifest+json"
        return response

    @app.route("/sw.js")
    def service_worker():
        response = app.send_static_file("sw.js")
        response.mimetype = "text/javascript"
        response.headers["Service-Worker-Allowed"] = "/"
        return response

    @app.route("/activity", methods=["POST"])
    def activity():
        return "", 204

    @app.route("/lock", methods=["POST"])
    def lock():
        session["return_to"] = safe_return_to(request.form.get("return_to"))
        session["locked"] = True
        return jsonify({"login": url_for("login")})

    def passkey_config():
        origin = app.config.get("PUBLIC_ORIGIN", "https://ledger.titanyung.top").rstrip("/")
        return origin, urlsplit(origin).hostname

    @app.route("/passkeys/register/options", methods=["POST"])
    def passkey_register_options():
        if not limited() or not check_password((request.get_json(silent=True) or {}).get("password", ""),
                                               auth_state()["password_hash"]):
            abort(403)
        from webauthn import generate_registration_options, options_to_json
        from webauthn.helpers.structs import (AuthenticatorAttachment, AuthenticatorSelectionCriteria,
                                              ResidentKeyRequirement, UserVerificationRequirement,
                                              PublicKeyCredentialDescriptor)
        _, rp_id = passkey_config()
        credentials = db().execute("SELECT credential_id FROM passkeys").fetchall()
        options = generate_registration_options(
            rp_id=rp_id, rp_name="Ledger", user_id=b"ledger-single-account",
            user_name="ledger", user_display_name="Ledger",
            exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"]))
                                 for row in credentials],
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED),
        )
        payload = json.loads(options_to_json(options))
        session["passkey_registration"] = {"challenge": payload["challenge"], "at": int(time.time())}
        return jsonify(payload)

    @app.route("/passkeys/register/verify", methods=["POST"])
    def passkey_register_verify():
        from webauthn import verify_registration_response
        challenge = session.pop("passkey_registration", None)
        if not challenge or int(time.time()) - challenge["at"] > 120:
            abort(400)
        origin, rp_id = passkey_config()
        try:
            result = verify_registration_response(
                credential=request.get_json(), expected_challenge=base64url_to_bytes(challenge["challenge"]),
                expected_rp_id=rp_id, expected_origin=origin, require_user_verification=True)
        except Exception:
            abort(400)
        credential_id = bytes_to_base64url(result.credential_id)
        db().execute("INSERT OR REPLACE INTO passkeys(credential_id,public_key,sign_count,created_at) "
                     "VALUES(?,?,?,datetime('now'))",
                     (credential_id, bytes_to_base64url(result.credential_public_key), result.sign_count))
        db().commit()
        return jsonify({"ok": True})

    @app.route("/passkeys/auth/options", methods=["POST"])
    def passkey_auth_options():
        if auth_state()["password_hash"] is None:
            abort(403)
        from webauthn import generate_authentication_options, options_to_json
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement
        rows = db().execute("SELECT credential_id FROM passkeys").fetchall()
        if not rows:
            abort(404)
        _, rp_id = passkey_config()
        options = generate_authentication_options(
            rp_id=rp_id, allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"]))
                                             for row in rows],
            user_verification=UserVerificationRequirement.REQUIRED)
        payload = json.loads(options_to_json(options))
        session["passkey_auth"] = {"challenge": payload["challenge"], "at": int(time.time())}
        return jsonify(payload)

    @app.route("/passkeys/auth/verify", methods=["POST"])
    def passkey_auth_verify():
        if not limited():
            abort(429)
        from webauthn import verify_authentication_response
        challenge = session.pop("passkey_auth", None)
        if not challenge or int(time.time()) - challenge["at"] > 120:
            abort(400)
        credential = request.get_json(silent=True) or {}
        row = db().execute("SELECT * FROM passkeys WHERE credential_id=?", (credential.get("id", ""),)).fetchone()
        if row is None:
            abort(403)
        origin, rp_id = passkey_config()
        try:
            result = verify_authentication_response(
                credential=credential, expected_challenge=base64url_to_bytes(challenge["challenge"]),
                expected_rp_id=rp_id, expected_origin=origin,
                credential_public_key=base64url_to_bytes(row["public_key"]),
                credential_current_sign_count=row["sign_count"], require_user_verification=True)
        except Exception:
            abort(403)
        db().execute("UPDATE passkeys SET sign_count=? WHERE credential_id=?",
                     (result.new_sign_count, row["credential_id"]))
        db().execute("UPDATE auth_state SET failed_passwords=0 WHERE id=1")
        db().commit()
        destination = safe_return_to(session.get("return_to")) if session.get("locked") else url_for("dashboard")
        state = auth_state()
        session.clear()
        session["auth_version"] = state["version"]
        session["last_active"] = int(time.time())
        session.permanent = True
        remember_device_response = remember_device(jsonify({"next": destination}), state)
        return remember_device_response

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if auth_state()["password_hash"] is not None:
            return redirect(url_for("login"))
        if request.method == "POST":
            if not limited():
                abort(429)
            if not hmac.compare_digest(request.form.get("token", ""), app.config["SETUP_TOKEN"]):
                flash("初始化密钥不正确", "error")
            else:
                secret = new_totp_secret()
                db().execute("UPDATE auth_state SET pending_secret=? WHERE id=1", (secret,))
                db().commit()
                session["setup_verified"] = True
                return redirect(url_for("setup_finish"))
        return render_template("setup.html", stage="token")

    @app.route("/setup/finish", methods=["GET", "POST"])
    def setup_finish():
        if not session.get("setup_verified"):
            return redirect(url_for("setup"))
        state = auth_state()
        secret = state["pending_secret"]
        if not secret:
            return redirect(url_for("setup"))
        if request.method == "POST":
            if not limited():
                abort(429)
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
            code = request.form.get("code", "")
            if len(password) < 10 or password != confirm:
                flash("密码至少 10 位，并且两次输入一致", "error")
            elif not verify_totp(secret, code):
                flash("验证器代码不正确，请等待下一组代码再试", "error")
            else:
                hashed = hash_password(password)
                db().execute(
                    "UPDATE auth_state SET totp_secret=?, pending_secret=NULL, password_hash=?, "
                    "failed_passwords=0, last_totp_step=-1, version=version+1 WHERE id=1",
                    (secret, hashed),
                )
                db().commit()
                session.clear()
                flash("初始化完成；首次在此浏览器登录需密码和验证器代码", "success")
                return redirect(url_for("login"))
        uri = "otpauth://totp/" + quote("Ledger titanyung.top") + "?secret=" + secret + "&issuer=" + quote("Ledger")
        qr_image = None
        try:
            import qrcode
            image = qrcode.make(uri)
            output = io.BytesIO()
            image.save(output, format="PNG")
            qr_image = base64.b64encode(output.getvalue()).decode("ascii")
        except ImportError:
            pass
        return render_template("setup.html", stage="finish", totp_secret=secret, qr_image=qr_image)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        state = auth_state()
        if state["password_hash"] is None:
            return redirect(url_for("setup"))
        if state["failed_passwords"] >= 3:
            return redirect(url_for("recover"))
        remembered = trusted_device(state)
        if request.method == "POST":
            if not limited():
                abort(429)
            password = request.form.get("password", "")
            code = request.form.get("code", "")
            if not check_password(password, state["password_hash"]):
                db().execute("UPDATE auth_state SET failed_passwords=failed_passwords+1 WHERE id=1")
                db().commit()
                flash("密码或验证器代码不正确", "error")
                if state["failed_passwords"] + 1 >= 3:
                    return redirect(url_for("recover"))
            elif not remembered and not code:
                flash("此浏览器尚未验证，请输入验证器动态代码", "error")
            elif not remembered and not consume_totp(code):
                flash("验证器代码不正确", "error")
            else:
                db().execute("UPDATE auth_state SET failed_passwords=0 WHERE id=1")
                db().commit()
                destination = safe_return_to(session.get("return_to")) if session.get("locked") else url_for("dashboard")
                session.clear()
                session["auth_version"] = state["version"]
                session["last_active"] = int(time.time())
                session.permanent = True
                return remember_device(redirect(destination), state)
        return render_template("login.html", trusted_device=remembered,
                               passkey_available=bool(db().execute("SELECT 1 FROM passkeys LIMIT 1").fetchone()),
                               locked=bool(session.get("locked")))

    @app.route("/recover", methods=["GET", "POST"])
    def recover():
        if auth_state()["failed_passwords"] < 3:
            return redirect(url_for("login"))
        if request.method == "POST":
            if not limited():
                abort(429)
            if consume_totp(request.form.get("code", "")):
                session["recovery_ok"] = True
                return redirect(url_for("recover_action"))
            flash("验证器代码不正确", "error")
        return render_template("recover.html", stage="verify")

    @app.route("/recover/action", methods=["GET", "POST"])
    def recover_action():
        if not session.get("recovery_ok"):
            return redirect(url_for("recover"))
        if request.method == "POST":
            action = request.form.get("action")
            if action == "retry":
                db().execute("UPDATE auth_state SET failed_passwords=0 WHERE id=1")
                db().commit()
                session.clear()
                return redirect(url_for("login"))
            if action == "reset":
                password = request.form.get("password", "")
                if len(password) < 10 or password != request.form.get("confirm", ""):
                    flash("新密码至少 10 位，并且两次输入一致", "error")
                else:
                    db().execute(
                        "UPDATE auth_state SET password_hash=?, failed_passwords=0, version=version+1 WHERE id=1",
                        (hash_password(password),),
                    )
                    db().execute("DELETE FROM passkeys")
                    db().commit()
                    session.clear()
                    flash("密码已重置，请重新登录", "success")
                    return redirect(url_for("login"))
        return render_template("recover.html", stage="action")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    def categories():
        return db().execute("SELECT * FROM categories ORDER BY name COLLATE NOCASE").fetchall()

    def category_tree():
        rows = [dict(row) for row in categories()]
        by_parent = {}
        for row in rows:
            by_parent.setdefault(row["parent_id"], []).append(row)
        output = []
        def walk(parent, depth, visited):
            for row in by_parent.get(parent, []):
                if row["id"] in visited:
                    continue
                row["depth"] = depth
                output.append(row)
                walk(row["id"], depth + 1, visited | {row["id"]})
        walk(None, 0, set())
        return output

    def descendants(category_id):
        result = {category_id}
        pending = [category_id]
        while pending:
            parent = pending.pop()
            children = db().execute("SELECT id FROM categories WHERE parent_id=?", (parent,)).fetchall()
            for child in children:
                if child["id"] not in result:
                    result.add(child["id"])
                    pending.append(child["id"])
        return result

    def budget_for(category_id, month):
        row = db().execute(
            "SELECT amount_cents FROM budget_rules WHERE category_id=? AND effective_month<=? "
            "ORDER BY effective_month DESC LIMIT 1", (category_id, month),
        ).fetchone()
        if row is None:
            # The launch cycle may have begun before the first budget was set.
            # Keep that partial cycle comparable without rewriting old rules.
            started_at = db().execute("SELECT started_at FROM settings WHERE id=1").fetchone()["started_at"]
            category = db().execute("SELECT created_at FROM categories WHERE id=?", (category_id,)).fetchone()
            if (month == billing_cycle_month(date.fromisoformat(started_at[:10])) and
                    category and billing_cycle_month(date.fromisoformat(category["created_at"][:10])) == month):
                row = db().execute(
                    "SELECT amount_cents FROM budget_rules WHERE category_id=? "
                    "ORDER BY effective_month ASC LIMIT 1", (category_id,),
                ).fetchone()
        return row["amount_cents"] if row else 0

    def month_budget(month):
        return sum(budget_for(row["id"], month) for row in categories() if row["parent_id"] is None)

    def month_spent(month):
        start, end = billing_cycle_bounds(month)
        row = db().execute("SELECT COALESCE(SUM(amount_cents),0) AS total FROM bills "
                           "WHERE occurred_at>=? AND occurred_at<?", (start.isoformat(), end.isoformat())).fetchone()
        return row["total"]

    def project_budget_entries(month, comparison_month=None):
        tree = category_tree()
        if not tree:
            return []

        def direct_spending(candidate):
            start, end = billing_cycle_bounds(candidate)
            rows = db().execute(
                "SELECT category_id,SUM(amount_cents) AS spent FROM bills "
                "WHERE occurred_at>=? AND occurred_at<? GROUP BY category_id",
                (start.isoformat(), end.isoformat()),
            ).fetchall()
            return {row["category_id"]: row["spent"] for row in rows}

        def with_children(direct):
            totals = {row["id"]: direct.get(row["id"], 0) for row in tree}
            for row in reversed(tree):
                if row["parent_id"] in totals:
                    totals[row["parent_id"]] += totals[row["id"]]
            return totals

        direct = direct_spending(month)
        spent = with_children(direct)
        previous = with_children(direct_spending(comparison_month)) if comparison_month else None
        budgets_by_id = {row["id"]: budget_for(row["id"], month) for row in tree}
        entries = []
        for row in tree:
            budget = budgets_by_id[row["id"]]
            entries.append({"category": row, "budget": budget,
                            "direct_spent": direct.get(row["id"], 0),
                            "spent": spent[row["id"]], "remaining": budget - spent[row["id"]],
                            "previous_spent": previous[row["id"]] if previous is not None else None})
        return entries

    @app.route("/")
    def dashboard():
        today = date.today()
        current_month = billing_cycle_month(today)
        day = parse_day(request.args.get("day"), today)
        week_day = parse_day(request.args.get("week"), today)
        month = parse_month(request.args.get("month"), current_month)
        year = parse_year(request.args.get("year"), int(current_month[:4]))
        week_start = week_day - timedelta(days=week_day.weekday())
        week_end = week_start + timedelta(days=7)
        month_start, month_end = billing_cycle_bounds(month)
        year_start, year_end = billing_cycle_bounds("%04d-01" % year)[0], billing_cycle_bounds("%04d-01" % (year + 1))[0]
        periods = [
            ("日", day.isoformat(), (day + timedelta(days=1)).isoformat()),
            ("周", week_start.isoformat(), week_end.isoformat()),
            ("账单月", month_start.isoformat(), month_end.isoformat()),
            ("账单年", year_start.isoformat(), year_end.isoformat()),
        ]
        roots = [row for row in categories() if row["parent_id"] is None]
        period_data = []
        for label, start, end in periods:
            total = db().execute("SELECT COALESCE(SUM(amount_cents),0) AS total FROM bills "
                                 "WHERE occurred_at>=? AND occurred_at<?", (start, end)).fetchone()["total"]
            breakdown = []
            for root in roots:
                ids = sorted(descendants(root["id"]))
                marks = ",".join("?" * len(ids))
                amount = db().execute("SELECT COALESCE(SUM(amount_cents),0) AS total FROM bills "
                                      "WHERE occurred_at>=? AND occurred_at<? AND category_id IN (" + marks + ")",
                                      (start, end, *ids)).fetchone()["total"]
                breakdown.append({"name": root["name"], "amount": amount})
            period_data.append({"label": label, "start": start,
                                "end": (date.fromisoformat(end) - timedelta(days=1)).isoformat(),
                                "total": total, "breakdown": breakdown})
        previous = previous_month(current_month)
        current = monthly_summary(current_month)
        started_at = db().execute("SELECT started_at FROM settings WHERE id=1").fetchone()["started_at"][:10]
        started = billing_cycle_month(date.fromisoformat(started_at))
        prior = monthly_summary(previous) if previous >= started else None
        project_previous = previous_month(month)
        project_entries = (project_budget_entries(month, project_previous if project_previous >= started else None)
                           if month >= started else [])
        twelve = [monthly_summary(candidate) for i in range(11, -1, -1)
                  for candidate in [month_shift(current_month, -i)] if candidate >= started]
        yearly = [monthly_summary(candidate) for m in range(1, int(current_month[5:]) + 1)
                  for candidate in ["%s-%02d" % (current_month[:4], m)] if candidate >= started]
        trend_view = request.args.get("trend") if request.args.get("trend") in ("twelve", "yearly") else "twelve"
        trend_items = twelve if trend_view == "twelve" else yearly
        trend_projects = {}
        for item in trend_items:
            candidate = item["month"]
            previous_candidate = previous_month(candidate)
            comparison_month = previous_candidate if previous_candidate >= started else None
            trend_projects[candidate] = (project_entries if candidate == month else
                                         project_budget_entries(candidate, comparison_month))
            item["previous_spent"] = month_spent(previous_candidate) if comparison_month else None
        all_months = []
        cursor = started if re.fullmatch(r"\d{4}-\d{2}", started) else current_month
        while cursor <= current_month and len(all_months) < 600:
            all_months.append(monthly_summary(cursor))
            cursor = next_month(cursor)
        return render_template("dashboard.html", periods=period_data,
                               day=day.isoformat(), week=week_day.isoformat(), month=month, year=year,
                               current=current, prior=prior, twelve=twelve, yearly=yearly,
                               project_month=month, project_entries=project_entries,
                               trend_view=trend_view, trend_items=trend_items,
                               trend_projects=trend_projects, trend_counts=count_remaining(trend_items),
                               year_remaining=sum(item["remaining"] for item in yearly),
                               all_remaining=sum(item["remaining"] for item in all_months),
                               delta=current["spent"] - prior["spent"] if prior else None,
                               started=started, started_at=started_at,
                               project_period=billing_cycle_label(month))

    def monthly_summary(month):
        budget = month_budget(month)
        spent = month_spent(month)
        return {"month": month, "period": billing_cycle_label(month),
                "budget": budget, "spent": spent, "remaining": budget - spent}

    @app.route("/bills")
    def bills():
        month = parse_month(request.args.get("month"), billing_cycle_month(date.today()))
        started_at = db().execute("SELECT started_at FROM settings WHERE id=1").fetchone()["started_at"]
        default_start, default_end = export_range_since_start(date.today(), started_at)
        cycle_start, cycle_end = billing_cycle_bounds(month)
        rows = db().execute(
            "SELECT b.*, c.name AS category_name FROM bills b JOIN categories c ON c.id=b.category_id "
            "WHERE b.occurred_at>=? AND b.occurred_at<? ORDER BY b.occurred_at, b.id",
            (cycle_start.isoformat(), cycle_end.isoformat()),
        ).fetchall()
        tree = category_tree()
        by_id = {row["id"]: row for row in tree}
        running_total = 0
        running_category = {}
        display = []
        for row in rows:
            running_total += row["amount_cents"]
            current_id = row["category_id"]
            seen = set()
            while current_id and current_id not in seen:
                seen.add(current_id)
                running_category[current_id] = running_category.get(current_id, 0) + row["amount_cents"]
                current_id = by_id[current_id]["parent_id"] if current_id in by_id else None
            tags = db().execute("SELECT t.name FROM tags t JOIN bill_tags bt ON bt.tag_id=t.id "
                                "WHERE bt.bill_id=? ORDER BY t.name", (row["id"],)).fetchall()
            display.append({"bill": row, "tags": [tag["name"] for tag in tags],
                            "total_remaining": month_budget(month) - running_total,
                            "category_remaining": budget_for(row["category_id"], month) - running_category.get(row["category_id"], 0)})
        return render_template("bills.html", bills=list(reversed(display)), month=month,
                               period=billing_cycle_label(month),
                               month_total=running_total, month_budget=month_budget(month),
                               categories=tree, tags=db().execute("SELECT name FROM tags ORDER BY name").fetchall(),
                               export_start=request.args.get("export_start") or default_start.isoformat(),
                               export_end=request.args.get("export_end") or default_end.isoformat())

    @app.route("/bills/export")
    def bill_export():
        started_at = db().execute("SELECT started_at FROM settings WHERE id=1").fetchone()["started_at"]
        default_start, default_end = export_range_since_start(date.today(), started_at)
        start_raw = request.args.get("start", default_start.isoformat())
        end_raw = request.args.get("end", default_end.isoformat())
        try:
            start, end = parse_export_range(start_raw, end_raw)
        except ValueError as exc:
            flash(str(exc), "error")
            month = parse_month(request.args.get("month"), billing_cycle_month(date.today()))
            return redirect(url_for("bills", month=month,
                                    export_start=start_raw[:10], export_end=end_raw[:10]))

        end_exclusive = (end + timedelta(days=1)).isoformat()
        rows = db().execute(
            "SELECT b.id,b.occurred_at,b.amount_cents,b.note,c.name AS category_name "
            "FROM bills b JOIN categories c ON c.id=b.category_id "
            "WHERE b.occurred_at>=? AND b.occurred_at<? ORDER BY b.occurred_at,b.id",
            (start.isoformat(), end_exclusive),
        ).fetchall()
        tag_rows = db().execute(
            "SELECT bt.bill_id,t.name FROM bill_tags bt JOIN tags t ON t.id=bt.tag_id "
            "JOIN bills b ON b.id=bt.bill_id "
            "WHERE b.occurred_at>=? AND b.occurred_at<? ORDER BY bt.bill_id,t.name",
            (start.isoformat(), end_exclusive),
        ).fetchall()
        tags_by_bill = {}
        for tag in tag_rows:
            tags_by_bill.setdefault(tag["bill_id"], []).append(tag["name"])

        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(("账单ID", "时间", "类型", "金额（元）", "消费项目", "标签", "备注"))
        for row in rows:
            writer.writerow((
                row["id"], row["occurred_at"], "支出" if row["amount_cents"] > 0 else "退款",
                format(Decimal(row["amount_cents"]) / 100, ".2f"),
                csv_safe_text(row["category_name"]),
                csv_safe_text("、".join(tags_by_bill.get(row["id"], []))),
                csv_safe_text(row["note"]),
            ))
        filename = "ledger-bills-%s-%s.csv" % (start.strftime("%Y%m%d"), end.strftime("%Y%m%d"))
        response = Response(output.getvalue().encode("utf-8-sig"), content_type="text/csv; charset=utf-8")
        response.headers["Content-Disposition"] = 'attachment; filename="%s"' % filename
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def bill_form_values():
        occurred = request.form.get("occurred_at", "").strip()
        if occurred.lower() == "n":
            occurred = datetime.now().strftime("%Y-%m-%dT%H:%M")
        try:
            datetime.strptime(occurred, "%Y-%m-%dT%H:%M")
        except ValueError:
            raise ValueError("请选择有效的消费时间")
        amount = parse_amount(request.form.get("amount"), allow_negative=True, zero=False)
        category_id = parse_id(request.form.get("category_id"))
        if not db().execute("SELECT 1 FROM categories WHERE id=?", (category_id,)).fetchone():
            raise ValueError("请选择有效的消费项目")
        note = request.form.get("note", "").strip()
        if len(note) > 2000:
            raise ValueError("备注最多 2000 字")
        names = unique_tags(request.form.get("tags", ""))
        return occurred.replace("T", " ") + ":00", amount, category_id, note, names

    def assign_tags(bill_id, names):
        db().execute("DELETE FROM bill_tags WHERE bill_id=?", (bill_id,))
        for name in names:
            normalized = name.casefold()
            db().execute("INSERT OR IGNORE INTO tags(name,normalized) VALUES(?,?)", (name, normalized))
            tag = db().execute("SELECT id FROM tags WHERE normalized=?", (normalized,)).fetchone()
            db().execute("INSERT INTO bill_tags(bill_id,tag_id) VALUES(?,?)", (bill_id, tag["id"]))

    @app.route("/bills/new", methods=["GET", "POST"])
    def bill_new():
        if request.method == "POST":
            try:
                occurred, amount, category_id, note, names = bill_form_values()
                with db():
                    cursor = db().execute("INSERT INTO bills(occurred_at,amount_cents,category_id,note,created_at,updated_at) "
                                          "VALUES(?,?,?,?,datetime('now'),datetime('now'))",
                                          (occurred, amount, category_id, note))
                    assign_tags(cursor.lastrowid, names)
                flash("账单已新增", "success")
                return redirect(url_for("bills", month=billing_cycle_month(date.fromisoformat(occurred[:10]))))
            except ValueError as exc:
                flash(str(exc), "error")
        return render_bill_form(None)

    @app.route("/quick-add", methods=["POST"])
    def quick_add():
        try:
            occurred, amount, category_id, note, names = bill_form_values()
            with db():
                cursor = db().execute("INSERT INTO bills(occurred_at,amount_cents,category_id,note,created_at,updated_at) "
                                      "VALUES(?,?,?,?,datetime('now'),datetime('now'))",
                                      (occurred, amount, category_id, note))
                assign_tags(cursor.lastrowid, names)
            flash("账单已快捷添加", "success")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(safe_return_to(request.form.get("return_to")))

    @app.route("/bills/<int:bill_id>/edit", methods=["GET", "POST"])
    def bill_edit(bill_id):
        row = db().execute("SELECT * FROM bills WHERE id=?", (bill_id,)).fetchone()
        if row is None:
            abort(404)
        if request.method == "POST":
            try:
                occurred, amount, category_id, note, names = bill_form_values()
                with db():
                    db().execute("UPDATE bills SET occurred_at=?,amount_cents=?,category_id=?,note=?, "
                                 "updated_at=datetime('now') WHERE id=?",
                                 (occurred, amount, category_id, note, bill_id))
                    assign_tags(bill_id, names)
                flash("账单已修改", "success")
                return redirect(url_for("bills", month=billing_cycle_month(date.fromisoformat(occurred[:10]))))
            except ValueError as exc:
                flash(str(exc), "error")
        return render_bill_form(row)

    def render_bill_form(row):
        tag_names = []
        if row:
            tag_names = [item["name"] for item in db().execute("SELECT t.name FROM tags t "
                          "JOIN bill_tags bt ON bt.tag_id=t.id WHERE bt.bill_id=? ORDER BY t.name", (row["id"],))]
        return render_template("bill_form.html", bill=row, categories=category_tree(), tag_names=tag_names,
                               tags=db().execute("SELECT name FROM tags ORDER BY name").fetchall(),
                               now=datetime.now().strftime("%Y-%m-%dT%H:%M"))

    @app.route("/bills/<int:bill_id>/delete", methods=["POST"])
    def bill_delete(bill_id):
        row = db().execute("SELECT occurred_at FROM bills WHERE id=?", (bill_id,)).fetchone()
        if row is None:
            abort(404)
        if request.form.get("confirm") != "delete":
            abort(400)
        db().execute("DELETE FROM bills WHERE id=?", (bill_id,))
        db().commit()
        flash("账单已删除", "success")
        return redirect(url_for("bills", month=billing_cycle_month(date.fromisoformat(row["occurred_at"][:10]))))

    @app.route("/budgets")
    def budgets():
        month = parse_month(request.args.get("month"), billing_cycle_month(date.today()))
        entries = project_budget_entries(month)
        return render_template("budgets.html", month=month, entries=entries,
                               period=billing_cycle_label(month),
                               total_budget=month_budget(month), total_spent=month_spent(month))

    @app.route("/categories", methods=["GET", "POST"])
    def category_manage():
        if request.method == "POST":
            try:
                name = valid_name(request.form.get("name"), 80)
                parent_raw = request.form.get("parent_id", "")
                parent_id = parse_id(parent_raw) if parent_raw else None
                if parent_id is not None and not db().execute("SELECT 1 FROM categories WHERE id=?", (parent_id,)).fetchone():
                    raise ValueError("上级项目不存在")
                budget = parse_amount(request.form.get("budget", "0"), allow_negative=False, zero=True)
                with db():
                    cursor = db().execute("INSERT INTO categories(parent_id,name,created_at) VALUES(?,?,datetime('now'))",
                                          (parent_id, name))
                    db().execute("INSERT INTO budget_rules(category_id,effective_month,amount_cents) VALUES(?,?,?)",
                                 (cursor.lastrowid, billing_cycle_month(date.today()), budget))
                flash("项目已新增", "success")
                return redirect(url_for("category_manage"))
            except (ValueError, sqlite3.IntegrityError) as exc:
                flash("新增失败：" + str(exc), "error")
        current_cycle = billing_cycle_month(date.today())
        return render_template("categories.html", categories=category_tree(), month=current_cycle,
                               period=billing_cycle_label(current_cycle),
                               budget_for=budget_for)

    @app.route("/categories/<int:category_id>/edit", methods=["POST"])
    def category_edit(category_id):
        if not db().execute("SELECT 1 FROM categories WHERE id=?", (category_id,)).fetchone():
            abort(404)
        try:
            name = valid_name(request.form.get("name"), 80)
            budget = parse_amount(request.form.get("budget"), allow_negative=False, zero=True)
            month = billing_cycle_month(date.today())
            with db():
                db().execute("UPDATE categories SET name=? WHERE id=?", (name, category_id))
                db().execute("INSERT INTO budget_rules(category_id,effective_month,amount_cents) VALUES(?,?,?) "
                             "ON CONFLICT(category_id,effective_month) DO UPDATE SET amount_cents=excluded.amount_cents",
                             (category_id, month, budget))
            flash("项目和本月起生效的预算已更新", "success")
        except (ValueError, sqlite3.IntegrityError) as exc:
            flash("修改失败：" + str(exc), "error")
        return redirect(url_for("category_manage"))

    @app.route("/categories/<int:category_id>/delete", methods=["POST"])
    def category_delete(category_id):
        if request.form.get("confirm") != "delete":
            abort(400)
        if not db().execute("SELECT 1 FROM categories WHERE id=?", (category_id,)).fetchone():
            abort(404)
        ids = sorted(descendants(category_id))
        marks = ",".join("?" * len(ids))
        if db().execute("SELECT 1 FROM bills WHERE category_id IN (" + marks + ") LIMIT 1", ids).fetchone():
            flash("该项目或子项目已有交易，不能删除", "error")
        elif len(ids) > 1:
            flash("请先删除子项目", "error")
        else:
            db().execute("DELETE FROM categories WHERE id=?", (category_id,))
            db().commit()
            flash("项目已删除", "success")
        return redirect(url_for("category_manage"))

    @app.route("/tags", methods=["GET", "POST"])
    def tag_manage():
        if request.method == "POST":
            try:
                name = valid_name(request.form.get("name"), 60)
                db().execute("INSERT INTO tags(name,normalized) VALUES(?,?)", (name, name.casefold()))
                db().commit()
                flash("标签已新增", "success")
            except (ValueError, sqlite3.IntegrityError) as exc:
                flash("新增失败：" + str(exc), "error")
            return redirect(url_for("tag_manage"))
        tags = db().execute("SELECT t.*,COUNT(bt.bill_id) AS uses FROM tags t LEFT JOIN bill_tags bt ON bt.tag_id=t.id "
                            "GROUP BY t.id ORDER BY t.name").fetchall()
        return render_template("tags.html", tags=tags)

    @app.route("/tags/<int:tag_id>/edit", methods=["POST"])
    def tag_edit(tag_id):
        if not db().execute("SELECT 1 FROM tags WHERE id=?", (tag_id,)).fetchone():
            abort(404)
        try:
            name = valid_name(request.form.get("name"), 60)
            db().execute("UPDATE tags SET name=?,normalized=? WHERE id=?", (name, name.casefold(), tag_id))
            db().commit()
            flash("标签已修改", "success")
        except (ValueError, sqlite3.IntegrityError) as exc:
            flash("修改失败：" + str(exc), "error")
        return redirect(url_for("tag_manage"))

    @app.route("/tags/<int:tag_id>/delete", methods=["POST"])
    def tag_delete(tag_id):
        if request.form.get("confirm") != "delete":
            abort(400)
        if db().execute("SELECT 1 FROM bill_tags WHERE tag_id=?", (tag_id,)).fetchone():
            flash("标签已绑定交易，不能删除", "error")
        else:
            db().execute("DELETE FROM tags WHERE id=?", (tag_id,))
            db().commit()
            flash("标签已删除", "success")
        return redirect(url_for("tag_manage"))

    @app.route("/settings")
    def settings():
        return render_template("settings.html")

    @app.route("/settings/password", methods=["POST"])
    def change_password():
        if not limited():
            abort(429)
        state = auth_state()
        old = request.form.get("old_password", "")
        new = request.form.get("new_password", "")
        if len(new) < 10 or new != request.form.get("confirm", ""):
            flash("新密码至少 10 位，并且两次输入一致", "error")
        elif not check_password(old, state["password_hash"]) or not consume_totp(request.form.get("code", "")):
            flash("当前密码或验证器代码不正确", "error")
        else:
            db().execute("UPDATE auth_state SET password_hash=?,version=version+1 WHERE id=1", (hash_password(new),))
            db().execute("DELETE FROM passkeys")
            db().commit()
            session.clear()
            flash("密码已修改，请重新登录", "success")
            return redirect(url_for("login"))
        return redirect(url_for("settings"))

    @app.route("/settings/unbind", methods=["POST"])
    def unbind():
        if not limited():
            abort(429)
        if request.form.get("confirm") != "清空全部账单数据并解绑":
            flash("请完整输入二次确认文字", "error")
            return redirect(url_for("settings"))
        if not consume_totp(request.form.get("code", "")):
            flash("验证器代码不正确", "error")
            return redirect(url_for("settings"))
        # Only tables of this independent ledger database are cleared; the pre-existing Bill app is untouched.
        with db():
            for table in ("ingest_requests", "bill_tags", "bills", "budget_rules", "tags", "rate_attempts", "passkeys"):
                db().execute("DELETE FROM " + table)
            # Parent deletion is RESTRICT, so remove deepest children first.
            while db().execute("SELECT 1 FROM categories LIMIT 1").fetchone():
                db().execute("DELETE FROM categories WHERE id IN "
                             "(SELECT c.id FROM categories c LEFT JOIN categories child ON child.parent_id=c.id "
                             "WHERE child.id IS NULL)")
            db().execute("UPDATE auth_state SET totp_secret=NULL,password_hash=NULL,pending_secret=NULL,"
                         "failed_passwords=0,last_totp_step=-1,version=version+1 WHERE id=1")
            db().execute("UPDATE settings SET started_at=datetime('now','localtime') WHERE id=1")
        session.clear()
        flash("验证器已解绑，本系统全部账单数据已清空", "success")
        return redirect(url_for("setup"))

    def limited():
        now = int(time.time())
        ip = request.remote_addr or "unknown"
        key = hashlib.sha256((ip + app.config["SECRET_KEY"]).encode()).hexdigest()
        conn = db()
        conn.execute("DELETE FROM rate_attempts WHERE at_epoch<?", (now - 900,))
        count = conn.execute("SELECT COUNT(*) AS n FROM rate_attempts WHERE ip_hash=?", (key,)).fetchone()["n"]
        if count >= 30:
            conn.commit()
            return False
        conn.execute("INSERT INTO rate_attempts(ip_hash,at_epoch) VALUES(?,?)", (key, now))
        conn.commit()
        return True

    def consume_totp(code):
        state = auth_state()
        matched = verify_totp(state["totp_secret"], code, state["last_totp_step"])
        if matched is None:
            return False
        updated = db().execute("UPDATE auth_state SET last_totp_step=? WHERE id=1 AND last_totp_step<?",
                               (matched, matched))
        db().commit()
        return updated.rowcount == 1

    return app


def money(cents):
    return "¥{:,.2f}".format((cents or 0) / 100)


def parse_amount(raw, allow_negative, zero):
    try:
        number = Decimal(str(raw).strip())
    except (InvalidOperation, TypeError):
        raise ValueError("请输入有效金额")
    if not number.is_finite() or number.as_tuple().exponent < -2:
        raise ValueError("金额最多两位小数")
    cents = int(number * 100)
    if abs(cents) > 10**12:
        raise ValueError("金额过大")
    if cents < 0 and not allow_negative:
        raise ValueError("预算不能为负")
    if cents == 0 and not zero:
        raise ValueError("账单金额不能为 0")
    return cents


def parse_id(raw):
    try:
        value = int(raw)
        if value <= 0:
            raise ValueError
        return value
    except (TypeError, ValueError):
        raise ValueError("项目编号无效")


def valid_name(raw, length):
    value = (raw or "").strip()
    if not value or len(value) > length or any(ord(char) < 32 for char in value):
        raise ValueError("名称不能为空、过长或包含控制字符")
    return value


def unique_tags(raw):
    names = []
    seen = set()
    for part in re.split(r"[,，;；\s]+", raw or ""):
        name = part.strip()
        if not name:
            continue
        name = valid_name(name, 60)
        if name.casefold() not in seen:
            names.append(name)
            seen.add(name.casefold())
    if len(names) > 20:
        raise ValueError("每笔账单最多 20 个标签")
    return names


def parse_day(raw, fallback):
    try:
        return date.fromisoformat(raw) if raw else fallback
    except (ValueError, TypeError):
        return fallback


def default_export_range(today):
    completed_month = previous_month(billing_cycle_month(today))
    start, end = billing_cycle_bounds(completed_month)
    return start, end - timedelta(days=1)


def export_range_since_start(today, started_at):
    """Never default the CSV form to dates before this ledger began collecting."""
    launch_day = date.fromisoformat(started_at[:10])
    start, end = default_export_range(today)
    if end < launch_day:
        current_start, _ = billing_cycle_bounds(billing_cycle_month(today))
        return max(launch_day, current_start), today
    return max(start, launch_day), end


def parse_export_range(start_raw, end_raw):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", start_raw or "") or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", end_raw or ""):
        raise ValueError("请选择有效的开始日期和结束日期")
    try:
        start, end = date.fromisoformat(start_raw), date.fromisoformat(end_raw)
    except ValueError:
        raise ValueError("请选择有效的开始日期和结束日期") from None
    if end < start:
        raise ValueError("结束日期不能早于开始日期")
    if end == date.max:
        raise ValueError("结束日期超出可导出范围")
    days = (end - start).days + 1
    full_31_day_month = (days == 31 and start.day == 1 and
                         start.year == end.year and start.month == end.month and
                         end.day == calendar.monthrange(end.year, end.month)[1])
    full_31_day_cycle = (days == 31 and start.day == 13 and
                         end == billing_cycle_bounds(start.strftime("%Y-%m"))[1] - timedelta(days=1))
    if days > 30 and not (full_31_day_month or full_31_day_cycle):
        raise ValueError("最多导出连续 30 天；完整的 31 天自然月或账单周期可以例外")
    return start, end


def csv_safe_text(value):
    text = str(value or "")
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def parse_month(raw, fallback):
    if raw and re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", raw) and 1 <= int(raw[:4]) <= 9998:
        return raw
    return fallback


def parse_year(raw, fallback):
    try:
        value = int(raw)
        return value if 1900 <= value <= 9998 else fallback
    except (ValueError, TypeError):
        return fallback


def month_shift(month, offset):
    year, number = map(int, month.split("-"))
    value = year * 12 + number - 1 + offset
    return "%04d-%02d" % (value // 12, value % 12 + 1)


def next_month(month):
    return month_shift(month, 1)


def previous_month(month):
    return month_shift(month, -1)


def billing_cycle_month(day):
    month = day.strftime("%Y-%m")
    return previous_month(month) if day.day < 13 else month


def billing_cycle_bounds(month):
    """Inclusive 13th to exclusive 13th of the following month."""
    return date.fromisoformat(month + "-13"), date.fromisoformat(next_month(month) + "-13")


def billing_cycle_label(month):
    start, end = billing_cycle_bounds(month)
    return "%s 至 %s" % (start.isoformat(), (end - timedelta(days=1)).isoformat())


def count_remaining(items):
    return {"positive": sum(item["remaining"] > 0 for item in items),
            "negative": sum(item["remaining"] < 0 for item in items),
            "zero": sum(item["remaining"] == 0 for item in items)}


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, maxmem=64 * 1024 * 1024)
    return "scrypt$16384$8$1$" + salt.hex() + "$" + digest.hex()


def check_password(password, encoded):
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$")
        if algorithm != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                                maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(digest, bytes.fromhex(expected))
    except (ValueError, AttributeError, TypeError):
        return False


def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_at(secret, step):
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return "%06d" % (number % 1000000)


def verify_totp(secret, code, last_step=-1, now=None):
    if not secret or not re.fullmatch(r"\d{6}", code or ""):
        return None
    step = int((time.time() if now is None else now) // 30)
    for candidate in (step, step - 1, step + 1):
        if candidate > last_step and hmac.compare_digest(totp_at(secret, candidate), code):
            return candidate
    return None


if __name__ == "__main__":
    application = create_app()
    application.run(host="127.0.0.1", port=int(os.environ.get("LEDGER_PORT", "28908")), debug=False)

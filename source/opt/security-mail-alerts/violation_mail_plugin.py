"""Small Flask registration hook for the existing protected security page."""
import json
import os
import secrets
import urllib.parse
import urllib.request
from pathlib import Path

from flask import Response, jsonify, request
from alerts import DEFAULT_CONFIG, DEFAULT_DB, RECIPIENT, Store, private_json, validate_smtp

ASSETS = Path(__file__).with_name('ui')


def exact_origin():
    supplied = request.headers.get('Origin', '')
    host = request.headers.get('X-Forwarded-Host') or request.host
    try:
        origin = urllib.parse.urlsplit(supplied)
        expected = urllib.parse.urlsplit('https://' + host)
        return bool(supplied and origin.scheme == 'https' and not origin.username and
                    not origin.password and not origin.query and not origin.fragment and
                    origin.path in ('', '/') and origin.hostname == expected.hostname and
                    (origin.port or 443) == (expected.port or 443))
    except ValueError:
        return False


def write_configuration(path, data):
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(12))
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
        if os.name == 'posix':
            os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def worker_get(path, port):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1:{}/api/{}'.format(port, path), timeout=3) as response:
        raw = response.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError('worker_response_too_large')
    return json.loads(raw)


def register(app, admin_request, same_origin_request, verify_view_key,
             config_path=DEFAULT_CONFIG, db_path=DEFAULT_DB, worker_port=18112,
             get_worker=None):
    if app.extensions.get('violation_mail_plugin'):
        return
    app.extensions['violation_mail_plugin'] = True
    fetch = get_worker or (lambda path: worker_get(path, worker_port))

    def guard():
        if not admin_request():
            return jsonify(error='admin_required'), 403
        if not exact_origin() or not same_origin_request():
            return jsonify(error='same_origin_required'), 403
        if not verify_view_key():
            return jsonify(error='second_factor_required'), 403
        return None

    @app.route('/api/violation-mail/status', methods=['GET'])
    def violation_mail_status():
        try:
            return jsonify(fetch('status'))
        except Exception:
            return jsonify(available=False, recipient=RECIPIENT,
                           error='notification_worker_unavailable'), 503

    @app.route('/api/violation-mail/events', methods=['GET'])
    def violation_mail_events():
        try:
            return jsonify(fetch('events'))
        except Exception:
            return jsonify(error='notification_worker_unavailable'), 503

    @app.route('/api/violation-mail/config', methods=['POST'])
    def violation_mail_config():
        denied = guard()
        if denied:
            return denied
        if request.content_length is None or request.content_length > 16384:
            return jsonify(error='configuration_size_invalid'), 400
        raw = request.get_json(silent=True)
        allowed = {'host', 'port', 'mode', 'sender', 'username', 'password'}
        if not isinstance(raw, dict) or set(raw) - allowed:
            return jsonify(error='smtp_fields_invalid'), 400
        try:
            current = private_json(config_path)
            smtp = {key: raw.get(key) for key in allowed if key != 'password'}
            if smtp.get('mode') not in ('ssl', 'starttls'):
                raise ValueError('smtp_tls_mode_required')
            supplied = raw.get('password')
            if supplied is not None and (not isinstance(supplied, str) or len(supplied) > 1024):
                raise ValueError('smtp_password_invalid')
            smtp['password'] = supplied or (current.get('smtp') or {}).get('password', '')
            for key in ('host', 'sender', 'username'):
                if not isinstance(smtp[key], str) or len(smtp[key]) > 300 or any(ord(c) < 32 for c in smtp[key]):
                    raise ValueError('smtp_field_invalid')
                smtp[key] = smtp[key].strip()
            configured, error = validate_smtp(smtp)
            if not configured:
                raise ValueError(error)
            current['recipient'] = RECIPIENT
            current['smtp'] = configured
            write_configuration(config_path, current)
        except ValueError as error:
            code = str(error) if str(error).replace('_', '').isalnum() else 'smtp_configuration_invalid'
            return jsonify(error=code), 400
        except Exception:
            return jsonify(error='configuration_storage_unavailable'), 503
        return jsonify(ok=True, configured=True, recipient=RECIPIENT, password_saved=True)

    @app.route('/api/violation-mail/test', methods=['POST'])
    def violation_mail_test():
        denied = guard()
        if denied:
            return denied
        try:
            current = private_json(config_path)
            configured, _ = validate_smtp(current.get('smtp'))
            if not configured:
                return jsonify(error='smtp_not_configured'), 409
            key = Store(db_path).enqueue_test()
        except ValueError as error:
            if str(error) == 'test_recently_requested':
                return jsonify(error='test_recently_requested'), 429
            return jsonify(error='test_queue_unavailable'), 503
        except Exception:
            return jsonify(error='test_queue_unavailable'), 503
        return jsonify(ok=True, state='queued', recipient=RECIPIENT,
                       test_notification=True, event_key=key), 202

    @app.route('/violation-mail-ui.js', methods=['GET'])
    def violation_mail_js():
        return Response((ASSETS / 'violation-mail-ui.js').read_text(encoding='utf-8'),
                        content_type='application/javascript; charset=utf-8',
                        headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})

    @app.route('/violation-mail-ui.css', methods=['GET'])
    def violation_mail_css():
        return Response((ASSETS / 'violation-mail-ui.css').read_text(encoding='utf-8'),
                        content_type='text/css; charset=utf-8',
                        headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})

    @app.after_request
    def inject_violation_mail_ui(response):
        if request.path == '/' and response.mimetype == 'text/html':
            text = response.get_data(as_text=True)
            marker = '<script defer src="./violation-mail-ui.js"></script>'
            if marker not in text:
                text = text.replace('</head>', '<link rel="stylesheet" href="./violation-mail-ui.css">' + marker + '</head>', 1)
                response.set_data(text)
        return response

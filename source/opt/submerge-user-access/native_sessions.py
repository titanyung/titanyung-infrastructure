"""Authenticated native sing-box snapshot and exact UUID closure.

Official v1.14.3 daemon/started_service.proto defines CloseConnectionRequest
as string id = 1. The existing monitor's generated stub is a partial proto;
this module adds the wire-compatible unary call without editing that stub.
No hot user-management RPC exists in that version. Closing a session alone
does not revoke a cached credential; runtime credential reload is required.
"""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import stat
import sys
import uuid

from runtime_revoke import RevokeError, ScopedSessionCloser, _require


def encode_close_request(identifier):
    try:
        parsed = uuid.UUID(identifier)
    except (ValueError, TypeError, AttributeError):
        raise RevokeError('native_connection_uuid_invalid') from None
    _require(parsed.int != 0 and str(parsed) == identifier.lower(), 'native_connection_uuid_invalid')
    value = str(parsed).encode('ascii')
    # UUID text is exactly 36 bytes, so a single-byte protobuf length suffices.
    return b'\x0a' + bytes([len(value)]) + value


class NativeSessionControl:
    def __init__(self, address, secret, *, proto=None, channel=None, timeout=5):
        _require(isinstance(address, str) and address.startswith('127.0.0.1:')
                 and address.rsplit(':', 1)[1].isdigit()
                 and 1 <= int(address.rsplit(':', 1)[1]) <= 65535,
                 'native_control_must_be_loopback')
        _require(isinstance(secret, str) and len(secret) >= 32, 'native_control_secret_invalid')
        if proto is None:
            for path in ('/opt/static-connection-events', str(Path(__file__).resolve().parents[1] / 'static-connection-events')):
                if path not in sys.path:
                    sys.path.insert(0, path)
            proto = importlib.import_module('connection_events_pb2')
        if channel is None:
            import grpc
            channel = grpc.insecure_channel(address,
                options=[('grpc.max_receive_message_length', 16 * 1024 * 1024)])
        self.proto, self.channel, self.timeout = proto, channel, timeout
        self.metadata = (('authorization', 'Bearer ' + secret),)
        self.subscribe = channel.unary_stream('/daemon.StartedService/SubscribeConnections',
            request_serializer=proto.SubscribeConnectionsRequest.SerializeToString,
            response_deserializer=proto.ConnectionEvents.FromString)
        self.close_rpc = channel.unary_unary('/daemon.StartedService/CloseConnection',
            request_serializer=lambda payload: payload, response_deserializer=lambda _: None)

    @classmethod
    def from_runtime(cls, path='/run/dmit-direct-staging/config.json', *, secret_file=None, **kwargs):
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(str(path), flags)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
                     'runtime_control_file_permissions_invalid')
            raw = stream.read(16 * 1024 * 1024 + 1)
        _require(len(raw) <= 16 * 1024 * 1024, 'runtime_control_config_too_large')
        config = json.loads(raw)
        services = [item for item in config.get('services', [])
                    if isinstance(item, dict) and item.get('type') == 'api']
        _require(len(services) == 1, 'runtime_native_api_ambiguous')
        api = services[0]
        _require(api.get('listen') == '127.0.0.1' and type(api.get('listen_port')) is int,
                 'runtime_native_api_not_loopback')
        secret = api.get('secret', api.get('auth_token'))
        if secret_file is not None:
            secret_path = Path(secret_file)
            info = secret_path.stat()
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
                     'runtime_native_secret_permissions_invalid')
            value = secret_path.read_text(encoding='utf-8').strip()
            _require(secret is None or secret == value, 'runtime_native_secret_binding_mismatch')
            secret = value
        return cls('127.0.0.1:' + str(api['listen_port']), secret, **kwargs)

    def snapshot(self):
        stream = self.subscribe(self.proto.SubscribeConnectionsRequest(interval=1_000_000_000),
                                metadata=self.metadata, timeout=self.timeout, wait_for_ready=False)
        try:
            message = next(stream)
            _require(message.reset is True, 'native_snapshot_not_complete')
            _require(len(message.events) <= 100000, 'native_snapshot_too_large')
            rows = []
            for event in message.events:
                connection = event.connection
                # Initial reset includes retained closed connections too.
                if not connection.id or connection.closedAt > 0:
                    continue
                _require(event.id == connection.id, 'native_snapshot_uuid_mismatch')
                rows.append({'id': connection.id, 'user': connection.user,
                             'inbound': connection.inbound})
            return rows
        except StopIteration:
            raise RevokeError('native_snapshot_missing') from None
        finally:
            stream.cancel()

    def close_connection(self, identifier):
        self.close_rpc(encode_close_request(identifier), metadata=self.metadata,
                       timeout=self.timeout, wait_for_ready=False)

    def scoped(self, inbounds=None):
        if inbounds is None:
            # Read durable intent at operation time so a long-lived worker
            # cannot keep the old inventory after a six-server release.
            from production_adapter import expected_fronts
            fronts = expected_fronts()
            # The legacy snapshot helper historically included Taiwan even
            # before its optional marker was committed during staging.
            inbounds = frozenset(fronts) | (frozenset({'dmit-taiwan'})
                if 'dmit-zorocloud' in fronts else frozenset())
        return ScopedSessionCloser(self.snapshot, self.close_connection, inbounds=inbounds)

    def shutdown(self):
        self.channel.close()

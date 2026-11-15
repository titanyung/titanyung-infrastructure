"""Isolated INFO-only BT quarantine test; every possible outbound is loopback.

Run with the existing sing-box binary. Never reads/modifies a production config.
The specially tagged SOCKS outbound points to a loopback socket held bound but
not listening, so no process can forward BT traffic or claim its local port.
"""
import json
import re
import socket
import struct
import subprocess
import tempfile
import time

binary = '/root/lazycat-test-config/sing-box'
with tempfile.TemporaryDirectory(prefix='info-bt-fixture-') as folder, socket.socket() as quarantine:
    quarantine.bind(('127.0.0.1', 0))
    quarantine_port = quarantine.getsockname()[1]
    with socket.socket() as bind:
        bind.bind(('127.0.0.1', 0))
        port = bind.getsockname()[1]
    config = {
        'log': {'level': 'info', 'timestamp': True},
        'inbounds': [{'type': 'socks', 'tag': 'fixture-in', 'listen': '127.0.0.1',
                      'listen_port': port, 'users': [{'username': 'fixture-user', 'password': 'fixture-password'}]}],
        'outbounds': [{'type': 'socks', 'tag': 'violation-bt-quarantine',
                       'server': '127.0.0.1', 'server_port': quarantine_port,
                       'connect_timeout': '1s'}],
        'route': {'rules': [{'action': 'sniff'},
                            {'protocol': ['bittorrent'], 'action': 'route', 'outbound': 'violation-bt-quarantine'},
                            {'action': 'reject'}]}}
    path = folder + '/config.json'
    with open(path, 'w') as output:
        json.dump(config, output)
    subprocess.run([binary, 'check', '-c', path], check=True, capture_output=True)

    def authenticated_socket():
        client = socket.create_connection(('127.0.0.1', port), timeout=2)
        client.sendall(bytes([5, 1, 2])); assert client.recv(2) == b'\x05\x02'
        user, password = b'fixture-user', b'fixture-password'
        client.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
        assert client.recv(2) == b'\x01\x00'
        return client

    with open(folder + '/log', 'w+') as log:
        process = subprocess.Popen([binary, 'run', '-c', path], stdout=log, stderr=log)
        try:
            for _ in range(40):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            payloads = [b'\x13BitTorrent protocol' + bytes(8) + b'01234567890123456789' + b'-QA0001-0123456789012',
                        b'GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n']
            for payload in payloads:
                with authenticated_socket() as client:
                    client.sendall(bytes([5, 1, 0, 1]) + socket.inet_aton('203.0.113.10') + struct.pack('!H', 6881))
                    client.recv(10)
                    client.sendall(payload)
                    try:
                        while client.recv(64):
                            pass
                    except OSError:
                        pass
                time.sleep(.1)
            with authenticated_socket() as client:
                client.sendall(b'\x05\x03\x00\x01' + bytes(6))
                reply = client.recv(64)
                assert reply[:4] == b'\x05\x00\x00\x01', repr(reply)
                relay = (socket.inet_ntoa(reply[4:8]), struct.unpack('!H', reply[8:10])[0])
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as packet:
                    packet.sendto(b'\x00\x00\x00\x01' + socket.inet_aton('203.0.113.10') +
                                  struct.pack('!H', 6969) + struct.pack('!QII', 0x41727101980, 0, 123), relay)
                time.sleep(.3)
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        log.flush(); log.seek(0)
        lines = [re.sub(r'\x1b\[[0-9;]*m', '', line.rstrip()) for line in log]
        evidence = [line for line in lines if 'inbound connection' in line or 'inbound packet' in line or
                    'violation-bt-quarantine' in line or 'ERROR' in line]
        print(json.dumps({'info_logs': evidence, 'debug_disabled': not any(' DEBUG ' in x for x in lines),
                          'bt_tag_hits': sum('outbound/socks[violation-bt-quarantine]' in x for x in lines),
                          'outbound_restricted_to_loopback': True}, ensure_ascii=False))

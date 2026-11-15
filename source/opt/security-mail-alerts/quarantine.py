#!/usr/bin/env python3
"""Loopback-only SOCKS refusal endpoint. No forwarding, DNS, or outbound calls."""
import socket
import socketserver
import threading


class Refuse(socketserver.BaseRequestHandler):
    def handle(self):
        # The SOX5 no-acceptable-methods response cannot establish CONNECT or
        # UDP ASSOCIATE. No application payload is requested or forwarded.
        self.request.settimeout(.2)
        try:
            self.request.recv(258)
            self.request.sendall(b'\x05\xff')
        except OSError:
            pass


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64
    slots = threading.BoundedSemaphore(32)

    def process_request(self, request, address):
        if not self.slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


if __name__ == '__main__':
    with Server(('127.0.0.1', 18115), Refuse) as server:
        server.serve_forever(poll_interval=.5)

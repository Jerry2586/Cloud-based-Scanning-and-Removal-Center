#!/usr/bin/env python3
"""Root-owned cloud update bridge: three fixed routes, no caller-selected commands."""
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import sys

sys.dont_write_bytecode = True


def trusted_directory(path):
    for entry in (path, *path.parents):
        meta = entry.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise ValueError('update directory invalid')


def handler(bridge):
    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def send(self, status, value):
            payload = json.dumps(value, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def allowed(self):
            _, uid, gid = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            return uid == 0 or (uid == 10001 and gid == 10001)

        def do_GET(self):
            if not self.allowed():
                return self.send(403, {'state': 'unavailable'})
            if self.path != '/update-status':
                return self.send(404, {'state': 'unavailable'})
            try:
                self.send(200, bridge.status())
            except Exception:
                self.send(503, {'state': 'unavailable'})

        def do_POST(self):
            if not self.allowed():
                return self.send(403, {'state': 'unavailable'})
            actions = {'/update-check': 'check', '/update': 'update'}
            if self.path not in actions:
                return self.send(404, {'state': 'unavailable'})
            if self.headers.get('Transfer-Encoding') or self.headers.get_all('Content-Length') != ['0']:
                return self.send(400, {'state': 'unavailable'})
            try:
                self.send(*bridge.trigger(actions[self.path]))
            except Exception:
                self.send(503, {'state': 'unavailable'})

        def log_message(self, *_):
            pass
    return Handler


class Server(socketserver.UnixStreamServer):
    allow_reuse_address = False


def serve():
    if os.geteuid() != 0:
        raise SystemExit('root required')
    directory = Path('/run/ironcurtain-update-cloud')
    trusted_directory(directory)
    if stat.S_IMODE(directory.stat().st_mode) != 0o750 or directory.stat().st_gid != 10001:
        raise ValueError('socket directory permissions invalid')
    socket_path = directory / 'control.sock'
    if socket_path.exists() or socket_path.is_symlink():
        meta = socket_path.lstat()
        if not stat.S_ISSOCK(meta.st_mode) or meta.st_uid != 0:
            raise ValueError('socket invalid')
        socket_path.unlink()
    spec = importlib.util.spec_from_file_location('cloud_update_host', Path(__file__).with_name('agent.py'))
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    bridge = host.updates.Bridge(host.private_bytes, host.atomic_json, base=Path('/opt/ironcurtain/cloud'), data=Path('/var/lib/ironcurtain/cloud'), role='cloud')
    with Server(str(socket_path), handler(bridge)) as server:
        os.chown(socket_path, 0, 10001)
        os.chmod(socket_path, 0o660)
        server.serve_forever(poll_interval=0.5)


if __name__ == '__main__':
    serve()

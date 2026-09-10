import concurrent.futures
import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

RUNTIME = Path(__file__).resolve().parents[1]


def receive_all(sock):
    chunks = []
    while chunk := sock.recv(65536):
        chunks.append(chunk)
    return b''.join(chunks)


def encode(kind, payload=b''):
    return kind + struct.pack('!I', len(payload)) + payload


def read_frames(stream):
    result = bytearray()
    while True:
        header = stream.read(5)
        if len(header) != 5:
            raise AssertionError('missing framed EOF')
        length = struct.unpack('!I', header[1:])[0]
        if header[:1] == b'F':
            if length:
                raise AssertionError('invalid EOF frame')
            return bytes(result)
        if header[:1] != b'D' or not 0 < length <= 65536:
            raise AssertionError('invalid data frame')
        payload = stream.read(length)
        if len(payload) != length:
            raise AssertionError('truncated payload')
        result.extend(payload)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.control = self.tmp.name + '/bridge/control.sock'
        self.actions = self.tmp.name + '/actions.sock'
        self.ready = self.tmp.name + '/gateway.ready'
        self.process = subprocess.Popen([sys.executable, str(RUNTIME / 'gateway.py'),
            '--control', self.control, '--actions', self.actions,
            '--port', '0', '--pending-seconds', '.3'])
        deadline = time.monotonic() + 5
        while not Path(self.ready).exists():
            if self.process.poll() is not None or time.monotonic() > deadline:
                self.fail('gateway failed startup')
            time.sleep(.01)
        self.port = int(Path(self.ready).read_text())

    def tearDown(self):
        self.process.terminate()
        self.process.wait(timeout=5)
        self.tmp.cleanup()

    def connect(self, path):
        sock = socket.socket(socket.AF_UNIX)
        sock.settimeout(5)
        self.addCleanup(sock.close)
        sock.connect(path)
        return sock

    def test_concurrent_bidirectional_exact_stream_and_halfclose(self):
        def transfer(index):
            control = self.connect(self.control)
            client = self.connect(self.actions)
            self.assertEqual(control.recv(1), b'A')
            payload = bytes(range(256)) * 5000
            def send():
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
            with concurrent.futures.ThreadPoolExecutor(1) as pool:
                sending = pool.submit(send)
                self.assertEqual(receive_all(control), payload)
                sending.result()
            control.sendall(b'reply after EOF')
            control.shutdown(socket.SHUT_WR)
            self.assertEqual(receive_all(client), b'reply after EOF')
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            list(pool.map(transfer, range(8)))

    def test_pending_timeout_and_queue_bound(self):
        clients = []
        for _ in range(40):
            try:
                clients.append(self.connect(self.actions))
            except ConnectionRefusedError:
                # BSD Unix sockets may reject at the bounded kernel backlog
                # before the event loop accepts and applies its pending limit.
                pass
        self.assertTrue(clients)
        time.sleep(.6)
        for client in clients:
            self.assertEqual(client.recv(1), b'')

    def test_control_registration_bound(self):
        controls = [self.connect(self.control) for _ in range(17)]
        self.assertEqual(controls[-1].recv(1), b'')

    def test_channel_idle_host_eof_exits(self):
        channel = subprocess.Popen([sys.executable, str(RUNTIME / 'channel.py'),
            '--control', self.control], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        out, _ = channel.communicate(timeout=3)
        self.assertEqual(channel.returncode, 0)
        self.assertEqual(out, b'')

    def spawn_channel(self):
        channel = subprocess.Popen([sys.executable, str(RUNTIME / 'channel.py'),
            '--control', self.control], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        def cleanup():
            if channel.poll() is None:
                channel.kill()
            channel.wait(timeout=3)
            channel.stdin.close()
            channel.stdout.close()
        self.addCleanup(cleanup)
        return channel

    def test_channel_stream(self):
        channel = self.spawn_channel()
        client = self.connect(self.actions)
        payload = bytes(range(256)) * 5000
        self.assertEqual(channel.stdout.read(1), b'A')
        def send_request():
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            sending = pool.submit(send_request)
            self.assertEqual(read_frames(channel.stdout), payload)
            sending.result()
        # Docker's process must stay alive after directional EOF to accept reply.
        self.assertIsNone(channel.poll())
        channel.stdin.write(encode(b'D', b'response') + encode(b'F'))
        channel.stdin.flush()
        self.assertEqual(receive_all(client), b'response')
        channel.wait(timeout=3)
        self.assertEqual(channel.returncode, 0)

    def test_channel_rejects_malformed_frames(self):
        for data in (b'X' + bytes(4), encode(b'D'),
                     b'D' + struct.pack('!I', 65537), encode(b'F', b'x'),
                     encode(b'F') + encode(b'F'), encode(b'F') + encode(b'D', b'x')):
            with self.subTest(data=data):
                channel = self.spawn_channel()
                client = self.connect(self.actions)
                self.assertEqual(channel.stdout.read(1), b'A')
                channel.stdin.write(data)
                channel.stdin.flush()
                channel.wait(timeout=3)
                self.assertEqual(channel.returncode, 1)
                client.close()

    def test_channels_ready_tracks_registration_lifecycle(self):
        ready = Path(self.control).parent / 'channels.ready'
        self.assertFalse(ready.exists())
        control = self.connect(self.control)
        deadline = time.monotonic() + 2
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(ready.exists())
        control.close()
        deadline = time.monotonic() + 2
        while ready.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertFalse(ready.exists())

    def test_channel_pending_host_bytes_and_eof_cancel(self):
        channel = subprocess.Popen([sys.executable, str(RUNTIME / 'channel.py'),
            '--control', self.control], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, _ = channel.communicate(encode(b'D', b'unsolicited'), timeout=3)
        self.assertEqual(channel.returncode, 0)
        self.assertEqual(out, b'')

    def test_proxy_kind(self):
        control = self.connect(self.control)
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as client:
            client.sendall(b'GET')
            self.assertEqual(control.recv(1), b'P')
            self.assertEqual(control.recv(3), b'GET')

    def test_pair_backpressure_bounds_buffers(self):
        spec = importlib.util.spec_from_file_location('gateway', RUNTIME / 'gateway.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        for sock in (a, b, c, d):
            self.addCleanup(sock.close)
            sock.setblocking(False)
        pair = module.Pair(a, c, b'P')
        while len(pair.output[1]) < module.LIMIT:
            b.send(b'x' * min(4096, module.LIMIT - len(pair.output[1])))
            pair.pump([a], [])
        self.assertEqual(len(pair.output[1]), module.LIMIT)
        reads, writes = [], []
        pair.interests(reads, writes)
        self.assertNotIn(a, reads)
        self.assertIn(c, writes)
        pair.pump([], [c])
        pair.interests(reads, writes)
        self.assertIn(a, reads)

    def test_shutdown_removes_sockets(self):
        self.process.terminate()
        self.process.wait(timeout=3)
        self.assertFalse(Path(self.control).exists())
        self.assertFalse(Path(self.actions).exists())
        self.assertFalse(Path(self.ready).exists())


if __name__ == '__main__':
    unittest.main()

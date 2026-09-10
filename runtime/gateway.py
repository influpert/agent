#!/usr/bin/env python3
"""Bounded, single-threaded assignment transport; never interprets request bytes."""
import argparse
from collections import deque
import os
from pathlib import Path
import select
import signal
import socket
import time

LIMIT = 65536
SLOTS = 16
PENDING = 32


class Pair:
    def __init__(self, client, control, kind):
        self.sockets = [client, control]
        self.output = [bytearray(), bytearray(kind)]
        self.eof = [False, False]
        self.closed_write = [False, False]

    def close(self):
        for sock in self.sockets:
            sock.close()

    def interests(self, reads, writes):
        for i, sock in enumerate(self.sockets):
            if not self.eof[i] and len(self.output[1-i]) < LIMIT:
                reads.append(sock)
            if self.output[i]:
                writes.append(sock)

    def pump(self, readable, writable):
        try:
            for i, sock in enumerate(self.sockets):
                if sock in writable and self.output[i]:
                    count = sock.send(self.output[i])
                    del self.output[i][:count]
                if sock in readable and not self.eof[i]:
                    chunk = sock.recv(LIMIT - len(self.output[1-i]))
                    if chunk:
                        self.output[1-i].extend(chunk)
                    else:
                        self.eof[i] = True
            for i, sock in enumerate(self.sockets):
                if self.eof[1-i] and not self.output[i] and not self.closed_write[i]:
                    sock.shutdown(socket.SHUT_WR)
                    self.closed_write[i] = True
            return not (all(self.eof) and not any(self.output))
        except BlockingIOError:
            return True
        except OSError:
            return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--control', default='/run/hatchward/bridge/control.sock')
    parser.add_argument('--actions', default='/run/hatchward/gateway/actions.sock')
    parser.add_argument('--port', type=int, default=3128)
    parser.add_argument('--pending-seconds', type=float, default=15)
    args = parser.parse_args()
    bridge = Path(args.control).parent
    bridge.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(bridge, 0o700)
    ready = Path(args.actions).parent / 'gateway.ready'
    channels_ready = bridge / 'channels.ready'
    channels_present = False
    listeners = []
    idle = deque()
    pending = deque()
    pairs = []
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for path, mode in [(args.control, 0o600), (args.actions, 0o666)]:
            sock = socket.socket(socket.AF_UNIX)
            listeners.append(sock)
            sock.bind(path)
            os.chmod(path, mode)
            sock.listen(32)
            sock.setblocking(False)
        proxy = socket.socket()
        listeners.append(proxy)
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy.bind(('127.0.0.1', args.port))
        proxy.listen(32)
        proxy.setblocking(False)
        ready.write_text(str(proxy.getsockname()[1]))
        while running:
            reads, writes = list(listeners) + list(idle), []
            for pair in pairs:
                pair.interests(reads, writes)
            readable, writable, _ = select.select(reads, writes, [], .1)
            # An idle host channel carries no bytes until assigned. EOF is cancellation.
            for sock in list(idle):
                if sock in readable:
                    idle.remove(sock)
                    sock.close()
            for index, listener in enumerate(listeners):
                if listener not in readable:
                    continue
                try:
                    sock, _ = listener.accept()
                except BlockingIOError:
                    continue
                sock.setblocking(False)
                if index == 0:
                    if len(idle) + len(pairs) >= SLOTS:
                        sock.close()
                    else:
                        idle.append(sock)
                elif len(pending) >= PENDING:
                    sock.close()
                else:
                    pending.append((sock, b'A' if index == 1 else b'P',
                                    time.monotonic() + args.pending_seconds))
            now = time.monotonic()
            while pending and pending[0][2] <= now:
                pending.popleft()[0].close()
            for pair in list(pairs):
                if not pair.pump(readable, writable):
                    pairs.remove(pair)
                    pair.close()
            while idle and pending:
                client, kind, _ = pending.popleft()
                pairs.append(Pair(client, idle.popleft(), kind))
            present = bool(idle or pairs)
            if present != channels_present:
                if present:
                    channels_ready.touch(mode=0o600)
                else:
                    channels_ready.unlink(missing_ok=True)
                channels_present = present
    finally:
        for pair in pairs:
            pair.close()
        for sock in list(idle) + [entry[0] for entry in pending] + listeners:
            sock.close()
        for path in [ready, channels_ready, Path(args.control), Path(args.actions)]:
            path.unlink(missing_ok=True)


if __name__ == '__main__':
    main()

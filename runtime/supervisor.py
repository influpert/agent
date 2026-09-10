"""Capability-free PID 1; expose readiness only after privilege drop."""
import os
from pathlib import Path
import signal
import sys
import time

critical_children = {int(pid) for pid in sys.argv[1:]}
assert len(critical_children) == 2

for line in Path('/proc/self/status').read_text().splitlines():
    if line.startswith(('CapInh:', 'CapPrm:', 'CapEff:', 'CapBnd:', 'CapAmb:')):
        assert int(line.split()[1], 16) == 0
signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
signal.signal(signal.SIGINT, lambda *_: os._exit(0))
for _ in range(150):
    child, _status = os.waitpid(-1, os.WNOHANG)
    if child in critical_children:
        raise SystemExit('runtime child exited before readiness')
    if Path('/run/hatchward/gateway/gateway.ready').exists():
        break
    time.sleep(0.1)
else:
    raise SystemExit('runtime gateway did not become ready')
Path('/run/hatchward/ready').touch(mode=0o444)
while True:
    child, _status = os.wait()
    if child in critical_children:
        raise SystemExit('runtime child exited')

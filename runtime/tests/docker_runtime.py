"""Opt-in integration test: python3 runtime/tests/docker_runtime.py IMAGE."""
import io
import json
import subprocess
import sys
import tarfile
import time
import uuid

name = 'hw-runtime-test-' + uuid.uuid4().hex[:10]
image = sys.argv[1]
size_mib = int(sys.argv[2]) if len(sys.argv) > 2 else 256

def docker(*args, data=None, check=True):
    p = subprocess.run(['docker', *args], input=data, capture_output=True, timeout=120)
    if check and p.returncode:
        raise RuntimeError(p.stderr.decode(errors='replace') + p.stdout.decode(errors='replace'))
    return p

try:
    docker('volume', 'create', name)
    args = ['run', '-d', '--name', name, '--network', 'none', '--read-only', '--ipc', 'none',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--device', '/dev/fuse',
            '--memory', '256m', '--memory-swap', '256m', '--pids-limit', '64',
            '--mount', f'type=volume,src={name},dst=/hatchward-backing',
            '-e', f'HATCHWARD_DISK_MIB={size_mib}', '--entrypoint', '/usr/local/bin/hatchward-bootstrap']
    for cap in ['SYS_ADMIN', 'CHOWN', 'SETUID', 'SETGID', 'SETPCAP']:
        args += ['--cap-add', cap]
    docker(*args, image)
    for _ in range(60):
        if docker('exec', name, 'test', '-f', '/run/hatchward/ready', check=False).returncode == 0:
            break
        time.sleep(.25)
    else:
        raise RuntimeError(docker('logs', name).stdout.decode()+docker('logs', name).stderr.decode())
    # Read process status in a trusted exec; all pre-existing processes must have no caps.
    audit = docker('exec', name, 'python3', '-c', '''import pathlib,os,json
out=[]
for p in pathlib.Path('/proc').glob('[0-9]*/status'):
 try:
  if p.parent.name==str(os.getpid()): continue
  data=dict(x.split(':',1) for x in p.read_text().splitlines() if ':' in x)
  assert all(int(data[k].strip(),16)==0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']),data
  assert data['NoNewPrivs'].strip()=='1'
  out.append({k:data[k].strip() for k in ['Name','Uid','CapEff','CapBnd','NoNewPrivs']})
 except FileNotFoundError: pass
print(json.dumps(out))''')
    print(audit.stdout.decode())
    # Ordinary orphan completion must be reaped without terminating the runtime.
    docker('exec', '--user', '1000:1000', name, '/usr/bin/python3', '-c',
           'import os,time; pid=os.fork(); time.sleep(.1) if pid==0 else None; os._exit(0)')
    docker('exec', name, '/usr/bin/test', '-f', '/run/hatchward/ready')
    # A hostile workload may shadow PATH tools before channel replenishment.
    docker('exec', '--user', '1000:1000', name, '/usr/bin/python3', '-c', """from pathlib import Path
folder=Path('/home/agent/.local/bin');folder.mkdir(parents=True,exist_ok=True)
for tool in ['setpriv','python3']:
 p=folder/tool
 p.write_bytes(bytes.fromhex('23212f62696e2f73680a2f62696e2f636174202f70726f632f73656c662f737461747573203e202f746d702f70726976696c656765642d706174682d70776e65640a657869742039310a'))
 p.chmod(0o755)
""")
    docker('exec', '-i', name, '/usr/local/bin/hatchward-channel', data=b'')
    assert docker('exec', name, '/usr/bin/test', '-e', '/tmp/privileged-path-pwned', check=False).returncode != 0
    docker('exec', '-i', name, 'hatchward-configure', data=b'{}')
    b=io.BytesIO()
    with tarfile.open(fileobj=b, mode='w') as tar:
        content=b'import-sentinel'
        info=tarfile.TarInfo('sentinel');info.size=len(content);tar.addfile(info,io.BytesIO(content))
    docker('exec','-i',name,'hatchward-import',data=b.getvalue())
    script='''import os,pathlib,errno,json,shutil,subprocess,socket
assert os.getuid()==1000
assert not pathlib.Path('/tmp/privileged-path-pwned').exists()
status=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
assert all(int(status[k].strip(),16)==0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])
assert status['NoNewPrivs'].strip()=='1'
assert len({os.stat(p).st_dev for p in ['/workspace','/home/agent','/tmp','/var/tmp','/run']})==1
control=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
try: control.connect('/run/hatchward/bridge/control.sock')
except PermissionError: pass
else: raise AssertionError('workload attached privileged host channel')
finally: control.close()
network=socket.socket();network.settimeout(1)
try: network.connect(('1.1.1.1',443))
except OSError: pass
else: raise AssertionError('direct network egress escaped isolation')
finally: network.close()
if shutil.which('claude'): subprocess.run(['claude','--version'],check=True)
assert pathlib.Path('/workspace/sentinel').read_text()=='import-sentinel'
assert json.loads(pathlib.Path('/run/hatchward/manifest.json').read_text())=={'agent':{}}
for path in ['/hatchward-backing/quota.ext4','/run/hatchward/config.json','/run/hatchward/bridge/control.sock','/etc/escape','/dev/shm/escape','/dev/fuse']:
 try:
  with open(path,'ab') as f: f.write(b'x')
 except OSError: pass
 else: raise AssertionError('write escape '+path)
with open('/workspace/large','wb') as f:
 try:
  for _ in range(SIZE_MIB + 100): f.write(bytes(1048576))
  f.flush();os.fsync(f.fileno())
 except OSError as e: assert e.errno==errno.ENOSPC
 else: raise AssertionError('quota bypass')
try: pathlib.Path('/home/agent/overflow').write_bytes(bytes(1048576))
except OSError as e: assert e.errno==errno.ENOSPC
else: raise AssertionError('home quota bypass')
print('PASS runtime import, manifest, privileges, protected paths, shared disk quota')'''
    result=docker('exec','-i',name,'hatchward-run','/usr/bin/python3','-c',script.replace('SIZE_MIB', str(size_mib)),data=b'{"agent":{}}')
    print(result.stdout.decode())
    docker('exec', '--user', '10002:10002', name, '/usr/bin/python3', '-c', '''import pathlib,os,signal
for p in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
 try:
  if b'/usr/local/lib/hatchward/runtime/gateway.py' in p.read_bytes().split(bytes([0])):
   os.kill(int(p.parent.name),signal.SIGTERM)
 except (FileNotFoundError,PermissionError): pass
''')
    for _ in range(40):
        if docker('inspect','--format','{{.State.Running}}',name).stdout.strip()==b'false': break
        time.sleep(.1)
    else: raise AssertionError('gateway failure did not stop container')
    print('PASS orphan reaping and daemon-failure shutdown')
finally:
    docker('rm','-f',name,check=False)
    docker('volume','rm',name)

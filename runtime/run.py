"""Unprivileged workload launch. All mutable files reside on the bounded volume."""
import json
import os
from pathlib import Path
import subprocess
import sys

RUN = Path('/run/hatchward')


def main():
    if len(sys.argv) < 2:
        raise ValueError('image command is missing')
    config = json.loads((RUN / 'config.json').read_text())
    manifest = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
    if len(manifest) > 16 * 1024 * 1024:
        raise ValueError('manifest exceeds 16 MiB')
    json.loads(manifest)
    path = RUN / 'workload/manifest.json'
    with path.open('xb') as output:
        output.write(manifest)
    path.chmod(0o600)
    env = os.environ.copy()
    env.update(PATH='/home/agent/.local/share/mise/shims:/home/agent/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', HOME='/home/agent', AGENT_RUN_DIR=str(RUN), AGENT_WORKSPACE='/workspace',
               CLAUDE_PROJECT_DIR='/workspace', HATCHWARD_ASSIGNMENT_ACTION_SOCKET=str(RUN / 'actions.sock'))
    env.update(config['env'])
    proxy = config['proxyUrl']
    if proxy:
        ca = str(RUN / 'ca.pem')
        for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'AGENT_PROXY_URL'):
            env[key] = proxy
        env.update(NO_PROXY='localhost,127.0.0.1,::1', no_proxy='localhost,127.0.0.1,::1',
                   NODE_USE_ENV_PROXY='1', CARGO_NET_GIT_FETCH_WITH_CLI='true', CLAUDE_CODE_CERT_STORE='system')
        for key in ('AGENT_CA_FILE', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'CURL_CA_BUNDLE',
                    'GIT_SSL_CAINFO', 'REQUESTS_CA_BUNDLE', 'PIP_CERT', 'CARGO_HTTP_CAINFO',
                    'AWS_CA_BUNDLE', 'DENO_CERT'):
            env[key] = ca
    for key, value in [('safe.directory', '/workspace'), ('user.name', 'hatchward-agent'),
                       ('user.email', 'agent@hatchward.invalid')]:
        subprocess.run(['git', 'config', '--global', '--replace-all', key, value], env=env, check=True)
    subprocess.run(['git', 'config', '--global', 'credential.helper', '!gh auth git-credential'], env=env, check=True)
    os.chdir('/workspace')
    fd = os.open('/dev/null', os.O_RDONLY)
    os.dup2(fd, 0)
    os.close(fd)
    os.execvpe(sys.argv[1], sys.argv[1:], env)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit('hatchward-run: workload preparation failed')

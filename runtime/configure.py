"""Accept public trust material and literal proxy sentinels, never credentials."""
import json
import os
from pathlib import Path
import ssl
import sys
from urllib.parse import urlsplit

RUN = Path('/run/hatchward')
SENTINEL = 'hatchward-proxy-managed'
ALLOWED = {'GH_TOKEN', 'GITHUB_TOKEN', 'ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN'}


def validate_config(value):
    if not isinstance(value, dict) or set(value) - {'ca', 'proxyUrl', 'env'}:
        raise ValueError('unsupported configuration')
    ca, proxy, env = value.get('ca', ''), value.get('proxyUrl', ''), value.get('env', {})
    if not isinstance(ca, str) or not isinstance(proxy, str) or not isinstance(env, dict):
        raise ValueError('invalid configuration types')
    if set(env) - ALLOWED or any(v != SENTINEL for v in env.values()):
        raise ValueError('only literal proxy sentinels are accepted')
    if bool(ca) != bool(proxy) or (env and not proxy):
        raise ValueError('proxy and public CA must be configured together')
    if proxy:
        parsed = urlsplit(proxy)
        if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.port != 3128
                or not parsed.username or parsed.path or parsed.query or parsed.fragment):
            raise ValueError('proxy must address the isolated loopback gateway')
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ca)
    return ca, proxy, env


def main():
    os.umask(0o077)
    if not (RUN / 'ready').is_file():
        raise ValueError('runtime not ready')
    data = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('configuration exceeds limit')
    ca, proxy, env = validate_config(json.loads(data))
    if proxy:
        bundle = Path('/etc/ssl/certs/ca-certificates.crt').read_text() + '\n' + ca
        (RUN / 'ca.pem').write_text(bundle)
        (RUN / 'ca.pem').chmod(0o444)
        (RUN / 'proxy-mode').touch(mode=0o444)
    (RUN / 'config.json').write_text(json.dumps({'proxyUrl': proxy, 'env': env}))
    (RUN / 'config.json').chmod(0o444)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit('hatchward-configure: invalid or unavailable runtime configuration')

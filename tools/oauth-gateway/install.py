#!/usr/bin/env python3
"""Install two user launch agents; credentials stay in the untracked runtime."""
import argparse
import os
from pathlib import Path
import plistlib
import secrets
import shutil
import subprocess
from urllib.parse import urlsplit

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runtime', type=Path, required=True)
parser.add_argument('--public-url', required=True)
args = parser.parse_args()
public_url = urlsplit(args.public_url)
if (public_url.scheme != 'https' or not public_url.hostname
        or public_url.path not in ('', '/') or public_url.query
        or public_url.fragment or public_url.username or public_url.password):
    parser.error('--public-url must be an HTTPS origin')
runtime = args.runtime.expanduser().resolve()
gateway = Path(__file__).resolve().parent
node = shutil.which('node')
if not node:
    parser.error('Node.js is required')
if not (runtime / 'bin/xiaohongshu-mcp').is_file():
    parser.error('Install the official Xiaohongshu binary in RUNTIME/bin first')
if not (gateway / 'node_modules').is_dir():
    parser.error('Run npm ci in the gateway directory first')
secret_dir = runtime / 'oauth'
secret_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
secret_dir.chmod(0o700)
password_file = secret_dir / 'owner-password.txt'
if not password_file.exists():
    with password_file.open('x') as f:
        os.chmod(f.fileno(), 0o600)
        f.write(secrets.token_urlsafe(32) + '\n')
password_file.chmod(0o600)
agent_dir = Path.home() / 'Library/LaunchAgents'
agent_dir.mkdir(parents=True, exist_ok=True)
common = {'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 10, 'WorkingDirectory': str(runtime), 'EnvironmentVariables': {'PATH': f'{Path(node).parent}:/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(Path.home())}}
services = {
    'com.owlinlight.explore.xiaohongshu-mcp': {
        'ProgramArguments': [str(runtime / 'bin/xiaohongshu-mcp'), '-port', '127.0.0.1:18060'],
    },
    'com.owlinlight.explore.xiaohongshu-oauth': {
        'ProgramArguments': [node, str(gateway / 'gateway.mjs')],
        'EnvironmentVariables': {**common['EnvironmentVariables'], 'PUBLIC_URL': args.public_url, 'PORT': '18061', 'UPSTREAM_URL': 'http://127.0.0.1:18060/mcp', 'OWNER_PASSWORD_FILE': str(password_file), 'OAUTH_STATE_FILE': str(secret_dir / 'state.json')},
    },
}
# Refuse to replace an agent owned by another installation.
for label, config in services.items():
    path = agent_dir / f'{label}.plist'
    if path.exists():
        previous = plistlib.loads(path.read_bytes())
        if previous.get('ProgramArguments') != config['ProgramArguments']:
            parser.error(f'Existing service at {path} belongs to another installation')
for label, config in services.items():
    path = agent_dir / f'{label}.plist'
    content = {**common, **config, 'Label': label, 'StandardOutPath': str(runtime / f'{label}.log'), 'StandardErrorPath': str(runtime / f'{label}.log')}
    path.write_bytes(plistlib.dumps(content))
    subprocess.run(['launchctl', 'bootout', f'gui/{os.getuid()}/{label}'], capture_output=True)
    subprocess.run(['launchctl', 'bootstrap', f'gui/{os.getuid()}', str(path)], check=True)
    print(f'Installed {label}')
print(f'Owner password file: {password_file}')
print('Local MCP: http://127.0.0.1:18060/mcp')
print('Local OAuth gateway: http://127.0.0.1:18061/mcp')

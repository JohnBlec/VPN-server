#!/usr/bin/env python3
"""Host initialization. Creates secrets once and refuses accidental overwrites."""
import argparse
import base64
import os
from pathlib import Path
import re
import secrets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--endpoint', required=True, help='Public IPv4 or DNS hostname, without scheme/port')
    parser.add_argument('--port', type=int, default=443)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?', args.endpoint):
        parser.error('Endpoint must be an IPv4 address or DNS hostname without scheme or port.')
    if args.endpoint.endswith('.example') or args.endpoint in ('vpn.example.com', 'localhost'):
        parser.error('Use the actual public address of your VPS.')
    if not 1 <= args.port <= 65535:
        parser.error('Invalid UDP port.')
    root = Path(__file__).resolve().parents[1]
    if ((root / '.env').exists() or (root / 'secrets').exists()
            or (root / 'data/state.json').exists() or (root / 'data/.initialized').exists()):
        parser.error('Existing deployment found. Do not rerun setup: edit .env or follow the recovery guide.')
    os.umask(0o077)
    for name in ('data', 'secrets', 'exports', 'backups'):
        (root / name).mkdir(mode=0o700, exist_ok=True)
    (root / 'secrets/agent_token').write_text(secrets.token_urlsafe(48) + '\n', encoding='ascii')
    (root / 'secrets/client_key').write_bytes(base64.urlsafe_b64encode(secrets.token_bytes(32)) + b'\n')
    text = (root / '.env.example').read_text(encoding='utf-8')
    text = text.replace('VPN_ENDPOINT=vpn.example.com', f'VPN_ENDPOINT={args.endpoint}')
    text = text.replace('VPN_PORT=443', f'VPN_PORT={args.port}')
    (root / '.env').write_text(text, encoding='utf-8')
    print('Created .env, secrets and data directories. Keys were not printed.')
    print('Next: docker compose config --quiet && docker compose build --pull && docker compose up -d --wait')


if __name__ == '__main__':
    main()

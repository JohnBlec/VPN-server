#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
docker compose exec -T vpn python3 - <<'PY'
import json
from pathlib import Path
import uuid
from urllib.request import Request, urlopen
from urllib.error import HTTPError
token = Path('/run/secrets/agent_token').read_text().strip()
peer = 'smoke-' + uuid.uuid4().hex
route = '/v1/peers/' + peer
def call(method, path, data=None):
    req = Request('http://127.0.0.1:8787' + path, method=method,
                  data=json.dumps(data).encode() if data is not None else None,
                  headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    with urlopen(req, timeout=20) as response:
        return response.read()
try:
    assert json.loads(call('GET', '/healthz'))['ready']
    first = call('PUT', route, {'name': 'Disposable smoke test'})
    assert first == call('PUT', route, {'name': 'Disposable smoke test'})
    config = call('GET', route + '/config')
    assert b'HeaderProtectionKey' in config and b'PrivateKey' in config
    call('PATCH', route, {'enabled': False})
    try:
        call('GET', route + '/config')
        raise AssertionError('Disabled config was accessible')
    except HTTPError as error:
        assert error.code == 403
    call('PATCH', route, {'enabled': True})
    assert config == call('GET', route + '/config')
    print('PASS: health, create, retry, download, disable and enable. No keys printed.')
finally:
    call('DELETE', route)
PY

"""Private, single-process VPN control plane. Website integration uses /v1/peers.

State is the desired configuration; changes are persisted before application.
A failed application is retried by the reconciler and never reported as success.
"""
import argparse
from datetime import datetime, timezone
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.fernet import Fernet

INTERFACE = 'awg0'
INTERNAL_PORT = 51820
IPV6_NETWORK = ipaddress.ip_network('fd42:77:77::/64')
PEER_ID = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')


class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def command(*args, input=None):
    # Never use a shell or place keys in the process command line.
    result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError('VPN command failed')  # stderr may contain secret config lines
    return result.stdout.strip()


def atomic_write(path, data):
    path = Path(path)
    fd, temp = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            os.chmod(temp, 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        if os.name == 'posix':
            fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def load_settings(environ=os.environ):
    endpoint = environ.get('VPN_ENDPOINT', '')
    if not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?', endpoint):
        raise ValueError('VPN_ENDPOINT must be a public IPv4/DNS hostname without scheme or port')
    if endpoint in ('localhost', 'vpn.example.com') or endpoint.endswith('.example'):
        raise ValueError('Replace the example VPN_ENDPOINT')
    port = int(environ.get('VPN_PORT', '443'))
    mtu = int(environ.get('VPN_MTU', '1280'))
    if not 1 <= port <= 65535 or not 1280 <= mtu <= 1420:
        raise ValueError('Invalid VPN_PORT or VPN_MTU')
    subnet = ipaddress.ip_network(environ.get('VPN_SUBNET', '10.77.0.0/24'), strict=True)
    private = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
    if subnet.version != 4 or not 16 <= subnet.prefixlen <= 28 or not any(subnet.subnet_of(ipaddress.ip_network(n)) for n in private):
        raise ValueError('VPN_SUBNET must be an RFC1918 IPv4 subnet /16 through /28')
    dns = [str(ipaddress.IPv4Address(item.strip())) for item in environ.get('VPN_DNS', '1.1.1.1,1.0.0.1').split(',')]
    if not dns or len(dns) > 3:
        raise ValueError('Configure 1 to 3 public IPv4 DNS resolvers')
    for item in dns:
        if not ipaddress.ip_address(item).is_global:
            raise ValueError('VPN_DNS must use public addresses (private destinations are blocked)')
    return {'endpoint': endpoint, 'port': port, 'mtu': mtu, 'subnet': str(subnet), 'dns': dns}


class Manager:
    def __init__(self, directory, cipher, settings, runner=command, runtime='/run'):
        self.directory = Path(directory)
        self.path = self.directory / 'state.json'
        self.runtime = Path(runtime)
        self.settings = settings
        self.cipher = cipher
        self.runner = runner
        self.lock = threading.RLock()
        self.applied_revision = -1

    def encrypt(self, value):
        return self.cipher.encrypt(value.encode()).decode()

    def decrypt(self, value):
        return self.cipher.decrypt(value.encode()).decode()

    def initialize(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        marker = self.directory / '.initialized'
        if not self.path.exists():
            if marker.exists():
                raise RuntimeError('state.json is missing: restore a backup instead of regenerating keys')
            private = self.runner('awg', 'genkey')
            # Distinct scalar H headers; sizes satisfy AWG3 header protection >=12.
            obfuscation = {
                'Jc': 6, 'Jmin': 40, 'Jmax': 1200,
                'S1': 64 + secrets.randbelow(65), 'S2': 32 + secrets.randbelow(17),
                'S3': 16, 'S4': 16,
                **{f'H{i + 1}': 10000 + i * 1000000000 + secrets.randbelow(900000000) for i in range(4)},
                'HeaderProtectionKey': self.runner('awg', 'genkey'),
                'ContentPaddingAddition': '0-32',
            }
            self.state = {
                'schema': 1, 'revision': 1, 'subnet': self.settings['subnet'],
                'server_private': private,
                'server_public': self.runner('awg', 'pubkey', input=private + '\n'),
                'obfuscation': obfuscation, 'peers': {},
            }
            self.save()
        else:
            self.state = json.loads(self.path.read_text(encoding='utf-8'))
        if self.state.get('schema') != 1:
            raise RuntimeError('Unsupported state schema; use a compatible image')
        if self.state['subnet'] != self.settings['subnet']:
            raise RuntimeError('VPN_SUBNET differs from persistent state; revert .env or plan a migration')
        for peer in self.state['peers'].values():
            self.decrypt(peer['private_encrypted'])
            self.decrypt(peer['psk_encrypted'])
        if not marker.exists():
            atomic_write(marker, '1\n')

    def save(self):
        try:
            atomic_write(self.path, json.dumps(self.state, ensure_ascii=False, indent=2) + '\n')
        except Exception:
            # Never let the background reconciler apply an uncommitted memory-only mutation.
            if self.path.exists():
                self.state = json.loads(self.path.read_text(encoding='utf-8'))
            raise

    def obfuscation_lines(self):
        return [f'{key} = {value}' for key, value in self.state['obfuscation'].items()]

    def server_config(self):
        lines = ['[Interface]', f'PrivateKey = {self.state["server_private"]}', f'ListenPort = {INTERNAL_PORT}', *self.obfuscation_lines()]
        for peer in self.state['peers'].values():
            if peer['enabled']:
                lines += ['', '[Peer]', f'PublicKey = {peer["public_key"]}',
                          f'PresharedKey = {self.decrypt(peer["psk_encrypted"])}',
                          f'AllowedIPs = {peer["address"]}/32, {peer["ipv6"]}/128']
        return '\n'.join(lines) + '\n'

    def apply(self):
        with self.lock:
            config = self.runtime / 'aegis-server.conf'
            atomic_write(config, self.server_config())
            try:
                self.runner('awg', 'syncconf', INTERFACE, str(config))
                self.applied_revision = self.state['revision']
            except (RuntimeError, OSError, subprocess.TimeoutExpired):
                self.applied_revision = -1
                raise APIError(503, 'Desired state saved; VPN apply failed. Retry the same peer ID.') from None
            finally:
                config.unlink(missing_ok=True)

    def ready(self):
        with self.lock:
            try:
                return (self.applied_revision == self.state['revision']
                        and self.runner('awg', 'show', INTERFACE, 'listen-port') == str(INTERNAL_PORT))
            except (RuntimeError, OSError, subprocess.TimeoutExpired):
                return False

    def public_peer(self, peer):
        return {key: peer[key] for key in ('id', 'name', 'public_key', 'address', 'ipv6', 'enabled', 'created_at')}

    def get_peer(self, peer_id):
        if not PEER_ID.fullmatch(peer_id):
            raise APIError(400, 'Invalid peer ID')
        if peer_id not in self.state['peers']:
            raise APIError(404, 'Peer not found')
        return self.state['peers'][peer_id]

    def create(self, peer_id, data):
        if not PEER_ID.fullmatch(peer_id):
            raise APIError(400, 'Use a stable ID of 1-64 ASCII letters, digits, underscores or hyphens')
        name = data.get('name', peer_id)
        if set(data) - {'name'} or not isinstance(name, str) or not 1 <= len(name) <= 80 or not name.isprintable():
            raise APIError(400, 'Only a printable name (1-80 characters) is accepted')
        with self.lock:
            if peer_id in self.state['peers']:
                peer = self.get_peer(peer_id)
                if peer['name'] != name:
                    raise APIError(409, 'Peer ID already exists with a different name')
                self.apply()
                return self.public_peer(peer)
            network = ipaddress.ip_network(self.state['subnet'])
            used = {p['address'] for p in self.state['peers'].values()}
            if len(used) >= min(network.num_addresses - 3, 1000):
                raise APIError(409, 'Peer capacity reached')
            offset = next(i for i in range(2, network.num_addresses - 1) if str(network[i]) not in used)
            private = self.runner('awg', 'genkey')
            peer = {
                'id': peer_id, 'name': name, 'enabled': True,
                'address': str(network[offset]), 'ipv6': str(IPV6_NETWORK[offset]),
                'private_encrypted': self.encrypt(private),
                'public_key': self.runner('awg', 'pubkey', input=private + '\n'),
                'psk_encrypted': self.encrypt(self.runner('awg', 'genpsk')),
                'created_at': datetime.now(timezone.utc).isoformat(),
            }
            self.state['peers'][peer_id] = peer
            self.state['revision'] += 1
            self.save()
            self.apply()
            return self.public_peer(peer)

    def set_enabled(self, peer_id, data):
        if set(data) != {'enabled'} or type(data['enabled']) is not bool:
            raise APIError(400, 'Expected {"enabled": true|false}')
        with self.lock:
            peer = self.get_peer(peer_id)
            if peer['enabled'] != data['enabled']:
                peer['enabled'] = data['enabled']
                self.state['revision'] += 1
                self.save()
            self.apply()
            return self.public_peer(peer)

    def delete(self, peer_id):
        if not PEER_ID.fullmatch(peer_id):
            raise APIError(400, 'Invalid peer ID')
        with self.lock:
            if peer_id in self.state['peers']:
                del self.state['peers'][peer_id]
                self.state['revision'] += 1
                self.save()
            self.apply()
            return {'deleted': True}

    def config(self, peer_id):
        with self.lock:
            peer = self.get_peer(peer_id)
            if not peer['enabled']:
                raise APIError(403, 'Peer is disabled')
            if not self.ready():
                raise APIError(503, 'VPN is not synchronized')
            lines = ['[Interface]', f'PrivateKey = {self.decrypt(peer["private_encrypted"])}',
                     f'Address = {peer["address"]}/32, {peer["ipv6"]}/128',
                     'DNS = ' + ', '.join(self.settings['dns']), f'MTU = {self.settings["mtu"]}',
                     *self.obfuscation_lines(), '', '[Peer]',
                     f'PublicKey = {self.state["server_public"]}',
                     f'PresharedKey = {self.decrypt(peer["psk_encrypted"])}',
                     f'Endpoint = {self.settings["endpoint"]}:{self.settings["port"]}',
                     'AllowedIPs = 0.0.0.0/0, ::/0', 'PersistentKeepalive = 25']
            return '\n'.join(lines) + '\n'


class Handler(BaseHTTPRequestHandler):
    server_version = 'AegisVPN'

    def log_message(self, fmt, *args):
        pass  # No URL, credentials, config or request-body logging.

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def respond(self, code, data, content_type='application/json'):
        payload = json.dumps(data).encode() if content_type == 'application/json' else data.encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def dispatch(self):
        manager = self.server.manager
        if self.command == 'GET' and self.path == '/healthz':
            ready = manager.ready()
            self.respond(200 if ready else 503, {'ready': ready})
            return
        expected = ('Bearer ' + self.server.token).encode()
        if not hmac.compare_digest(self.headers.get('Authorization', '').encode(), expected):
            self.respond(401, {'error': 'Unauthorized'})
            return
        try:
            data = {}
            if self.command in ('PUT', 'PATCH'):
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 4096 or self.headers.get('Transfer-Encoding'):
                    raise APIError(400, 'JSON body of 1-4096 bytes required')
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise APIError(400, 'JSON object required')
            with manager.lock:
                if self.command == 'GET' and self.path == '/v1/peers':
                    self.respond(200, {'peers': [manager.public_peer(p) for p in manager.state['peers'].values()],
                                       'revision': manager.state['revision'], 'applied_revision': manager.applied_revision})
                    return
                match = re.fullmatch(r'/v1/peers/([a-zA-Z0-9_-]{1,64})(/config)?', self.path)
                if not match:
                    raise APIError(404, 'Route not found')
                peer_id, suffix = match.groups()
                if suffix:
                    if self.command != 'GET':
                        raise APIError(405, 'Use GET')
                    self.respond(200, manager.config(peer_id), 'text/plain; charset=utf-8')
                    return
                if self.command == 'GET':
                    result = manager.public_peer(manager.get_peer(peer_id))
                elif self.command == 'PUT':
                    result = manager.create(peer_id, data)
                elif self.command == 'PATCH':
                    result = manager.set_enabled(peer_id, data)
                elif self.command == 'DELETE':
                    result = manager.delete(peer_id)
                else:
                    raise APIError(405, 'Method not allowed')
                self.respond(200, result)
        except APIError as exc:
            self.respond(exc.status, {'error': exc.message})
        except (ValueError, UnicodeDecodeError):
            self.respond(400, {'error': 'Invalid request'})
        except Exception:
            # Do not return exceptions that might include private keys or config lines.
            self.respond(500, {'error': 'Internal error; inspect container health'})

    do_GET = do_PUT = do_PATCH = do_DELETE = dispatch


def make_server(manager, token, address=('0.0.0.0', 8787)):
    if len(token) < 32:
        raise ValueError('Agent token must contain at least 32 characters')
    server = ThreadingHTTPServer(address, Handler)
    server.daemon_threads = True
    server.manager, server.token = manager, token
    return server


def cli():
    parser = argparse.ArgumentParser(description='Local CLI for the private Aegis VPN API')
    parser.add_argument('command', choices=['health', 'list', 'create', 'get', 'enable', 'disable', 'delete', 'config'])
    parser.add_argument('id', nargs='?')
    parser.add_argument('--name')
    args = parser.parse_args()
    token = Path(os.getenv('AGENT_TOKEN_FILE', '/run/secrets/agent_token')).read_text().strip()
    if args.command not in ('health', 'list') and (not args.id or not PEER_ID.fullmatch(args.id)):
        parser.error('A valid peer ID is required')
    route, method, body = '/v1/peers', 'GET', None
    if args.id:
        route += '/' + args.id
    if args.command == 'health':
        route = '/healthz'
    elif args.command == 'create':
        method, body = 'PUT', {'name': args.name or args.id}
    elif args.command in ('enable', 'disable'):
        method, body = 'PATCH', {'enabled': args.command == 'enable'}
    elif args.command == 'delete':
        method = 'DELETE'
    elif args.command == 'config':
        route += '/config'
    request = Request('http://127.0.0.1:8787' + route, method=method,
                      data=json.dumps(body).encode() if body is not None else None,
                      headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with urlopen(request, timeout=20) as response:
            sys.stdout.buffer.write(response.read())
    except HTTPError as exc:
        print(exc.read().decode(), file=sys.stderr)
        return 1
    except OSError:
        print('Agent unavailable', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(cli())

#!/usr/bin/env python3
"""Persistent UDP DNAT relay for Docker/iptables hosts. Run on the Moscow VPS.

Only rules bearing this program's tag and exact tuple are added or removed.
No AWG keys, peers, Docker rules or existing firewall policies are modified.
"""
import argparse
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import socket
import socketserver
import struct
from http.server import BaseHTTPRequestHandler

STATE = Path('/etc/aegis-relay')
PROGRAM = Path('/usr/local/lib/aegis-relay/relay.py')
UNIT = Path('/etc/systemd/system/aegis-relay.service')
SYSCTL = Path('/etc/sysctl.d/70-aegis-relay.conf')
CONTROL_DIR = Path('/var/lib/aegis-relay-control')
SERVICE = '''[Unit]
Description=Aegis UDP relay to foreign VPN servers
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/lib/aegis-relay/relay.py run
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
UMask=0077

[Install]
WantedBy=multi-user.target
'''


def command(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=20)
    if check and result.returncode:
        raise RuntimeError(f'{shlex.join(args)}: {result.stderr.strip()}')
    return result


def validate_route(route):
    expected = {'public_ip', 'listen_port', 'target_ip', 'target_port', 'interface', 'out_interface'}
    if set(route) != expected:
        raise ValueError('Invalid route fields')
    for key in ('public_ip', 'target_ip'):
        address = ipaddress.ip_address(route[key])
        if address.version != 4 or not address.is_global:
            raise ValueError(f'{key} must be a public IPv4 address')
        route[key] = str(address)
    if route['public_ip'] == route['target_ip']:
        raise ValueError('Target must be a different VPS')
    for key in ('listen_port', 'target_port'):
        if type(route[key]) is not int or not 1 <= route[key] <= 65535:
            raise ValueError(f'{key} must be in 1..65535')
    for key in ('interface', 'out_interface'):
        if not isinstance(route[key], str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', route[key]):
            raise ValueError(f'Invalid {key}')
    return route


def rules(route, tag=None):
    """Filter and source NAT are installed before DNAT starts accepting traffic."""
    r = validate_route(dict(route))
    tracking = ['-m', 'conntrack', '--ctorigdst', r['public_ip'], '--ctorigdstport', str(r['listen_port'])]
    comment = ['-m', 'comment', '--comment', tag or f'aegis-relay-{r["listen_port"]}']
    return [
        ('filter', 'DOCKER-USER', ['-p', 'udp', *tracking, '--ctstate', 'NEW,ESTABLISHED', *comment, '-j', 'ACCEPT']),
        ('nat', 'POSTROUTING', ['-o', r['out_interface'], '-p', 'udp', '-d', r['target_ip'],
                              '--dport', str(r['target_port']), *tracking, *comment, '-j', 'MASQUERADE']),
        ('nat', 'PREROUTING', ['-i', r['interface'], '-d', r['public_ip'], '-p', 'udp',
                             '--dport', str(r['listen_port']), *comment, '-j', 'DNAT',
                             '--to-destination', f'{r["target_ip"]}:{r["target_port"]}']),
    ]


def iptables(table, operation, chain, rule, check=True):
    return command('iptables', '-w', '5', '-t', table, operation, chain, *rule, check=check)


def apply_routes(routes):
    command('iptables', '-w', '5', '-S', 'DOCKER-USER')
    command('iptables', '-w', '5', '-C', 'FORWARD', '-j', 'DOCKER-USER')
    command('sysctl', '-w', 'net.ipv4.ip_forward=1')
    inserted = []
    try:
        for route in routes:
            for table, chain, rule in rules(route):
                found = iptables(table, '-C', chain, rule, check=False)
                if found.returncode == 1:
                    iptables(table, '-I', chain, ['1', *rule])
                    inserted.append((table, chain, rule))
                elif found.returncode:
                    raise RuntimeError(f'Could not check relay rule: {found.stderr.strip()}')
    except Exception:
        for table, chain, rule in reversed(inserted):
            iptables(table, '-D', chain, rule, check=False)
        raise


def delete_rules(route, tag=None):
    for table, chain, rule in reversed(rules(route, tag)):
        # Also remove duplicate copies of this exact rule from an earlier manual run.
        for _ in range(100):
            result = iptables(table, '-C', chain, rule, check=False)
            if result.returncode == 1:
                break
            if result.returncode:
                raise RuntimeError(f'Could not check relay rule: {result.stderr.strip()}')
            iptables(table, '-D', chain, rule)
        else:
            raise RuntimeError('Too many duplicate relay rules')


@contextmanager
def state_lock():
    import fcntl  # Linux only; pure rule tests also run on Windows.
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / '.lock').open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def load_routes():
    path = STATE / 'routes.json'
    if not path.exists():
        return []
    routes = json.loads(path.read_text())
    if not isinstance(routes, list):
        raise ValueError('Invalid routes.json')
    routes = [validate_route(dict(route)) for route in routes]
    if len({r['listen_port'] for r in routes}) != len(routes):
        raise ValueError('Duplicate listening port')
    return routes


def save_routes(routes):
    temporary = STATE / 'routes.json.tmp'
    temporary.write_text(json.dumps(routes, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(STATE / 'routes.json')


def matches_port(tokens, port):
    for option in ('--dport', '--dports'):
        if option in tokens:
            for value in tokens[tokens.index(option) + 1].split(','):
                limits = value.split(':')
                if all(item.isdecimal() for item in limits) and 1 <= len(limits) <= 2:
                    if int(limits[0]) <= port <= int(limits[-1]):
                        return True
    return False


def check_host(route, adopt_test=False):
    command('iptables', '-w', '5', '-S', 'DOCKER-USER')
    command('iptables', '-w', '5', '-C', 'FORWARD', '-j', 'DOCKER-USER')
    addresses = json.loads(command('ip', '-j', '-4', 'address', 'show', 'dev', route['interface']).stdout)
    if not any(a.get('local') == route['public_ip'] for item in addresses for a in item.get('addr_info', [])):
        raise ValueError('Public IPv4 is not assigned to the incoming interface')
    listeners = command('ss', '-H', '-lun', f'sport = :{route["listen_port"]}').stdout.strip()
    if listeners:
        raise ValueError('UDP port is already used by a listening process')
    owned_tags = {f'aegis-relay-{route["listen_port"]}'}
    if adopt_test:
        owned_tags.add('aegis-relay-test')
    for chain in ('PREROUTING', 'DOCKER'):
        for line in command('iptables', '-w', '5', '-t', 'nat', '-S', chain).stdout.splitlines():
            tokens = shlex.split(line)
            if matches_port(tokens, route['listen_port']) and '-p' in tokens and tokens[tokens.index('-p') + 1] == 'udp':
                tag = tokens[tokens.index('--comment') + 1] if '--comment' in tokens else ''
                if tag not in owned_tags:
                    raise ValueError(f'UDP port conflicts with an existing {chain} rule')
                destination = tokens[tokens.index('--to-destination') + 1] if '--to-destination' in tokens else ''
                incoming = tokens[tokens.index('-i') + 1] if '-i' in tokens else ''
                public = tokens[tokens.index('-d') + 1].removesuffix('/32') if '-d' in tokens else ''
                if (destination != f'{route["target_ip"]}:{route["target_port"]}'
                        or incoming != route['interface'] or public != route['public_ip']):
                    raise ValueError('Existing tagged rule forwards this port to a different destination')


def install(route, adopt_test):
    with state_lock():
        current = load_routes()
        existing = next((r for r in current if r['listen_port'] == route['listen_port']), None)
        if existing and existing != route:
            raise ValueError('Port already has a different relay route; remove it explicitly first')
        check_host(route, adopt_test)
        if not existing:
            current.append(route)
        PROGRAM.parent.mkdir(parents=True, exist_ok=True)
        if Path(__file__).resolve() != PROGRAM.resolve():
            shutil.copyfile(__file__, PROGRAM)
        PROGRAM.chmod(0o755)
        UNIT.write_text(SERVICE)
        UNIT.chmod(0o644)
        SYSCTL.write_text('net.ipv4.ip_forward=1\n')
        SYSCTL.chmod(0o644)
        save_routes(current)
        apply_routes(current)
        if adopt_test:
            # Adopt only this exact test mapping, never other ports or Docker rules.
            delete_rules(route, 'aegis-relay-test')
    command('systemctl', 'daemon-reload')
    # Restart also loads updated manager code on a repeated installation.
    command('systemctl', 'enable', 'aegis-relay.service')
    command('systemctl', 'restart', 'aegis-relay.service')
    command('systemctl', 'is-active', '--quiet', 'aegis-relay.service')
    print(f'Installed {route["public_ip"]}:{route["listen_port"]}/UDP -> {route["target_ip"]}:{route["target_port"]}')
    print('Service reapplies missing rules every 15 seconds, including after Docker restarts.')


def remove(port):
    with state_lock():
        current = load_routes()
        route = next((r for r in current if r['listen_port'] == port), None)
        if not route:
            raise ValueError('No saved relay route for this port')
        delete_rules(route)
        remaining = [r for r in current if r != route]
        save_routes(remaining)
    if not remaining:
        command('systemctl', 'disable', '--now', 'aegis-relay.service')
        SYSCTL.unlink(missing_ok=True)
    print('Removed relay route. IP forwarding remains enabled for existing Docker/VPN traffic.')


def mapping(route):
    return {key: route[key] for key in ('public_ip', 'listen_port', 'target_ip', 'target_port')}


def resolve_mapping(value):
    if not isinstance(value, dict) or set(value) != {'public_ip', 'listen_port', 'target_ip', 'target_port'}:
        raise ValueError('Укажите публичный IPv4 и UDP-порты обоих серверов.')
    # Validate all supplied fields before they reach a system command.
    route = validate_route({**value, 'interface': 'eth0', 'out_interface': 'eth0'})
    addresses = json.loads(command('ip', '-j', '-4', 'address').stdout)
    if any(a.get('local') == route['target_ip'] for item in addresses for a in item.get('addr_info', [])):
        raise ValueError('Назначение должно находиться на другом VPS, а не на локальном интерфейсе Москвы.')
    interface = next((item['ifname'] for item in addresses
        if any(a.get('local') == route['public_ip'] for a in item.get('addr_info', []))), None)
    if not interface:
        raise ValueError('Указанный московский IPv4 не принадлежит этому серверу.')
    route['interface'] = interface
    route['out_interface'] = json.loads(command('ip', '-j', '-4', 'route', 'get', route['target_ip']).stdout)[0]['dev']
    return validate_route(route)


def replace_routes(current, desired):
    """Apply a complete desired list; recover exact previous rules if persistence fails."""
    if len({r['listen_port'] for r in desired}) != len(desired):
        raise ValueError('Московский порт уже занят другим маршрутом.')
    old_rules = {(t, c, tuple(r)) for route in current for t, c, r in rules(route)}
    new_rules = {(t, c, tuple(r)) for route in desired for t, c, r in rules(route)}
    try:
        apply_routes(desired)
        for table, chain, rule in old_rules - new_rules:
            # Delete only rules absent from the new list, preserving shared filter rules.
            for _ in range(100):
                probe = iptables(table, '-C', chain, list(rule), check=False)
                if probe.returncode == 1:
                    break
                if probe.returncode:
                    raise RuntimeError('Не удалось проверить прежнее правило.')
                iptables(table, '-D', chain, list(rule))
        save_routes(desired)
    except Exception:
        for table, chain, rule in new_rules - old_rules:
            iptables(table, '-D', chain, list(rule), check=False)
        apply_routes(current)
        raise


def configure_mapping(previous, desired):
    """Compare-and-set protects unrelated/manual routes and makes retries idempotent."""
    if previous is not None and (not isinstance(previous, dict) or set(previous) != {'public_ip', 'listen_port', 'target_ip', 'target_port'}):
        raise ValueError('Некорректные прежние параметры.')
    old = validate_route({**previous, 'interface': 'eth0', 'out_interface': 'eth0'}) if previous is not None else None
    new = resolve_mapping(desired) if desired is not None else None
    with state_lock():
        current = load_routes()
        existing_new = next((r for r in current if new and r['listen_port'] == new['listen_port']), None)
        if existing_new and mapping(existing_new) != mapping(new):
            raise ValueError('Порт уже направлен на другой сервер. Сначала отключите прежний маршрут.')
        existing_old = next((r for r in current if old and r['listen_port'] == old['listen_port']), None)
        if existing_old and mapping(existing_old) != mapping(old):
            raise ValueError('Прежние параметры не совпадают с правилами Москвы. Проверьте status ретранслятора.')
        if new:
            check_host(new)
        remaining = [r for r in current if not (old and mapping(r) == mapping(old))]
        if new and not any(mapping(r) == mapping(new) for r in remaining):
            remaining.append(new)
        replace_routes(current, remaining)
        return {'applied': True, 'route': mapping(new) if new else None}


def peer_allowed(connection, uid):
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    _, actual_uid, _ = struct.unpack('3i', credentials)
    return actual_uid in (0, uid)


class ControlHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not peer_allowed(self.connection, self.server.allowed_uid):
            return self.reply(403, {'detail': 'Нет доступа к службе ретранслятора.'})
        if self.path != '/v1/route':
            return self.reply(404, {'detail': 'Неизвестная операция.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 1 <= length <= 4096 or self.headers.get('Transfer-Encoding'):
                raise ValueError('Некорректный размер запроса.')
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or set(payload) != {'previous', 'desired'}:
                raise ValueError('Укажите previous и desired.')
            self.reply(200, configure_mapping(payload['previous'], payload['desired']))
        except (ValueError, TypeError) as exc:
            self.reply(409, {'detail': str(exc) or 'Проверьте IPv4 и порты маршрута.'})
        except (RuntimeError, OSError, KeyError, subprocess.TimeoutExpired) as exc:
            print(f'Relay control failed ({type(exc).__name__}); inspect host rules.', file=sys.stderr, flush=True)
            self.reply(503, {'detail': 'Не удалось применить правила на Москве. Проверьте журнал aegis-relay.'})


class ControlServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    address_family = getattr(socket, 'AF_UNIX', None)
    daemon_threads = False

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address


def start_control():
    if sys.platform != 'linux':
        raise RuntimeError('Relay control socket requires Linux')
    uid = int(os.environ.get('AEGIS_RELAY_API_UID', '10001'))
    gid = int(os.environ.get('AEGIS_RELAY_API_GID', '10001'))
    if uid <= 0 or gid <= 0:
        raise ValueError('Invalid relay API UID/GID')
    CONTROL_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(CONTROL_DIR, 0, gid)
    CONTROL_DIR.chmod(0o750)
    path = CONTROL_DIR / 'control.sock'
    path.unlink(missing_ok=True)
    server = ControlServer(str(path), ControlHandler)
    server.allowed_uid = uid
    os.chown(path, 0, gid)
    path.chmod(0o660)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def run_service():
    stopping = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stopping.set())
    control = start_control()
    try:
        while not stopping.is_set():
            try:
                with state_lock():
                    apply_routes(load_routes())
            except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                print(f'Relay apply failed; retrying in 15 seconds: {exc}', file=sys.stderr, flush=True)
            stopping.wait(15)
    finally:
        control.shutdown()
        control.server_close()
        (CONTROL_DIR / 'control.sock').unlink(missing_ok=True)
        with state_lock():
            for route in load_routes():
                try:
                    delete_rules(route)
                except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                    print(f'Could not remove relay rule on stop: {exc}', file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    add = sub.add_parser('install', help='Install/update persistent service and add one route')
    add.add_argument('--public-ip', required=True)
    add.add_argument('--listen-port', type=int, default=14443)
    add.add_argument('--target-ip', required=True)
    add.add_argument('--target-port', type=int, default=443)
    add.add_argument('--interface', default='eth0')
    add.add_argument('--adopt-test', action='store_true', help='Remove exact aegis-relay-test rules after installing persistent rules')
    delete = sub.add_parser('remove', help='Remove one route without touching other firewall rules')
    delete.add_argument('--listen-port', type=int, required=True)
    sub.add_parser('status')
    sub.add_parser('apply')
    sub.add_parser('run')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Run as root on the Linux relay VPS')
    os.umask(0o077)
    if args.action == 'install':
        # Validate before running any commands with supplied addresses.
        route = validate_route({'public_ip': args.public_ip, 'listen_port': args.listen_port,
            'target_ip': args.target_ip, 'target_port': args.target_port,
            'interface': args.interface, 'out_interface': args.interface})
        route['out_interface'] = json.loads(command('ip', '-j', '-4', 'route', 'get', route['target_ip']).stdout)[0]['dev']
        install(validate_route(route), args.adopt_test)
    elif args.action == 'remove':
        remove(args.listen_port)
    elif args.action == 'run':
        run_service()
    elif args.action == 'apply':
        with state_lock():
            apply_routes(load_routes())
    else:
        with state_lock():
            for route in load_routes():
                present = all(iptables(t, '-C', c, r, check=False).returncode == 0 for t, c, r in rules(route))
                print(json.dumps({**route, 'rules_present': present}))
        print(command('systemctl', 'is-active', 'aegis-relay.service', check=False).stdout.strip())


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, KeyError, subprocess.TimeoutExpired) as exc:
        print(f'Relay operation failed: {exc}', file=sys.stderr)
        raise SystemExit(1)

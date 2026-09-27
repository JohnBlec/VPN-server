"""Supervise AWG userspace process and reconcile durable desired state."""
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

from cryptography.fernet import Fernet
from agent import Manager, INTERFACE, IPV6_NETWORK, command, load_settings, make_server


def configure_network(settings):
    import ipaddress
    network = ipaddress.ip_network(settings['subnet'])
    command('ip', 'address', 'add', f'{network[1]}/{network.prefixlen}', 'dev', INTERFACE)
    command('ip', '-6', 'address', 'add', f'{IPV6_NETWORK[1]}/64', 'dev', INTERFACE)
    command('ip', 'link', 'set', 'dev', INTERFACE, 'mtu', str(settings['mtu']), 'up')
    # Container network namespace only. No host networking, Docker socket or SYS_MODULE.
    command('iptables', '-A', 'INPUT', '-i', INTERFACE, '-j', 'DROP')
    command('iptables', '-A', 'FORWARD', '-i', INTERFACE, '-o', INTERFACE, '-j', 'DROP')
    for cidr in ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                 '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4'):
        command('iptables', '-A', 'FORWARD', '-i', INTERFACE, '-d', cidr, '-j', 'DROP')
    command('iptables', '-A', 'FORWARD', '-i', INTERFACE, '-o', 'eth0', '-j', 'ACCEPT')
    command('iptables', '-A', 'FORWARD', '-i', 'eth0', '-o', INTERFACE,
            '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT')
    command('iptables', '-A', 'FORWARD', '-o', INTERFACE, '-j', 'DROP')
    command('iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', settings['subnet'], '-o', 'eth0', '-j', 'MASQUERADE')
    # Full-tunnel IPv6 is intentionally dropped instead of leaking outside the VPN.
    command('ip6tables', '-A', 'INPUT', '-i', INTERFACE, '-j', 'DROP')
    command('ip6tables', '-A', 'FORWARD', '-i', INTERFACE, '-j', 'DROP')
    command('ip6tables', '-A', 'FORWARD', '-o', INTERFACE, '-j', 'DROP')


def main():
    os.umask(0o077)
    settings = load_settings()
    cipher = Fernet(Path(os.environ['CLIENT_KEY_FILE']).read_bytes().strip())
    token = Path(os.environ['AGENT_TOKEN_FILE']).read_text().strip()
    manager = Manager('/var/lib/aegis-vpn', cipher, settings)
    manager.initialize()
    try:
        manager.enable_traffic()
    except Exception:
        # Monitoring failure must not prevent existing VPN clients from connecting.
        print('Traffic storage unavailable; VPN will start without monitoring. Restore traffic.sqlite3 and restart.', flush=True)
    stopping = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopping.set())
    process = subprocess.Popen(['amneziawg-go', '-f', INTERFACE], env={**os.environ, 'LOG_LEVEL': 'error'})
    server = None
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError('AmneziaWG process exited during startup')
            if Path(f'/var/run/amneziawg/{INTERFACE}.sock').exists():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError('AmneziaWG control socket did not appear')
        configure_network(settings)
        manager.apply()
        manager.sample_traffic()
        server = make_server(manager, token)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print('Aegis VPN ready; control API on container port 8787.', flush=True)
        last_apply = time.monotonic()
        last_traffic = time.monotonic()
        while not stopping.wait(1):
            if process.poll() is not None:
                raise RuntimeError('AmneziaWG exited; container must restart')
            if time.monotonic() - last_apply >= 15:
                try:
                    manager.apply()
                except Exception:
                    print('VPN reconciliation failed; desired state retained for retry.', flush=True)
                last_apply = time.monotonic()
            if time.monotonic() - last_traffic >= 60:
                manager.sample_traffic()
                last_traffic = time.monotonic()
    finally:
        if server:
            server.shutdown()
            server.server_close()
            manager.sample_traffic()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Intentional concise log, without arbitrary config/state contents.
        print(f'Aegis VPN startup/runtime error ({type(exc).__name__}). Check configuration and restore instructions.', flush=True)
        raise SystemExit(1)

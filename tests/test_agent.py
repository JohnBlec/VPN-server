import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.fernet import Fernet, InvalidToken

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('aegis_test_agent', ROOT / 'agent.py')
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class FakeAWG:
    """No real keys or network commands: capture exactly what would be applied."""
    def __init__(self):
        self.counter = 0
        self.fail = False
        self.config = ''

    def __call__(self, *args, input=None):
        if args[1] in ('genkey', 'genpsk'):
            self.counter += 1
            return base64.b64encode(hashlib.sha256(str(self.counter).encode()).digest()).decode()
        if args[1] == 'pubkey':
            return base64.b64encode(hashlib.sha256(input.encode()).digest()).decode()
        if args[1] == 'syncconf':
            if self.fail:
                raise RuntimeError('fake apply failure')
            self.config = Path(args[3]).read_text()
            return ''
        if args[1:] == ('show', 'awg0', 'listen-port'):
            return '51820'
        raise AssertionError(args)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = FakeAWG()
        self.cipher = Fernet(Fernet.generate_key())
        self.settings = agent.load_settings({'VPN_ENDPOINT': 'vpn.test'})
        self.manager = self.new_manager()
        self.manager.initialize()
        self.manager.apply()

    def new_manager(self, **kwargs):
        return agent.Manager(self.root / 'data', kwargs.get('cipher', self.cipher),
                             kwargs.get('settings', self.settings), self.runner, self.root)

    def assert_api_error(self, status, function, *args):
        with self.assertRaises(agent.APIError) as error:
            function(*args)
        self.assertEqual(error.exception.status, status)

    def test_restart_preserves_keys_addresses_and_profile(self):
        self.manager.create('phone', {'name': 'Телефон'})
        profile = self.manager.config('phone')
        other = self.new_manager()
        other.initialize()
        other.apply()
        self.assertEqual(other.config('phone'), profile)
        self.assertEqual(other.state, self.manager.state)
        self.assertFalse((self.root / 'aegis-server.conf').exists())

    def test_private_client_material_encrypted_and_metadata_safe(self):
        metadata = self.manager.create('phone', {})
        peer = self.manager.get_peer('phone')
        disk = self.manager.path.read_text()
        for field in ('private_encrypted', 'psk_encrypted'):
            plaintext = self.cipher.decrypt(peer[field].encode()).decode()
            self.assertNotIn(plaintext, disk)
            self.assertNotIn(field, metadata)
        self.assertNotIn('server_private', metadata)

    def test_repeated_create_is_idempotent(self):
        first = self.manager.create('phone', {})
        revision, counter = self.manager.state['revision'], self.runner.counter
        self.assertEqual(first, self.manager.create('phone', {}))
        self.assertEqual(revision, self.manager.state['revision'])
        self.assertEqual(counter, self.runner.counter)
        self.assert_api_error(409, self.manager.create, 'phone', {'name': 'Another'})

    def test_disable_removes_live_peer_then_enable_keeps_profile(self):
        peer = self.manager.create('phone', {})
        profile = self.manager.config('phone')
        self.manager.set_enabled('phone', {'enabled': False})
        self.assertNotIn(peer['public_key'], self.runner.config)
        self.assert_api_error(403, self.manager.config, 'phone')
        self.manager.set_enabled('phone', {'enabled': True})
        self.assertIn(peer['public_key'], self.runner.config)
        self.assertEqual(profile, self.manager.config('phone'))

    def test_delete_is_idempotent_and_removes_live_key(self):
        peer = self.manager.create('phone', {})
        self.manager.delete('phone')
        revision = self.manager.state['revision']
        self.manager.delete('phone')
        self.assertEqual(revision, self.manager.state['revision'])
        self.assertNotIn(peer['public_key'], self.runner.config)
        self.assert_api_error(404, self.manager.config, 'phone')

    def test_failed_apply_persists_desired_state_and_retry_preserves_keys(self):
        self.runner.fail = True
        self.assert_api_error(503, self.manager.create, 'phone', {})
        self.assertFalse(self.manager.ready())
        public = self.manager.get_peer('phone')['public_key']
        other = self.new_manager()
        other.initialize()
        self.runner.fail = False
        self.assertEqual(public, other.create('phone', {})['public_key'])
        self.assertTrue(other.ready())

    def test_failed_disable_is_pending_not_reported_successful(self):
        self.manager.create('phone', {})
        self.runner.fail = True
        self.assert_api_error(503, self.manager.set_enabled, 'phone', {'enabled': False})
        self.assertFalse(json.loads(self.manager.path.read_text())['peers']['phone']['enabled'])
        self.assertFalse(self.manager.ready())
        self.runner.fail = False
        self.manager.apply()
        self.assertNotIn('[Peer]', self.runner.config)

    def test_disk_failure_rolls_back_memory_before_reconciliation(self):
        self.manager.create('phone', {})
        before = self.manager.path.read_text()
        with patch.object(agent, 'atomic_write', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.manager.set_enabled('phone', {'enabled': False})
        self.assertTrue(self.manager.get_peer('phone')['enabled'])
        self.assertEqual(before, self.manager.path.read_text())
        self.manager.apply()
        self.assertIn('[Peer]', self.runner.config)

    def test_lost_state_never_silently_regenerates(self):
        self.manager.path.unlink()
        with self.assertRaises(RuntimeError):
            self.new_manager().initialize()

    def test_wrong_cipher_and_changed_subnet_refuse_start(self):
        self.manager.create('phone', {})
        with self.assertRaises(InvalidToken):
            self.new_manager(cipher=Fernet(Fernet.generate_key())).initialize()
        with self.assertRaises(RuntimeError):
            self.new_manager(settings={**self.settings, 'subnet': '10.78.0.0/24'}).initialize()

    def test_capacity_counts_disabled_peers_and_unique_addresses(self):
        small = agent.Manager(self.root / 'small', self.cipher,
                              {**self.settings, 'subnet': '10.79.0.0/28'}, self.runner, self.root)
        small.initialize()
        for i in range(13):
            small.create(f'p{i}', {})
        self.assertEqual(13, len({p['address'] for p in small.state['peers'].values()}))
        small.set_enabled('p0', {'enabled': False})
        self.assert_api_error(409, small.create, 'extra', {})
        small.delete('p0')
        self.assertEqual('10.79.0.2', small.create('extra', {})['address'])

    def test_untrusted_input_cannot_supply_keys_paths_or_commands(self):
        for peer_id in ('../secrets', 'a;whoami', '-option', ''):
            self.assert_api_error(400, self.manager.create, peer_id, {})
        for body in ({'name': '\nPrivateKey=x'}, {'private_key': 'x'}, {'name': 1}):
            self.assert_api_error(400, self.manager.create, 'phone', body)
        self.manager.create('phone', {})
        self.assert_api_error(400, self.manager.set_enabled, 'phone', {'enabled': 'false'})

    def test_http_auth_config_cache_and_error_contract(self):
        token = 'a' * 48
        server = agent.make_server(self.manager, token, ('127.0.0.1', 0))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(2)
        self.addCleanup(cleanup)
        base = f'http://127.0.0.1:{server.server_port}'

        def request(path, method='GET', body=None, authenticated=True):
            headers = {'Authorization': f'Bearer {token}'} if authenticated else {}
            req = Request(base + path, method=method, headers=headers, data=body)
            try:
                response = urlopen(req, timeout=3)
            except HTTPError as exc:
                response = exc
            with response:
                return response.status, response.headers, response.read().decode()

        self.assertEqual(200, request('/healthz', authenticated=False)[0])
        self.assertEqual(401, request('/v1/peers', authenticated=False)[0])
        self.assertEqual(401, request('/v1/traffic?after=0', authenticated=False)[0])
        self.manager.enable_traffic()
        status, headers, payload = request('/v1/traffic?after=0')
        self.assertEqual(200, status)
        self.assertEqual('no-store', headers['Cache-Control'])
        self.assertEqual([], json.loads(payload)['days'])
        self.assertNotIn('private', payload)
        self.assertEqual(200, request('/v1/peers/phone', 'PUT', b'{}')[0])
        status, headers, profile = request('/v1/peers/phone/config')
        self.assertEqual(200, status)
        self.assertEqual('no-store', headers['Cache-Control'])
        self.assertIn('PrivateKey = ', profile)
        self.assertNotIn('private_encrypted', request('/v1/peers')[2])
        self.assertEqual(400, request('/v1/peers/phone', 'PATCH', b'[]')[0])
        self.assertEqual(400, request('/v1/peers/phone', 'PUT', b' ' * 4097)[0])
        self.assertEqual(200, request('/v1/peers/phone', 'PATCH', b'{"enabled":false}')[0])
        self.assertEqual(403, request('/v1/peers/phone/config')[0])


    def test_sampling_is_allowlisted_and_failure_preserves_previous_snapshot(self):
        self.manager.create('phone', {})
        self.manager.enable_traffic()
        key = self.manager.get_peer('phone')['public_key']
        calls = []
        def runner(*args, **kwargs):
            calls.append(args)
            if args[-1] == 'transfer':
                return f'{key}\t100\t200'
            if args[-1] == 'latest-handshakes':
                return f'{key}\t1700000000'
            return self.runner(*args, **kwargs)
        self.manager.runner = runner
        self.manager.sample_traffic()
        self.assertEqual([('awg', 'show', 'awg0', 'transfer'), ('awg', 'show', 'awg0', 'latest-handshakes')], calls)
        before = self.manager.traffic.snapshot(0, ['phone'])
        self.assertEqual(200, before['days'][0]['received'])
        self.manager.runner = lambda *a, **kw: 'invalid'
        self.manager.sample_traffic()
        self.assertTrue(self.manager.traffic_error)
        self.assertEqual(before, self.manager.traffic.snapshot(0, ['phone']))


class SetupTests(unittest.TestCase):
    def test_setup_is_one_time_and_does_not_print_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            shutil.copy(ROOT / 'scripts/setup.py', root / 'scripts/setup.py')
            shutil.copy(ROOT / '.env.example', root / '.env.example')
            cmd = [sys.executable, str(root / 'scripts/setup.py'), '--endpoint', 'vpn.test']
            first = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(0, first.returncode, first.stderr)
            token = (root / 'secrets/agent_token').read_text().strip()
            key = (root / 'secrets/client_key').read_bytes().strip()
            Fernet(key)
            self.assertNotIn(token, first.stdout)
            second = subprocess.run(cmd, capture_output=True, text=True)
            self.assertNotEqual(0, second.returncode)
            self.assertEqual(key, (root / 'secrets/client_key').read_bytes().strip())
            self.assertEqual(token, (root / 'secrets/agent_token').read_text().strip())

    def test_invalid_network_settings(self):
        for settings in ({'VPN_SUBNET': '8.8.0.0/16'}, {'VPN_SUBNET': '10.0.0.1/24'},
                         {'VPN_DNS': '127.0.0.1'}, {'VPN_PORT': '0'}, {'VPN_MTU': '9000'},
                         {'VPN_ENDPOINT': 'https://vpn.test'}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                agent.load_settings({'VPN_ENDPOINT': 'vpn.test', **settings})

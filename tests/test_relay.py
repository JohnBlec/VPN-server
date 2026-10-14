import importlib.util
from contextlib import nullcontext
import json
from pathlib import Path
import tempfile
import socket
import threading
from http.client import HTTPConnection
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('relay_manager', Path(__file__).resolve().parents[1] / 'scripts/relay.py')
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


def route(**changes):
    return {'public_ip': '62.113.42.137', 'listen_port': 14443, 'target_ip': '83.171.225.80',
            'target_port': 443, 'interface': 'eth0', 'out_interface': 'eth0', **changes}


def result(code=0, stdout=''):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr='test failure' if code else '')


class RelayRuleTests(unittest.TestCase):
    def test_invalid_routes_cannot_generate_commands(self):
        for changes in ({'public_ip': '127.0.0.1'}, {'target_ip': '10.0.0.1'},
                        {'target_ip': '62.113.42.137'}, {'target_ip': '::1'},
                        {'target_ip': 'example.org'}, {'listen_port': 0}, {'target_port': 65536},
                        {'listen_port': True}, {'interface': 'eth0;rm -rf /'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                relay.rules(route(**changes))

    def test_rules_are_scoped_to_original_destination_and_install_dnat_last(self):
        rules = relay.rules(route())
        self.assertEqual(['DOCKER-USER', 'POSTROUTING', 'PREROUTING'], [r[1] for r in rules])
        for _, _, rule in rules[:2]:
            self.assertIn('--ctorigdst', rule)
            self.assertIn('--ctorigdstport', rule)
            self.assertIn('62.113.42.137', rule)
            self.assertIn('14443', rule)
        self.assertIn('83.171.225.80:443', rules[-1][2])
        for _, _, rule in rules:
            self.assertIn('aegis-relay-14443', rule)

    def test_repeated_apply_does_not_add_duplicate_rules(self):
        with patch.object(relay, 'command', return_value=result()) as command:
            relay.apply_routes([route()])
        self.assertEqual(3, sum('-C' in call.args and '-t' in call.args for call in command.call_args_list))
        self.assertFalse(any('-I' in call.args for call in command.call_args_list))

    def test_first_apply_inserts_only_missing_exact_rules(self):
        def fake(*args, **kwargs):
            return result(1 if '-C' in args and '-t' in args else 0)
        with patch.object(relay, 'command', side_effect=fake) as command:
            relay.apply_routes([route()])
        inserted = [call.args for call in command.call_args_list if '-I' in call.args]
        self.assertEqual(3, len(inserted))
        self.assertIn('DNAT', inserted[-1])
        self.assertFalse(any('-F' in call.args or '-P' in call.args for call in command.call_args_list))

    def test_failed_apply_rolls_back_only_rules_added_by_that_call(self):
        def fake(*args, **kwargs):
            if '-I' in args and 'DNAT' in args:
                raise RuntimeError('failed DNAT')
            return result(1 if '-C' in args and '-t' in args else 0)
        with patch.object(relay, 'command', side_effect=fake) as command:
            with self.assertRaises(RuntimeError):
                relay.apply_routes([route()])
        removed = [call.args for call in command.call_args_list if '-D' in call.args]
        self.assertEqual(2, len(removed))
        self.assertTrue(all('aegis-relay-14443' in args for args in removed))

    def test_remove_deletes_only_exact_owned_rules_and_handles_duplicates(self):
        counts = {}
        def fake(*args, **kwargs):
            if '-C' in args:
                key = args[args.index('-C') + 1]
                counts[key] = counts.get(key, 0) + 1
                return result(0 if counts[key] <= 2 else 1)
            return result()
        with patch.object(relay, 'command', side_effect=fake) as command:
            relay.delete_rules(route())
        removed = [call.args for call in command.call_args_list if '-D' in call.args]
        self.assertEqual(6, len(removed))
        self.assertTrue(all('aegis-relay-14443' in args for args in removed))
        self.assertIn('DNAT', removed[0])

    def test_probe_errors_do_not_count_as_a_missing_rule(self):
        def fake(*args, **kwargs):
            return result(2 if '-C' in args and '-t' in args else 0)
        with patch.object(relay, 'command', side_effect=fake) as command:
            with self.assertRaises(RuntimeError):
                relay.apply_routes([route()])
        self.assertFalse(any('-I' in call.args for call in command.call_args_list))

    def test_adoption_matches_the_proven_manual_test_rules(self):
        rules = relay.rules(route(), 'aegis-relay-test')
        self.assertTrue(all('aegis-relay-test' in args for _, _, args in rules))
        self.assertEqual('83.171.225.80:443', rules[-1][2][-1])

    def test_port_conflict_detection_handles_ranges_and_multiport(self):
        for tokens in (['--dport', '14443'], ['--dport', '14000:15000'], ['--dports', '443,14443,14444']):
            self.assertTrue(relay.matches_port(tokens, 14443))
        self.assertFalse(relay.matches_port(['--dport', '443'], 14443))

    def test_control_rejects_a_target_on_another_local_public_address(self):
        addresses = [{'ifname': 'eth0', 'addr_info': [{'local': '62.113.42.137'}, {'local': '83.171.225.80'}]}]
        with patch.object(relay, 'command', return_value=result(stdout=json.dumps(addresses))) as command:
            with self.assertRaisesRegex(ValueError, 'другом VPS'):
                relay.resolve_mapping(relay.mapping(route()))
        command.assert_called_once_with('ip', '-j', '-4', 'address')


class RelayLifecycleTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        state = root / 'state'
        state.mkdir()
        for name, value in {'STATE': state, 'PROGRAM': root / 'lib/relay.py', 'UNIT': root / 'relay.service',
                            'SYSCTL': root / 'sysctl.conf'}.items():
            patcher = patch.object(relay, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(relay, 'state_lock', side_effect=nullcontext)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_installer_saves_multiple_routes_enables_service_and_adopts_only_test(self):
        with patch.object(relay, 'check_host'), patch.object(relay, 'apply_routes') as apply, \
                patch.object(relay, 'delete_rules') as delete, patch.object(relay, 'command', return_value=result()) as command:
            relay.install(route(), True)
            relay.install(route(listen_port=14444, target_ip='45.9.18.245'), False)
            relay.install(route(), True)
        saved = relay.load_routes()
        self.assertEqual([14443, 14444], [r['listen_port'] for r in saved])
        self.assertEqual(saved, apply.call_args.args[0])
        self.assertEqual(2, delete.call_count)
        self.assertEqual((route(), 'aegis-relay-test'), delete.call_args.args)
        self.assertTrue(relay.PROGRAM.exists())
        self.assertIn('ExecStart=/usr/bin/python3', relay.UNIT.read_text())
        self.assertEqual('net.ipv4.ip_forward=1\n', relay.SYSCTL.read_text())
        self.assertIn(('systemctl', 'enable', 'aegis-relay.service'), [c.args for c in command.call_args_list])
        self.assertIn(('systemctl', 'restart', 'aegis-relay.service'), [c.args for c in command.call_args_list])

    def test_existing_port_cannot_be_reassigned_without_explicit_removal(self):
        relay.save_routes([route()])
        with patch.object(relay, 'command') as command:
            with self.assertRaises(ValueError):
                relay.install(route(target_ip='45.9.18.245'), False)
        command.assert_not_called()
        self.assertEqual([route()], relay.load_routes())

    def test_remove_one_keeps_other_routes_and_only_last_disables_service(self):
        second = route(listen_port=14444, target_ip='45.9.18.245')
        relay.save_routes([route(), second])
        relay.SYSCTL.write_text('net.ipv4.ip_forward=1\n')
        with patch.object(relay, 'delete_rules') as delete, patch.object(relay, 'command', return_value=result()) as command:
            relay.remove(14443)
            self.assertEqual([second], relay.load_routes())
            command.assert_not_called()
            self.assertTrue(relay.SYSCTL.exists())
            relay.remove(14444)
        self.assertEqual([], relay.load_routes())
        self.assertEqual([(route(),), (second,)], [c.args for c in delete.call_args_list])
        command.assert_called_once_with('systemctl', 'disable', '--now', 'aegis-relay.service')
        self.assertFalse(relay.SYSCTL.exists())

    def test_corrupted_saved_routes_are_rejected_before_firewall_changes(self):
        (relay.STATE / 'routes.json').write_text(json.dumps([route(), route()]))
        with self.assertRaises(ValueError):
            relay.load_routes()

    def host_command(self, nat_rule='', listener=''):
        def fake(*args, **kwargs):
            if args[0] == 'ip':
                return result(stdout=json.dumps([{'addr_info': [{'local': '62.113.42.137'}]}]))
            if args[0] == 'ss':
                return result(stdout=listener)
            if args[-1] == 'DOCKER' and '-t' in args:
                return result(stdout=nat_rule)
            return result()
        return fake

    def test_busy_or_docker_published_port_is_refused_before_install(self):
        for nat_rule, listener in (('', 'UNCONN 0 0 0.0.0.0:14443'),
                                  ('-A DOCKER -p udp --dport 14443 -j DNAT --to-destination 172.17.0.2:443', ''),
                                  ('-A DOCKER -p udp --dport 14000:15000 -j DNAT --to-destination 172.17.0.2:443', '')):
            with patch.object(relay, 'command', side_effect=self.host_command(nat_rule, listener)), self.assertRaises(ValueError):
                relay.check_host(route())

    def test_manual_rule_can_only_be_adopted_for_the_exact_proven_destination(self):
        correct = ('-A PREROUTING -i eth0 -d 62.113.42.137/32 -p udp --dport 14443 '
                   '-m comment --comment aegis-relay-test -j DNAT --to-destination 83.171.225.80:443')
        with patch.object(relay, 'command', side_effect=self.host_command(correct)):
            relay.check_host(route(), adopt_test=True)
            with self.assertRaises(ValueError):
                relay.check_host(route(), adopt_test=False)
        wrong = correct.replace('83.171.225.80:443', '45.9.18.245:443')
        with patch.object(relay, 'command', side_effect=self.host_command(wrong)), self.assertRaises(ValueError):
            relay.check_host(route(), adopt_test=True)

    def test_service_retries_after_docker_restarts_and_removes_rules_on_stop(self):
        relay.save_routes([route()])
        class StopAfterTwoPasses:
            passes = 0
            def is_set(self):
                return self.passes == 2
            def set(self):
                self.passes = 2
            def wait(self, interval):
                self.passes += 1
        with patch.object(relay.threading, 'Event', return_value=StopAfterTwoPasses()), \
                patch.object(relay.signal, 'signal'), \
                patch.object(relay, 'start_control'), \
                patch.object(relay, 'CONTROL_DIR', relay.STATE), \
                patch.object(relay, 'apply_routes', side_effect=[RuntimeError('Docker restarting'), None]) as apply, \
                patch.object(relay, 'delete_rules') as delete:
            relay.run_service()
        self.assertEqual(2, apply.call_count)
        delete.assert_called_once_with(route())


class ControlMappingTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.runtime = set()
        for name, value in [('STATE', Path(directory.name)), ('state_lock', lambda: nullcontext()),
                            ('check_host', lambda *args: None), ('command', lambda *args, **kw: result()),
                            ('resolve_mapping', lambda value: relay.validate_route(route(**value)))]:
            patcher = patch.object(relay, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        def iptables(table, operation, chain, rule, check=True):
            key = (table, chain, tuple(rule[1:] if operation == '-I' else rule))
            if operation == '-C':
                return result(0 if key in self.runtime else 1)
            if operation == '-I':
                self.runtime.add(key)
            elif operation == '-D':
                self.runtime.discard(key)
            return result()
        patcher = patch.object(relay, 'iptables', side_effect=iptables)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_create_retry_move_and_delete_preserve_other_routes(self):
        other = route(listen_port=14445, target_ip='45.9.18.245')
        relay.save_routes([other])
        self.runtime.update((t, c, tuple(r)) for t, c, r in relay.rules(other))
        new = relay.mapping(route(listen_port=14446))
        self.assertTrue(relay.configure_mapping(None, new)['applied'])
        relay.configure_mapping(None, new)
        self.assertEqual(2, len(relay.load_routes()))
        moved = {**new, 'listen_port': 14447}
        relay.configure_mapping(new, moved)
        expected = {key for r in [other, route(listen_port=14447)] for t, c, args in relay.rules(r) for key in [(t, c, tuple(args))]}
        self.assertEqual(expected, self.runtime)
        relay.configure_mapping(moved, None)
        relay.configure_mapping(moved, None)
        self.assertEqual([other], relay.load_routes())
        self.assertEqual({(t, c, tuple(r)) for t, c, r in relay.rules(other)}, self.runtime)

    def test_wrong_target_cannot_overwrite_or_delete_an_existing_route(self):
        relay.save_routes([route()])
        wrong = relay.mapping(route(target_ip='45.9.18.245'))
        for old, new in [(None, wrong), (wrong, None)]:
            with self.assertRaises(ValueError):
                relay.configure_mapping(old, new)
        self.assertEqual([route()], relay.load_routes())

    def test_failed_disk_write_restores_previous_rules_and_state(self):
        existing = route()
        relay.save_routes([existing])
        self.runtime.update((t, c, tuple(r)) for t, c, r in relay.rules(existing))
        before = set(self.runtime)
        with patch.object(relay, 'save_routes', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                relay.configure_mapping(relay.mapping(existing), relay.mapping(route(listen_port=14446)))
        self.assertEqual(before, self.runtime)
        self.assertEqual([existing], relay.load_routes())

    def test_shared_filter_rule_survives_a_change_of_interface_metadata(self):
        old, new = route(), route(out_interface='eth1')
        relay.save_routes([old])
        self.runtime.update((t, c, tuple(r)) for t, c, r in relay.rules(old))
        relay.replace_routes([old], [new])
        self.assertEqual({(t, c, tuple(r)) for t, c, r in relay.rules(new)}, self.runtime)


class ControlProtocolTests(unittest.TestCase):
    def setUp(self):
        class LocalTestServer(relay.ControlServer):
            address_family = socket.AF_INET
        self.server = LocalTestServer(('127.0.0.1', 0), relay.ControlHandler)
        self.server.allowed_uid = 10001
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def post(self, data, path='/v1/route'):
        connection = HTTPConnection(*self.server.server_address, timeout=3)
        try:
            connection.request('POST', path, json.dumps(data))
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_peer_denied_before_any_rule_changes(self):
        with patch.object(relay, 'peer_allowed', return_value=False), patch.object(relay, 'configure_mapping') as configure:
            status, _ = self.post({'previous': None, 'desired': relay.mapping(route())})
        self.assertEqual(403, status)
        configure.assert_not_called()

    def test_valid_request_has_confirmation_and_invalid_operations_do_not_execute(self):
        desired = relay.mapping(route())
        with patch.object(relay, 'peer_allowed', return_value=True), \
                patch.object(relay, 'configure_mapping', return_value={'applied': True, 'route': desired}) as configure:
            status, body = self.post({'previous': None, 'desired': desired})
            self.assertEqual(200, status)
            self.assertEqual(desired, body['route'])
            self.assertEqual(409, self.post({'command': 'reboot'})[0])
            self.assertEqual(404, self.post({}, '/v1/shell')[0])
            self.assertEqual(409, self.post({'previous': None, 'desired': desired, 'extra': 'x' * 5000})[0])
        configure.assert_called_once_with(None, desired)

    def test_peer_credentials_require_root_or_the_backend_uid(self):
        from unittest.mock import Mock
        peer = Mock()
        with patch.object(relay.socket, 'SO_PEERCRED', 17, create=True):
            for uid, allowed in [(0, True), (10001, True), (10002, False)]:
                peer.getsockopt.return_value = relay.struct.pack('3i', 123, uid, 10001)
                self.assertEqual(allowed, relay.peer_allowed(peer, 10001))


if __name__ == '__main__':
    unittest.main()

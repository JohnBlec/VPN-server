import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from traffic import TrafficStore

class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'traffic.sqlite3'
        self.store = TrafficStore(self.path)
        self.peer = {'id': 'phone', 'public_key': 'public'}
        self.now = datetime(2026, 9, 27, 20, 59, 30, tzinfo=timezone.utc)

    def sample(self, rx, tx, epoch='one', now=None):
        self.store.sample([self.peer], {'public': (rx, tx)}, {'public': 1700000000}, epoch, now or self.now)

    def test_cumulative_days_timezone_restart_and_counter_reset(self):
        self.sample(100, 200)
        self.sample(150, 300)
        first = self.store.snapshot(0, ['phone'])
        self.assertEqual((150, 300), (first['days'][0]['sent'], first['days'][0]['received']))
        self.assertEqual('2026-09-27', first['days'][0]['day'])
        self.store = TrafficStore(self.path)
        self.sample(160, 330, now=self.now + timedelta(minutes=1))
        days = self.store.snapshot(0, ['phone'])['days']
        self.assertEqual('2026-09-28', days[1]['day'])
        self.assertEqual((10, 30), (days[1]['sent'], days[1]['received']))
        self.sample(500, 700, epoch='recreated', now=self.now + timedelta(minutes=2))
        row = self.store.snapshot(first['next_cursor'], ['phone'])['days'][0]
        self.assertEqual((510, 730), (row['sent'], row['received']))
        self.sample(5, 7, epoch='recreated', now=self.now + timedelta(minutes=3))
        self.assertEqual(515, self.store.snapshot(0, ['phone'])['days'][1]['sent'])

    def test_disable_reset_does_not_lose_new_traffic_when_new_counter_is_larger(self):
        self.sample(100, 200)
        self.store.removed(['phone'])
        self.sample(1000, 2000)
        row = self.store.snapshot(0, ['phone'])['days'][0]
        self.assertEqual((1100, 2200), (row['sent'], row['received']))

    def test_retry_pagination_changed_old_day_and_deleted_peer_history(self):
        self.sample(10, 20)
        page = self.store.snapshot(0, [], limit=1)
        self.assertEqual('phone', page['peers'][0]['id'])
        self.assertEqual(page, self.store.snapshot(0, [], limit=1))
        self.sample(30, 40)
        updated = self.store.snapshot(page['next_cursor'], [], limit=1)
        self.assertEqual(30, updated['days'][0]['sent'])
        self.assertEqual([], self.store.snapshot(updated['next_cursor'], [])['days'])

    def test_no_traffic_keeps_measurement_but_creates_no_day_samples(self):
        self.sample(0, 0)
        result = self.store.snapshot(0, ['phone'])
        self.assertEqual([], result['days'])
        self.assertIsNotNone(result['sampled_at'])
        self.assertIsNone(result['peers'][0]['activity'])

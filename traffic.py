"""Durable per-peer daily counters. No keys, endpoints or speed samples are stored."""
from contextlib import closing
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3
import uuid

MOSCOW = timezone(timedelta(hours=3))

class TrafficStore:
    def __init__(self, path):
        self.path = Path(path)
        with closing(self.connect()) as db, db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS peers (
                    id TEXT PRIMARY KEY, epoch TEXT NOT NULL, rx INTEGER NOT NULL, tx INTEGER NOT NULL,
                    handshake INTEGER, activity TEXT, sampled TEXT NOT NULL, started TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS daily (
                    peer TEXT NOT NULL, day TEXT NOT NULL, received INTEGER NOT NULL, sent INTEGER NOT NULL,
                    revision INTEGER NOT NULL UNIQUE, PRIMARY KEY(peer, day));
            ''')
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('source', ?)", (str(uuid.uuid4()),))
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('revision', '0')")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def sample(self, peers, transfers, handshakes, epoch, now=None):
        now = now or datetime.now(timezone.utc)
        stamp, day = now.isoformat(), now.astimezone(MOSCOW).date().isoformat()
        with closing(self.connect()) as db, db:
            revision = int(db.execute("SELECT value FROM metadata WHERE key='revision'").fetchone()[0])
            for peer in peers:
                key, peer_id = peer['public_key'], peer['id']
                rx, tx = transfers.get(key, (0, 0))
                old = db.execute('SELECT * FROM peers WHERE id=?', (peer_id,)).fetchone()
                # A fresh interface or removed/re-added peer has restarted its counters.
                old_rx, old_tx = (old['rx'], old['tx']) if old and old['epoch'] == epoch else (0, 0)
                delta_rx = rx - old_rx if rx >= old_rx else rx
                delta_tx = tx - old_tx if tx >= old_tx else tx
                handshake = handshakes.get(key, 0) or (old['handshake'] if old else None)
                activity = stamp if delta_rx or delta_tx else (old['activity'] if old else None)
                started = old['started'] if old else stamp
                db.execute('INSERT OR REPLACE INTO peers VALUES (?,?,?,?,?,?,?,?)',
                           (peer_id, epoch, rx, tx, handshake, activity, stamp, started))
                # Client perspective: server TX is client received, server RX is client sent.
                if delta_rx or delta_tx:
                    revision += 1
                    db.execute('''INSERT INTO daily VALUES (?,?,?,?,?) ON CONFLICT(peer,day) DO UPDATE SET
                        received=received+excluded.received, sent=sent+excluded.sent, revision=excluded.revision''',
                               (peer_id, day, delta_tx, delta_rx, revision))
            db.execute("UPDATE metadata SET value=? WHERE key='revision'", (str(revision),))
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('sampled', ?)", (stamp,))

    def removed(self, peer_ids):
        with closing(self.connect()) as db, db:
            db.executemany('UPDATE peers SET rx=0,tx=0 WHERE id=? AND (rx!=0 OR tx!=0)', [(p,) for p in peer_ids])

    def snapshot(self, after, live_ids, limit=250):
        with closing(self.connect()) as db:
            meta = dict(db.execute('SELECT key,value FROM metadata'))
            revision = int(meta['revision'])
            rows = db.execute('SELECT * FROM daily WHERE revision>? ORDER BY revision LIMIT ?', (after, limit)).fetchall()
            live = set(live_ids) | {r['peer'] for r in rows}
            peers = [dict(r) for r in db.execute(
                'SELECT id,handshake,activity,sampled,started FROM peers WHERE id IN (' + ','.join('?' for _ in live) + ')',
                list(live))] if live else []
            return {'source': meta['source'], 'revision': revision,
                    'next_cursor': rows[-1]['revision'] if rows else revision,
                    'more': bool(rows and rows[-1]['revision'] < revision),
                    'sampled_at': meta.get('sampled'), 'peers': peers,
                    'days': [dict(r) for r in rows]}

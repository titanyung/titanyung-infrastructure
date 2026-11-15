"""Optional bounded S-UI ingest hook; never scan or alter access history."""
import os
from contextlib import closing
import sqlite3
import time

from daily_accounting import DailyLedger
from daily_expiry import load_policy
from role_policy import FIRST_HOPS, sui_observations


class DailyCollectorHook:
    def __init__(self, path, host):
        if host not in FIRST_HOPS:
            raise ValueError('daily collector host is not an active first hop')
        self.host = host
        self.path = path
        self.ledger = None
        self.last_open = 0
        self.last_gap = {}
        self.last_cohort = 0
        self._open()

    def _open(self):
        if self.ledger is not None:
            return True
        now = time.monotonic()
        if now - self.last_open < 5:
            return False
        self.last_open = now
        try:
            self.ledger = DailyLedger(self.path, source_key=self.host)
            self.ledger.db.execute('PRAGMA busy_timeout=250')
            return True
        except Exception as error:
            self.ledger = None
            print('daily accounting open deferred: ' + type(error).__name__, flush=True)
            return False

    @classmethod
    def from_environment(cls):
        path = os.environ.get('DAILY_TRAFFIC_DB')
        if not path:
            return None
        host = os.environ.get('DAILY_TRAFFIC_HOST')
        return cls(path, host)

    def gap(self, reason, observed_at=None, user=''):
        if not self._open():
            return
        now = int(observed_at or time.time())
        key = (reason, user)
        if now - self.last_gap.get(key, 0) < 60:
            return
        self.last_gap[key] = now
        try:
            self.ledger.record_gap(reason, observed_at=now, user=user,
                host=self.host, runtime='sui')
        except Exception as error:
            print('daily gap write failed: ' + type(error).__name__, flush=True)

    def record_sui(self, connections, rows, observed_at):
        try:
            policy=load_policy()
            if policy and policy.expired(self.host,observed_at):return None
            if not self._open():
                return None
            if observed_at - self.last_cohort >= 60:
                self.last_cohort = observed_at
                try:
                    path = os.environ.get('SUI_DB', '/usr/local/s-ui/db/s-ui.db')
                    with closing(sqlite3.connect('file:' + path + '?mode=ro', uri=True, timeout=.25)) as database:
                        users = [row[0] for row in database.execute('SELECT name FROM clients WHERE enable=1')
                                 if isinstance(row[0], str) and row[0]]
                    self.ledger.register_users(users, host=self.host, runtime='sui', observed_at=observed_at)
                except (OSError, sqlite3.Error, ValueError):
                    # A cohort read failure must not discard measured rows.
                    self.gap('sui_cohort_unavailable', observed_at)
            observations, unknown = sui_observations(connections, rows, self.host)
            result = self.ledger.record(observations, observed_at=observed_at)
            self.gap('sui_polling_coverage', observed_at)
            if len(observations) < len(connections):
                self.gap('sui_user_attribution_incomplete', observed_at)
            for user in set(unknown):
                self.gap('unclassified_sui_route', observed_at, user)
            if result.get('rejected'):
                self.gap('daily_observation_rejected', observed_at)
            return result
        except Exception as error:
            # Existing collector measurements must continue even if this new
            # optional accounting sink is unavailable. Emit only error type.
            print('daily accounting failed: ' + type(error).__name__, flush=True)
            self.gap('daily_ingest_unavailable', observed_at)
            return None

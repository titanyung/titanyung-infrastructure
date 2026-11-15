"""Authoritative admin identity facade; no credentials or subscription URLs out."""
import os

from lifecycle import BindingMismatch, LifecycleStore
from identity import IdentityResolver, IdentityError
from access_policy import DEFAULT_DB


class ControlBackend:
    def __init__(self, store=None, resolver=None):
        self.store = store or LifecycleStore(os.environ.get('USER_ACCESS_CONTROL_DB', DEFAULT_DB))
        self.resolver = resolver or IdentityResolver()

    def subject(self, target_id):
        return self.resolver.by_client_id(str(target_id))

    def overview(self):
        rows = []
        cursor = ''
        while True:
            page = self.store.overview(after_client_id=cursor, limit=500)
            rows.extend(page)
            if len(page) < 500:
                return rows
            cursor = page[-1]['client_id']

    def list_users(self):
        result = {row['client_id']: {'target_id':row['client_id'],
            'username':row['username'], 'eligible':row['eligible'],
            'enabled':row['enabled'], 'unavailable_reason':row['unavailable_reason']}
            for row in self.resolver.list_inventory()}
        revision = getattr(self.resolver, 'revision_for_client_id', None)
        if callable(revision):
            for row in result.values():
                row['revision'] = revision(row['target_id'])
        return sorted(result.values(), key=lambda row: (row['username'], row['target_id']))

    def state(self, subject):
        try:
            return self.store.state(subject)
        except BindingMismatch:
            return {'state': 'identity_conflict', 'client_id': subject.client_id,
                    'username': subject.username}

    def arm(self, subject, *, actor, operation_id, reason):
        if self.subject(subject.client_id) != subject:
            raise BindingMismatch('authoritative_identity_changed')
        if subject.client_id not in {row['client_id'] for row in self.resolver.list_eligible(include_disabled=True)}:
            raise ValueError('target_not_eligible')
        return self.store.arm(subject, actor=actor, operation_id=operation_id,
                              reason=reason or '管理员安排下次更新后封停')

    def restore(self, subject, *, actor, operation_id, reason):
        if self.subject(subject.client_id) != subject:
            raise BindingMismatch('authoritative_identity_changed')
        return self.store.restore(subject, actor=actor, operation_id=operation_id,
                                  reason=reason or '管理员恢复订阅及访问')

    def audit(self, **filters):
        return self.store.audit(**filters)

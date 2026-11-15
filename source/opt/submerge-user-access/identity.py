"""Read-only canonical S-UI identity/legacy alias resolution. No credentials out."""
from __future__ import annotations
from contextlib import closing
from pathlib import Path
import hashlib
import json
import re
import sqlite3
import urllib.parse

from lifecycle import Subject


class IdentityError(ValueError):pass


SAFE=re.compile(r'^[A-Za-z0-9_+.-]{1,128}$')
ALIAS=re.compile(r'^\s*"/sub/([^"\\]+)"\s+"/sub/([^"\\]+)"\s*;\s*(?:#.*)?$')


def canonical_slug(value):
    if not isinstance(value,str) or not SAFE.fullmatch(value) or value in {'.','..'}:
        raise IdentityError('invalid_subscription_identity')
    return value


def binding_id(client_id, name):
    # S-UI INTEGER PRIMARY KEY can be reused after deletion. Namespace an
    # account by its numeric row and canonical name so an old audit tombstone
    # cannot block or target a different newly created user at the same row ID.
    return str(client_id) + ':' + hashlib.sha256(canonical_slug(name).encode()).hexdigest()[:24]


def physical_client_id(value):
    if not isinstance(value, str) or re.fullmatch(r'[1-9][0-9]*(?::[0-9a-f]{24})?', value) is None:
        raise IdentityError('invalid_client_id')
    return int(value.split(':', 1)[0])


def slug_from_path(path):
    if not isinstance(path,str) or len(path)>2048:raise IdentityError('invalid_subscription_path')
    raw=urllib.parse.urlsplit(path).path
    match=re.fullmatch(r'/(?:sub|merge|test/sub)/([^/]+)',raw)
    if match is None:raise IdentityError('invalid_subscription_path')
    value=urllib.parse.unquote(match[1],errors='strict')
    return canonical_slug(value)


class IdentityResolver:
    def __init__(self,db_path='/usr/local/s-ui/db/s-ui.db',
                 aliases_path='/etc/nginx/conf.d/submerge-delivery-format-map.conf',
                 *,identity_reader=None,allow_trial=False):
        self.db_path=Path(db_path);self.alias_path=Path(aliases_path) if aliases_path else None
        self.identity_reader=identity_reader;self.allow_trial=allow_trial
        self._alias_key=None;self._aliases={}

    def aliases(self):
        if self.alias_path is None:return {}
        try:info=self.alias_path.stat()
        except FileNotFoundError:return {}
        key=(info.st_mtime_ns,info.st_size)
        if key==self._alias_key:return dict(self._aliases)
        if info.st_size>2*1024*1024:raise IdentityError('alias_map_too_large')
        values={}
        for line in self.alias_path.read_text(encoding='utf-8').splitlines():
            match=ALIAS.fullmatch(line)
            if match is None:continue
            old,new=map(canonical_slug,match.groups())
            if old in values and values[old]!=new:raise IdentityError('conflicting_legacy_alias')
            values[old]=new
        for old in values:
            seen=set();value=old
            while value in values:
                if value in seen:raise IdentityError('legacy_alias_cycle')
                seen.add(value);value=values[value]
        self._alias_key=key;self._aliases=values
        return dict(values)

    def _db(self):
        db=sqlite3.connect(self.db_path.resolve().as_uri()+'?mode=ro',uri=True,timeout=3)
        db.execute('PRAGMA query_only=ON');return db

    def resolve(self,slug):
        value=canonical_slug(slug);aliases=self.aliases();seen=set()
        while value in aliases:
            if value in seen:raise IdentityError('legacy_alias_cycle')
            seen.add(value);value=aliases[value]
        try:
            with closing(self._db()) as db:
                rows=db.execute('SELECT id,name FROM clients WHERE name=? OR sub_secret=?',(value,value)).fetchall()
        except sqlite3.Error:raise IdentityError('identity_store_unavailable') from None
        if len(rows)!=1 or type(rows[0][0]) is not int or rows[0][0]<=0:
            raise IdentityError('identity_not_unique_or_missing')
        # Disabled identities intentionally remain resolvable for the gate.
        return Subject(canonical_slug(rows[0][1]),binding_id(rows[0][0],rows[0][1]))

    def by_client_id(self,client_id):
        numeric_id=physical_client_id(client_id)
        try:
            with closing(self._db()) as db:rows=db.execute('SELECT id,name FROM clients WHERE id=?',(numeric_id,)).fetchall()
        except sqlite3.Error:raise IdentityError('identity_store_unavailable') from None
        if len(rows)!=1:raise IdentityError('identity_not_unique_or_missing')
        subject=Subject(canonical_slug(rows[0][1]),binding_id(rows[0][0],rows[0][1]))
        if ':' in client_id and subject.client_id!=client_id:raise IdentityError('identity_binding_changed')
        return subject

    def revision_for_client_id(self,client_id):
        """Opaque confirmation fingerprint, never expose credential contents."""
        numeric_id=physical_client_id(client_id)
        try:
            with closing(self._db()) as db:
                rows=db.execute('SELECT id,name,enable,sub_secret,config,inbounds FROM clients WHERE id=?',
                    (numeric_id,)).fetchall()
        except sqlite3.Error:raise IdentityError('identity_store_unavailable') from None
        if len(rows)!=1:raise IdentityError('identity_not_unique_or_missing')
        canonical_slug(rows[0][1])
        if ':' in client_id and binding_id(rows[0][0],rows[0][1])!=client_id:raise IdentityError('identity_binding_changed')
        # SQLite JSON configuration can be stored as TEXT or BLOB. Preserve
        # both its exact bytes and storage type in the opaque confirmation hash.
        values=[{'blob_hex':bytes(value).hex()} if isinstance(value,(bytes,bytearray,memoryview))
                else {'value':value} for value in rows[0]]
        value=json.dumps(values,ensure_ascii=False,separators=(',',':'))
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def list_eligible(self, *, include_disabled=False):
        if type(include_disabled) is not bool:raise IdentityError('invalid_inventory_policy')
        try:
            with closing(self._db()) as db:
                rows=db.execute('SELECT id,name FROM clients WHERE '+
                    ('enable IN (0,1)' if include_disabled else 'enable=1')+' ORDER BY id').fetchall()
        except sqlite3.Error:raise IdentityError('identity_store_unavailable') from None
        reader=self.identity_reader
        if reader is None:
            from new_enrollment import read_sui_identity
            reader=read_sui_identity
        result=[]
        for client_id,name in rows:
            try:
                allow=self.allow_trial(name) if callable(self.allow_trial) else bool(self.allow_trial)
                options={'allow_trial':allow}
                if include_disabled:options['allow_disabled']=True
                identity=reader(name,self.db_path,**options)
                if identity.client_id!=client_id or identity.name!=name:continue
                result.append({'client_id':binding_id(client_id,name),'username':name})
            except Exception:continue
        return result

    def list_inventory(self):
        """Complete admin roster, independent of proxy-operation eligibility.

        Listing never enables or admits an account. Valid disabled accounts
        remain eligible for an explicitly confirmed revocation; trial and
        not-yet-configured identities stay visible with a reason.
        """
        eligible = {row['client_id'] for row in self.list_eligible(include_disabled=True)}
        try:
            with closing(self._db()) as db:
                rows = db.execute('SELECT id,name,enable FROM clients ORDER BY id').fetchall()
        except sqlite3.Error:
            raise IdentityError('identity_store_unavailable') from None
        result = []
        for client_id, name, enable in rows:
            name = canonical_slug(name)
            if type(client_id) is not int or client_id <= 0 or enable not in (0, 1):
                raise IdentityError('inventory_identity_invalid')
            key = binding_id(client_id, name)
            allowed = key in eligible
            reason = ('disabled' if not enable else '' if allowed else
                      'trial' if name == 'test' else 'unconfigured')
            result.append({'client_id':key, 'username':name, 'enabled':enable == 1,
                'eligible':allowed, 'unavailable_reason':reason})
        return result

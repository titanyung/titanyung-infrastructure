"""Thin adapter over the existing production expiry policy, with no new dates."""
from datetime import date, datetime, time, timedelta, timezone
import os
from pathlib import Path
import runpy

TZ=timezone(timedelta(hours=8))
CANONICAL=Path('/opt/sg-traffic-dashboard-expiry-prod/expiry_policy.py')
LOCAL_COPY=Path(__file__).with_name('canonical_expiry_policy.py')
ALIASES={
    'bwh':'BWH','gomami':'GoMami','nosla':'NoSLA',
    'lazycat-sg':'Lazycat-SG','lazycat sg':'Lazycat-SG','lazycat_sg':'Lazycat-SG',
    'lazycat-hkt':'Lazycat-HKT','lazycat hkt':'Lazycat-HKT','lazycat_hkt':'Lazycat-HKT',
    'proxyhive':'proxyhive.io','proxyhive.io':'proxyhive.io',
    'ip2up':'ip2up.com','ip2up.com':'ip2up.com',
    'kookey':'kookey','kookeey':'kookey',
}
_CACHE={}


class ExpiryPolicy:
    def __init__(self,dates):
        self.cutoffs={}
        for service,day in dates.items():
            if type(day) is datetime:
                if day.tzinfo is None or day.utcoffset() is None:
                    raise ValueError('canonical expiry datetime must be timezone-aware')
                deadline=day.astimezone(TZ)
            elif type(day) is date:
                deadline=datetime.combine(day,time.min,TZ)
            else:
                raise ValueError('invalid canonical expiry date')
            self.cutoffs[str(service)]=int(deadline.timestamp())

    def canonical(self,value):
        return ALIASES.get(str(value).casefold(),str(value))

    def cutoff(self,*services):
        values=[self.cutoffs[self.canonical(value)] for value in services
                if self.canonical(value) in self.cutoffs]
        return min(values) if values else None

    def flow_cutoff(self,host,claims):
        return self.cutoff(host,*(item.get('peer','') for item in claims))

    def expired(self,host,now):
        end=self.cutoff(host)
        return end is not None and int(now)>=end

    def permits(self,host,claims,observed_at):
        end=self.flow_cutoff(host,claims)
        return end is None or int(observed_at)<end

    def frozen_aliases(self,now):
        expired={service for service,end in self.cutoffs.items() if int(now)>=end}
        return sorted({name.casefold() for name in expired}|
            {alias.casefold() for alias,service in ALIASES.items() if service in expired})

    def metadata(self,host,peer='',now=None,real_sample_at=None):
        end=self.cutoff(host,peer)
        return {'expires_at':end,'freeze_at':end-1 if end is not None else None,
                'frozen':end is not None and int(now if now is not None else datetime.now(TZ).timestamp())>=end,
                'real_sample_at':real_sample_at or None}


def load_policy(required=False):
    explicit=os.environ.get('USER_DAILY_EXPIRY_POLICY')
    path=Path(explicit) if explicit else (CANONICAL if CANONICAL.is_file() else LOCAL_COPY)
    if not path.is_file():
        if explicit or required:raise RuntimeError('canonical expiry policy unavailable')
        return None
    stat=path.stat();key=(str(path.resolve()),stat.st_mtime_ns,stat.st_size)
    if key not in _CACHE:
        module=runpy.run_path(str(path))
        policy=ExpiryPolicy(module['EXPIRY_DATES'])
        _CACHE.clear();_CACHE[key]=policy
    return _CACHE[key]


def source_metadata(policy,host,peer='',now=None,real_sample_at=None):
    if policy is None:return {'freeze_at':None,'expires_at':None,'frozen':False,'real_sample_at':real_sample_at or None}
    return policy.metadata(host,peer,now,real_sample_at)


_canonical_load_policy = load_policy


def load_policy(required=False):
    from topology_archive import apply_daily_archive
    return apply_daily_archive(_canonical_load_policy(required=required))

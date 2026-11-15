"""Singapore-time expiry boundaries for the isolated dashboard candidate.

The freeze boundary is a business cutoff, not a claim that a NIC was sampled
at exactly that second.  Actual sample timestamps are stored separately.
"""

from datetime import date, datetime, time, timedelta, timezone


SINGAPORE = timezone(timedelta(hours=8), "Asia/Singapore")
EXPIRY_DATES = {
    "GoMami": date(2026, 10, 22),
    "BWH": date(2026, 11, 24),
    "proxyhive.io": datetime(2026, 10, 28, 22, 27, 54, tzinfo=SINGAPORE),
    "kookey": date(2027, 1, 15),
    "NoSLA": date(2026, 10, 22),
    "Lazycat-HKT": date(2026, 11, 17),
    "ip2up.com": datetime(2026, 11, 23, 7, 28, 51, tzinfo=SINGAPORE),
}
HOST_SERVICES = ("GoMami", "BWH", "NoSLA", "Lazycat-HKT")
OUTBOUND_TAGS = {
    "proxyhive.io": "stage:proxyhive",
    "kookey": "residential-out",
    "ip2up.com": "stage:ip2up",
}


def expires_at(service):
    day = EXPIRY_DATES[service]
    if type(day) is datetime:
        if day.tzinfo is None or day.utcoffset() is None:
            raise ValueError("precise expiry must be timezone-aware")
        return int(day.astimezone(SINGAPORE).timestamp())
    if type(day) is not date:
        raise ValueError("invalid expiry boundary")
    return int(datetime.combine(day, time.min, SINGAPORE).timestamp())


def freeze_at(service):
    return expires_at(service) - 1


def is_expired(service, now):
    return int(now) >= expires_at(service)


def active_hosts(host_commands, now):
    """Keep non-expiring hosts; leave access-record export separate."""
    return {name: command for name, command in host_commands.items()
            if name not in HOST_SERVICES or not is_expired(name, now)}


def may_store_measurement(server, item, now):
    """Reject an in-flight poll that crossed midnight before measurement."""
    if server not in HOST_SERVICES:
        return True
    if item is None:
        return not is_expired(server, now)
    return int(item["ts"]) < expires_at(server)

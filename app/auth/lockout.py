from datetime import datetime, timedelta, timezone

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def utc_now():
    return datetime.now(timezone.utc)


def as_utc(value):
    # SQLite may return datetimes without a timezone; treat them as UTC
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def is_locked(user, now):
    return user.locked_until is not None and as_utc(user.locked_until) > now


def record_failed_login(user, now):
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
        user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
        user.failed_login_count = 0


def reset_failed_logins(user):
    user.failed_login_count = 0
    user.locked_until = None
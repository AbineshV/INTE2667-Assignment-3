import json
from datetime import date
from types import SimpleNamespace

from app.audit.models import AuditLogEntry
from app.auth.eligibility import (
    NO_DIVISION,
    NO_DOB,
    NO_USER,
    NOT_CITIZEN,
    NOT_ENROLLED,
    UNDER_AGE,
    calculate_age,
    check_and_log_eligibility,
    check_eligibility,
)
from app.extensions import db
from app.models import User

TODAY = date(2026, 10, 26)


def eligible_user(**changes):
    """An eligible voter on TODAY; pass keyword arguments to change one field."""
    fields = dict(
        is_enrolled=True,
        is_citizen=True,
        date_of_birth=date(1990, 5, 1),
        division="Melbourne",
    )
    fields.update(changes)
    return SimpleNamespace(**fields)


# ---------- check_eligibility ----------

def test_eligible_user():
    assert check_eligibility(eligible_user(), TODAY) == (True, None)


def test_no_user():
    assert check_eligibility(None, TODAY) == (False, NO_USER)


def test_not_enrolled():
    assert check_eligibility(eligible_user(is_enrolled=False), TODAY) == (False, NOT_ENROLLED)


def test_not_citizen():
    assert check_eligibility(eligible_user(is_citizen=False), TODAY) == (False, NOT_CITIZEN)


def test_booleans_fail_closed_on_non_true_values():
    for value in (None, 1, "yes"):
        assert check_eligibility(eligible_user(is_enrolled=value), TODAY) == (False, NOT_ENROLLED)
        assert check_eligibility(eligible_user(is_citizen=value), TODAY) == (False, NOT_CITIZEN)


def test_no_date_of_birth():
    assert check_eligibility(eligible_user(date_of_birth=None), TODAY) == (False, NO_DOB)


def test_turns_18_tomorrow_is_refused():
    user = eligible_user(date_of_birth=date(2008, 10, 27))
    assert check_eligibility(user, TODAY) == (False, UNDER_AGE)


def test_turned_18_today_is_eligible():
    user = eligible_user(date_of_birth=date(2008, 10, 26))
    assert check_eligibility(user, TODAY) == (True, None)


def test_date_of_birth_in_future_is_refused():
    user = eligible_user(date_of_birth=date(2027, 1, 1))
    assert check_eligibility(user, TODAY) == (False, UNDER_AGE)


def test_leap_day_birthday_not_18_on_28_feb():
    user = eligible_user(date_of_birth=date(2008, 2, 29))
    assert check_eligibility(user, date(2026, 2, 28)) == (False, UNDER_AGE)


def test_leap_day_birthday_18_on_1_mar():
    user = eligible_user(date_of_birth=date(2008, 2, 29))
    assert check_eligibility(user, date(2026, 3, 1)) == (True, None)


def test_division_none():
    assert check_eligibility(eligible_user(division=None), TODAY) == (False, NO_DIVISION)


def test_division_empty_or_whitespace():
    for value in ("", "   "):
        assert check_eligibility(eligible_user(division=value), TODAY) == (False, NO_DIVISION)


def test_first_failed_check_decides_the_reason():
    user = eligible_user(is_enrolled=False, date_of_birth=date(2010, 1, 1), division="")
    assert check_eligibility(user, TODAY) == (False, NOT_ENROLLED)


# ---------- calculate_age ----------

def test_age_day_before_birthday():
    assert calculate_age(date(2008, 10, 27), TODAY) == 17


def test_age_on_birthday():
    assert calculate_age(date(2008, 10, 26), TODAY) == 18


def test_age_day_after_birthday():
    assert calculate_age(date(2008, 10, 25), TODAY) == 18

def save_user(**changes):
    """Save a real User to the test database; call inside app.app_context()."""
    fields = dict(
        email="voter@example.com",
        password_hash="not-a-real-hash",
        is_enrolled=True,
        is_citizen=True,
        date_of_birth=date(1990, 5, 1),
        division="Melbourne",
    )
    fields.update(changes)
    user = User(**fields)
    db.session.add(user)
    db.session.commit()
    return user


def test_refusal_is_logged_with_reason_only(app):
    with app.app_context():
        user = save_user(is_enrolled=False)
        before = AuditLogEntry.query.count()

        assert check_and_log_eligibility(user, TODAY) == (False, NOT_ENROLLED)

        assert AuditLogEntry.query.count() == before + 1
        entry = AuditLogEntry.query.order_by(AuditLogEntry.id.desc()).first()
        assert entry.action == "eligibility.denied"
        assert json.loads(entry.details)["reason"] == NOT_ENROLLED
        assert "Melbourne" not in str(entry.details)
        assert "1990" not in str(entry.details)


def test_success_is_not_logged(app):
    with app.app_context():
        user = save_user()
        before = AuditLogEntry.query.count()

        assert check_and_log_eligibility(user, TODAY) == (True, None)

        assert AuditLogEntry.query.count() == before


def test_refusal_of_missing_user_is_logged(app):
    with app.app_context():
        before = AuditLogEntry.query.count()

        assert check_and_log_eligibility(None, TODAY) == (False, NO_USER)

        assert AuditLogEntry.query.count() == before + 1
        entry = AuditLogEntry.query.order_by(AuditLogEntry.id.desc()).first()
        assert json.loads(entry.details)["reason"] == NO_USER
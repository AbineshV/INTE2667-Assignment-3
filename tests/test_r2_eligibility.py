from datetime import date
from types import SimpleNamespace

from app.auth.eligibility import (
    NO_DIVISION,
    NO_DOB,
    NO_USER,
    NOT_CITIZEN,
    NOT_ENROLLED,
    UNDER_AGE,
    calculate_age,
    check_eligibility,
)

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
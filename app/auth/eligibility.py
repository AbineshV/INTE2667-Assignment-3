"""Voter eligibility rules (R2).

Implements R2: only enrolled citizens aged 18 or over, with an electoral
division on record, are eligible to vote.

Sources: Venkatesan Req 15, a1-sss R03, Aravind A2 T01.
"""

from datetime import date
from app.audit import log_event  # match the path used in tests/test_audit_log.py

MINIMUM_AGE = 18

# Reason codes returned when a user is not eligible
NO_USER = "NO_USER"
NOT_ENROLLED = "NOT_ENROLLED"
NOT_CITIZEN = "NOT_CITIZEN"
NO_DOB = "NO_DOB"
UNDER_AGE = "UNDER_AGE"
NO_DIVISION = "NO_DIVISION"


def calculate_age(dob, today):
    """Return the age in whole years on `today` for someone born on `dob`.

    The age goes up on the birthday itself. Someone born on 29 February
    turns a year older on 1 March in non-leap years.
    """
    age = today.year - dob.year
    if (today.month, today.day) < (dob.month, dob.day):
        age -= 1
    return age


def check_eligibility(user, today=None):
    """Check whether `user` may vote.

    Returns (True, None) if eligible, or (False, reason_code) at the first
    failed check, where reason_code is one of the constants above.

    Checks run in this fixed order, so the first failure decides the reason:
      1. user exists               -> NO_USER
      2. is_enrolled is True       -> NOT_ENROLLED
      3. is_citizen is True        -> NOT_CITIZEN
      4. date_of_birth is recorded -> NO_DOB
      5. age is at least 18        -> UNDER_AGE
      6. division is not blank     -> NO_DIVISION

    The booleans must be exactly True; None or any other value fails closed.

    `today` can be passed in for testing. If omitted, the server's local
    date is used. Assumption: dates are server-local in this prototype; a
    production system would use the official polling-day date.
    """
    if today is None:
        today = date.today()

    if user is None:
        return False, NO_USER
    if user.is_enrolled is not True:
        return False, NOT_ENROLLED
    if user.is_citizen is not True:
        return False, NOT_CITIZEN
    if user.date_of_birth is None:
        return False, NO_DOB
    if calculate_age(user.date_of_birth, today) < MINIMUM_AGE:
        return False, UNDER_AGE
    if user.division is None or not str(user.division).strip():
        return False, NO_DIVISION

    return True, None

def check_and_log_eligibility(user, today=None):
    """Check eligibility and record any refusal in the signed audit log.

    Returns the same tuple as check_eligibility: (True, None) or
    (False, reason_code). Only the reason code is logged, never the
    voter's date of birth, name or division.
    """
    eligible, reason = check_eligibility(user, today)
    if not eligible:
        log_event(
            actor=user.email if user is not None else "unknown",
            action="eligibility.denied",
            target=str(user.id) if user is not None else None,
            details={"reason": reason},
        )
    return eligible, reason
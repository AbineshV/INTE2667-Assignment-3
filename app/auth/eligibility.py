"""Voter eligibility rules (R2).

Implements R2: only enrolled citizens aged 18 or over, with an electoral
division on record, are eligible to vote.

Sources: Venkatesan Req 15, a1-sss R03, Aravind A2 T01.
"""

from datetime import date

MINIMUM_AGE = 18

# Reason codes returned when a user is not eligible
NO_USER = "NO_USER"
NOT_ENROLLED = "NOT_ENROLLED"
NOT_CITIZEN = "NOT_CITIZEN"
NO_DOB = "NO_DOB"
UNDER_AGE = "UNDER_AGE"
NO_DIVISION = "NO_DIVISION"


def calculate_age(dob, today):
    age = today.year - dob.year
    if (today.month, today.day) < (dob.month, dob.day):
        age -= 1
    return age


def check_eligibility(user, today=None):
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
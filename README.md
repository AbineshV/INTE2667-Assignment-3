
# Electronic Voting Platform – Secure Prototype
INTE2667 Assignment 3

## Team
| Name | Student ID | GitHub |
|---|---|---|
| Abinesh V | s4221033 | AbineshV |
| Hariharan Govindasamy Venkatraman | s4205841 | hariharan2k03 |
| Roshan Daniel Raj| s4220866 | roshandanraj |
| Aravind Gurumurthy Kanagambal | s4175149 | aravind-P-tester |
| Venkatesh | <ID> | <username> |

## Subsystems
- S1 Voter Enrolment & Administration
- S2 Online Voting Gateway / Vote Casting
- S3 Ballot Definition
- S4 Results Computation & Distribution

## Tech stack
Python, Flask, SQLAlchemy, SQLite, pytest, GitHub Actions

## How to run
Requires Python 3.9 or newer.

1. Clone the repo and open the folder in VS Code.
2. Create and activate a virtual environment:
   python3 -m venv .venv
   source .venv/bin/activate        (Windows: .venv\Scripts\activate)
3. Install dependencies:
   pip install -r requirements.txt
4. Copy .env.example to .env, then set SECRET_KEY to a long random value:
   python3 -c "import secrets; print(secrets.token_hex(32))"
5. Run the app:
   flask --app run run --debug
   Open http://127.0.0.1:5000/auth/login
6. Run the tests:
   pytest -v

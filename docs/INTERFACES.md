# Interfaces between modules

## App factory
- File: app/__init__.py
- Function: create_app(config_class=Config)
- *write one line: what it does and that it stops if SECRET_KEY is missing*

## Shared extensions (app/extensions.py)
| Name | What it is |
|---|---|
| db | SQLAlchemy database object |
| login_manager | Flask-Login session manager (login view: auth.login) |
| csrf | CSRF protection for all forms |

*write one line: how to import them, e.g. from app.extensions import db*

## User model (app/models.py)
| Field | Used by |
|---|---|
| email, password_hash | R3 (S1) |
| role | R5 (S2) |
| division | R5 (S2), R2 (S1) |
| date_of_birth, is_citizen, is_enrolled | R2 (S1) |
| totp_secret | R1 (S1) |
| failed_login_count, locked_until | R4 (S1) |

## Blueprints
| Module | Blueprint name | URL prefix | File | Owner |
|---|---|---|---|---|
| Auth | auth | /auth | app/auth/routes.py | S1 |
| Enrolment | enrolment | /enrolment | app/enrolment/routes.py | S2 |
| Voting | voting | /vote | app/voting/routes.py | S3 |
| Admin | admin | /admin | app/admin/routes.py | S2 / S5 |
| Results | results | /results | app/results/routes.py | S5 |

*write one line: add your routes to your own blueprint only*

## Testing
- Fixtures in tests/conftest.py: app, client
- *write one line: database queries in tests need `with app.app_context():`*

## Still to be added by teammates
- S2: session protection settings (R8)
- S3: has_voted field (R12)
- S4: rate limiting (R16)
- S5: election and candidate models (R19)
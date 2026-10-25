# Interfaces between modules

## App factory
- File: app/__init__.py
- Function: create_app(config_class=Config)
- Creates and configures the Flask application, initializes shared extensions, registers blueprints, and applies default-deny access control. Application startup fails if `SECRET_KEY` is missing.

## Shared extensions (app/extensions.py)
| Name | What it is |
|---|---|
| db | SQLAlchemy database object |
| login_manager | Flask-Login session manager (login view: auth.login) |
| csrf | CSRF protection for all forms |

- Import shared instances using `from app.extensions import db, login_manager, csrf`. Use these instances throughout the application instead of creating duplicate extensions.

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

- Define routes in the appropriate feature blueprint and register blueprints through `create_app()` in `app/__init__.py`. Protect routes using explicit role or division permissions, or mark intentionally public endpoints appropriately.

## Access control (R5, S2)

- `app/access/permissions.py` provides `require_roles()` for role-based access control and `require_division_access()` for role and division scoping.
- Administrators may access any division through the division-access decorator. Other permitted roles must have a matching assigned division.
- The enrolment blueprint exposes `/enrolment/divisions/<division>` as a division-scoped placeholder route.
- Unclassified routes are denied by the application-wide default-deny policy unless explicitly classified.
- Tests in `tests/test_r5_permissions.py` and `tests/test_r5_admin_integration.py` cover role permissions and division-access decisions.

## Audit log (R18, S5)
- Import: `from app.audit import log_event`
- Call: `log_event(actor, action, target=None, details=None)` after your change is saved; it commits the session
- `actor`: who did it, e.g. `"user:12"`, `"admin:3"`, `"system"`
- `action`: lower-case dotted name, `module.event`, e.g. `"auth.login_failed"`, `"auth.account_locked"`, `"admin.role_changed"`, `"election.signed"`, `"vote.cast"`
- `target`: what it was done to, e.g. `"user:15"`, `"election:2"` (optional)
- `details`: small dict of extra facts, e.g. `{"ip": "1.2.3.4"}` (optional, max 2000 chars)
- Never put passwords, tokens, MFA codes or anything about how someone voted in `details`; keys containing words like `password`, `token`, `totp`, `ballot` or `preference` are refused with ValueError
- For `vote.cast`, log only that the voter voted (e.g. `actor="user:12"`), never the ballot
- Bad input raises ValueError, so a mistake shows up in your tests
- `verify_audit_log()` checks the whole chain and returns `ok`, `failed_sequence`, `reason`, `head_hash`

## Elections and ballot definition (R19, S5)
- Models in `app/elections/models.py`: `Election` (name, chamber `house`/`senate`, status), `Division`, `Group` (Senate above the line), `Candidate`, `ElectionSignature`
- Import: `from app.elections import sign_election, verify_election, ElectionError`
- `sign_election(election, admin)`: admin role only; the second signature from a different admin locks the election
- `verify_election(election)` returns `ok`, `reason`, `definition_hash`; **S3: only show the ballot and accept votes when `ok` is True**
- Once locked, any ORM change to the election, its divisions, groups, candidates or signatures raises `ElectionError`
- Editing a definition after the first signature removes that signature; both admins must sign the new version
- Statuses: `draft` → `awaiting_second_signature` → `locked`

## Testing
- Fixtures in tests/conftest.py: app, client
- Use the `app` and `client` fixtures from `tests/conftest.py`. Wrap database operations performed outside a request in `with app.app_context():`. Test important security decisions through actual HTTP routes as well as isolated permission helpers.

## Remaining requirements to verify

- R12 (S3): Verify the `has_voted` field and duplicate-voting prevention.
- R16 (S4): Verify that rate limiting is implemented and tested.

## Multi-factor authentication (R1)

- A user has MFA enabled when `User.totp_secret` is set (not `None`).
  The value is Fernet-encrypted; never read or compare it directly.
- Login for MFA users is two-step: after the password, the session holds only
  `mfa_user_id` and `mfa_started`. `login_user` is called only after a correct
  code, so `@login_required` routes stay closed until both factors pass.
- Staff-only routes can require MFA in the role decorator (S2, R5), for example:
  refuse access when `current_user.role != "voter" and not current_user.totp_secret`.
- Users without MFA are sent to `/auth/mfa/setup` after login.
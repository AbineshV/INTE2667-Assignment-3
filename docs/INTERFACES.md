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

## Audit log (R18, S5)
- Import: `from app.audit import log_event`
- Call: `log_event(actor, action, target=None, details=None)` after your change is saved; it commits the session
- `actor`: who did it, e.g. `"user:12"`, `"admin:3"`, `"system"`
- `action`: lower-case dotted name, `module.event`, e.g. `"auth.login_failed"`, `"auth.account_locked"`, `"admin.role_changed"`, `"election.signed"`, `"vote.cast"`
- `target`: what it was done to, e.g. `"user:15"`, `"election:2"` (optional)
- `details`: small dict of extra facts, e.g. `{"ip": "1.2.3.4"}` (optional, max 2000 chars)
- Never put passwords, tokens, MFA codes or anything about how someone voted in `details`; keys containing words like `password`, `token`, `totp`, `ballot` or `preference` are refused with ValueError
- For `vote.cast`, use `actor="system"` and `target="election:<id>"` with no voter id; the order of entries could otherwise link a voter to their ledger position (R11)
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

## Ballot ledger (R17, S5)
- Import: `from app.ledger import append_ballot, LedgerError`
- **S3:** after validating and encrypting a ballot, call `code = append_ballot(election, division, ciphertext)`; `ciphertext` is your encrypted ballot as a string (max 20000 chars)
- Show `code` to the voter once on the confirmation page; it is not stored anywhere (only its SHA-256 is)
- Refuses ballots unless `verify_election(election)` is ok
- The ledger has no voter id and no timestamp; keep it that way, and don't store the ledger id against the voter
- `verify_ledger(election_id)` returns `ok`, `failed_sequence`, `reason`, `head_hash`; R20 signs `head_hash` with the results
- Voters check their code at `/results/track`

## Signed results (R20, S5)
- Import: `from app.results.publication import publish_results, verify_publication, ResultsError`
- `publish_results(election, admin, tallies)`: admin only, once per election; `tallies` is `{division_id: {candidate_id: votes}}` covering every division and candidate
- **S3:** after decrypting and counting, pass your counts here; it refuses if the definition (R19) or ledger (R17) fails verification, or a division has more votes than ballots
- The signed document includes the definition hash and the ledger head hash, so results are tied to exactly those ballots
- API: `GET /results/api/<election_id>` returns `document` (the exact signed string), `signature`, `algorithm`, `key_id`
- Public key: `GET /results/api/public-key`
- Pages: `/results/` (list) and `/results/<election_id>` (tables plus live verification)
- **S4:** please include `/results/api/...` in rate limiting (R16)

## Testing
- Fixtures in tests/conftest.py: app, client
- *write one line: database queries in tests need `with app.app_context():`*

## Still to be added by teammates
- S2: session protection settings (R8)
- S3: has_voted field (R12)
- S4: rate limiting (R16)
- S5: election and candidate models (R19)
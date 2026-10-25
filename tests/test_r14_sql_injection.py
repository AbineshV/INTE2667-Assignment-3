"""
S4 - R14: SQL Injection Prevention
All database access goes through SQLAlchemy ORM (parameterised queries).
SQL injection payloads in user-controlled fields are treated as literal
data, not executable SQL.
"""
import inspect

import pytest

from app import db
from app.elections.models import Candidate, Division, Election
from app.models import User


@pytest.fixture
def clean_db(app):
    with app.app_context():
        db.create_all()
        yield
        db.drop_all()


# ---------------------------------------------------------------------------
# Source-level: no raw-SQL escape hatches in the codebase
# ---------------------------------------------------------------------------

class TestNoRawSql:
    """R14: codebase must not bypass the ORM with raw SQL calls."""

    def test_casting_has_no_cursor_execute(self):
        from app.voting import casting
        assert "cursor.execute" not in inspect.getsource(casting)

    def test_casting_has_no_engine_execute(self):
        from app.voting import casting
        assert "engine.execute" not in inspect.getsource(casting)

    def test_casting_uses_orm_select(self):
        from app.voting import casting
        assert "db.select(" in inspect.getsource(casting)

    def test_user_model_has_no_raw_sql(self):
        from app import models
        src = inspect.getsource(models)
        assert "cursor.execute" not in src
        assert "engine.execute" not in src

    def test_election_models_have_no_raw_sql(self):
        from app.elections import models as em
        src = inspect.getsource(em)
        assert "cursor.execute" not in src
        assert "engine.execute" not in src

    def test_voting_models_have_no_raw_sql(self):
        from app.voting import models as vm
        src = inspect.getsource(vm)
        assert "cursor.execute" not in src
        assert "engine.execute" not in src


# ---------------------------------------------------------------------------
# Functional: injection payloads in ORM filters are treated as data
# ---------------------------------------------------------------------------

class TestInjectionPayloads:
    """R14: SQL injection strings in filter arguments return no data."""

    def test_or_1_equals_1_returns_no_user(self, app, clean_db):
        with app.app_context():
            result = db.session.execute(
                db.select(User).filter_by(email="' OR '1'='1")
            ).scalar_one_or_none()
            assert result is None

    def test_comment_injection_returns_no_user(self, app, clean_db):
        with app.app_context():
            result = db.session.execute(
                db.select(User).filter_by(email="admin@example.com'--")
            ).scalar_one_or_none()
            assert result is None

    def test_union_select_injection_returns_no_user(self, app, clean_db):
        with app.app_context():
            payload = "x' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13 --"
            result = db.session.execute(
                db.select(User).filter_by(email=payload)
            ).scalar_one_or_none()
            assert result is None

    def test_drop_table_payload_stored_as_literal(self, app, clean_db):
        """A DROP TABLE string stored as an election name does not destroy the table."""
        with app.app_context():
            admin = User(email="a@a.com", password_hash="x", role="admin")
            db.session.add(admin)
            db.session.flush()
            malicious = "'; DROP TABLE elections; --"
            election = Election(name=malicious, chamber="house",
                                created_by_id=admin.id)
            db.session.add(election)
            db.session.commit()
            fetched = db.session.get(Election, election.id)
            assert fetched is not None
            assert fetched.name == malicious

    def test_stacked_query_in_candidate_name_stored_as_literal(self, app, clean_db):
        """Stacked-query payload in a candidate name is stored and retrieved intact."""
        with app.app_context():
            admin = User(email="b@b.com", password_hash="x", role="admin")
            db.session.add(admin)
            db.session.flush()
            election = Election(name="E", chamber="house", created_by_id=admin.id)
            db.session.add(election)
            db.session.flush()
            division = Division(election_id=election.id, name="D")
            db.session.add(division)
            db.session.flush()
            malicious = "Robert'); DROP TABLE candidates; --"
            candidate = Candidate(division_id=division.id,
                                  name=malicious, position=1)
            db.session.add(candidate)
            db.session.commit()
            fetched = db.session.get(Candidate, candidate.id)
            assert fetched is not None
            assert fetched.name == malicious
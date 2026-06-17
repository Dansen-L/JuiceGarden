"""
test_flask_platform.py — Docker-independent Flask platform tests.

Uses Flask TestClient with SQLite in-memory database (no Docker needed).

Verifies:
  - Flag submission accepts correct flag → awards points → records Solve
  - Flag submission rejects wrong flag → 400
  - Flag submission records already-solved state correctly
  - Hint purchase: T1 purchasable, T2 requires T1, T3 cost deducted
  - Hint purchase rejects purchase when points insufficient
  - Hint purchase returns idempotent result on re-purchase
"""
import sys
import os
import pytest

# Add flask-platform/src to path so imports resolve
_PLATFORM_SRC = os.path.join(os.path.dirname(__file__), '..', 'flask-platform', 'src')
sys.path.insert(0, os.path.abspath(_PLATFORM_SRC))
# Add flask-platform to path for package-level imports
_PLATFORM_PKG = os.path.join(os.path.dirname(__file__), '..', 'flask-platform')
sys.path.insert(0, os.path.abspath(_PLATFORM_PKG))


# ─────────────────────────────────────────────────────────────────────────────
# App factory for in-memory testing
# ─────────────────────────────────────────────────────────────────────────────

def make_test_app():
    """Create a Flask app with SQLite in-memory database for unit tests."""
    from flask import Flask
    from src.extensions import db, login_manager
    from src.models import (
        Challenge, Flag, PlatformUser, Solve, HintPurchase
    )
    from src.routes.main import main_bp
    from src.routes.auth import auth_bp

    app = Flask(__name__, template_folder=os.path.join(_PLATFORM_SRC, 'templates'))
    app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'test-secret',
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'WTF_CSRF_ENABLED': False,
        'LOGIN_DISABLED': False,
    })

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    app.register_blueprint(main_bp, url_prefix='/platform')
    app.register_blueprint(auth_bp, url_prefix='/platform/auth')

    with app.app_context():
        db.create_all()
        _seed_test_data(db)

    return app, db


def _seed_test_data(db):
    """Seed minimal test data (one challenge + flag)."""
    from src.models import Challenge, Flag

    ch = Challenge(
        code='AUTH-01',
        track='auth',
        title='JWT kid Path Traversal',
        description_md='Test challenge',
        difficulty='moderate',
        points=200,
        hint_t1='Hint 1 text',
        hint_t2='Hint 2 text',
        hint_t3='Hint 3 text',
        solution_notes_md='Solution notes',
        is_hidden=False,
        is_mission=False,
    )
    db.session.add(ch)
    db.session.flush()

    flag = Flag(
        challenge_id=ch.id,
        flag_value='JG{deadbeefdeadbeefdeadbeefdeadbeef}'
    )
    db.session.add(flag)
    db.session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def app():
    _app, _db = make_test_app()
    yield _app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(client):
    """A test client with a logged-in platform user."""
    # Register and log in
    r = client.post('/platform/auth/register', json={
        'username': 'tester',
        'password': 'testpass123'
    })
    assert r.status_code == 200
    yield client


@pytest.fixture
def rich_auth_client(app):
    """A test client logged in as a user with 500 points."""
    client = app.test_client()
    r = client.post('/platform/auth/register', json={
        'username': 'richuser',
        'password': 'testpass123'
    })
    assert r.status_code == 200
    # Give user points directly in DB
    with app.app_context():
        from src.models import PlatformUser
        from src.extensions import db
        user = PlatformUser.query.filter_by(username='richuser').first()
        user.total_points = 500
        db.session.commit()
    yield client


# ─────────────────────────────────────────────────────────────────────────────
# Flag submission tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFlagSubmission:
    def test_correct_flag_accepted(self, auth_client):
        """Correct flag → 200 success, points awarded."""
        r = auth_client.post('/platform/submit-flag', json={
            'flag': 'JG{deadbeefdeadbeefdeadbeefdeadbeef}'
        })
        data = r.get_json()
        assert r.status_code == 200
        assert data['success'] is True
        assert data['already_solved'] is False
        assert data['points_earned'] == 200

    def test_correct_flag_returns_challenge_info(self, auth_client):
        """Response includes challenge_code and challenge_title."""
        r = auth_client.post('/platform/submit-flag', json={
            'flag': 'JG{deadbeefdeadbeefdeadbeefdeadbeef}'
        })
        data = r.get_json()
        assert data['challenge_code'] == 'AUTH-01'
        assert 'JWT' in data['challenge_title']

    def test_wrong_flag_rejected(self, auth_client):
        """Wrong flag → 400, success=False."""
        r = auth_client.post('/platform/submit-flag', json={
            'flag': 'JG{aaaabbbbccccddddaaaabbbbccccdddd}'
        })
        data = r.get_json()
        assert r.status_code == 400
        assert data['success'] is False

    def test_empty_flag_rejected(self, auth_client):
        """Empty flag → 400."""
        r = auth_client.post('/platform/submit-flag', json={'flag': ''})
        assert r.status_code == 400

    def test_missing_flag_field_rejected(self, auth_client):
        """Missing flag field → 400."""
        r = auth_client.post('/platform/submit-flag', json={})
        assert r.status_code == 400

    def test_duplicate_submission_returns_already_solved(self, auth_client):
        """Submitting the same flag twice → already_solved=True on second attempt."""
        payload = {'flag': 'JG{deadbeefdeadbeefdeadbeefdeadbeef}'}
        r1 = auth_client.post('/platform/submit-flag', json=payload)
        assert r1.get_json()['success'] is True

        r2 = auth_client.post('/platform/submit-flag', json=payload)
        data2 = r2.get_json()
        assert r2.status_code == 200
        assert data2['success'] is True
        assert data2['already_solved'] is True

    def test_points_awarded_once(self, app, auth_client):
        """Points are awarded only on first solve, not on re-submit."""
        payload = {'flag': 'JG{deadbeefdeadbeefdeadbeefdeadbeef}'}
        auth_client.post('/platform/submit-flag', json=payload)
        auth_client.post('/platform/submit-flag', json=payload)

        with app.app_context():
            from src.models import PlatformUser
            user = PlatformUser.query.filter_by(username='tester').first()
            assert user.total_points == 200   # awarded exactly once

    def test_unauthenticated_submit_redirects(self, client):
        """Unauthenticated user → redirect to login (Flask-Login behavior)."""
        r = client.post('/platform/submit-flag', json={
            'flag': 'JG{deadbeefdeadbeefdeadbeefdeadbeef}'
        })
        # Flask-Login redirects unauthenticated requests
        assert r.status_code in (302, 401)


# ─────────────────────────────────────────────────────────────────────────────
# Hint purchase tests
# ─────────────────────────────────────────────────────────────────────────────

class TestHintPurchase:
    def _challenge_id(self, app):
        with app.app_context():
            from src.models import Challenge
            return Challenge.query.filter_by(code='AUTH-01').first().id

    def test_t1_hint_purchasable(self, app, rich_auth_client):
        """T1 hint can be purchased when user has enough points."""
        cid = self._challenge_id(app)
        r = rich_auth_client.post('/platform/buy-hint', json={
            'challenge_id': cid,
            'tier': 1
        })
        data = r.get_json()
        assert r.status_code == 200
        assert data['success'] is True
        assert data['hint'] == 'Hint 1 text'
        # T1 costs 5% of 200 = 10 points
        assert data['cost'] == 10
        assert data['points_remaining'] == 490

    def test_t2_requires_t1_first(self, app, rich_auth_client):
        """T2 hint purchase fails when T1 has not been purchased."""
        cid = self._challenge_id(app)
        r = rich_auth_client.post('/platform/buy-hint', json={
            'challenge_id': cid,
            'tier': 2
        })
        data = r.get_json()
        assert r.status_code == 400
        assert data['success'] is False
        assert 'T1' in data['message']

    def test_t2_unlocked_after_t1(self, app, rich_auth_client):
        """T2 hint is accessible after T1 has been purchased."""
        cid = self._challenge_id(app)
        # Buy T1 first
        rich_auth_client.post('/platform/buy-hint', json={'challenge_id': cid, 'tier': 1})
        # Now buy T2
        r = rich_auth_client.post('/platform/buy-hint', json={'challenge_id': cid, 'tier': 2})
        data = r.get_json()
        assert r.status_code == 200
        assert data['success'] is True
        assert data['hint'] == 'Hint 2 text'
        # T2 costs 15% of 200 = 30 points
        assert data['cost'] == 30

    def test_invalid_tier_rejected(self, app, rich_auth_client):
        """Tier values outside [1, 2, 3] are rejected."""
        cid = self._challenge_id(app)
        r = rich_auth_client.post('/platform/buy-hint', json={
            'challenge_id': cid,
            'tier': 4
        })
        assert r.status_code == 400

    def test_insufficient_points_rejected(self, app, client):
        """User with 0 points cannot purchase hints."""
        client.post('/platform/auth/register', json={
            'username': 'pooruser',
            'password': 'testpass123'
        })
        cid = self._challenge_id(app)
        r = client.post('/platform/buy-hint', json={
            'challenge_id': cid,
            'tier': 1
        })
        # T1 costs 10 points; user has 0
        data = r.get_json()
        assert r.status_code == 400
        assert data['success'] is False
        assert 'points' in data['message'].lower()

    def test_repurchase_is_idempotent(self, app, rich_auth_client):
        """Purchasing the same hint twice does not deduct points twice."""
        cid = self._challenge_id(app)
        r1 = rich_auth_client.post('/platform/buy-hint', json={'challenge_id': cid, 'tier': 1})
        r2 = rich_auth_client.post('/platform/buy-hint', json={'challenge_id': cid, 'tier': 1})

        data2 = r2.get_json()
        assert data2['success'] is True
        assert data2.get('already_purchased') is True
        # Points deducted only once
        with app.app_context():
            from src.models import PlatformUser
            user = PlatformUser.query.filter_by(username='richuser').first()
            assert user.total_points == 490   # only 10 deducted, not 20

    def test_t1_cost_is_5_percent_of_points(self, app, rich_auth_client):
        """T1 cost = round(challenge.points * 0.05)."""
        cid = self._challenge_id(app)
        r = rich_auth_client.post('/platform/buy-hint', json={'challenge_id': cid, 'tier': 1})
        data = r.get_json()
        assert data['cost'] == round(200 * 0.05)   # = 10

    def test_t3_cost_is_30_percent_of_points(self, app, rich_auth_client):
        """T3 cost = round(challenge.points * 0.30)."""
        cid = self._challenge_id(app)
        # Buy T1 and T2 first (T3 has no T2 prerequisite per code, but need points)
        rich_auth_client.post('/platform/buy-hint', json={'challenge_id': cid, 'tier': 1})
        r = rich_auth_client.post('/platform/buy-hint', json={'challenge_id': cid, 'tier': 3})
        data = r.get_json()
        assert r.status_code == 200
        assert data['cost'] == round(200 * 0.30)   # = 60

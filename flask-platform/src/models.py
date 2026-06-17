"""
SQLAlchemy models for the Challenge Platform.
"""
from datetime import datetime
from flask_login import UserMixin
from .extensions import db


class Challenge(db.Model):
    __tablename__ = 'challenges'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)
    track = db.Column(db.String(32), nullable=False)
    title = db.Column(db.String(256), nullable=False)
    description_md = db.Column(db.Text, default='')
    difficulty = db.Column(db.String(16), default='moderate')
    points = db.Column(db.Integer, default=100)
    hint_t1 = db.Column(db.Text)
    hint_t2 = db.Column(db.Text)
    hint_t3 = db.Column(db.Text)
    solution_notes_md = db.Column(db.Text)
    is_hidden = db.Column(db.Boolean, default=False)
    is_mission = db.Column(db.Boolean, default=False)
    mission_step = db.Column(db.Integer)

    flags = db.relationship('Flag', back_populates='challenge', lazy='dynamic')
    solves = db.relationship('Solve', back_populates='challenge', lazy='dynamic')


class Flag(db.Model):
    __tablename__ = 'flags'

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenges.id'), nullable=False)
    flag_value = db.Column(db.String(64), nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)

    challenge = db.relationship('Challenge', back_populates='flags')


class PlatformUser(UserMixin, db.Model):
    __tablename__ = 'platform_users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    total_points = db.Column(db.Integer, default=0)

    solves = db.relationship('Solve', back_populates='platform_user', lazy='dynamic')
    hint_purchases = db.relationship('HintPurchase', back_populates='platform_user', lazy='dynamic')

    def get_id(self):
        return str(self.id)


class Solve(db.Model):
    __tablename__ = 'solves'

    id = db.Column(db.Integer, primary_key=True)
    platform_user_id = db.Column(db.Integer, db.ForeignKey('platform_users.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenges.id'), nullable=False)
    solved_at = db.Column(db.DateTime, default=datetime.utcnow)
    time_to_solve_seconds = db.Column(db.Integer)
    hints_purchased_count = db.Column(db.Integer, default=0)

    platform_user = db.relationship('PlatformUser', back_populates='solves')
    challenge = db.relationship('Challenge', back_populates='solves')


class HintPurchase(db.Model):
    __tablename__ = 'hint_purchases'

    id = db.Column(db.Integer, primary_key=True)
    platform_user_id = db.Column(db.Integer, db.ForeignKey('platform_users.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenges.id'), nullable=False)
    tier = db.Column(db.Integer, nullable=False)  # 1, 2, or 3
    purchased_at = db.Column(db.DateTime, default=datetime.utcnow)
    points_deducted = db.Column(db.Integer, default=0)

    platform_user = db.relationship('PlatformUser', back_populates='hint_purchases')


class ExploitServerPayload(db.Model):
    __tablename__ = 'exploit_server_payloads'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    hosted_path = db.Column(db.String(256))
    origin_type = db.Column(db.String(32), default='cross-origin')  # cross-origin or cross-site
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('platform_users.id'))


class ExploitServerCollection(db.Model):
    __tablename__ = 'exploit_server_collections'

    id = db.Column(db.Integer, primary_key=True)
    received_at = db.Column(db.DateTime, default=datetime.utcnow)
    query_string = db.Column(db.Text)
    body = db.Column(db.Text)
    source_ip = db.Column(db.String(64))
    headers = db.Column(db.Text)


class BotVisitQueue(db.Model):
    __tablename__ = 'bot_visit_queue'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    visited_at = db.Column(db.DateTime)
    submitted_by = db.Column(db.Integer, db.ForeignKey('platform_users.id'))
    status = db.Column(db.String(32), default='pending')  # pending, visited, error

"""Platform auth routes."""
import bcrypt
from flask import Blueprint, request, jsonify, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from ..models import PlatformUser
from ..extensions import db, login_manager

auth_bp = Blueprint('auth', __name__)


@login_manager.user_loader
def load_user(user_id):
    return PlatformUser.query.get(int(user_id))


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or request.form
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400

    if PlatformUser.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already taken'}), 409

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = PlatformUser(username=username, password_hash=pw_hash)
    db.session.add(user)
    db.session.commit()

    login_user(user)
    return jsonify({'success': True, 'username': user.username, 'id': user.id})


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or request.form
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    user = PlatformUser.query.filter_by(username=username).first()
    if not user:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    login_user(user)
    return jsonify({'success': True, 'username': user.username, 'id': user.id, 'points': user.total_points})


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True})


@auth_bp.route('/me')
def me():
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'id': current_user.id,
            'username': current_user.username,
            'points': current_user.total_points
        })
    return jsonify({'authenticated': False})

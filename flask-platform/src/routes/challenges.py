"""Challenge-specific routes."""
from flask import Blueprint, jsonify
from ..models import Challenge, Flag, Solve

challenges_bp = Blueprint('challenges', __name__)


@challenges_bp.route('/')
def list_challenges():
    """List all non-hidden challenges."""
    challenges = Challenge.query.filter_by(is_hidden=False).order_by(
        Challenge.track, Challenge.code
    ).all()
    return jsonify([{
        'id': c.id,
        'code': c.code,
        'track': c.track,
        'title': c.title,
        'difficulty': c.difficulty,
        'points': c.points,
        'is_mission': c.is_mission,
        'solve_count': c.solves.count()
    } for c in challenges])

"""Main challenge board routes."""
import json
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, current_app
from flask_login import current_user, login_required
from ..models import Challenge, Solve, Flag, HintPurchase, PlatformUser
from ..extensions import db

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Challenge board — main page."""
    challenges = Challenge.query.filter_by(is_hidden=False).order_by(
        Challenge.track, Challenge.code
    ).all()

    solved_ids = set()
    if current_user.is_authenticated:
        solved_ids = {s.challenge_id for s in current_user.solves}

    return render_template('board.html',
                           challenges=challenges,
                           solved_ids=solved_ids,
                           user=current_user)


@main_bp.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'ok', 'service': 'flask-platform'})


@main_bp.route('/challenge/<int:challenge_id>')
def challenge_detail(challenge_id):
    """Get challenge details (JSON for slide-over)."""
    challenge = Challenge.query.get_or_404(challenge_id)

    solved = False
    purchased_hints = []
    if current_user.is_authenticated:
        solve = Solve.query.filter_by(
            platform_user_id=current_user.id,
            challenge_id=challenge_id
        ).first()
        solved = solve is not None

        purchased = HintPurchase.query.filter_by(
            platform_user_id=current_user.id,
            challenge_id=challenge_id
        ).all()
        purchased_hints = [p.tier for p in purchased]

    hints = {}
    for tier in [1, 2, 3]:
        if tier in purchased_hints:
            hints[tier] = getattr(challenge, f'hint_t{tier}')
        else:
            hints[tier] = None

    return jsonify({
        'id': challenge.id,
        'code': challenge.code,
        'track': challenge.track,
        'title': challenge.title,
        'description_md': challenge.description_md,
        'difficulty': challenge.difficulty,
        'points': challenge.points,
        'is_mission': challenge.is_mission,
        'solved': solved,
        'hints': hints,
        'purchased_hints': purchased_hints,
        'solution_notes': challenge.solution_notes_md if solved else None,
        'hint_costs': {
            '1': round(challenge.points * 0.05),
            '2': round(challenge.points * 0.15),
            '3': round(challenge.points * 0.30),
        }
    })


@main_bp.route('/submit-flag', methods=['POST'])
@login_required
def submit_flag():
    """Submit a flag for any challenge."""
    data = request.get_json() or request.form
    flag_value = (data.get('flag') or '').strip()
    challenge_id = data.get('challenge_id')

    if not flag_value:
        return jsonify({'success': False, 'message': 'Flag required'}), 400

    # Find the flag (search all challenges including hidden)
    flag_record = Flag.query.filter_by(flag_value=flag_value).first()
    if not flag_record:
        return jsonify({'success': False, 'message': 'Incorrect flag.'}), 400

    challenge = flag_record.challenge

    # Check if already solved
    existing = Solve.query.filter_by(
        platform_user_id=current_user.id,
        challenge_id=challenge.id
    ).first()

    if existing:
        return jsonify({'success': True, 'already_solved': True, 'message': f'Already solved: {challenge.title}'}), 200

    # Count hint purchases
    hints_count = HintPurchase.query.filter_by(
        platform_user_id=current_user.id,
        challenge_id=challenge.id
    ).count()

    # Record solve
    solve = Solve(
        platform_user_id=current_user.id,
        challenge_id=challenge.id,
        hints_purchased_count=hints_count
    )
    db.session.add(solve)

    # Award points
    current_user.total_points = (current_user.total_points or 0) + challenge.points
    db.session.commit()

    return jsonify({
        'success': True,
        'already_solved': False,
        'message': f'Correct! {challenge.title} solved.',
        'points_earned': challenge.points,
        'challenge_code': challenge.code,
        'challenge_title': challenge.title
    })


@main_bp.route('/buy-hint', methods=['POST'])
@login_required
def buy_hint():
    """Purchase a hint tier for a challenge."""
    data = request.get_json() or request.form
    challenge_id = int(data.get('challenge_id', 0))
    tier = int(data.get('tier', 0))

    if tier not in [1, 2, 3]:
        return jsonify({'success': False, 'message': 'Invalid tier'}), 400

    challenge = Challenge.query.get_or_404(challenge_id)

    # Check if already purchased
    existing = HintPurchase.query.filter_by(
        platform_user_id=current_user.id,
        challenge_id=challenge_id,
        tier=tier
    ).first()
    if existing:
        return jsonify({'success': True, 'hint': getattr(challenge, f'hint_t{tier}'), 'already_purchased': True})

    # T2 requires T1 first
    if tier == 2:
        t1 = HintPurchase.query.filter_by(
            platform_user_id=current_user.id,
            challenge_id=challenge_id,
            tier=1
        ).first()
        if not t1:
            return jsonify({'success': False, 'message': 'Must purchase T1 hint first'}), 400

    # Calculate cost
    costs = {1: 0.05, 2: 0.15, 3: 0.30}
    cost = round(challenge.points * costs[tier])

    if current_user.total_points < cost:
        return jsonify({'success': False, 'message': f'Insufficient points (need {cost}, have {current_user.total_points})'}), 400

    # Deduct points and record purchase
    current_user.total_points -= cost
    hp = HintPurchase(
        platform_user_id=current_user.id,
        challenge_id=challenge_id,
        tier=tier,
        points_deducted=cost
    )
    db.session.add(hp)
    db.session.commit()

    return jsonify({
        'success': True,
        'hint': getattr(challenge, f'hint_t{tier}'),
        'cost': cost,
        'points_remaining': current_user.total_points
    })

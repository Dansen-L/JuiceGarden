"""Scoreboard and user profile routes."""
from flask import Blueprint, jsonify, render_template_string
from flask_login import current_user
from sqlalchemy import func
from ..models import PlatformUser, Solve, Challenge
from ..extensions import db

scoreboard_bp = Blueprint('scoreboard', __name__)


@scoreboard_bp.route('/')
def scoreboard():
    """Global scoreboard."""
    users = PlatformUser.query.order_by(
        PlatformUser.total_points.desc()
    ).limit(50).all()

    ranked = []
    for i, user in enumerate(users):
        last_solve = Solve.query.filter_by(
            platform_user_id=user.id
        ).order_by(Solve.solved_at.desc()).first()

        ranked.append({
            'rank': i + 1,
            'username': user.username,
            'points': user.total_points,
            'solve_count': user.solves.count(),
            'last_solve': last_solve.solved_at.strftime('%Y-%m-%d %H:%M') if last_solve else '—'
        })

    return render_template_string(SCOREBOARD_TEMPLATE, ranked=ranked, user=current_user)


@scoreboard_bp.route('/api')
def scoreboard_api():
    """Scoreboard API endpoint."""
    users = PlatformUser.query.order_by(
        PlatformUser.total_points.desc()
    ).limit(50).all()

    return jsonify([{
        'rank': i + 1,
        'username': u.username,
        'points': u.total_points,
        'solve_count': u.solves.count()
    } for i, u in enumerate(users)])


@scoreboard_bp.route('/user/<username>')
def user_profile(username):
    """User profile page."""
    user = PlatformUser.query.filter_by(username=username).first_or_404()

    solves = Solve.query.filter_by(platform_user_id=user.id).order_by(
        Solve.solved_at.desc()
    ).all()

    total_users = PlatformUser.query.count()
    rank = PlatformUser.query.filter(
        PlatformUser.total_points > user.total_points
    ).count() + 1

    solve_data = []
    for s in solves:
        c = s.challenge
        # Show hidden bonus if solved
        solve_data.append({
            'code': c.code if not c.is_hidden else 'BONUS',
            'title': c.title if not c.is_hidden else 'Bonus (Hidden)',
            'track': c.track,
            'difficulty': c.difficulty,
            'points': c.points,
            'solved_at': s.solved_at.strftime('%Y-%m-%d %H:%M')
        })

    return render_template_string(PROFILE_TEMPLATE,
                                  profile_user=user,
                                  solve_data=solve_data,
                                  rank=rank,
                                  total_users=total_users,
                                  current_user=current_user)


SCOREBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Scoreboard — Juice Garden</title>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;700&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#0D0F14; --surface:#161A22; --primary:#E8A838; --text:#F0EDE8; --text-secondary:#8A8F9A; --border:#252C3A; }
    * { box-sizing:border-box; margin:0; padding:0; }
    body { font-family:'DM Sans',sans-serif; background:var(--bg); color:var(--text); min-height:100vh; }
    nav { background:var(--surface); border-bottom:1px solid var(--border); padding:1rem 2rem; display:flex; gap:1rem; align-items:center; }
    nav a { color:var(--primary); font-family:'Syne',sans-serif; font-weight:700; text-decoration:none; }
    .container { max-width:900px; margin:2rem auto; padding:0 1rem; }
    h1 { font-family:'Syne',sans-serif; font-size:2rem; margin-bottom:1.5rem; }
    table { width:100%; border-collapse:collapse; background:var(--surface); border-radius:12px; overflow:hidden; }
    th { text-align:left; padding:0.75rem 1rem; color:var(--text-secondary); font-size:0.85rem; border-bottom:1px solid var(--border); }
    td { padding:0.75rem 1rem; font-size:0.9rem; }
    tr:nth-child(even) { background:rgba(30,36,48,0.5); }
    .rank-1 { color:var(--primary); font-weight:700; }
    .rank-2 { color:#C0C0C0; }
    .rank-3 { color:#CD7F32; }
    a { color:var(--primary); text-decoration:none; }
  </style>
</head>
<body>
  <nav>
    <a href="/platform/">🥤 Juice Garden</a>
    <a href="/platform/scoreboard/">Scoreboard</a>
  </nav>
  <div class="container">
    <h1>🏆 Global Scoreboard</h1>
    <table>
      <thead><tr><th scope="col">Rank</th><th scope="col">Player</th><th scope="col">Points</th><th scope="col">Solves</th><th scope="col">Last Solve</th></tr></thead>
      <tbody>
        {% for u in ranked %}
        <tr>
          <td class="{{ 'rank-'+u.rank|string if u.rank <= 3 else '' }}">
            {{ '🥇' if u.rank == 1 else '🥈' if u.rank == 2 else '🥉' if u.rank == 3 else '#'+u.rank|string }}
          </td>
          <td><a href="/platform/scoreboard/user/{{ u.username }}">{{ u.username }}</a></td>
          <td style="font-weight:600">{{ u.points }}</td>
          <td>{{ u.solve_count }}</td>
          <td style="color:var(--text-secondary);font-size:0.85rem">{{ u.last_solve }}</td>
        </tr>
        {% else %}
        <tr><td colspan="5" style="text-align:center;padding:2rem;color:var(--text-secondary);">No solves yet. Be the first!</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</body>
</html>"""

PROFILE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{ profile_user.username }} — Juice Garden</title>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;700&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#0D0F14; --surface:#161A22; --primary:#E8A838; --secondary:#38C988; --text:#F0EDE8; --text-secondary:#8A8F9A; --border:#252C3A; }
    * { box-sizing:border-box; margin:0; padding:0; }
    body { font-family:'DM Sans',sans-serif; background:var(--bg); color:var(--text); min-height:100vh; }
    nav { background:var(--surface); border-bottom:1px solid var(--border); padding:1rem 2rem; display:flex; gap:1rem; align-items:center; }
    nav a { color:var(--primary); font-family:'Syne',sans-serif; font-weight:700; text-decoration:none; }
    .container { max-width:900px; margin:2rem auto; padding:0 1rem; }
    .stats-strip { display:flex; gap:2rem; background:var(--surface); border-radius:12px; padding:1.5rem; margin-bottom:2rem; }
    .stat { text-align:center; }
    .stat-value { font-size:2rem; font-weight:700; font-family:'Syne',sans-serif; color:var(--primary); }
    .stat-label { font-size:0.85rem; color:var(--text-secondary); margin-top:0.25rem; }
    h1 { font-family:'Syne',sans-serif; font-size:2rem; margin-bottom:1.5rem; }
    table { width:100%; border-collapse:collapse; background:var(--surface); border-radius:12px; overflow:hidden; }
    th { text-align:left; padding:0.75rem 1rem; color:var(--text-secondary); font-size:0.85rem; border-bottom:1px solid var(--border); }
    td { padding:0.75rem 1rem; font-size:0.9rem; }
    tr:nth-child(even) { background:rgba(30,36,48,0.5); }
    .difficulty-moderate { color:var(--secondary); }
    .difficulty-hard { color:#E84B38; }
  </style>
</head>
<body>
  <nav>
    <a href="/platform/">🥤 Juice Garden</a>
    <a href="/platform/scoreboard/">Scoreboard</a>
  </nav>
  <div class="container">
    <h1>{{ profile_user.username }}</h1>
    <div class="stats-strip">
      <div class="stat">
        <div class="stat-value">{{ profile_user.total_points }}</div>
        <div class="stat-label">Total Points</div>
      </div>
      <div class="stat">
        <div class="stat-value">#{{ rank }}</div>
        <div class="stat-label">Global Rank</div>
      </div>
      <div class="stat">
        <div class="stat-value">{{ solve_data|length }}</div>
        <div class="stat-label">Challenges Solved</div>
      </div>
    </div>
    <table>
      <thead><tr><th scope="col">Challenge</th><th scope="col">Track</th><th scope="col">Difficulty</th><th scope="col">Points</th><th scope="col">Solved At</th></tr></thead>
      <tbody>
        {% for s in solve_data %}
        <tr>
          <td style="font-weight:600">{{ s.code }}: {{ s.title }}</td>
          <td style="color:var(--text-secondary);text-transform:capitalize">{{ s.track }}</td>
          <td class="difficulty-{{ s.difficulty }}">{{ s.difficulty|title }}</td>
          <td style="color:var(--primary)">+{{ s.points }}</td>
          <td style="color:var(--text-secondary);font-size:0.85rem">{{ s.solved_at }}</td>
        </tr>
        {% else %}
        <tr><td colspan="5" style="text-align:center;padding:2rem;color:var(--text-secondary);">No solves yet.</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</body>
</html>"""

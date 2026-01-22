
import os
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, date, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

from flask import (
    Flask, g, render_template, request, redirect, url_for, session, flash, jsonify, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

# ------------------------------------------------------
# Dummy lecture structure (Coursera-style)
# ------------------------------------------------------

COURSE_LECTURES = {
    1: [  # Consultative Selling 101
        {"title": "Introduction to Consultative Selling", "duration": "6 min"},
        {"title": "Understanding Customer Pain Points", "duration": "12 min"},
        {"title": "Asking Powerful Discovery Questions", "duration": "15 min"},
        {"title": "Handling Objections Effectively", "duration": "14 min"},
        {"title": "Course Summary & Action Plan", "duration": "8 min"},
    ],
    2: [  # Pipeline Hygiene & Forecasting
        {"title": "Why Pipeline Hygiene Matters", "duration": "7 min"},
        {"title": "Stages of a Healthy Pipeline", "duration": "10 min"},
        {"title": "Forecasting Best Practices", "duration": "13 min"},
        {"title": "Common Forecasting Mistakes", "duration": "9 min"},
    ],
    3: [  # Customer Excellence Fundamentals
        {"title": "Customer Expectations Today", "duration": "6 min"},
        {"title": "Active Listening Techniques", "duration": "11 min"},
        {"title": "Empathy in Support Conversations", "duration": "10 min"},
        {"title": "Closing the Loop with Customers", "duration": "9 min"},
    ],
    5: [  # Secure Coding Basics
        {"title": "Introduction to Secure Coding", "duration": "8 min"},
        {"title": "Top OWASP Vulnerabilities", "duration": "15 min"},
        {"title": "Secure Authentication Patterns", "duration": "12 min"},
        {"title": "Handling Secrets Safely", "duration": "9 min"},
    ],
}

# ------------------------------------------------------
# Build Coursera-style learner structure
# ------------------------------------------------------

def build_learner_program_view(enrollments, course_lectures):
    programs = {}

    for e in enrollments:
        program_id = e["program_id"]
        course_id = e["course_id"]

        if program_id not in programs:
            programs[program_id] = {
                "program_id": program_id,
                "program_title": e["program_title"],
                "courses": []
            }

        lectures = course_lectures.get(course_id, [])
        total_lectures = len(lectures)

        completed = 1 if e["status"] == "COMPLETED" else 0
        progress = int((completed / 1) * 100) if total_lectures else 0

        programs[program_id]["courses"].append({
            "enrollment_id": e["enrollment_id"],
            "course_id": course_id,
            "course_title": e["course_title"],
            "due_date": e["due_date"],
            "status": e["status"],
            "progress": progress,
            "lectures": lectures
        })

    return list(programs.values())

# --------------------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------------------

APP_NAME = "LearningStat Enterprise Demo"
DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "learningstat_demo.sqlite3")

ROLE_PLATFORM_ADMIN = "PLATFORM_ADMIN"
ROLE_ORG_ADMIN = "ORG_ADMIN"
ROLE_LD_ADMIN = "LD_ADMIN"
ROLE_LD_ANALYST = "LD_ANALYST"
ROLE_FINANCE = "FINANCE"
ROLE_MANAGER = "MANAGER"
ROLE_EXECUTIVE = "EXECUTIVE"
ROLE_LEARNER = "LEARNER"

ALL_ROLES = [
    ROLE_PLATFORM_ADMIN,
    ROLE_ORG_ADMIN,
    ROLE_LD_ADMIN,
    ROLE_LD_ANALYST,
    ROLE_FINANCE,
    ROLE_MANAGER,
    ROLE_EXECUTIVE,
    ROLE_LEARNER,
]


# --------------------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("LEARNINGSTAT_SECRET_KEY", "dev-secret-change-me")
app.config["DB_PATH"] = os.environ.get("LEARNINGSTAT_DB_PATH", DEFAULT_DB_PATH)


# --------------------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    """Get a SQLite connection for this request."""
    if "db" not in g:
        conn = sqlite3.connect(app.config["DB_PATH"])
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception: Optional[BaseException] = None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def query_one(sql: str, params: Tuple = ()) -> Optional[sqlite3.Row]:
    cur = get_db().execute(sql, params)
    row = cur.fetchone()
    cur.close()
    return row


def query_all(sql: str, params: Tuple = ()) -> List[sqlite3.Row]:
    cur = get_db().execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    return rows


def exec_sql(sql: str, params: Tuple = ()) -> int:
    cur = get_db().execute(sql, params)
    get_db().commit()
    last_id = cur.lastrowid
    cur.close()
    return last_id


def exec_many(sql: str, rows: List[Tuple]):
    get_db().executemany(sql, rows)
    get_db().commit()


def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------------------
# Auth + RBAC
# --------------------------------------------------------------------------------------

@dataclass
class UserCtx:
    id: int
    org_id: int
    email: str
    full_name: str
    role: str
    department_id: Optional[int]
    manager_id: Optional[int]


def current_user() -> Optional[UserCtx]:
    uid = session.get("user_id")
    if not uid:
        return None
    row = query_one(
        """
        SELECT id, org_id, email, full_name, role, department_id, manager_id
        FROM users
        WHERE id = ? AND is_active = 1
        """,
        (uid,),
    )
    if not row:
        return None
    return UserCtx(
        id=row["id"],
        org_id=row["org_id"],
        email=row["email"],
        full_name=row["full_name"],
        role=row["role"],
        department_id=row["department_id"],
        manager_id=row["manager_id"],
    )


def current_org() -> Optional[sqlite3.Row]:
    u = current_user()
    if not u:
        return None
    return query_one("SELECT * FROM orgs WHERE id = ?", (u.org_id,))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def role_required(*allowed_roles: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            u = current_user()
            if not u:
                return redirect(url_for("login", next=request.path))
            if u.role not in allowed_roles:
                flash("You do not have access to that page.", "warning")
                return redirect(url_for("home"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


def audit(action: str, entity: str, entity_id: Optional[int] = None, details: Optional[Dict[str, Any]] = None):
    u = current_user()
    if not u:
        return
    exec_sql(
        """
        INSERT INTO audit_log (org_id, user_id, action, entity, entity_id, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (u.org_id, u.id, action, entity, entity_id, json.dumps(details or {}), now_iso()),
    )


# --------------------------------------------------------------------------------------
# Settings + gamification
# --------------------------------------------------------------------------------------

DEFAULT_SETTINGS = {
    "points": {
        "course_completion": 100,
        "assessment_submitted": 50,
        "survey_submitted": 25,
        "manager_observation_submitted": 30,
        "daily_activity_streak": 10,
    }
}


def get_settings(org_id: int) -> Dict[str, Any]:
    row = query_one("SELECT value_json FROM settings WHERE org_id = ? AND key = 'app_settings'", (org_id,))
    if not row:
        return DEFAULT_SETTINGS.copy()
    try:
        data = json.loads(row["value_json"])
        # merge with defaults (so we can add new keys safely)
        merged = DEFAULT_SETTINGS.copy()
        merged.update(data)
        if "points" in data:
            merged["points"].update(data["points"])
        return merged
    except Exception:
        return DEFAULT_SETTINGS.copy()


def save_settings(org_id: int, settings: Dict[str, Any]):
    existing = query_one("SELECT id FROM settings WHERE org_id = ? AND key = 'app_settings'", (org_id,))
    if existing:
        exec_sql("UPDATE settings SET value_json = ? WHERE id = ?", (json.dumps(settings), existing["id"]))
    else:
        exec_sql("INSERT INTO settings (org_id, key, value_json) VALUES (?, 'app_settings', ?)", (org_id, json.dumps(settings)))


def award_points(user_id: int, org_id: int, points: int, reason: str, ref_type: str = "", ref_id: Optional[int] = None):
    if points == 0:
        return
    exec_sql(
        """
        INSERT INTO gamification_points (org_id, user_id, points, reason, created_at, ref_type, ref_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (org_id, user_id, points, reason, now_iso(), ref_type, ref_id),
    )
    maybe_award_badges(user_id, org_id)
    # streak points: if this is first activity today, award streak points.
    maybe_award_streak_points(user_id, org_id)


def total_points(user_id: int, org_id: int) -> int:
    row = query_one(
        "SELECT COALESCE(SUM(points), 0) AS pts FROM gamification_points WHERE org_id = ? AND user_id = ?",
        (org_id, user_id),
    )
    return int(row["pts"]) if row else 0


def get_activity_days(user_id: int, org_id: int, limit: int = 30) -> List[date]:
    rows = query_all(
        """
        SELECT created_at
        FROM gamification_points
        WHERE org_id = ? AND user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (org_id, user_id, limit * 10),
    )
    days = []
    for r in rows:
        try:
            d = datetime.strptime(r["created_at"], "%Y-%m-%d %H:%M:%S").date()
            if d not in days:
                days.append(d)
        except Exception:
            continue
    return days[:limit]


def compute_streak_days(user_id: int, org_id: int) -> int:
    days = set(get_activity_days(user_id, org_id, limit=60))
    if not days:
        return 0
    streak = 0
    today = datetime.utcnow().date()
    # allow streak counting from today or yesterday if no activity yet today
    cursor = today
    if cursor not in days and (cursor - timedelta(days=1)) in days:
        cursor = cursor - timedelta(days=1)
    while cursor in days:
        streak += 1
        cursor = cursor - timedelta(days=1)
    return streak


def maybe_award_streak_points(user_id: int, org_id: int):
    u_settings = get_settings(org_id)
    streak_points = int(u_settings["points"].get("daily_activity_streak", 10))

    today = datetime.utcnow().date().strftime("%Y-%m-%d")
    row = query_one(
        """
        SELECT id FROM gamification_points
        WHERE org_id = ? AND user_id = ? AND reason = 'Daily streak'
          AND substr(created_at, 1, 10) = ?
        """,
        (org_id, user_id, today),
    )
    if row:
        return  # already awarded today

    # Only award streak if there is at least one other activity today besides streak
    row2 = query_one(
        """
        SELECT COUNT(*) AS c FROM gamification_points
        WHERE org_id = ? AND user_id = ? AND substr(created_at, 1, 10) = ?
          AND reason != 'Daily streak'
        """,
        (org_id, user_id, today),
    )
    if row2 and int(row2["c"]) >= 1:
        exec_sql(
            """
            INSERT INTO gamification_points (org_id, user_id, points, reason, created_at, ref_type, ref_id)
            VALUES (?, ?, ?, 'Daily streak', ?, '', NULL)
            """,
            (org_id, user_id, streak_points, now_iso()),
        )


def maybe_award_badges(user_id: int, org_id: int):
    # Simple badge criteria types:
    # - points_total >= X
    # - courses_completed >= X
    # - surveys_submitted >= X
    # - streak_days >= X
    # - avg_assessment_score >= X
    badges = query_all("SELECT * FROM badges WHERE org_id = ?", (org_id,))
    if not badges:
        return
    for b in badges:
        bid = b["id"]
        already = query_one(
            "SELECT 1 FROM user_badges WHERE org_id = ? AND user_id = ? AND badge_id = ?",
            (org_id, user_id, bid),
        )
        if already:
            continue
        try:
            criteria = json.loads(b["criteria_json"] or "{}")
        except Exception:
            criteria = {}
        if badge_criteria_met(user_id, org_id, criteria):
            exec_sql(
                "INSERT INTO user_badges (org_id, user_id, badge_id, earned_at) VALUES (?, ?, ?, ?)",
                (org_id, user_id, bid, now_iso()),
            )


def badge_criteria_met(user_id: int, org_id: int, criteria: Dict[str, Any]) -> bool:
    t = (criteria or {}).get("type")
    threshold = criteria.get("threshold")
    if t == "points_total":
        return total_points(user_id, org_id) >= int(threshold or 0)
    if t == "courses_completed":
        row = query_one(
            """
            SELECT COUNT(*) AS c FROM enrollments
            WHERE org_id = ? AND user_id = ? AND status = 'COMPLETED'
            """,
            (org_id, user_id),
        )
        return int(row["c"]) >= int(threshold or 0)
    if t == "surveys_submitted":
        row = query_one(
            """
            SELECT COUNT(*) AS c FROM survey_responses
            WHERE org_id = ? AND user_id = ?
            """,
            (org_id, user_id),
        )
        return int(row["c"]) >= int(threshold or 0)
    if t == "streak_days":
        return compute_streak_days(user_id, org_id) >= int(threshold or 0)
    if t == "avg_assessment_score":
        row = query_one(
            """
            SELECT AVG(score) AS avg_score FROM assessment_attempts
            WHERE org_id = ? AND user_id = ?
            """,
            (org_id, user_id),
        )
        avg_score = float(row["avg_score"]) if row and row["avg_score"] is not None else 0.0
        return avg_score >= float(threshold or 0)
    return False


def leaderboard(org_id: int, department_id: Optional[int] = None, limit: int = 10) -> List[sqlite3.Row]:
    if department_id:
        return query_all(
            """
            SELECT u.full_name, u.role, d.name AS department, COALESCE(SUM(gp.points), 0) AS pts
            FROM users u
            LEFT JOIN departments d ON d.id = u.department_id
            LEFT JOIN gamification_points gp ON gp.user_id = u.id AND gp.org_id = u.org_id
            WHERE u.org_id = ? AND u.is_active = 1 AND u.department_id = ?
            GROUP BY u.id
            ORDER BY pts DESC, u.full_name ASC
            LIMIT ?
            """,
            (org_id, department_id, limit),
        )
    return query_all(
        """
        SELECT u.full_name, u.role, d.name AS department, COALESCE(SUM(gp.points), 0) AS pts
        FROM users u
        LEFT JOIN departments d ON d.id = u.department_id
        LEFT JOIN gamification_points gp ON gp.user_id = u.id AND gp.org_id = u.org_id
        WHERE u.org_id = ? AND u.is_active = 1
        GROUP BY u.id
        ORDER BY pts DESC, u.full_name ASC
        LIMIT ?
        """,
        (org_id, limit),
    )


# --------------------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------------------

def notify(org_id: int, user_id: int, title: str, body: str, link: str = ""):
    exec_sql(
        """
        INSERT INTO notifications (org_id, user_id, title, body, link, is_read, created_at)
        VALUES (?, ?, ?, ?, ?, 0, ?)
        """,
        (org_id, user_id, title, body, link, now_iso()),
    )


def unread_notifications_count(org_id: int, user_id: int) -> int:
    row = query_one(
        "SELECT COUNT(*) AS c FROM notifications WHERE org_id = ? AND user_id = ? AND is_read = 0",
        (org_id, user_id),
    )
    return int(row["c"]) if row else 0


# --------------------------------------------------------------------------------------
# DB schema + seeding
# --------------------------------------------------------------------------------------

SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS orgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    department_id INTEGER,
    manager_id INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    UNIQUE(org_id, email),
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(department_id) REFERENCES departments(id) ON DELETE SET NULL,
    FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    duration_minutes INTEGER NOT NULL DEFAULT 60,
    created_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    start_date TEXT,
    end_date TEXT,
    owner_user_id INTEGER,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS program_courses (
    program_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    PRIMARY KEY(program_id, course_id),
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
    FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cohorts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    program_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cohort_members (
    cohort_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    PRIMARY KEY(cohort_id, user_id),
    FOREIGN KEY(cohort_id) REFERENCES cohorts(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    program_id INTEGER NOT NULL,
    assigned_at TEXT NOT NULL,
    due_date TEXT,
    status TEXT NOT NULL DEFAULT 'ASSIGNED',
    completed_at TEXT,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    max_score INTEGER NOT NULL DEFAULT 100,
    questions_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assessment_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    assessment_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    attempt_type TEXT NOT NULL, -- PRE or POST
    score REAL NOT NULL,
    taken_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS surveys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    program_id INTEGER NOT NULL,
    survey_type TEXT NOT NULL, -- REACTION / CONFIDENCE
    questions_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS survey_responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    survey_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    responses_json TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(survey_id) REFERENCES surveys(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS manager_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    program_id INTEGER NOT NULL,
    manager_user_id INTEGER NOT NULL,
    learner_user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL, -- 1..5
    notes TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
    FOREIGN KEY(manager_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(learner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS kpis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    unit TEXT NOT NULL,
    description TEXT NOT NULL,
    direction TEXT NOT NULL, -- UP or DOWN
    created_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS kpi_measurements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    kpi_id INTEGER NOT NULL,
    program_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    value REAL NOT NULL,
    source TEXT NOT NULL,
    notes TEXT,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(kpi_id) REFERENCES kpis(id) ON DELETE CASCADE,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS roi_cost_lines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    program_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'INR',
    created_by_user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'DRAFT', -- DRAFT / APPROVED
    approved_by_user_id INTEGER,
    approved_at TEXT,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
    FOREIGN KEY(created_by_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(approved_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS roi_benefit_lines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    program_id INTEGER NOT NULL,
    kpi_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    baseline_value REAL NOT NULL,
    post_value REAL NOT NULL,
    unit_value REAL NOT NULL, -- monetary value per unit improvement
    attribution_pct REAL NOT NULL, -- 0..1
    annualisation_factor REAL NOT NULL DEFAULT 1.0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
    FOREIGN KEY(kpi_id) REFERENCES kpis(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS roi_scenarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    program_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    benefit_multiplier REAL NOT NULL DEFAULT 1.0,
    cost_multiplier REAL NOT NULL DEFAULT 1.0,
    attribution_multiplier REAL NOT NULL DEFAULT 1.0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS gamification_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    points INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    ref_type TEXT,
    ref_id INTEGER,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS badges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    criteria_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(org_id, code),
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_badges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    badge_id INTEGER NOT NULL,
    earned_at TEXT NOT NULL,
    UNIQUE(org_id, user_id, badge_id),
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(badge_id) REFERENCES badges(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    link TEXT,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    entity TEXT NOT NULL,
    entity_id INTEGER,
    details_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    UNIQUE(org_id, key),
    FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
);
"""


def init_db():
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()


def db_has_data() -> bool:
    if not os.path.exists(app.config["DB_PATH"]):
        return False
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute("SELECT COUNT(*) AS c FROM orgs")
        c = cur.fetchone()["c"]
        return c > 0
    except Exception:
        return False
    finally:
        conn.close()


def seed_demo_data():
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")

    def _exec(sql: str, params: Tuple = ()) -> int:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid

    def _execmany(sql: str, rows: List[Tuple]):
        conn.executemany(sql, rows)
        conn.commit()

    # Org
    org_id = _exec(
        "INSERT INTO orgs (name, slug, created_at) VALUES (?, ?, ?)",
        ("ABC Private Limited", "abc-private-limited", now_iso()),
    )

    # Departments
    dept_names = ["Sales", "Customer Support", "Engineering", "HR"]
    dept_ids = {}
    for dn in dept_names:
        dept_ids[dn] = _exec("INSERT INTO departments (org_id, name) VALUES (?, ?)", (org_id, dn))

    # Users
    demo_pw_admin = "Admin123!"
    demo_pw = "Demo123!"

    # Platform org + platform admin (to demonstrate multi-tenant management)
    platform_org_id = _exec(
        "INSERT INTO orgs (name, slug, created_at) VALUES (?, ?, ?)",
        ("LearningStat Platform", "learningstat-platform", now_iso()),
    )
    _exec(
        """
        INSERT INTO users (org_id, email, full_name, password_hash, role, department_id, manager_id, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, NULL, NULL, 1, ?)
        """,
        (platform_org_id, "platform@learningstat.com", "Platform Admin", generate_password_hash(demo_pw_admin), ROLE_PLATFORM_ADMIN, now_iso()),
    )


    # Create executives & admins
    org_admin_id = _exec(
        """
        INSERT INTO users (org_id, email, full_name, password_hash, role, department_id, manager_id, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, NULL, NULL, 1, ?)
        """,
        (org_id, "admin@abc.com", "Asha Admin", generate_password_hash(demo_pw_admin), ROLE_ORG_ADMIN, now_iso()),
    )
    ld_admin_id = _exec(
        """
        INSERT INTO users (org_id, email, full_name, password_hash, role, department_id, manager_id, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL, 1, ?)
        """,
        (org_id, "ld_admin@abc.com", "Liam L&D", generate_password_hash(demo_pw), ROLE_LD_ADMIN, dept_ids["HR"], now_iso()),
    )
    analyst_id = _exec(
        """
        INSERT INTO users (org_id, email, full_name, password_hash, role, department_id, manager_id, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL, 1, ?)
        """,
        (org_id, "analyst@abc.com", "Priya Analyst", generate_password_hash(demo_pw), ROLE_LD_ANALYST, dept_ids["HR"], now_iso()),
    )
    finance_id = _exec(
        """
        INSERT INTO users (org_id, email, full_name, password_hash, role, department_id, manager_id, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL, 1, ?)
        """,
        (org_id, "finance@abc.com", "Farhan Finance", generate_password_hash(demo_pw), ROLE_FINANCE, dept_ids["HR"], now_iso()),
    )
    exec_id = _exec(
        """
        INSERT INTO users (org_id, email, full_name, password_hash, role, department_id, manager_id, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, NULL, NULL, 1, ?)
        """,
        (org_id, "exec@abc.com", "Esha Executive", generate_password_hash(demo_pw), ROLE_EXECUTIVE, now_iso()),
    )

    # Managers for each department (except HR because L&D lives there)
    manager_ids = {}
    for dept in ["Sales", "Customer Support", "Engineering"]:
        manager_ids[dept] = _exec(
            """
            INSERT INTO users (org_id, email, full_name, password_hash, role, department_id, manager_id, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, NULL, 1, ?)
            """,
            (org_id, f"manager_{dept.lower().replace(' ', '')}@abc.com", f"{dept} Manager", generate_password_hash(demo_pw), ROLE_MANAGER, dept_ids[dept], now_iso()),
        )

    # Learners
    learners = []
    # Sales learners
    for i in range(1, 8):
        learners.append(("learner_sales_%02d@abc.com" % i, f"Sales Learner {i:02d}", dept_ids["Sales"], manager_ids["Sales"]))
    # Support learners
    for i in range(1, 6):
        learners.append(("learner_support_%02d@abc.com" % i, f"Support Learner {i:02d}", dept_ids["Customer Support"], manager_ids["Customer Support"]))
    # Engineering learners
    for i in range(1, 6):
        learners.append(("learner_eng_%02d@abc.com" % i, f"Engineering Learner {i:02d}", dept_ids["Engineering"], manager_ids["Engineering"]))

    learner_ids = []
    for email, name, did, mid in learners:
        learner_ids.append(
            _exec(
                """
                INSERT INTO users (org_id, email, full_name, password_hash, role, department_id, manager_id, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (org_id, email, name, generate_password_hash(demo_pw), ROLE_LEARNER, did, mid, now_iso()),
            )
        )

    # Courses
    course_rows = [
        ("Consultative Selling 101", "Core consultative selling behaviours: discovery, value framing, objection handling.", 90),
        ("Pipeline Hygiene & Forecasting", "Build predictable forecasts by improving pipeline discipline and deal reviews.", 60),
        ("Customer Excellence Fundamentals", "Reduce escalations by improving listening, empathy, and resolution skills.", 75),
        ("Quality Assurance Playbook", "Standardise QA checks and reduce rework with practical checklists.", 60),
        ("Secure Coding Basics", "Avoid common security vulnerabilities with practical secure coding patterns.", 80),
        ("Security Incident Response", "How to identify, triage, and escalate incidents effectively.", 60),
        ("Leadership Essentials for Managers", "Coaching, feedback, and driving accountability in teams.", 90),
    ]
    course_ids = {}
    for title, desc, mins in course_rows:
        cid = _exec(
            "INSERT INTO courses (org_id, title, description, duration_minutes, created_at) VALUES (?, ?, ?, ?, ?)",
            (org_id, title, desc, mins, now_iso()),
        )
        course_ids[title] = cid

    # Programs
    today = date.today()
    p1 = _exec(
        """
        INSERT INTO programs (org_id, title, description, start_date, end_date, owner_user_id, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
        """,
        (
            org_id,
            "Q1 Sales Uplift Program",
            "A focused initiative to improve discovery quality and conversion rate through consultative selling.",
            (today - timedelta(days=14)).isoformat(),
            (today + timedelta(days=45)).isoformat(),
            ld_admin_id,
            now_iso(),
        ),
    )
    p2 = _exec(
        """
        INSERT INTO programs (org_id, title, description, start_date, end_date, owner_user_id, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
        """,
        (
            org_id,
            "Support Quality Accelerator",
            "Reduce Average Handle Time and improve CSAT by standardising QA and customer excellence skills.",
            (today - timedelta(days=7)).isoformat(),
            (today + timedelta(days=35)).isoformat(),
            ld_admin_id,
            now_iso(),
        ),
    )
    p3 = _exec(
        """
        INSERT INTO programs (org_id, title, description, start_date, end_date, owner_user_id, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
        """,
        (
            org_id,
            "Security & Compliance Bootcamp",
            "Reduce security incidents through secure coding and response training for engineering teams.",
            (today - timedelta(days=3)).isoformat(),
            (today + timedelta(days=60)).isoformat(),
            ld_admin_id,
            now_iso(),
        ),
    )

    # Program courses
    _execmany(
        "INSERT INTO program_courses (program_id, course_id) VALUES (?, ?)",
        [
            (p1, course_ids["Consultative Selling 101"]),
            (p1, course_ids["Pipeline Hygiene & Forecasting"]),
            (p1, course_ids["Leadership Essentials for Managers"]),
            (p2, course_ids["Customer Excellence Fundamentals"]),
            (p2, course_ids["Quality Assurance Playbook"]),
            (p2, course_ids["Leadership Essentials for Managers"]),
            (p3, course_ids["Secure Coding Basics"]),
            (p3, course_ids["Security Incident Response"]),
        ],
    )

    # Cohorts
    c1 = _exec("INSERT INTO cohorts (org_id, program_id, name, created_at) VALUES (?, ?, ?, ?)", (org_id, p1, "Sales Cohort A", now_iso()))
    c2 = _exec("INSERT INTO cohorts (org_id, program_id, name, created_at) VALUES (?, ?, ?, ?)", (org_id, p2, "Support Cohort A", now_iso()))
    c3 = _exec("INSERT INTO cohorts (org_id, program_id, name, created_at) VALUES (?, ?, ?, ?)", (org_id, p3, "Engineering Cohort A", now_iso()))

    # Cohort members
    # Assign by department
    sales_learners = [lid for lid in learner_ids if conn.execute("SELECT department_id FROM users WHERE id = ?", (lid,)).fetchone()["department_id"] == dept_ids["Sales"]]
    support_learners = [lid for lid in learner_ids if conn.execute("SELECT department_id FROM users WHERE id = ?", (lid,)).fetchone()["department_id"] == dept_ids["Customer Support"]]
    eng_learners = [lid for lid in learner_ids if conn.execute("SELECT department_id FROM users WHERE id = ?", (lid,)).fetchone()["department_id"] == dept_ids["Engineering"]]

    _execmany("INSERT INTO cohort_members (cohort_id, user_id) VALUES (?, ?)", [(c1, uid) for uid in sales_learners])
    _execmany("INSERT INTO cohort_members (cohort_id, user_id) VALUES (?, ?)", [(c2, uid) for uid in support_learners])
    _execmany("INSERT INTO cohort_members (cohort_id, user_id) VALUES (?, ?)", [(c3, uid) for uid in eng_learners])

    # Enrollments: create for each cohort member for each course in program
    def assign_enrollments(program_id: int, cohort_user_ids: List[int], due_in_days: int = 21):
        course_ids_for_program = [r["course_id"] for r in conn.execute("SELECT course_id FROM program_courses WHERE program_id = ?", (program_id,)).fetchall()]
        rows = []
        for uid in cohort_user_ids:
            for cid in course_ids_for_program:
                rows.append((org_id, uid, cid, program_id, now_iso(), (date.today() + timedelta(days=due_in_days)).isoformat(), "ASSIGNED", None))
        _execmany(
            """
            INSERT INTO enrollments (org_id, user_id, course_id, program_id, assigned_at, due_date, status, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    assign_enrollments(p1, sales_learners, due_in_days=20)
    assign_enrollments(p2, support_learners, due_in_days=18)
    assign_enrollments(p3, eng_learners, due_in_days=30)

    # Assessments (simple 3-question quizzes) for a subset of courses
    questions_selling = [
        {"q": "Which question is best for discovery?", "choices": ["What is your budget?", "Tell me about your current process and pain points.", "Can you sign today?"], "answer": 1},
        {"q": "Value framing should focus on…", "choices": ["Features", "Outcomes", "Discounts"], "answer": 1},
        {"q": "An objection is often…", "choices": ["A buying signal", "A reason to end the call", "Always about price"], "answer": 0},
    ]
    questions_support = [
        {"q": "A good first response should include…", "choices": ["Empathy and acknowledgement", "A long explanation", "A transfer"], "answer": 0},
        {"q": "QA checklists help primarily by…", "choices": ["Increasing handle time", "Reducing variance and rework", "Avoiding documentation"], "answer": 1},
        {"q": "To reduce escalations, focus on…", "choices": ["Closing tickets fast", "Clarifying and confirming resolution", "Avoiding tough cases"], "answer": 1},
    ]
    questions_security = [
        {"q": "Which is a common web vulnerability?", "choices": ["SQL Injection", "HDMI", "IPv4"], "answer": 0},
        {"q": "Secrets should be stored…", "choices": ["In code", "In a secrets manager / env vars", "In public docs"], "answer": 1},
        {"q": "Incident response starts with…", "choices": ["Ignoring alerts", "Triage and scope", "Blaming"], "answer": 1},
    ]

    a1 = _exec(
        "INSERT INTO assessments (org_id, course_id, name, max_score, questions_json, created_at) VALUES (?, ?, ?, 100, ?, ?)",
        (org_id, course_ids["Consultative Selling 101"], "Consultative Selling Quiz", json.dumps(questions_selling), now_iso()),
    )
    a2 = _exec(
        "INSERT INTO assessments (org_id, course_id, name, max_score, questions_json, created_at) VALUES (?, ?, ?, 100, ?, ?)",
        (org_id, course_ids["Customer Excellence Fundamentals"], "Customer Excellence Quiz", json.dumps(questions_support), now_iso()),
    )
    a3 = _exec(
        "INSERT INTO assessments (org_id, course_id, name, max_score, questions_json, created_at) VALUES (?, ?, ?, 100, ?, ?)",
        (org_id, course_ids["Secure Coding Basics"], "Secure Coding Quiz", json.dumps(questions_security), now_iso()),
    )

    # Seed pre-assessment attempts (baseline) for learners to make analytics richer
    import random as _random
    pre_rows = []
    for uid in sales_learners:
        pre_rows.append((org_id, a1, uid, "PRE", _random.randint(35, 65), now_iso()))
    for uid in support_learners:
        pre_rows.append((org_id, a2, uid, "PRE", _random.randint(40, 70), now_iso()))
    for uid in eng_learners:
        pre_rows.append((org_id, a3, uid, "PRE", _random.randint(30, 60), now_iso()))
    _execmany(
        """
        INSERT INTO assessment_attempts (org_id, assessment_id, user_id, attempt_type, score, taken_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        pre_rows,
    )

    # Surveys per program
    reaction_qs = [
        {"id": "relevance", "label": "How relevant was this program to your role?", "type": "rating_1_5"},
        {"id": "quality", "label": "How would you rate the quality of the learning experience?", "type": "rating_1_5"},
        {"id": "comment", "label": "One thing you will apply immediately:", "type": "text"},
    ]
    confidence_qs = [
        {"id": "confidence", "label": "How confident are you to apply the skills on the job?", "type": "rating_1_5"},
        {"id": "barrier", "label": "Biggest barrier to applying the learning:", "type": "text"},
    ]
    for pid in [p1, p2, p3]:
        _exec(
            "INSERT INTO surveys (org_id, program_id, survey_type, questions_json, created_at) VALUES (?, ?, 'REACTION', ?, ?)",
            (org_id, pid, json.dumps(reaction_qs), now_iso()),
        )
        _exec(
            "INSERT INTO surveys (org_id, program_id, survey_type, questions_json, created_at) VALUES (?, ?, 'CONFIDENCE', ?, ?)",
            (org_id, pid, json.dumps(confidence_qs), now_iso()),
        )

    # KPIs
    kpi_sales = _exec(
        "INSERT INTO kpis (org_id, name, unit, description, direction, created_at) VALUES (?, ?, ?, ?, 'UP', ?)",
        (org_id, "Sales Conversion Rate", "%", "Percent of qualified opportunities that convert to won.", now_iso()),
    )
    kpi_aht = _exec(
        "INSERT INTO kpis (org_id, name, unit, description, direction, created_at) VALUES (?, ?, ?, ?, 'DOWN', ?)",
        (org_id, "Average Handle Time", "minutes", "Average time to resolve a customer ticket.", now_iso()),
    )
    kpi_incidents = _exec(
        "INSERT INTO kpis (org_id, name, unit, description, direction, created_at) VALUES (?, ?, ?, ?, 'DOWN', ?)",
        (org_id, "Security Incidents", "count", "Number of security incidents per month.", now_iso()),
    )

    # KPI measurements (baseline then post)
    # Put two points for trend charts
    m_rows = []
    # Sales conversion rate baseline ~18%, post ~22%
    m_rows.extend([
        (org_id, kpi_sales, p1, (today - timedelta(days=30)).isoformat(), 18.0, "CRM", "Baseline"),
        (org_id, kpi_sales, p1, (today).isoformat(), 22.0, "CRM", "Post training"),
    ])
    # AHT baseline 14 min, post 12 min
    m_rows.extend([
        (org_id, kpi_aht, p2, (today - timedelta(days=30)).isoformat(), 14.0, "Ticketing", "Baseline"),
        (org_id, kpi_aht, p2, (today).isoformat(), 12.0, "Ticketing", "Post training"),
    ])
    # Incidents baseline 6/month, post 4/month
    m_rows.extend([
        (org_id, kpi_incidents, p3, (today - timedelta(days=30)).isoformat(), 6.0, "Security", "Baseline"),
        (org_id, kpi_incidents, p3, (today).isoformat(), 4.0, "Security", "Post training"),
    ])
    _execmany(
        """
        INSERT INTO kpi_measurements (org_id, kpi_id, program_id, date, value, source, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        m_rows,
    )

    # ROI cost lines (draft; finance can approve in app)
    cost_rows = [
        (org_id, p1, "Vendor/Content", "Sales enablement content license", 120000.0, "INR", ld_admin_id, now_iso(), "DRAFT", None, None),
        (org_id, p1, "Learner Time", "Estimated learner time cost (hrs x rate)", 180000.0, "INR", ld_admin_id, now_iso(), "DRAFT", None, None),
        (org_id, p2, "Facilitation", "Internal facilitation time allocation", 90000.0, "INR", ld_admin_id, now_iso(), "DRAFT", None, None),
        (org_id, p2, "Learner Time", "Estimated learner time cost (hrs x rate)", 110000.0, "INR", ld_admin_id, now_iso(), "DRAFT", None, None),
        (org_id, p3, "Vendor/Content", "Security course bundle", 150000.0, "INR", ld_admin_id, now_iso(), "DRAFT", None, None),
        (org_id, p3, "Learner Time", "Estimated learner time cost (hrs x rate)", 140000.0, "INR", ld_admin_id, now_iso(), "DRAFT", None, None),
    ]
    _execmany(
        """
        INSERT INTO roi_cost_lines (org_id, program_id, category, description, amount, currency, created_by_user_id, created_at, status, approved_by_user_id, approved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        cost_rows,
    )

    # ROI benefit lines (baseline and post, plus unit value and attribution)
    # For sales conversion: Assume improvement 4 percentage points results in additional margin. We'll model benefit as (post-baseline)*unit_value
    benefit_rows = [
        (org_id, p1, kpi_sales, "Improved conversion rate impact (modelled)", 18.0, 22.0, 80000.0, 0.35, 4.0, now_iso()),
        (org_id, p2, kpi_aht, "Reduced AHT time savings (modelled)", 14.0, 12.0, 5000.0, 0.40, 12.0, now_iso()),
        (org_id, p3, kpi_incidents, "Avoided incident cost (modelled)", 6.0, 4.0, 60000.0, 0.30, 12.0, now_iso()),
    ]
    _execmany(
        """
        INSERT INTO roi_benefit_lines (org_id, program_id, kpi_id, description, baseline_value, post_value, unit_value, attribution_pct, annualisation_factor, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        benefit_rows,
    )

    # ROI scenarios
    scen_rows = [
        (org_id, p1, "Conservative", 0.85, 1.00, 0.80, now_iso()),
        (org_id, p1, "Expected", 1.00, 1.00, 1.00, now_iso()),
        (org_id, p1, "Aggressive", 1.15, 1.00, 1.10, now_iso()),
        (org_id, p2, "Conservative", 0.85, 1.00, 0.80, now_iso()),
        (org_id, p2, "Expected", 1.00, 1.00, 1.00, now_iso()),
        (org_id, p2, "Aggressive", 1.15, 1.00, 1.10, now_iso()),
        (org_id, p3, "Conservative", 0.85, 1.00, 0.80, now_iso()),
        (org_id, p3, "Expected", 1.00, 1.00, 1.00, now_iso()),
        (org_id, p3, "Aggressive", 1.15, 1.00, 1.10, now_iso()),
    ]
    _execmany(
        """
        INSERT INTO roi_scenarios (org_id, program_id, name, benefit_multiplier, cost_multiplier, attribution_multiplier, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        scen_rows,
    )

    # Settings
    _exec(
        "INSERT INTO settings (org_id, key, value_json) VALUES (?, 'app_settings', ?)",
        (org_id, json.dumps(DEFAULT_SETTINGS)),
    )

    # Badges
    badge_rows = [
        ("first_steps", "First Steps", "Complete your first course.", {"type": "courses_completed", "threshold": 1}),
        ("feedback_champion", "Feedback Champion", "Submit 5 surveys.", {"type": "surveys_submitted", "threshold": 5}),
        ("consistency_5", "Consistency", "Maintain a 5-day activity streak.", {"type": "streak_days", "threshold": 5}),
        ("high_scorer", "High Scorer", "Maintain an average assessment score of 80+.", {"type": "avg_assessment_score", "threshold": 80}),
        ("point_master_500", "Point Master", "Earn 500 total points.", {"type": "points_total", "threshold": 500}),
    ]
    _execmany(
        """
        INSERT INTO badges (org_id, code, name, description, criteria_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [(org_id, code, name, desc, json.dumps(criteria), now_iso()) for code, name, desc, criteria in badge_rows],
    )

    # Seed a few notifications (to show the feature)
    notify(org_id, exec_id, "Welcome to LearningStat", "Explore your executive dashboard to view program ROI and KPI impact.", "/exec/dashboard")
    notify(org_id, manager_ids["Sales"], "Manager Action Required", "Please submit behaviour observations for your team after they complete the Sales Uplift Program.", "/manager/observations")

    conn.commit()
    conn.close()


# --------------------------------------------------------------------------------------
# Startup: init+seed if needed
# --------------------------------------------------------------------------------------

with app.app_context():
    init_db()
    if not db_has_data():
        seed_demo_data()


# --------------------------------------------------------------------------------------
# Route helpers
# --------------------------------------------------------------------------------------

def dashboard_route_for_role(role: str) -> str:
    return {
        ROLE_ORG_ADMIN: "admin_dashboard",
        ROLE_LD_ADMIN: "ld_dashboard",
        ROLE_LD_ANALYST: "ld_dashboard",
        ROLE_FINANCE: "finance_dashboard",
        ROLE_MANAGER: "manager_dashboard",
        ROLE_EXECUTIVE: "exec_dashboard",
        ROLE_LEARNER: "learner_dashboard",
        ROLE_PLATFORM_ADMIN: "platform_dashboard",
    }.get(role, "home")


def require_org_scope(entity_org_id: int):
    u = current_user()
    if not u:
        return False
    return int(entity_org_id) == int(u.org_id)


# --------------------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------------------

@app.route("/")
def home():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    return redirect(url_for(dashboard_route_for_role(u.role)))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        org_slug = (request.form.get("org_slug") or "").strip().lower()

        # Multi-tenant login: if the same email can exist in multiple organisations,
        # ask for org slug to disambiguate.
        if org_slug:
            candidates = query_all(
                '''
                SELECT u.*, o.name AS org_name, o.slug AS org_slug
                FROM users u
                JOIN orgs o ON o.id = u.org_id
                WHERE u.email = ? AND u.is_active = 1 AND o.slug = ?
                ''',
                (email, org_slug),
            )
        else:
            candidates = query_all(
                '''
                SELECT u.*, o.name AS org_name, o.slug AS org_slug
                FROM users u
                JOIN orgs o ON o.id = u.org_id
                WHERE u.email = ? AND u.is_active = 1
                ''',
                (email,),
            )
            if len(candidates) > 1:
                flash("Multiple organisations found for this email. Please enter the organisation slug.", "warning")
                return render_template("login.html", app_name=APP_NAME, org_choices=candidates)

        row = candidates[0] if candidates else None
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"] = row["id"]
            session["org_id"] = row["org_id"]
            audit("login", "user", row["id"], {"email": email, "org_slug": row["org_slug"] if "org_slug" in row.keys() else None})
            nxt = request.args.get("next")
            return redirect(nxt or url_for("home"))
        flash("Invalid email, password, or organisation.", "danger")
    return render_template("login.html", app_name=APP_NAME)


@app.route("/logout")
@login_required
def logout():
    audit("logout", "user", current_user().id)
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------------------
# Common routes
# --------------------------------------------------------------------------------------

@app.route("/notifications")
@login_required
def notifications():
    u = current_user()
    rows = query_all(
        """
        SELECT * FROM notifications
        WHERE org_id = ? AND user_id = ?
        ORDER BY created_at DESC
        LIMIT 50
        """,
        (u.org_id, u.id),
    )
    # mark read
    exec_sql("UPDATE notifications SET is_read = 1 WHERE org_id = ? AND user_id = ?", (u.org_id, u.id))
    return render_template("notifications.html", user=u, org=current_org(), items=rows)


@app.route("/profile")
@login_required
def profile():
    u = current_user()
    org = current_org()
    pts = total_points(u.id, u.org_id)
    streak = compute_streak_days(u.id, u.org_id)
    badges = query_all(
        """
        SELECT b.name, b.description, ub.earned_at
        FROM user_badges ub
        JOIN badges b ON b.id = ub.badge_id
        WHERE ub.org_id = ? AND ub.user_id = ?
        ORDER BY ub.earned_at DESC
        """,
        (u.org_id, u.id),
    )
    recent = query_all(
        """
        SELECT points, reason, created_at
        FROM gamification_points
        WHERE org_id = ? AND user_id = ?
        ORDER BY created_at DESC
        LIMIT 15
        """,
        (u.org_id, u.id),
    )
    return render_template(
        "profile.html",
        user=u,
        org=org,
        points=pts,
        streak=streak,
        badges=badges,
        recent_points=recent,
    )


# --------------------------------------------------------------------------------------
# Learner experience
# --------------------------------------------------------------------------------------

@app.route("/learner/dashboard")
@login_required
@role_required(ROLE_LEARNER)
def learner_dashboard():
    u = current_user()
    org = current_org()

    pts = total_points(u.id, u.org_id)
    streak = compute_streak_days(u.id, u.org_id)
    unread = unread_notifications_count(u.org_id, u.id)

    # -------------------------------
    # Continue Learning (not completed)
    # -------------------------------
    in_progress = query_all(
        """
        SELECT
            e.id AS enrollment_id,
            e.status,
            e.due_date,
            c.title AS course_title,
            p.title AS program_title
        FROM enrollments e
        JOIN courses c ON c.id = e.course_id
        JOIN programs p ON p.id = e.program_id
        WHERE e.org_id = ?
          AND e.user_id = ?
          AND e.status != 'COMPLETED'
        ORDER BY e.due_date ASC
        """,
        (u.org_id, u.id),
    )

    # -------------------------------
    # ALL Enrolled Courses (FIX)
    # -------------------------------
    all_enrollments = query_all(
        """
        SELECT
            e.id AS enrollment_id,
            e.status,
            e.due_date,
            c.title AS course_title,
            p.title AS program_title
        FROM enrollments e
        JOIN courses c ON c.id = e.course_id
        JOIN programs p ON p.id = e.program_id
        WHERE e.org_id = ?
          AND e.user_id = ?
        ORDER BY p.title, c.title
        """,
        (u.org_id, u.id),
    )

    # -------------------------------
    # Completion summary
    # -------------------------------
    summary = query_one(
        """
        SELECT
            SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) AS completed,
            COUNT(*) AS total
        FROM enrollments
        WHERE org_id = ? AND user_id = ?
        """,
        (u.org_id, u.id),
    )

    completed = int(summary["completed"] or 0)
    total = int(summary["total"] or 0)
    completion_rate = round((completed / total) * 100, 1) if total else 0.0

    return render_template(
        "learner_dashboard.html",
        user=u,
        org=org,
        points=pts,
        streak=streak,
        unread=unread,
        in_progress=in_progress,
        all_enrollments=all_enrollments,
        completed=completed,
        total=total,
        completion_rate=completion_rate,
    )


@app.route("/learner/catalog")
@login_required
@role_required(ROLE_LEARNER)
def learner_catalog():
    u = current_user()
    org = current_org()
    items = query_all(
        """
        SELECT e.id AS enrollment_id, e.status, e.due_date, c.*, p.title AS program_title, p.id AS program_id
        FROM enrollments e
        JOIN courses c ON c.id = e.course_id
        JOIN programs p ON p.id = e.program_id
        WHERE e.org_id = ? AND e.user_id = ?
        ORDER BY (CASE e.status WHEN 'COMPLETED' THEN 2 ELSE 1 END), e.due_date ASC
        """,
        (u.org_id, u.id),
    )
    return render_template("learner_catalog.html", user=u, org=org, items=items)


@app.route("/learner/course/<int:enrollment_id>")
@login_required
@role_required(ROLE_LEARNER)
def learner_course(enrollment_id: int):
    u = current_user()
    org = current_org()
    e = query_one(
        """
        SELECT e.*, c.title, c.description, c.duration_minutes, p.title AS program_title, p.id AS program_id
        FROM enrollments e
        JOIN courses c ON c.id = e.course_id
        JOIN programs p ON p.id = e.program_id
        WHERE e.id = ? AND e.org_id = ? AND e.user_id = ?
        """,
        (enrollment_id, u.org_id, u.id),
    )
    if not e:
        flash("Course not found.", "warning")
        return redirect(url_for("learner_catalog"))

    assessment = query_one(
        "SELECT * FROM assessments WHERE org_id = ? AND course_id = ?",
        (u.org_id, e["course_id"]),
    )
    # Survey for program
    survey_reaction = query_one(
        "SELECT * FROM surveys WHERE org_id = ? AND program_id = ? AND survey_type = 'REACTION'",
        (u.org_id, e["program_id"]),
    )
    survey_conf = query_one(
        "SELECT * FROM surveys WHERE org_id = ? AND program_id = ? AND survey_type = 'CONFIDENCE'",
        (u.org_id, e["program_id"]),
    )
    # check if already responded
    has_reaction = False
    has_conf = False
    if survey_reaction:
        has_reaction = query_one(
            "SELECT 1 FROM survey_responses WHERE org_id = ? AND survey_id = ? AND user_id = ?",
            (u.org_id, survey_reaction["id"], u.id),
        ) is not None
    if survey_conf:
        has_conf = query_one(
            "SELECT 1 FROM survey_responses WHERE org_id = ? AND survey_id = ? AND user_id = ?",
            (u.org_id, survey_conf["id"], u.id),
        ) is not None

    # assessment attempts
    pre = post = None
    if assessment:
        pre = query_one(
            """
            SELECT * FROM assessment_attempts
            WHERE org_id = ? AND assessment_id = ? AND user_id = ? AND attempt_type = 'PRE'
            ORDER BY taken_at DESC LIMIT 1
            """,
            (u.org_id, assessment["id"], u.id),
        )
        post = query_one(
            """
            SELECT * FROM assessment_attempts
            WHERE org_id = ? AND assessment_id = ? AND user_id = ? AND attempt_type = 'POST'
            ORDER BY taken_at DESC LIMIT 1
            """,
            (u.org_id, assessment["id"], u.id),
        )

    return render_template(
        "learner_course.html",
        user=u,
        org=org,
        enrollment=e,
        assessment=assessment,
        pre_attempt=pre,
        post_attempt=post,
        survey_reaction=survey_reaction,
        survey_conf=survey_conf,
        has_reaction=has_reaction,
        has_conf=has_conf,
    )


@app.route("/learner/course/<int:enrollment_id>/complete", methods=["POST"])
@login_required
@role_required(ROLE_LEARNER)
def learner_complete_course(enrollment_id: int):
    u = current_user()
    e = query_one(
        "SELECT * FROM enrollments WHERE id = ? AND org_id = ? AND user_id = ?",
        (enrollment_id, u.org_id, u.id),
    )
    if not e:
        flash("Course not found.", "warning")
        return redirect(url_for("learner_catalog"))
    if e["status"] == "COMPLETED":
        flash("Already completed.", "info")
        return redirect(url_for("learner_course", enrollment_id=enrollment_id))

    exec_sql(
        "UPDATE enrollments SET status = 'COMPLETED', completed_at = ? WHERE id = ?",
        (now_iso(), enrollment_id),
    )
    audit("complete_course", "enrollment", enrollment_id, {"course_id": e["course_id"]})

    settings = get_settings(u.org_id)
    pts = int(settings["points"].get("course_completion", 100))
    award_points(u.id, u.org_id, pts, "Course completion", "enrollment", enrollment_id)

    # notify manager to submit observation (optional)
    if u.manager_id:
        notify(u.org_id, u.manager_id, "Observation requested", f"Please submit a behaviour observation for {u.full_name}.", "/manager/observations")

    flash(f"Course marked complete. +{pts} points!", "success")
    return redirect(url_for("learner_course", enrollment_id=enrollment_id))


@app.route("/learner/assessment/<int:assessment_id>/<attempt_type>", methods=["GET", "POST"])
@login_required
@role_required(ROLE_LEARNER)
def learner_assessment(assessment_id: int, attempt_type: str):
    u = current_user()
    attempt_type = attempt_type.upper()
    if attempt_type not in ["PRE", "POST"]:
        flash("Invalid attempt type.", "warning")
        return redirect(url_for("learner_dashboard"))

    assessment = query_one("SELECT * FROM assessments WHERE id = ? AND org_id = ?", (assessment_id, u.org_id))
    if not assessment:
        flash("Assessment not found.", "warning")
        return redirect(url_for("learner_dashboard"))

    questions = json.loads(assessment["questions_json"] or "[]")

    if request.method == "POST":
        score = 0
        for idx, q in enumerate(questions):
            ans = request.form.get(f"q{idx}")
            if ans is not None and ans.isdigit() and int(ans) == int(q.get("answer")):
                score += 1
        max_score = len(questions) or 1
        pct = round((score / max_score) * 100.0, 1)

        exec_sql(
            """
            INSERT INTO assessment_attempts (org_id, assessment_id, user_id, attempt_type, score, taken_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (u.org_id, assessment_id, u.id, attempt_type, pct, now_iso()),
        )
        audit("submit_assessment", "assessment", assessment_id, {"attempt_type": attempt_type, "score": pct})

        settings = get_settings(u.org_id)
        pts = int(settings["points"].get("assessment_submitted", 50))
        award_points(u.id, u.org_id, pts, "Assessment submitted", "assessment", assessment_id)

        flash(f"Assessment submitted. Score: {pct}%. +{pts} points!", "success")
        return redirect(url_for("learner_dashboard"))

    return render_template(
        "learner_assessment.html",
        user=u,
        org=current_org(),
        assessment=assessment,
        attempt_type=attempt_type,
        questions=questions,
    )


@app.route("/learner/survey/<int:survey_id>", methods=["GET", "POST"])
@login_required
@role_required(ROLE_LEARNER)
def learner_survey(survey_id: int):
    u = current_user()
    survey = query_one("SELECT * FROM surveys WHERE id = ? AND org_id = ?", (survey_id, u.org_id))
    if not survey:
        flash("Survey not found.", "warning")
        return redirect(url_for("learner_dashboard"))

    already = query_one(
        "SELECT 1 FROM survey_responses WHERE org_id = ? AND survey_id = ? AND user_id = ?",
        (u.org_id, survey_id, u.id),
    )
    if already:
        flash("You already submitted this survey.", "info")
        return redirect(url_for("learner_dashboard"))

    questions = json.loads(survey["questions_json"] or "[]")

    if request.method == "POST":
        resp = {}
        for q in questions:
            qid = q.get("id")
            if not qid:
                continue
            resp[qid] = request.form.get(qid, "")
        exec_sql(
            """
            INSERT INTO survey_responses (org_id, survey_id, user_id, responses_json, submitted_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (u.org_id, survey_id, u.id, json.dumps(resp), now_iso()),
        )
        audit("submit_survey", "survey", survey_id, {"survey_type": survey["survey_type"]})

        settings = get_settings(u.org_id)
        pts = int(settings["points"].get("survey_submitted", 25))
        award_points(u.id, u.org_id, pts, "Survey submitted", "survey", survey_id)

        flash(f"Thanks for your feedback! +{pts} points.", "success")
        return redirect(url_for("learner_dashboard"))

    return render_template(
        "learner_survey.html",
        user=u,
        org=current_org(),
        survey=survey,
        questions=questions,
    )

@app.route("/learner/programs")
@login_required
@role_required(ROLE_LEARNER)
def learner_programs():
    u = current_user()

    programs = query_all(
        """
        SELECT
            p.id AS program_id,
            p.title AS program_title,
            p.description,
            COUNT(e.id) AS total_courses,
            SUM(CASE WHEN e.status = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_courses,
            ROUND(
                100.0 * SUM(CASE WHEN e.status = 'COMPLETED' THEN 1 ELSE 0 END)
                / COUNT(e.id), 1
            ) AS completion_pct
        FROM enrollments e
        JOIN programs p ON p.id = e.program_id
        WHERE e.org_id = ?
          AND e.user_id = ?
        GROUP BY p.id, p.title, p.description
        ORDER BY p.title
        """,
        (u.org_id, u.id),
    )

    return render_template(
        "learner_programs.html",
        programs=programs,
    )
    
@app.route("/learner/program/<int:program_id>")
@login_required
@role_required(ROLE_LEARNER)
def learner_program_detail(program_id):
    u = current_user()

    program = query_one(
        """
        SELECT id, title, description
        FROM programs
        WHERE id = ? AND org_id = ?
        """,
        (program_id, u.org_id),
    )

    if not program:
        abort(404)

    courses = query_all(
        """
        SELECT
            e.id AS enrollment_id,
            c.title AS course_title,
            c.description,
            e.status,
            e.due_date
        FROM enrollments e
        JOIN courses c ON c.id = e.course_id
        WHERE e.program_id = ?
          AND e.user_id = ?
          AND e.org_id = ?
        ORDER BY c.title
        """,
        (program_id, u.id, u.org_id),
    )

    return render_template(
        "learner_program_detail.html",
        program=program,
        courses=courses,
    )

# --------------------------------------------------------------------------------------
# MANAGER DASHBOARD + DRILL-DOWN LOOP (FINAL, STABLE)
# --------------------------------------------------------------------------------------

@app.route("/manager/dashboard")
@login_required
@role_required(ROLE_MANAGER)
def manager_dashboard():
    u = current_user()

    team = query_all(
        """
        SELECT id, full_name, email
        FROM users
        WHERE org_id = ? AND manager_id = ? AND is_active = 1
        ORDER BY full_name
        """,
        (u.org_id, u.id),
    )

    team_ids = [t["id"] for t in team] or [-1]

    stats = query_one(
        f"""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status='COMPLETED' THEN 1 ELSE 0 END) AS completed
        FROM enrollments
        WHERE org_id = ?
          AND user_id IN ({",".join(["?"] * len(team_ids))})
        """,
        tuple([u.org_id] + team_ids),
    )

    total = stats["total"] or 0
    completed = stats["completed"] or 0
    completion_rate = round((completed / total) * 100, 1) if total else 0

    course_health = query_all(
        f"""
        SELECT
            c.id AS course_id,
            c.title AS course_title,
            COUNT(DISTINCT e.user_id) AS learners,
            ROUND(
                100.0 * SUM(CASE WHEN e.status='COMPLETED' THEN 1 ELSE 0 END)
                / COUNT(e.id), 1
            ) AS completion_pct
        FROM enrollments e
        JOIN courses c ON c.id = e.course_id
        JOIN users u ON u.id = e.user_id
        WHERE e.org_id = ?
          AND u.manager_id = ?
        GROUP BY c.id, c.title
        ORDER BY completion_pct ASC
        """,
        (u.org_id, u.id),
    )

    overdue = query_all(
        """
        SELECT u.full_name, c.title AS course_title, e.due_date, e.id AS enrollment_id
        FROM enrollments e
        JOIN users u ON u.id = e.user_id
        JOIN courses c ON c.id = e.course_id
        WHERE e.org_id = ?
          AND u.manager_id = ?
          AND e.status != 'COMPLETED'
          AND e.due_date IS NOT NULL
          AND date(e.due_date) < date('now')
        """,
        (u.org_id, u.id),
    )

    return render_template(
        "manager_dashboard.html",
        team=team,
        total=total,
        completed=completed,
        completion_rate=completion_rate,
        course_health=course_health,
        overdue=overdue,
    )

# --------------------------------------------------------------------------------------
# VIEW LEARNERS INSIDE A COURSE
# --------------------------------------------------------------------------------------

@app.route("/manager/course/<int:course_id>")
@login_required
@role_required(ROLE_MANAGER)
def manager_course(course_id):
    u = current_user()

    learners = query_all(
        """
        SELECT
            u.id AS user_id,
            u.full_name,
            e.status,
            e.due_date,
            e.completed_at,
            e.id AS enrollment_id
        FROM enrollments e
        JOIN users u ON u.id = e.user_id
        WHERE e.course_id = ?
          AND u.manager_id = ?
          AND e.org_id = ?
        ORDER BY u.full_name
        """,
        (course_id, u.id, u.org_id),
    )

    course = query_one(
        "SELECT id, title FROM courses WHERE id = ? AND org_id = ?",
        (course_id, u.org_id),
    )

    if not course:
        abort(404)

    return render_template(
        "manager_course.html",
        course=course,
        learners=learners,
    )


# --------------------------------------------------------------------------------------
# VIEW SINGLE LEARNER PROGRESS (COURSE LEVEL)
# --------------------------------------------------------------------------------------

@app.route("/manager/learner/<int:learner_id>/course/<int:course_id>")
@login_required
@role_required(ROLE_MANAGER)
def manager_learner_progress(learner_id, course_id):
    u = current_user()

    learner = query_one(
        """
        SELECT id, full_name
        FROM users
        WHERE id = ? AND manager_id = ? AND org_id = ?
        """,
        (learner_id, u.id, u.org_id),
    )

    if not learner:
        abort(404)

    enrollment = query_one(
        """
        SELECT status, due_date, completed_at
        FROM enrollments
        WHERE user_id = ? AND course_id = ? AND org_id = ?
        """,
        (learner_id, course_id, u.org_id),
    )

    course = query_one(
        "SELECT id, title FROM courses WHERE id = ? AND org_id = ?",
        (course_id, u.org_id),
    )

    return render_template(
        "manager_learner_progress.html",
        learner=learner,
        course=course,
        enrollment=enrollment,
    )


# --------------------------------------------------------------------------------------
# NUDGE SINGLE ENROLLMENT
# --------------------------------------------------------------------------------------

@app.route("/manager/nudge/<int:enrollment_id>", methods=["POST"])
@login_required
@role_required(ROLE_MANAGER)
def manager_nudge(enrollment_id):
    u = current_user()

    e = query_one(
        """
        SELECT e.user_id, u.full_name
        FROM enrollments e
        JOIN users u ON u.id = e.user_id
        WHERE e.id = ? AND u.manager_id = ? AND e.org_id = ?
        """,
        (enrollment_id, u.id, u.org_id),
    )

    if not e:
        abort(404)

    notify(
        u.org_id,
        e["user_id"],
        "Reminder from your manager",
        "Please continue your assigned learning.",
        "/learner/catalog",
    )

    flash("Nudge sent successfully.", "success")
    return redirect(request.referrer or url_for("manager_dashboard"))


# --------------------------------------------------------------------------------------
# BULK NUDGE (OVERDUE)
# --------------------------------------------------------------------------------------

@app.route("/manager/bulk-nudge", methods=["POST"])
@login_required
@role_required(ROLE_MANAGER)
def manager_bulk_nudge():
    u = current_user()

    learners = query_all(
        """
        SELECT DISTINCT u.id
        FROM enrollments e
        JOIN users u ON u.id = e.user_id
        WHERE u.manager_id = ?
          AND e.org_id = ?
          AND e.status != 'COMPLETED'
          AND e.due_date IS NOT NULL
          AND date(e.due_date) < date('now')
        """,
        (u.id, u.org_id),
    )

    for l in learners:
        notify(
            u.org_id,
            l["id"],
            "Reminder from your manager",
            "You have overdue learning tasks.",
            "/learner/dashboard",
        )

    flash(f"Nudged {len(learners)} learners.", "success")
    return redirect(url_for("manager_dashboard"))

# --------------------------------------------------------------------------------------
# L&D DASHBOARD + PROGRAM ANALYTICS (CLEAN FINAL VERSION)
# --------------------------------------------------------------------------------------

from typing import Dict, Any, Optional
from flask import abort

# --------------------------------------------------------------------------------------
# L&D DASHBOARD
# --------------------------------------------------------------------------------------

@app.route("/ld/dashboard")
@login_required
@role_required(ROLE_LD_ADMIN, ROLE_LD_ANALYST)
def ld_dashboard():
    u = current_user()
    org = current_org()

    programs = query_all(
        """
        SELECT p.*, u.full_name AS owner_name
        FROM programs p
        LEFT JOIN users u ON u.id = p.owner_user_id
        WHERE p.org_id = ?
        ORDER BY p.created_at DESC
        """,
        (u.org_id,),
    )

    adoption = query_one(
        """
        SELECT
            COUNT(DISTINCT user_id) AS learners_engaged,
            SUM(CASE WHEN status='COMPLETED' THEN 1 ELSE 0 END) AS completed,
            COUNT(*) AS total
        FROM enrollments
        WHERE org_id = ?
        """,
        (u.org_id,),
    )

    learners_engaged = int(adoption["learners_engaged"] or 0)
    completed = int(adoption["completed"] or 0)
    total = int(adoption["total"] or 0)
    completion_rate = round((completed / total) * 100, 1) if total else 0

    return render_template(
        "ld_dashboard.html",
        user=u,
        org=org,
        programs=programs,
        learners_engaged=learners_engaged,
        completed=completed,
        total=total,
        completion_rate=completion_rate,
    )


# --------------------------------------------------------------------------------------
# PROGRAM METRICS (HELPER — SAFE)
# --------------------------------------------------------------------------------------

def program_metrics(org_id: int, program_id: int) -> Dict[str, Any]:
    enr = query_one(
        """
        SELECT
            COUNT(DISTINCT user_id) AS learners,
            SUM(CASE WHEN status='COMPLETED' THEN 1 ELSE 0 END) AS completed,
            COUNT(*) AS total
        FROM enrollments
        WHERE org_id = ? AND program_id = ?
        """,
        (org_id, program_id),
    )

    learners = int(enr["learners"] or 0)
    completed = int(enr["completed"] or 0)
    total = int(enr["total"] or 0)
    completion_rate = round((completed / total) * 100, 1) if total else 0

    obs = query_one(
        """
        SELECT ROUND(AVG(rating),1) AS avg_rating, COUNT(*) AS cnt
        FROM manager_observations
        WHERE org_id = ? AND program_id = ?
        """,
        (org_id, program_id),
    )

    return {
        "learners": learners,
        "completed": completed,
        "total": total,
        "completion_rate": completion_rate,
        "obs_avg": obs["avg_rating"] if obs and obs["avg_rating"] is not None else "—",
        "obs_cnt": obs["cnt"] if obs else 0,
    }


# --------------------------------------------------------------------------------------
# ROI HELPERS (UNCHANGED, SAFE)
# --------------------------------------------------------------------------------------

def compute_benefit_amount(
    baseline: float,
    post: float,
    direction: str,
    unit_value: float,
    annualisation_factor: float,
    attribution_pct: float,
) -> float:
    delta = (post - baseline)
    if direction == "DOWN":
        delta = (baseline - post)
    raw = delta * unit_value
    return max(0.0, raw * annualisation_factor * attribution_pct)


def roi_summary(org_id: int, program_id: int, scenario_id: Optional[int] = None):
    # -------------------------------
    # COSTS
    # -------------------------------
    costs = query_all(
        """
        SELECT amount, status
        FROM roi_cost_lines
        WHERE org_id = ? AND program_id = ?
        """,
        (org_id, program_id),
    )

    approved_cost = sum(float(c["amount"]) for c in costs if c["status"] == "APPROVED")
    draft_cost = sum(float(c["amount"]) for c in costs if c["status"] != "APPROVED")

    # -------------------------------
    # BENEFITS (BASE)
    # -------------------------------
    benefits = query_all(
        """
        SELECT b.*, k.direction
        FROM roi_benefit_lines b
        JOIN kpis k ON k.id = b.kpi_id
        WHERE b.org_id = ? AND b.program_id = ?
        """,
        (org_id, program_id),
    )

    base_benefit = 0.0
    for r in benefits:
        baseline = float(r["baseline_value"])
        post = float(r["post_value"])
        unit_value = float(r["unit_value"])
        attribution = float(r["attribution_pct"])
        annualisation = float(r["annualisation_factor"])
        direction = r["direction"]

        delta = (post - baseline)
        if direction == "DOWN":
            delta = (baseline - post)

        benefit = max(0.0, delta * unit_value * attribution * annualisation)
        base_benefit += benefit

    # -------------------------------
    # SCENARIO MULTIPLIERS
    # -------------------------------
    benefit_mult = 1.0
    cost_mult = 1.0
    attrib_mult = 1.0
    scenario_name = "Expected"

    if scenario_id:
        scenario = query_one(
            """
            SELECT *
            FROM roi_scenarios
            WHERE id = ? AND org_id = ? AND program_id = ?
            """,
            (scenario_id, org_id, program_id),
        )

        if scenario:
            scenario_name = scenario["name"]
            benefit_mult = float(scenario["benefit_multiplier"])
            cost_mult = float(scenario["cost_multiplier"])
            attrib_mult = float(scenario["attribution_multiplier"])

    # -------------------------------
    # APPLY MULTIPLIERS
    # -------------------------------
    benefit_amt = base_benefit * benefit_mult * attrib_mult
    cost_amt = approved_cost * cost_mult

    net = benefit_amt - cost_amt

    roi_pct = (net / cost_amt * 100.0) if cost_amt > 0 else None
    bcr = (benefit_amt / cost_amt) if cost_amt > 0 else None
    payback_months = (cost_amt / (benefit_amt / 12.0)) if benefit_amt > 0 else None

    return {
        "scenario": scenario_name,
        "approved_cost": round(approved_cost, 2),
        "draft_cost": round(draft_cost, 2),
        "benefit": round(benefit_amt, 2),
        "net_benefit": round(net, 2),
        "roi_pct": round(roi_pct, 2) if roi_pct is not None else None,
        "bcr": round(bcr, 2) if bcr is not None else None,
        "payback_months": round(payback_months, 1) if payback_months else None,
    }
    


# --------------------------------------------------------------------------------------
# L&D PROGRAM ANALYTICS (SINGLE ROUTE — NO COLLISIONS)
# --------------------------------------------------------------------------------------

@app.route("/ld/program/<int:program_id>", endpoint="ld_program_view")
@login_required
@role_required(ROLE_LD_ADMIN, ROLE_LD_ANALYST)
def ld_program_view(program_id):
    u = current_user()

    program = query_one(
        "SELECT * FROM programs WHERE id = ? AND org_id = ?",
        (program_id, u.org_id),
    )
    if not program:
        abort(404)

    learners = query_all(
        """
        SELECT
            u.id AS user_id,
            u.full_name,
            ROUND(
                100.0 * SUM(CASE WHEN e.status='COMPLETED' THEN 1 ELSE 0 END)
                / COUNT(e.id), 1
            ) AS completion_pct
        FROM enrollments e
        JOIN users u ON u.id = e.user_id
        WHERE e.program_id = ?
        GROUP BY u.id, u.full_name
        ORDER BY completion_pct ASC
        """,
        (program_id,),
    )

    assessment_stats = query_all(
        """
        SELECT
            a.name,
            ROUND(AVG(CASE WHEN aa.attempt_type='PRE' THEN aa.score END),1) AS pre_avg,
            ROUND(AVG(CASE WHEN aa.attempt_type='POST' THEN aa.score END),1) AS post_avg
        FROM assessments a
        JOIN assessment_attempts aa ON aa.assessment_id = a.id
        WHERE a.course_id IN (
            SELECT course_id FROM program_courses WHERE program_id = ?
        )
        GROUP BY a.id, a.name
        """,
        (program_id,),
    )

    survey_stats = query_all(
        """
        SELECT s.survey_type, COUNT(r.id) AS responses
        FROM surveys s
        LEFT JOIN survey_responses r ON r.survey_id = s.id
        WHERE s.program_id = ?
        GROUP BY s.survey_type
        """,
        (program_id,),
    )

    behaviour_row = query_one(
        """
        SELECT ROUND(AVG(rating),1) AS avg_rating, COUNT(*) AS count
        FROM manager_observations
        WHERE program_id = ?
        """,
        (program_id,),
    )

    behaviour = {
        "avg_rating": behaviour_row["avg_rating"] if behaviour_row and behaviour_row["avg_rating"] is not None else "—",
        "count": behaviour_row["count"] if behaviour_row else 0,
    }

    return render_template(
        "ld_program.html",
        program=program,
        learners=learners,
        assessment_stats=assessment_stats,
        survey_stats=survey_stats,
        behaviour=behaviour,
    )

@app.route("/exec/dashboard")
@login_required
@role_required(ROLE_EXECUTIVE)
def exec_dashboard():
    u = current_user()
    org = current_org()

    # -------------------------
    # PROGRAM LIST
    # -------------------------
    programs = query_all(
        "SELECT id, title FROM programs WHERE org_id = ? ORDER BY created_at DESC",
        (u.org_id,)
    )

    roi_rows = []
    total_benefit = 0.0
    total_cost = 0.0

    for p in programs:
        r = roi_summary(u.org_id, p["id"], None)

        benefit = float(r["benefit"] or 0)
        cost = float(r["approved_cost"] or 0)

        total_benefit += benefit
        total_cost += cost

        roi_rows.append({
            "program_id": p["id"],
            "title": p["title"],
            "benefit": benefit,
            "cost": cost,
            "net_benefit": benefit - cost,
            "roi_pct": r["roi_pct"],
            "bcr": r["bcr"],
            "payback_months": r["payback_months"]
        })

    # -------------------------
    # ENTERPRISE ROI
    # -------------------------
    enterprise_net = total_benefit - total_cost

    enterprise_roi = {
        "benefit": round(total_benefit, 0),
        "cost": round(total_cost, 0),
        "net_benefit": round(enterprise_net, 0),
        "roi_pct": round((enterprise_net / total_cost) * 100, 1) if total_cost > 0 else None,
        "bcr": round(total_benefit / total_cost, 2) if total_cost > 0 else None,
        "payback_months": round((total_cost / (total_benefit / 12)), 1) if total_benefit > 0 else None,
    }

    # -------------------------
    # ADOPTION
    # -------------------------
    adoption = query_one(
        """
        SELECT
            COUNT(DISTINCT user_id) AS learners,
            SUM(CASE WHEN status='COMPLETED' THEN 1 ELSE 0 END) AS completed,
            COUNT(*) AS total
        FROM enrollments
        WHERE org_id = ?
        """,
        (u.org_id,)
    )

    learners_engaged = int(adoption["learners"] or 0)
    completed = int(adoption["completed"] or 0)
    total = int(adoption["total"] or 0)
    completion_rate = round((completed / total) * 100, 1) if total else 0.0

    # -------------------------
    # BEHAVIOUR
    # -------------------------
    behaviour_row = query_one(
        "SELECT ROUND(AVG(rating),1) AS avg_rating FROM manager_observations WHERE org_id = ?",
        (u.org_id,)
    )

    avg_rating = behaviour_row["avg_rating"] if behaviour_row and behaviour_row["avg_rating"] is not None else None

    # -------------------------
    # RISK
    # -------------------------
    at_risk_count = sum(
        1 for r in roi_rows if r["roi_pct"] is not None and r["roi_pct"] < 0
    )

    return render_template(
        "exec_dashboard.html",
        user=u,
        org=org,
        enterprise_roi=enterprise_roi,
        learners_engaged=learners_engaged,
        adoption={"completion_rate": completion_rate},
        behaviour={"avg_rating": avg_rating},
        risk={"at_risk_programs": at_risk_count},
        programs=roi_rows
    )

# --------------------------------------------------------------------------------------
# FINANCE DASHBOARD + ROI GOVERNANCE (FINAL, FIXED)
# --------------------------------------------------------------------------------------

from flask import abort, request, redirect, url_for, flash
from typing import Optional


# -----------------------------------------
# FINANCE DASHBOARD
# -----------------------------------------

@app.route("/finance/dashboard")
@login_required
@role_required(ROLE_FINANCE)
def finance_dashboard():
    u = current_user()

    programs = query_all(
        """
        SELECT
            p.id,
            p.title,
            SUM(CASE WHEN c.status = 'PENDING' THEN c.amount ELSE 0 END) AS pending_cost,
            SUM(CASE WHEN c.status = 'APPROVED' THEN c.amount ELSE 0 END) AS approved_cost
        FROM programs p
        LEFT JOIN roi_cost_lines c ON c.program_id = p.id
        WHERE p.org_id = ?
        GROUP BY p.id, p.title
        ORDER BY p.title
        """,
        (u.org_id,),
    )

    totals = query_one(
        """
        SELECT
            SUM(CASE WHEN status='APPROVED' THEN amount ELSE 0 END) AS approved_cost,
            SUM(CASE WHEN status='PENDING' THEN amount ELSE 0 END) AS pending_cost,
            COUNT(DISTINCT program_id) AS programs
        FROM roi_cost_lines
        WHERE org_id = ?
        """,
        (u.org_id,),
    ) or {}

    return render_template(
        "finance_dashboard.html",
        programs=programs,
        total_approved=float(totals["approved_cost"] or 0),
        total_pending=float(totals["pending_cost"] or 0),
        programs_count=int(totals["programs"] or 0),
    )


# -----------------------------------------
# FINANCE PROGRAM REVIEW (DEFAULT SCENARIO)
# -----------------------------------------

@app.route("/finance/program/<int:program_id>")
@login_required
@role_required(ROLE_FINANCE)
def finance_program_view(program_id):
    return _finance_program(program_id, None)


@app.route("/finance/program/<int:program_id>/scenario/<int:scenario_id>")
@login_required
@role_required(ROLE_FINANCE)
def finance_program_scenario(program_id, scenario_id):
    return _finance_program(program_id, scenario_id)


def _finance_program(program_id, scenario_id):
    u = current_user()

    program = query_one(
        "SELECT * FROM programs WHERE id = ? AND org_id = ?",
        (program_id, u.org_id),
    )
    if not program:
        abort(404)

    roi = roi_summary(u.org_id, program_id, scenario_id)

    costs = query_all(
        """
        SELECT *
        FROM roi_cost_lines
        WHERE org_id = ? AND program_id = ?
        ORDER BY created_at
        """,
        (u.org_id, program_id),
    )

    scenarios = query_all(
        """
        SELECT *
        FROM roi_scenarios
        WHERE org_id = ? AND program_id = ?
        ORDER BY name
        """,
        (u.org_id, program_id),
    )

    return render_template(
        "finance_program.html",
        program=program,
        roi=roi,
        costs=costs,
        scenarios=scenarios,
        active_scenario=scenario_id,
    )


# -----------------------------------------
# APPROVE / REJECT COST LINE
# -----------------------------------------

@app.route("/finance/cost/<int:cost_id>/<action>", methods=["POST"])
@login_required
@role_required(ROLE_FINANCE)
def finance_cost_action(cost_id, action):
    u = current_user()

    if action not in ("approve", "reject"):
        abort(400)

    status = "APPROVED" if action == "approve" else "REJECTED"

    cost = query_one(
        "SELECT * FROM roi_cost_lines WHERE id = ? AND org_id = ?",
        (cost_id, u.org_id),
    )
    if not cost:
        abort(404)

    exec_sql(
        """
        UPDATE roi_cost_lines
        SET status = ?, reviewed_by = ?, reviewed_at = ?
        WHERE id = ?
        """,
        (status, u.id, now_iso(), cost_id),
    )

    exec_sql(
        """
        INSERT INTO finance_audit_log
        (org_id, program_id, cost_id, action, actor_user_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (u.org_id, cost["program_id"], cost_id, status, u.id, now_iso()),
    )

    flash(f"Cost {status.lower()} successfully.", "success")
    return redirect(request.referrer or url_for("finance_dashboard"))

# --------------------------------------------------------------------------------------
# Org admin (users + settings)
# --------------------------------------------------------------------------------------

@app.route("/admin/dashboard")
@login_required
@role_required(ROLE_ORG_ADMIN)
def admin_dashboard():
    u = current_user()
    org = current_org()

    user_count = query_one("SELECT COUNT(*) AS c FROM users WHERE org_id = ? AND is_active = 1", (u.org_id,))["c"]
    dept_count = query_one("SELECT COUNT(*) AS c FROM departments WHERE org_id = ?", (u.org_id,))["c"]

    return render_template("admin_dashboard.html", user=u, org=org, user_count=user_count, dept_count=dept_count)


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@role_required(ROLE_ORG_ADMIN)
def admin_users():
    u = current_user()
    org = current_org()

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        full_name = (request.form.get("full_name") or "").strip()
        role = request.form.get("role")
        dept_id = request.form.get("department_id")
        dept_id = int(dept_id) if dept_id and dept_id.isdigit() else None
        password = request.form.get("password") or "Demo123!"
        manager_id = request.form.get("manager_id")
        manager_id = int(manager_id) if manager_id and manager_id.isdigit() else None

        if role not in ALL_ROLES:
            flash("Invalid role.", "warning")
        elif not email or not full_name:
            flash("Email and full name are required.", "warning")
        else:
            try:
                new_id = exec_sql(
                    """
                    INSERT INTO users (org_id, email, full_name, password_hash, role, department_id, manager_id, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (u.org_id, email, full_name, generate_password_hash(password), role, dept_id, manager_id, now_iso()),
                )
                audit("create_user", "users", new_id, {"email": email, "role": role})
                flash("User created.", "success")
            except sqlite3.IntegrityError:
                flash("That email already exists for this organisation.", "warning")

        return redirect(url_for("admin_users"))

    users = query_all(
        """
        SELECT u.id, u.full_name, u.email, u.role, u.is_active, d.name AS department, m.full_name AS manager_name
        FROM users u
        LEFT JOIN departments d ON d.id = u.department_id
        LEFT JOIN users m ON m.id = u.manager_id
        WHERE u.org_id = ?
        ORDER BY u.created_at DESC
        """,
        (u.org_id,),
    )
    depts = query_all("SELECT id, name FROM departments WHERE org_id = ? ORDER BY name", (u.org_id,))
    managers = query_all("SELECT id, full_name FROM users WHERE org_id = ? AND role = 'MANAGER' ORDER BY full_name", (u.org_id,))
    return render_template("admin_users.html", user=u, org=org, users=users, depts=depts, roles=ALL_ROLES, managers=managers)

@app.route("/admin/users/<int:user_id>/update", methods=["POST"])
@login_required
@role_required(ROLE_ORG_ADMIN)
def admin_user_update(user_id):
    u = current_user()
    org = current_org()

    email = (request.form.get("email") or "").strip().lower()
    full_name = (request.form.get("full_name") or "").strip()
    role = request.form.get("role")
    dept_id = request.form.get("department_id")
    dept_id = int(dept_id) if dept_id and dept_id.isdigit() else None
    manager_id = request.form.get("manager_id")
    manager_id = int(manager_id) if manager_id and manager_id.isdigit() else None
    is_active = 1 if request.form.get("active") == "on" else 0

    if role not in ALL_ROLES:
        flash("Invalid role selected.", "warning")
        return redirect(url_for("admin_users"))

    if not email or not full_name:
        flash("Email and full name are required.", "warning")
        return redirect(url_for("admin_users"))

    exec_sql(
        """
        UPDATE users
        SET email = ?,
            full_name = ?,
            role = ?,
            department_id = ?,
            manager_id = ?,
            is_active = ?
        WHERE id = ? AND org_id = ?
        """,
        (email, full_name, role, dept_id, manager_id, is_active, user_id, u.org_id),
    )

    audit(
        "update_user",
        "users",
        user_id,
        {
            "email": email,
            "role": role,
            "department_id": dept_id,
            "manager_id": manager_id,
            "is_active": is_active,
        },
    )

    flash("User updated successfully.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/toggle_active", methods=["POST"])
@login_required
@role_required(ROLE_ORG_ADMIN)
def admin_user_toggle_active(user_id):
    u = current_user()

    user = query_one(
        "SELECT id, is_active FROM users WHERE id = ? AND org_id = ?",
        (user_id, u.org_id),
    )

    if not user:
        flash("User not found.", "warning")
        return redirect(url_for("admin_users"))

    new_status = 0 if user["is_active"] else 1

    exec_sql(
        "UPDATE users SET is_active = ? WHERE id = ? AND org_id = ?",
        (new_status, user_id, u.org_id),
    )

    audit(
        "toggle_user_active",
        "users",
        user_id,
        {"is_active": new_status},
    )

    if new_status:
        flash("User activated.", "success")
    else:
        flash("User deactivated.", "warning")

    return redirect(url_for("admin_users"))

@app.route("/admin/settings", methods=["GET", "POST"])
@login_required
@role_required(ROLE_ORG_ADMIN)
def admin_settings():
    u = current_user()
    org = current_org()
    settings = get_settings(u.org_id)

    if request.method == "POST":
        try:
            # Update points rules
            settings["points"]["course_completion"] = int(request.form.get("course_completion") or settings["points"]["course_completion"])
            settings["points"]["assessment_submitted"] = int(request.form.get("assessment_submitted") or settings["points"]["assessment_submitted"])
            settings["points"]["survey_submitted"] = int(request.form.get("survey_submitted") or settings["points"]["survey_submitted"])
            settings["points"]["manager_observation_submitted"] = int(request.form.get("manager_observation_submitted") or settings["points"]["manager_observation_submitted"])
            settings["points"]["daily_activity_streak"] = int(request.form.get("daily_activity_streak") or settings["points"]["daily_activity_streak"])
            save_settings(u.org_id, settings)
            audit("update_settings", "settings", None, {"points": settings["points"]})
            flash("Settings updated.", "success")
        except Exception:
            flash("Invalid settings values.", "warning")
        return redirect(url_for("admin_settings"))

    return render_template("admin_settings.html", user=u, org=org, settings=settings)


# --------------------------------------------------------------------------------------
# Platform dashboard (optional for multi-org demos)
# --------------------------------------------------------------------------------------

@app.route("/platform/dashboard")
@login_required
@role_required(ROLE_PLATFORM_ADMIN)
def platform_dashboard():
    u = current_user()
    orgs = query_all("SELECT * FROM orgs ORDER BY created_at DESC")
    return render_template("platform_dashboard.html", user=u, org=current_org(), orgs=orgs)

@app.route("/platform/create_org", methods=["GET", "POST"])
@login_required
@role_required(ROLE_PLATFORM_ADMIN)
def platform_create_org():
    if request.method == "POST":

        # ✅ DEBUG (TEMPORARY)
        print("FORM DATA:", request.form)

        org_name = (request.form.get("org_name") or "").strip()
        org_slug = (request.form.get("org_slug") or "").strip().lower()
        admin_email = (request.form.get("admin_email") or "").strip().lower()
        admin_password = request.form.get("admin_password") or "Admin123!"

        if not org_name or not org_slug or not admin_email:
            flash("All fields are required.", "warning")
            return redirect(url_for("platform_create_org"))

        try:
            # 1️⃣ Create organisation
            org_id = exec_sql(
                """
                INSERT INTO orgs (name, slug, created_at, is_active)
                VALUES (?, ?, ?, 1)
                """,
                (org_name, org_slug, now_iso()),
            )

            # 2️⃣ Create initial ORG ADMIN user
            exec_sql(
                """
                INSERT INTO users (org_id, email, full_name, password_hash, role, is_active, created_at)
                VALUES (?, ?, ?, ?, 'ORG_ADMIN', 1, ?)
                """,
                (
                    org_id,
                    admin_email,
                    "Organisation Admin",
                    generate_password_hash(admin_password),
                    now_iso(),
                ),
            )

            audit(
                "create_org",
                "orgs",
                org_id,
                {"name": org_name, "slug": org_slug},
            )

            flash("Organisation created successfully.", "success")
            return redirect(url_for("platform_dashboard"))

        except sqlite3.IntegrityError as e:
            print("DB ERROR:", e)  # optional debug
            flash("Organisation slug or admin email already exists.", "warning")
            return redirect(url_for("platform_create_org"))

    return render_template("platform_create_org.html")

# --------------------------------------------------------------------------------------
# Platform admin – organisation governance
# --------------------------------------------------------------------------------------

@app.route("/platform/org/<int:org_id>/update", methods=["POST"])
@login_required
@role_required(ROLE_PLATFORM_ADMIN)
def platform_org_update(org_id):
    name = (request.form.get("name") or "").strip()
    slug = (request.form.get("slug") or "").strip().lower()

    if not name or not slug:
        flash("Organisation name and slug are required.", "warning")
        return redirect(url_for("platform_dashboard"))

    exec_sql(
        """
        UPDATE orgs
        SET name = ?, slug = ?
        WHERE id = ?
        """,
        (name, slug, org_id),
    )

    audit("update_org", "orgs", org_id, {"name": name, "slug": slug})
    flash("Organisation updated.", "success")
    return redirect(url_for("platform_dashboard"))


@app.route("/platform/org/<int:org_id>/toggle_active", methods=["POST"])
@login_required
@role_required(ROLE_PLATFORM_ADMIN)
def platform_org_toggle_active(org_id):
    org = query_one(
        "SELECT id, is_active FROM orgs WHERE id = ?",
        (org_id,),
    )

    if not org:
        flash("Organisation not found.", "warning")
        return redirect(url_for("platform_dashboard"))

    new_status = 0 if org["is_active"] else 1

    exec_sql(
        "UPDATE orgs SET is_active = ? WHERE id = ?",
        (new_status, org_id),
    )

    audit(
        "toggle_org_active",
        "orgs",
        org_id,
        {"is_active": new_status},
    )

    if new_status:
        flash("Organisation activated.", "success")
    else:
        flash("Organisation deactivated.", "warning")

    return redirect(url_for("platform_dashboard"))

# --------------------------------------------------------------------------------------
# API endpoints for charts (simple JSON)
# --------------------------------------------------------------------------------------

@app.route("/api/program/<int:program_id>/completion_funnel")
@login_required
def api_completion_funnel(program_id: int):
    u = current_user()
    # Scope: only within org
    p = query_one("SELECT id, org_id FROM programs WHERE id = ?", (program_id,))
    if not p or not require_org_scope(p["org_id"]):
        return jsonify({"error": "not found"}), 404

    rows = query_one(
        """
        SELECT
          SUM(CASE WHEN status='ASSIGNED' THEN 1 ELSE 0 END) AS assigned,
          SUM(CASE WHEN status='COMPLETED' THEN 1 ELSE 0 END) AS completed,
          COUNT(*) AS total
        FROM enrollments WHERE org_id = ? AND program_id = ?
        """,
        (u.org_id, program_id),
    )
    assigned = int(rows["total"] or 0)
    completed = int(rows["completed"] or 0)
    in_progress = assigned - completed
    return jsonify({"assigned": assigned, "in_progress": in_progress, "completed": completed})


@app.route("/api/exec/roi")
@login_required
def api_exec_roi():
    u = current_user()
    if u.role not in [ROLE_EXECUTIVE, ROLE_LD_ADMIN, ROLE_LD_ANALYST, ROLE_ORG_ADMIN]:
        return jsonify({"error": "forbidden"}), 403
    programs = query_all("SELECT id, title FROM programs WHERE org_id = ? ORDER BY created_at DESC", (u.org_id,))
    data = []
    for p in programs:
        s = roi_summary(u.org_id, p["id"], None)
        data.append({"program": p["title"], "roi_pct": s["roi_pct"] or 0.0, "benefit": s["benefit"], "cost": s["approved_cost"]})
    return jsonify(data)


# --------------------------------------------------------------------------------------
# Jinja globals
# --------------------------------------------------------------------------------------

@app.context_processor
def inject_globals():
    u = current_user()
    if not u:
        return {}
    return {
        "APP_NAME": APP_NAME,
        "current_user": u,
        "current_org": current_org(),
        "current_points": total_points(u.id, u.org_id),
        "current_streak": compute_streak_days(u.id, u.org_id),
        "unread_notifications": unread_notifications_count(u.org_id, u.id),
    }


# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(debug=True, host="0.0.0.0", port=port)

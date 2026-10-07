"""SINCET – AI-Based Smart Attendance & Student Performance Monitoring System.

Three completely separate portals (separate login pages AND separate session cookies):
  /student/login  -> Student portal
  /faculty/login  -> Faculty portal
  /<secret slug>  -> Admin portal login (never linked anywhere, see .admin_path / ADMIN_LOGIN_PATH)

Attendance is marked with a rotating, time-limited class code + optional GPS geo-fence +
device binding.  No camera, no face recognition, no extra hardware.
"""
import csv
import hashlib
import hmac
import io
import json
import logging
import math
import os
import re
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
from functools import wraps

from flask.sessions import SecureCookieSessionInterface
from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db
from db import DatabaseError, IntegrityViolation

BASE = os.path.dirname(os.path.abspath(__file__))
log = logging.getLogger("sincet")
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)


def _secret_key():
    env = os.getenv("SECRET_KEY")
    if env:
        return env
    path = os.path.join(BASE, ".secret_key")
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(secrets.token_hex(32))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    with open(path) as fh:
        return fh.read().strip()


def _admin_slug():
    """Secret URL of the admin login. Not linked from any page."""
    env = os.getenv("ADMIN_LOGIN_PATH", "").strip().strip("/")
    if not env:
        path = os.path.join(BASE, ".admin_path")
        if not os.path.exists(path):
            with open(path, "w") as fh:
                fh.write("console-" + secrets.token_urlsafe(12))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        with open(path) as fh:
            env = fh.read().strip()
    if env.split("/")[0] in ("admin", "student", "faculty", "static", "login", ""):
        raise SystemExit("ADMIN_LOGIN_PATH must not be admin/student/faculty/static/login.")
    return env


ADMIN_SLUG = _admin_slug()
ADMIN_IPS = {ip.strip() for ip in os.getenv("ADMIN_ALLOWED_IPS", "").split(",") if ip.strip()}
CODE_STEP = 30          # the class code changes every 30 seconds
MAX_WRONG_CODES = 5     # wrong codes allowed per student per minute
AI_AUTO = 90            # confidence needed for the AI engine to mark Present by itself
AI_REVIEW = 60          # between this and AI_AUTO the case goes to the faculty review queue
PERSIST_SECONDS = 60    # steady presence needed for the full persistence score
BEACON_GAP = 8          # minimum seconds between two presence beacons of one student


def _now_ts():
    return time.time()
SESSION_TIMEOUT_MIN = int(os.getenv("SESSION_TIMEOUT_MIN", "15"))
app.config.update(
    SECRET_KEY=_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",  # set 1 behind HTTPS
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

def portal_of(path):
    if path.startswith("/admin") or path == "/" + ADMIN_SLUG:
        return "admin"
    if path.startswith("/faculty"):
        return "faculty"
    return "student"


class PortalSessions(SecureCookieSessionInterface):
    """One cookie per portal, so a student, a faculty member and the admin can be signed in
    at the same time in the same browser without ever sharing a session."""

    def get_cookie_name(self, app):
        return "sincet_" + portal_of(request.path)


app.session_interface = PortalSessions()

DEPARTMENTS = [
    ("AIDS", "AI & DS"), ("AIML", "AI & ML"), ("CSE", "CSE"),
    ("EEE", "EEE"), ("MECH", "Mechanical"), ("IT", "IT"),
]
ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
HASH_METHOD = "pbkdf2:sha256:200000"
MAX_BATCH = 100
LOCK_AFTER = 5
LOCK_MINUTES = 5
ATT_THRESHOLD = 75.0
EXAMS = ["Internal 1", "Internal 2", "Model Exam", "Semester"]

app.teardown_appcontext(db.close_db)


# --------------------------------------------------------------------------- helpers
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today():
    return date.today().isoformat()


def is_api():
    return "/api/" in request.path or request.path.endswith("/ping") \
        or request.headers.get("X-Requested-With") == "fetch"


def audit(action, detail=""):
    try:
        db.insert(
            "INSERT INTO audit_log (actor, action, detail, created_at) VALUES (%s,%s,%s,%s)",
            (session.get("username", "-"), action, detail[:250], now()),
        )
    except DatabaseError:
        log.exception("audit failed")


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.context_processor
def inject():
    role = session.get("role")
    return dict(
        logout_url=lambda: url_for("logout_" + role) if role else url_for("landing"),
        password_url=lambda: url_for("password_" + role) if role else url_for("landing"),
        portal=portal_of(request.path),
        timeout_seconds=SESSION_TIMEOUT_MIN * 60,
        cur=dict(role=session.get("role"), name=session.get("name"),
                 username=session.get("username")),
        year=datetime.now().year,
    )


@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(self)"
    if request.path.startswith(("/admin", "/faculty", "/student")) or request.path == "/" \
            or request.path == "/" + ADMIN_SLUG:
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.before_request
def guard():
    # the admin portal does not exist for anyone outside the allow-list
    if ADMIN_IPS and portal_of(request.path) == "admin" and request.remote_addr not in ADMIN_IPS:
        abort(404)
    # CSRF for state-changing requests
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not sent or not secrets.compare_digest(str(sent), str(session.get("csrf", ""))):
            if is_api():
                return jsonify(ok=False, error="Security token expired. Refresh the page."), 400
            flash("Your session expired. Please try again.", "error")
            return redirect(request.referrer or url_for("landing"))
    # idle session timeout
    if session.get("role"):
        last = session.get("last_seen", 0)
        if time.time() - last > SESSION_TIMEOUT_MIN * 60:
            role = session.get("role")
            session.clear()
            if is_api():
                return jsonify(ok=False, error="Session timed out", timeout=True), 401
            flash("Session timed out due to inactivity. Please sign in again.", "error")
            return redirect(login_url(role))
        session["last_seen"] = time.time()
        session.permanent = False


def login_url(role):
    return url_for({"admin": "admin_login", "faculty": "faculty_login"}.get(role, "student_login"))


def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            role = session.get("role")
            if role not in roles:
                if "admin" in roles:
                    abort(404)          # the admin portal is invisible to everybody else
                if not role:
                    if is_api():
                        return jsonify(ok=False, error="Please sign in"), 401
                    return redirect(login_url(portal_of(request.path)))
                if is_api():
                    return jsonify(ok=False, error="You do not have permission for this action"), 403
                abort(403)
            if session.get("must_change") and not (request.endpoint or "").startswith(("password_", "logout_")):
                return redirect(url_for("password_" + role))
            finalize_expired()
            return fn(*a, **kw)
        return wrapper
    return deco


@app.errorhandler(DatabaseError)
def db_error(exc):
    log.error("Database error: %s", exc)
    msg = "The database is currently unavailable. Please try again shortly."
    if isinstance(exc, IntegrityViolation):
        msg = "That change conflicts with existing data (duplicate or in use)."
    if is_api():
        return jsonify(ok=False, error=msg), 500
    return render_template("error.html", code=500, title="Database problem", message=msg), 500


@app.errorhandler(403)
def e403(_e):
    if is_api():
        return jsonify(ok=False, error="Forbidden"), 403
    return render_template("error.html", code=403, title="Access denied",
                           message="Your account does not have access to this area."), 403


@app.errorhandler(404)
def e404(_e):
    if is_api():
        return jsonify(ok=False, error="Not found"), 404
    return render_template("error.html", code=404, title="Page not found",
                           message="The page you requested does not exist."), 404


@app.errorhandler(413)
def e413(_e):
    return jsonify(ok=False, error="Request too large"), 413


def bad(msg, code=400):
    return jsonify(ok=False, error=msg), code


# --------------------------------------------------------------------------- passwords
LOWER = "abcdefghijkmnopqrstuvwxyz"
UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
DIGITS = "23456789"
SYMBOLS = "@#$%&*!?"


def gen_password(length=10):
    rng = secrets.SystemRandom()
    chars = [secrets.choice(UPPER), secrets.choice(LOWER), secrets.choice(DIGITS), secrets.choice(SYMBOLS)]
    pool = LOWER + UPPER + DIGITS + SYMBOLS
    chars += [secrets.choice(pool) for _ in range(length - 5)]
    rng.shuffle(chars)
    return secrets.choice(UPPER + LOWER) + "".join(chars)  # always starts with a letter


def hash_pw(pw):
    return generate_password_hash(pw, method=HASH_METHOD)


def password_problem(pw):
    if len(pw) < 8:
        return "Password must be at least 8 characters."
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw)):
        return "Use upper-case, lower-case and a digit."
    if len(pw) > 72:
        return "Password is too long."
    return None


_DUMMY = generate_password_hash("not-a-real-password", method=HASH_METHOD)


# --------------------------------------------------------------------------- bootstrap
def bootstrap():
    db.init_db()
    with app.app_context():
        for code, name in DEPARTMENTS:
            db.execute("INSERT IGNORE INTO departments (code, name) VALUES (%s,%s)", (code, name))
        if not db.query_one("SELECT id FROM admins LIMIT 1"):
            pw = os.getenv("ADMIN_PASSWORD") or gen_password(14)
            db.insert(
                "INSERT INTO admins (username, password_hash, full_name, created_at) VALUES (%s,%s,%s,%s)",
                (ADMIN_USER, hash_pw(pw), "System Administrator", now()),
            )
            print("\n" + "=" * 62)
            print(f" FIRST RUN - admin account created: {ADMIN_USER}")
            if not os.getenv("ADMIN_PASSWORD"):
                print(f" Generated password (shown only once): {pw}")
            print("=" * 62)


# --------------------------------------------------------------------------- auth
def authenticate(table, username, password):
    """Returns (row, error). Same message for unknown user / wrong password."""
    generic = "Invalid username or password."
    row = db.query_one(f"SELECT * FROM {table} WHERE username=%s", (username,))
    if not row:
        check_password_hash(_DUMMY, password)  # equalise timing
        return None, generic
    if row.get("locked_until") and row["locked_until"] > now():
        return None, f"Too many failed attempts. Try again after {row['locked_until'][11:16]}."
    if not check_password_hash(row["password_hash"], password):
        fails = row["failed_attempts"] + 1
        locked = None
        if fails >= LOCK_AFTER:
            locked = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
            fails = 0
        db.execute(f"UPDATE {table} SET failed_attempts=%s, locked_until=%s WHERE id=%s",
                   (fails, locked, row["id"]))
        return None, generic
    if table == "users" and row["status"] != "active":
        return None, "This account is deactivated. Contact the Administrator."
    db.execute(f"UPDATE {table} SET failed_attempts=0, locked_until=NULL, last_login=%s WHERE id=%s",
               (now(), row["id"]))
    return row, None


def start_session(role, row):
    session.clear()
    session["role"] = role
    session["uid"] = row["id"]
    session["username"] = row["username"]
    session["name"] = row.get("full_name") or row.get("name")
    session["last_seen"] = time.time()
    session["must_change"] = bool(row.get("must_change_password", 0)) if role != "admin" else False
    csrf_token()


def home_for(role):
    return {"admin": "admin_dashboard", "faculty": "faculty_dashboard",
            "student": "student_dashboard"}.get(role, "login")


@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/login")
def login_redirect():
    return redirect(url_for("landing"))


def _user_login(role):
    if session.get("role") == role:
        return redirect(url_for(home_for(role)))
    if request.method == "POST":
        username = request.form.get("username", "").strip().upper()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Enter both username and password.", "error")
        else:
            row, err = authenticate("users", username, password)
            if err:
                flash(err, "error")
            elif row["role"] != role:
                other = "faculty" if role == "student" else "student"
                flash(f"This is the {role.title()} login. {other.title()} accounts must sign in from the "
                      f"{other.title()} portal.", "error")
            else:
                start_session(role, row)
                return redirect(url_for("password_" + role) if session["must_change"]
                                else url_for(home_for(role)))
    return render_template("login.html", portal=role)


@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    return _user_login("student")


@app.route("/faculty/login", methods=["GET", "POST"])
def faculty_login():
    return _user_login("faculty")


@app.route("/" + ADMIN_SLUG, methods=["GET", "POST"])
def admin_login():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Enter both username and password.", "error")
        else:
            row, err = authenticate("admins", username, password)
            if err:
                flash(err, "error")
            else:
                start_session("admin", row)
                audit("admin_login")
                return redirect(url_for("admin_dashboard"))
    return render_template("login.html", portal="admin")


def _logout(portal):
    if session.get("role") not in (portal, None):
        abort(404)
    timeout = request.args.get("timeout")
    session.clear()
    flash("Session timed out due to inactivity." if timeout else "You have been signed out.",
          "error" if timeout else "ok")
    return redirect(login_url(portal))


def _ping(portal):
    if session.get("role") != portal:
        return jsonify(ok=False), 401
    return jsonify(ok=True)  # guard() already refreshed last_seen


def _password(portal):
    role = session.get("role")
    if role != portal:
        return redirect(login_url(portal)) if portal != "admin" else abort(404)
    table = "admins" if role == "admin" else "users"
    if request.method == "POST":
        old = request.form.get("old_password", "")
        new = request.form.get("new_password", "")
        conf = request.form.get("confirm_password", "")
        row = db.query_one(f"SELECT * FROM {table} WHERE id=%s", (session["uid"],))
        problem = password_problem(new)
        if not row or not check_password_hash(row["password_hash"], old):
            flash("Current password is incorrect.", "error")
        elif new != conf:
            flash("New passwords do not match.", "error")
        elif problem:
            flash(problem, "error")
        elif check_password_hash(row["password_hash"], new):
            flash("Choose a password different from the current one.", "error")
        else:
            if table == "admins":
                db.execute("UPDATE admins SET password_hash=%s WHERE id=%s", (hash_pw(new), row["id"]))
            else:
                db.execute("UPDATE users SET password_hash=%s, must_change_password=0 WHERE id=%s",
                           (hash_pw(new), row["id"]))
            session["must_change"] = False
            audit("password_changed")
            flash("Password updated successfully.", "ok")
            return redirect(url_for(home_for(role)))
    return render_template("password.html", forced=session.get("must_change"))


for _p in ("student", "faculty", "admin"):
    app.add_url_rule(f"/{_p}/logout", f"logout_{_p}", lambda _p=_p: _logout(_p))
    app.add_url_rule(f"/{_p}/ping", f"ping_{_p}", lambda _p=_p: _ping(_p), methods=["POST"])
    app.add_url_rule(f"/{_p}/password", f"password_{_p}", lambda _p=_p: _password(_p),
                     methods=["GET", "POST"])


# =========================================================================== ADMIN
@app.route("/admin")
@app.route("/admin/dashboard")
@role_required("admin")
def admin_dashboard():
    return render_template("admin/dashboard.html", active="dashboard")


def student_stats():
    """Per-student attendance + marks aggregates."""
    att = db.query(
        "SELECT u.id, u.username, u.name, d.code AS dept, "
        "SUM(CASE WHEN a.status='Present' THEN 1 ELSE 0 END) AS p, COUNT(a.id) AS t "
        "FROM users u JOIN departments d ON d.id=u.department_id "
        "LEFT JOIN attendance a ON a.student_id=u.id "
        "WHERE u.role='student' AND u.status='active' "
        "GROUP BY u.id, u.username, u.name, d.code")
    mk = {r["student_id"]: r for r in db.query(
        "SELECT student_id, SUM(marks) AS got, SUM(max_marks) AS mx FROM marks GROUP BY student_id")}
    out = []
    for r in att:
        pct = round(100.0 * (r["p"] or 0) / r["t"], 1) if r["t"] else None
        m = mk.get(r["id"])
        mp = round(100.0 * m["got"] / m["mx"], 1) if m and m["mx"] else None
        reasons = []
        if pct is not None and pct < ATT_THRESHOLD:
            reasons.append(f"Attendance {pct}%")
        if mp is not None and mp < 40:
            reasons.append(f"Marks {mp}%")
        out.append(dict(r, pct=pct, marks_pct=mp, reasons=reasons))
    return out


@app.route("/admin/api/stats")
@role_required("admin")
def api_stats():
    students = db.query_one("SELECT COUNT(*) AS c FROM users WHERE role='student'")["c"]
    faculty = db.query_one("SELECT COUNT(*) AS c FROM users WHERE role='faculty'")["c"]
    depts = db.query_one("SELECT COUNT(*) AS c FROM departments")["c"]
    td = db.query("SELECT status, COUNT(*) AS c FROM attendance WHERE att_date=%s GROUP BY status", (today(),))
    tmap = {r["status"]: r["c"] for r in td}
    tot = db.query_one("SELECT COUNT(*) AS t, SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) AS p FROM attendance")
    avg = round(100.0 * (tot["p"] or 0) / tot["t"], 1) if tot["t"] else 0
    ss = student_stats()
    risk = sorted([s for s in ss if s["reasons"]], key=lambda s: (s["pct"] if s["pct"] is not None else 101))

    by_dept = db.query(
        "SELECT d.code, SUM(CASE WHEN a.status='Present' THEN 1 ELSE 0 END) AS p, COUNT(a.id) AS t "
        "FROM departments d LEFT JOIN users u ON u.department_id=d.id AND u.role='student' "
        "LEFT JOIN attendance a ON a.student_id=u.id GROUP BY d.code ORDER BY d.code")
    since = (date.today() - timedelta(days=13)).isoformat()
    trend_rows = db.query(
        "SELECT att_date, SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) AS p, COUNT(*) AS t "
        "FROM attendance WHERE att_date>=%s GROUP BY att_date ORDER BY att_date", (since,))
    tr = {r["att_date"]: r for r in trend_rows}
    days = [(date.today() - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    trend = [round(100.0 * tr[d]["p"] / tr[d]["t"], 1) if d in tr and tr[d]["t"] else None for d in days]
    acc = db.query(
        "SELECT d.code, SUM(CASE WHEN u.role='student' THEN 1 ELSE 0 END) AS s, "
        "SUM(CASE WHEN u.role='faculty' THEN 1 ELSE 0 END) AS f "
        "FROM departments d LEFT JOIN users u ON u.department_id=d.id GROUP BY d.code ORDER BY d.code")
    return jsonify(
        ok=True,
        counters=dict(students=students, faculty=faculty, departments=depts,
                      present=tmap.get("Present", 0), absent=tmap.get("Absent", 0),
                      average=avg, at_risk=len(risk)),
        dept_att=dict(labels=[r["code"] for r in by_dept],
                      values=[round(100.0 * (r["p"] or 0) / r["t"], 1) if r["t"] else 0 for r in by_dept]),
        trend=dict(labels=[d[5:] for d in days], values=trend),
        accounts=dict(labels=[r["code"] for r in acc], students=[r["s"] or 0 for r in acc],
                      faculty=[r["f"] or 0 for r in acc]),
        at_risk=[dict(username=s["username"], name=s["name"], dept=s["dept"], pct=s["pct"],
                      marks=s["marks_pct"], reasons=", ".join(s["reasons"])) for s in risk[:8]],
    )


# ----------------------------------------------------------------- account generation
def dept_by_code(code):
    return db.query_one("SELECT * FROM departments WHERE code=%s", (code,))


@app.route("/admin/generate")
@role_required("admin")
def admin_generate():
    depts = db.query("SELECT id, code, name FROM departments ORDER BY name")
    return render_template("admin/generate.html", active="generate", depts=depts, max_batch=MAX_BATCH)


def _generate(role, dept, count, admin_username):
    prefix = "FAC" if role == "faculty" else "STU"
    stamp = now()
    batch_id = uuid.uuid4().hex[:10].upper()
    pws = [gen_password() for _ in range(count)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        hashes = list(pool.map(hash_pw, pws))

    row = db.query_one("SELECT last_no FROM sequences WHERE role=%s AND dept_code=%s FOR UPDATE",
                       (role, dept["code"]))
    if row is None:
        db.execute("INSERT IGNORE INTO sequences (role, dept_code, last_no) VALUES (%s,%s,0)",
                   (role, dept["code"]), commit=False)
        row = db.query_one("SELECT last_no FROM sequences WHERE role=%s AND dept_code=%s FOR UPDATE",
                           (role, dept["code"]))
    n = row["last_no"]
    existing = {r["username"] for r in db.query(
        "SELECT username FROM users WHERE username LIKE %s", (f"{prefix}-{dept['code']}-%",))}
    out = []
    for i in range(count):
        n += 1
        username = f"{prefix}-{dept['code']}-{n:03d}"
        while username in existing:  # never reuse / duplicate
            n += 1
            username = f"{prefix}-{dept['code']}-{n:03d}"
        existing.add(username)
        uid = db.insert(
            "INSERT INTO users (name, role, department_id, username, password_hash, status, "
            "must_change_password, created_at, created_by) VALUES (%s,%s,%s,%s,%s,'active',1,%s,%s)",
            (username, role, dept["id"], username, hashes[i], stamp, admin_username), commit=False)
        db.insert(
            "INSERT INTO generation_history (batch_id, user_id, username, role, department_code, "
            "generated_by, generated_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (batch_id, uid, username, role, dept["code"], admin_username, stamp), commit=False)
        out.append(dict(sn=i + 1, id=uid, name=username, role=role.title(), department=dept["name"],
                        username=username, password=pws[i], status="Active", created=stamp))
    db.execute("UPDATE sequences SET last_no=%s WHERE role=%s AND dept_code=%s",
               (n, role, dept["code"]), commit=False)
    return batch_id, out


@app.route("/admin/api/generate", methods=["POST"])
@role_required("admin")
def api_generate():
    data = request.get_json(silent=True) or {}
    role = str(data.get("role", "")).lower()
    code = str(data.get("department", "")).upper()
    try:
        count = int(data.get("count", 0))
    except (TypeError, ValueError):
        return bad("Enter a valid number of accounts.")
    if role not in ("faculty", "student"):
        return bad("Select Faculty or Student.")
    dept = dept_by_code(code)
    if not dept:
        return bad("Select a valid department.")
    if not 1 <= count <= MAX_BATCH:
        return bad(f"Number of accounts must be between 1 and {MAX_BATCH}.")
    for attempt in range(3):
        try:
            batch_id, accounts = _generate(role, dept, count, session["username"])
            db.commit()
            break
        except IntegrityViolation:
            db.rollback()
            if attempt == 2:
                return bad("Could not allocate unique usernames. Please try again.", 409)
    audit("generate_accounts", f"{count} {role} {dept['code']} batch {batch_id}")
    return jsonify(ok=True, batch_id=batch_id, accounts=accounts)


@app.route("/admin/api/history")
@role_required("admin")
def api_history():
    q = request.args.get("q", "").strip()
    role = request.args.get("role", "")
    dept = request.args.get("dept", "")
    sql = ("SELECT h.batch_id, h.username, h.role, h.department_code, h.generated_by, h.generated_at, "
           "u.status FROM generation_history h LEFT JOIN users u ON u.id=h.user_id WHERE 1=1")
    args = []
    if q:
        sql += " AND (h.username LIKE %s OR h.batch_id LIKE %s OR h.generated_by LIKE %s)"
        args += [f"%{q}%"] * 3
    if role in ("faculty", "student"):
        sql += " AND h.role=%s"; args.append(role)
    if dept:
        sql += " AND h.department_code=%s"; args.append(dept)
    sql += " ORDER BY h.id DESC LIMIT 500"
    rows = db.query(sql, tuple(args))
    batches = db.query(
        "SELECT batch_id, MAX(role) AS role, MAX(department_code) AS dept, MAX(generated_by) AS by_, "
        "MAX(generated_at) AS at, COUNT(*) AS n FROM generation_history GROUP BY batch_id "
        "ORDER BY MAX(generated_at) DESC LIMIT 20")
    return jsonify(ok=True, rows=rows, batches=batches)


@app.route("/admin/history")
@role_required("admin")
def admin_history():
    depts = db.query("SELECT code, name FROM departments ORDER BY name")
    return render_template("admin/history.html", active="history", depts=depts)


# ----------------------------------------------------------------- user management
@app.route("/admin/users")
@role_required("admin")
def admin_users():
    depts = db.query("SELECT id, code, name FROM departments ORDER BY name")
    sections = db.query("SELECT s.id, s.year_no, s.name, d.code AS dept FROM sections s "
                        "JOIN departments d ON d.id=s.department_id ORDER BY d.code, s.year_no, s.name")
    return render_template("admin/users.html", active="users", depts=depts, sections=sections)


def user_filters():
    q = request.values.get("q", "").strip()
    role = request.values.get("role", "")
    dept = request.values.get("dept", "")
    status = request.values.get("status", "")
    sql = ("SELECT u.id, u.name, u.role, u.username, u.status, u.year_no, u.section_id, u.department_id, "
           "u.created_at, u.created_by, u.last_login, "
           "d.code AS dept, d.name AS dept_name, s.name AS section "
           "FROM users u JOIN departments d ON d.id=u.department_id "
           "LEFT JOIN sections s ON s.id=u.section_id WHERE 1=1")
    args = []
    if q:
        sql += " AND (u.username LIKE %s OR u.name LIKE %s)"
        args += [f"%{q}%", f"%{q}%"]
    if role in ("faculty", "student"):
        sql += " AND u.role=%s"; args.append(role)
    if dept:
        sql += " AND d.code=%s"; args.append(dept)
    if status in ("active", "inactive"):
        sql += " AND u.status=%s"; args.append(status)
    return sql, args


@app.route("/admin/api/users")
@role_required("admin")
def api_users():
    sql, args = user_filters()
    rows = db.query(sql + " ORDER BY u.id DESC LIMIT 500", tuple(args))
    return jsonify(ok=True, rows=rows)


def clean_name(v):
    v = re.sub(r"\s+", " ", str(v or "")).strip()
    if not 2 <= len(v) <= 100 or not re.match(r"^[A-Za-z0-9 .,'\-_&()/]+$", v):
        return None
    return v


@app.route("/admin/api/users/<int:uid>", methods=["PUT"])
@role_required("admin")
def api_user_edit(uid):
    data = request.get_json(silent=True) or {}
    user = db.query_one("SELECT * FROM users WHERE id=%s", (uid,))
    if not user:
        return bad("User not found.", 404)
    name = clean_name(data.get("name"))
    if not name:
        return bad("Enter a valid name (2-100 letters, numbers or . , ' - characters).")
    dept = db.query_one("SELECT id FROM departments WHERE id=%s", (data.get("department_id"),))
    if not dept:
        return bad("Select a valid department.")
    status = data.get("status", user["status"])
    if status not in ("active", "inactive"):
        return bad("Invalid status.")
    year_no = section_id = None
    if user["role"] == "student":
        if data.get("year_no") not in (None, ""):
            try:
                year_no = int(data["year_no"])
            except (TypeError, ValueError):
                return bad("Year must be 1-4.")
            if not 1 <= year_no <= 4:
                return bad("Year must be 1-4.")
        if data.get("section_id") not in (None, ""):
            sec = db.query_one("SELECT id FROM sections WHERE id=%s AND department_id=%s",
                               (data["section_id"], dept["id"]))
            if not sec:
                return bad("Section does not belong to the selected department.")
            section_id = sec["id"]
    db.execute("UPDATE users SET name=%s, department_id=%s, year_no=%s, section_id=%s, status=%s WHERE id=%s",
               (name, dept["id"], year_no, section_id, status, uid))
    audit("edit_user", user["username"])
    return jsonify(ok=True)


@app.route("/admin/api/users/<int:uid>/status", methods=["POST"])
@role_required("admin")
def api_user_status(uid):
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("active", "inactive"):
        return bad("Invalid status.")
    if not db.execute("UPDATE users SET status=%s WHERE id=%s", (status, uid)):
        return bad("User not found.", 404)
    audit("set_status", f"{uid} {status}")
    return jsonify(ok=True)


@app.route("/admin/api/users/<int:uid>/reset-password", methods=["POST"])
@role_required("admin")
def api_user_reset(uid):
    user = db.query_one("SELECT username FROM users WHERE id=%s", (uid,))
    if not user:
        return bad("User not found.", 404)
    pw = gen_password()
    db.execute("UPDATE users SET password_hash=%s, must_change_password=1, failed_attempts=0, "
               "locked_until=NULL WHERE id=%s", (hash_pw(pw), uid))
    audit("reset_password", user["username"])
    return jsonify(ok=True, username=user["username"], password=pw)


@app.route("/admin/api/users/<int:uid>", methods=["DELETE"])
@role_required("admin")
def api_user_delete(uid):
    user = db.query_one("SELECT username FROM users WHERE id=%s", (uid,))
    if not user:
        return bad("User not found.", 404)
    db.execute("DELETE FROM users WHERE id=%s", (uid,))
    audit("delete_user", user["username"])
    return jsonify(ok=True)


@app.route("/admin/api/users/<int:uid>/reset-device", methods=["POST"])
@role_required("admin")
def api_user_reset_device(uid):
    """Unbinds the phone/browser registered for a student (e.g. after they get a new phone)."""
    db.execute("DELETE FROM student_devices WHERE student_id=%s", (uid,))
    audit("reset_device", str(uid))
    return jsonify(ok=True)


# ----------------------------------------------------------------- exports
def _safe_cell(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def send_csv(name, header, rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow([_safe_cell(c) for c in r])
    return Response("﻿" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={name}.csv"})


def send_pdf(name, title, header, rows):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=24, rightMargin=24,
                            topMargin=28, bottomMargin=28, title=title)
    st = getSampleStyleSheet()
    data = [header] + [[str(c) if c is not None else "" for c in r] for r in rows]
    t = Table(data, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b2a5b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#9aa7bd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef3fb")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    doc.build([Paragraph("Sir Issac College of Engineering and Technology", st["Title"]),
               Paragraph(f"{title} &nbsp;|&nbsp; {now()}", st["Normal"]), Spacer(1, 10), t])
    return Response(buf.getvalue(), mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={name}.pdf"})


@app.route("/admin/export/users.<fmt>")
@role_required("admin")
def export_users(fmt):
    if fmt not in ("csv", "pdf"):
        abort(404)
    sql, args = user_filters()
    rows = db.query(sql + " ORDER BY u.id", tuple(args))
    header = ["S.No", "Name", "Role", "Department", "Username", "Status", "Created Date"]
    body = [[i + 1, r["name"], r["role"].title(), r["dept_name"], r["username"],
             r["status"].title(), r["created_at"]] for i, r in enumerate(rows)]
    audit("export_users", fmt)
    if fmt == "csv":
        return send_csv("users", header, body)
    return send_pdf("users", "User Accounts", header, body)


@app.route("/admin/export/batch.<fmt>", methods=["POST"])
@role_required("admin")
def export_batch(fmt):
    """Exports the just-generated batch (temp passwords exist only in the admin's browser)."""
    if fmt not in ("csv", "pdf"):
        abort(404)
    try:
        rows = json.loads(request.form.get("rows", "[]"))
        assert isinstance(rows, list) and len(rows) <= 500
    except Exception:  # noqa: BLE001
        return bad("Invalid export data.")
    header = ["S.No", "Name/ID", "Role", "Department", "Username", "Temporary Password", "Status", "Created Date"]
    body = [[r.get("sn"), r.get("name"), r.get("role"), r.get("department"), r.get("username"),
             r.get("password"), r.get("status"), r.get("created")] for r in rows if isinstance(r, dict)]
    audit("export_batch", f"{fmt} {len(body)} rows")
    if fmt == "csv":
        return send_csv("generated_accounts", header, body)
    return send_pdf("generated_accounts", "Generated Accounts (CONFIDENTIAL - temporary passwords)", header, body)


# ----------------------------------------------------------------- generic academic CRUD
def _year(v):
    return int(v)


ENT = {
    "departments": dict(
        label="Departments", icon="🏛️",
        fields=[dict(name="code", label="Code", type="text", maxlen=10, upper=True),
                dict(name="name", label="Department Name", type="text", maxlen=100)],
        columns=[("code", "Code"), ("name", "Department")],
        sql="SELECT id, code, name FROM departments", search=["code", "name"], order="code",
        table="departments"),
    "sections": dict(
        label="Sections", icon="🧩",
        fields=[dict(name="department_id", label="Department", type="select", options="departments"),
                dict(name="year_no", label="Year", type="select", options="years"),
                dict(name="name", label="Section", type="text", maxlen=10, upper=True)],
        columns=[("department", "Department"), ("year_no", "Year"), ("name", "Section")],
        sql="SELECT s.id, s.department_id, d.code AS department, s.year_no, s.name FROM sections s "
            "JOIN departments d ON d.id=s.department_id",
        search=["d.code", "s.name"], dept="s.department_id", order="d.code, s.year_no, s.name",
        table="sections"),
    "subjects": dict(
        label="Subjects", icon="📚",
        fields=[dict(name="department_id", label="Department", type="select", options="departments"),
                dict(name="year_no", label="Year", type="select", options="years"),
                dict(name="code", label="Subject Code", type="text", maxlen=20, upper=True),
                dict(name="name", label="Subject Name", type="text", maxlen=120)],
        columns=[("department", "Department"), ("year_no", "Year"), ("code", "Code"), ("name", "Subject")],
        sql="SELECT s.id, s.department_id, d.code AS department, s.year_no, s.code, s.name FROM subjects s "
            "JOIN departments d ON d.id=s.department_id",
        search=["s.code", "s.name", "d.code"], dept="s.department_id", order="d.code, s.year_no, s.code",
        table="subjects"),
    "attendance": dict(
        label="Attendance Records", icon="🗓️",
        fields=[dict(name="student", label="Student Username", type="text", maxlen=40, upper=True),
                dict(name="subject_id", label="Subject", type="select", options="subjects"),
                dict(name="att_date", label="Date", type="date"),
                dict(name="status", label="Status", type="select", options=["Present", "Absent"])],
        columns=[("att_date", "Date"), ("student", "Student"), ("student_name", "Name"), ("department", "Dept"),
                 ("subject_code", "Subject"), ("status", "Status"), ("method", "Method"), ("marked_by", "Marked By")],
        sql="SELECT a.id, u.username AS student, u.name AS student_name, u.department_id, d.code AS department, "
            "a.subject_id, sb.code AS subject_code, a.att_date, a.status, a.method, a.marked_by "
            "FROM attendance a JOIN users u ON u.id=a.student_id JOIN subjects sb ON sb.id=a.subject_id "
            "JOIN departments d ON d.id=u.department_id",
        search=["u.username", "u.name", "sb.code"], dept="u.department_id", order="a.att_date DESC, a.id DESC",
        table="attendance"),
    "marks": dict(
        label="Performance Data", icon="📈",
        fields=[dict(name="student", label="Student Username", type="text", maxlen=40, upper=True),
                dict(name="subject_id", label="Subject", type="select", options="subjects"),
                dict(name="exam_type", label="Exam", type="select", options=EXAMS),
                dict(name="marks", label="Marks Obtained", type="number", min=0, max=1000),
                dict(name="max_marks", label="Maximum Marks", type="number", min=1, max=1000)],
        columns=[("student", "Student"), ("student_name", "Name"), ("department", "Dept"),
                 ("subject_code", "Subject"), ("exam_type", "Exam"), ("marks", "Marks"), ("max_marks", "Out of")],
        sql="SELECT m.id, u.username AS student, u.name AS student_name, u.department_id, d.code AS department, "
            "m.subject_id, sb.code AS subject_code, m.exam_type, m.marks, m.max_marks "
            "FROM marks m JOIN users u ON u.id=m.student_id JOIN subjects sb ON sb.id=m.subject_id "
            "JOIN departments d ON d.id=u.department_id",
        search=["u.username", "u.name", "sb.code"], dept="u.department_id", order="m.id DESC",
        table="marks"),
}


def get_options():
    return dict(
        departments=[dict(value=r["id"], label=f"{r['code']} – {r['name']}")
                     for r in db.query("SELECT id, code, name FROM departments ORDER BY name")],
        subjects=[dict(value=r["id"], label=f"{r['code']} – {r['name']} ({r['dept']} Y{r['year_no']})")
                  for r in db.query("SELECT s.id, s.code, s.name, s.year_no, d.code AS dept FROM subjects s "
                                    "JOIN departments d ON d.id=s.department_id ORDER BY d.code, s.code")],
        years=[dict(value=i, label=f"Year {i}") for i in range(1, 5)],
    )


@app.route("/admin/<ent>")
@role_required("admin")
def admin_entity(ent):
    if ent not in ENT:
        abort(404)
    cfg = ENT[ent]
    meta = dict(key=ent, label=cfg["label"], fields=cfg["fields"], columns=cfg["columns"],
                has_dept="dept" in cfg)
    depts = db.query("SELECT id, code, name FROM departments ORDER BY name")
    return render_template("admin/entity.html", active=ent, cfg=cfg, meta=meta, depts=depts,
                           options=get_options())


@app.route("/admin/api/e/<ent>")
@role_required("admin")
def api_ent_list(ent):
    if ent not in ENT:
        abort(404)
    cfg = ENT[ent]
    sql = cfg["sql"] + " WHERE 1=1"
    args = []
    q = request.args.get("q", "").strip()
    if q:
        sql += " AND (" + " OR ".join(f"{c} LIKE %s" for c in cfg["search"]) + ")"
        args += [f"%{q}%"] * len(cfg["search"])
    dept = request.args.get("dept", "")
    if dept.isdigit() and cfg.get("dept"):
        sql += f" AND {cfg['dept']}=%s"; args.append(int(dept))
    sql += f" ORDER BY {cfg['order']} LIMIT 300"
    return jsonify(ok=True, rows=db.query(sql, tuple(args)))


def validate_fields(cfg, data):
    vals, opts = {}, None
    for f in cfg["fields"]:
        raw = data.get(f["name"])
        raw = "" if raw is None else str(raw).strip()
        if raw == "":
            return None, f"{f['label']} is required."
        t = f["type"]
        if t == "text":
            if len(raw) > f.get("maxlen", 100) or not re.match(r"^[\w &.,'()/\-]+$", raw):
                return None, f"{f['label']} is invalid."
            raw = raw.upper() if f.get("upper") else raw
        elif t == "number":
            try:
                raw = float(raw)
            except ValueError:
                return None, f"{f['label']} must be a number."
            if not f.get("min", 0) <= raw <= f.get("max", 1000):
                return None, f"{f['label']} is out of range."
        elif t == "date":
            try:
                datetime.strptime(raw, "%Y-%m-%d")
            except ValueError:
                return None, f"{f['label']} must be a valid date."
        elif t == "select":
            o = f["options"]
            if isinstance(o, list):
                if raw not in o:
                    return None, f"{f['label']} is invalid."
            else:
                if opts is None:
                    opts = get_options()
                if raw not in {str(x["value"]) for x in opts[o]}:
                    return None, f"{f['label']} is invalid."
                raw = int(raw)
        vals[f["name"]] = raw
    return vals, None


def ent_columns(ent, vals, creating):
    """Map validated form values to DB columns (resolves student username -> id)."""
    cols = dict(vals)
    if ent in ("attendance", "marks"):
        stu = db.query_one("SELECT id FROM users WHERE username=%s AND role='student'", (cols.pop("student"),))
        if not stu:
            return None, "No student found with that username."
        cols["student_id"] = stu["id"]
    if ent == "sections" or ent == "subjects":
        cols["year_no"] = int(cols["year_no"])
    if ent == "marks":
        if cols["marks"] > cols["max_marks"]:
            return None, "Marks obtained cannot exceed maximum marks."
    if creating:
        if ent == "attendance":
            cols.update(method="admin", marked_by=session["username"], created_at=now())
        if ent == "marks":
            cols["created_at"] = now()
    return cols, None


@app.route("/admin/api/e/<ent>", methods=["POST"])
@app.route("/admin/api/e/<ent>/<int:rid>", methods=["PUT"])
@role_required("admin")
def api_ent_save(ent, rid=None):
    if ent not in ENT:
        abort(404)
    cfg = ENT[ent]
    vals, err = validate_fields(cfg, request.get_json(silent=True) or {})
    if err:
        return bad(err)
    cols, err = ent_columns(ent, vals, rid is None)
    if err:
        return bad(err)
    try:
        if rid is None:
            names = ", ".join(cols)
            ph = ", ".join(["%s"] * len(cols))
            db.insert(f"INSERT INTO {cfg['table']} ({names}) VALUES ({ph})", tuple(cols.values()))
            audit(f"create_{ent}", str(list(cols.values()))[:200])
        else:
            sets = ", ".join(f"{c}=%s" for c in cols)
            n = db.execute(f"UPDATE {cfg['table']} SET {sets} WHERE id=%s", tuple(cols.values()) + (rid,))
            audit(f"update_{ent}", str(rid))
            if not n and not db.query_one(f"SELECT id FROM {cfg['table']} WHERE id=%s", (rid,)):
                return bad("Record not found.", 404)
    except IntegrityViolation:
        return bad("A matching record already exists.", 409)
    return jsonify(ok=True)


@app.route("/admin/api/e/<ent>/<int:rid>", methods=["DELETE"])
@role_required("admin")
def api_ent_delete(ent, rid):
    if ent not in ENT:
        abort(404)
    try:
        n = db.execute(f"DELETE FROM {ENT[ent]['table']} WHERE id=%s", (rid,))
    except IntegrityViolation:
        return bad("Cannot delete – this record is still in use (users, subjects or sections depend on it).", 409)
    if not n:
        return bad("Record not found.", 404)
    audit(f"delete_{ent}", str(rid))
    return jsonify(ok=True)


# =========================================================================== ATTENDANCE ENGINE
def code_for(secret, window):
    mac = hmac.new(secret.encode(), str(window).encode(), hashlib.sha256).digest()
    return f"{int.from_bytes(mac[:4], 'big') % 1_000_000:06d}"


def code_matches(secret, code):
    w = int(time.time() // CODE_STEP)
    return any(hmac.compare_digest(code_for(secret, x), code) for x in (w, w - 1))


def haversine_m(lat1, lon1, lat2, lon2):
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def upsert_attendance(student_id, subject_id, status, method, by, day=None):
    day = day or today()
    existing = db.query_one("SELECT id FROM attendance WHERE student_id=%s AND subject_id=%s AND att_date=%s",
                            (student_id, subject_id, day))
    if existing:
        db.execute("UPDATE attendance SET status=%s, method=%s, marked_by=%s WHERE id=%s",
                   (status, method, by, existing["id"]), commit=False)
    else:
        db.insert("INSERT INTO attendance (student_id, subject_id, att_date, status, method, marked_by, "
                  "created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                  (student_id, subject_id, day, status, method, by, now()), commit=False)


def finalize_session(sess):
    """Closes a session and automatically marks everybody who did not check in as Absent."""
    with db.transaction():
        if db.execute("UPDATE class_sessions SET status='closed', closed_at=%s WHERE id=%s AND status='open'",
                      (now(), sess["id"]), commit=False) == 0:
            return 0
        students = db.query(
            "SELECT id FROM users WHERE role='student' AND status='active' AND department_id=%s "
            "AND year_no=%s AND section_id=%s", (sess["department_id"], sess["year_no"], sess["section_id"]))
        marked = {r["student_id"] for r in db.query(
            "SELECT student_id FROM attendance WHERE subject_id=%s AND att_date=%s",
            (sess["subject_id"], sess["att_date"]))}
        n = 0
        for st in students:
            if st["id"] not in marked:
                db.execute("INSERT IGNORE INTO attendance (student_id, subject_id, att_date, status, method, "
                           "marked_by, created_at) VALUES (%s,%s,%s,'Absent','auto',%s,%s)",
                           (st["id"], sess["subject_id"], sess["att_date"], f"session-{sess['id']}", now()),
                           commit=False)
                n += 1
    return n


def finalize_expired():
    for sess in db.query("SELECT * FROM class_sessions WHERE status='open' AND ends_at < %s", (now(),)):
        finalize_session(sess)


def class_students(sess):
    return db.query(
        "SELECT u.id, u.username, u.name FROM users u WHERE u.role='student' AND u.status='active' "
        "AND u.department_id=%s AND u.year_no=%s AND u.section_id=%s ORDER BY u.username",
        (sess["department_id"], sess["year_no"], sess["section_id"]))


# --------------------------------------------------------------------------- AI attendance engine
def add_flag(session_id, student_id, kind, detail=""):
    """Records a suspicious event once per (session, student, kind) for the faculty review queue."""
    db.execute("INSERT IGNORE INTO presence_flags (session_id, student_id, kind, detail, created_at) "
               "VALUES (%s,%s,%s,%s,%s)", (session_id, student_id, kind, detail[:200], now()))


def _subnet(ip):
    ip = (ip or "").strip()
    if "." in ip and ":" not in ip:
        return ".".join(ip.split(".")[:3])
    if ":" in ip:
        return ":".join(ip.split(":")[:4])
    return None


def ai_evaluate(sess, me, dev_hash, data, ip, state, ts):
    """Explainable trust score (0-100) for one presence beacon of one student.

    Signals: registered device (25) + place proof (50: GPS inside the class area, same campus network,
    or a valid class code) + steady presence over time (25).  Anomalies subtract points or block:
    other student's phone, shared device, GPS jumping, frozen (mock) GPS.
    Returns dict(score, decision, reasons, flags, place_ok, dist, lat, lon).
    """
    reasons, flags, penalty = [], [], 0
    out = dict(score=0, decision="pending", reasons=reasons, flags=flags, place_ok=False, dist=None,
               lat=None, lon=None)

    # ---- device (hard rule)
    bound = db.query_one("SELECT device_hash FROM student_devices WHERE student_id=%s", (me["id"],))
    owner = db.query_one("SELECT student_id FROM student_devices WHERE device_hash=%s", (dev_hash,))
    shared = db.query_one("SELECT student_id FROM presence_state WHERE session_id=%s AND device_hash=%s "
                          "AND student_id<>%s", (sess["id"], dev_hash, me["id"]))
    if (bound and bound["device_hash"] != dev_hash) or (owner and owner["student_id"] != me["id"]):
        flags.append(("device_mismatch", "Check-in attempted from a phone registered to a different account"))
        reasons.append("Not your registered phone")
        out["decision"] = "blocked"
        return out
    if shared:
        flags.append(("shared_device", "The same phone was used by two students in this class"))
        reasons.append("This phone is already used by another student")
        out["decision"] = "blocked"
        return out
    score = 25 if bound else 15
    reasons.append("Registered phone" if bound else "New phone (will be registered)")

    # ---- place proof
    place = 0
    loc_outside = False
    lat, lon = _float(data.get("lat"), -90, 90), _float(data.get("lon"), -180, 180)
    acc = _float(data.get("accuracy"), 0, 100000)
    acc = 0 if acc is None else acc
    if sess["lat"] is not None:
        if lat is None or lon is None:
            reasons.append("Location not shared - allow location")
        elif acc > max(150, sess["radius_m"]):
            reasons.append(f"Location too inaccurate (±{int(acc)} m) - turn on GPS")
        else:
            out["lat"], out["lon"] = lat, lon
            dist = haversine_m(sess["lat"], sess["lon"], lat, lon)
            out["dist"] = dist
            if dist - acc <= sess["radius_m"]:
                place += 50 if acc <= 50 else 35
                out["place_ok"] = True
                reasons.append("Inside the class area")
            else:
                reasons.append("Outside the class area")
                loc_outside = True      # GPS contradicts the classroom, so the network bonus must not count
                if dist - acc > 3 * sess["radius_m"]:
                    flags.append(("outside_area", f"Attempted check-in {int(dist)} m from the classroom"))
    elif lat is not None and lon is not None:
        out["lat"], out["lon"] = lat, lon
    if not loc_outside and sess["faculty_ip"] and _subnet(ip) and _subnet(ip) == _subnet(sess["faculty_ip"]):
        place += 20
        out["place_ok"] = True
        reasons.append("Same campus network as faculty")
    if data.get("code_ok"):
        place += 50
        out["place_ok"] = True
        reasons.append("Valid class code")
    score += min(50, place)

    # ---- anomaly checks on the movement history
    if out["place_ok"] and out["lat"] is not None and state and state.get("last_lat") is not None:
        jump = haversine_m(state["last_lat"], state["last_lon"], out["lat"], out["lon"])
        dt = max(1.0, ts - state["last_ts"])
        if jump > 100 and jump / dt > 15:
            penalty += 40
            flags.append(("teleport", f"Location jumped {int(jump)} m in {int(dt)} s"))
            reasons.append("Impossible location jump")
        same = state["same_count"] + (1 if jump < 0.5 else 0)
        jit = state["jitter_count"] + (0 if jump < 0.5 else 1)
        if jit == 0 and ((same >= 2 and acc <= 5) or same >= 6):
            penalty += 30
            flags.append(("static_gps", "Location never changes at all (possible mock-location app)"))
            reasons.append("Frozen GPS signal")

    # ---- persistence: the student must stay in the place for a while
    first = state["first_ok_ts"] if state and state["first_ok_ts"] else None
    count = (state["ok_count"] if state else 0)
    if out["place_ok"]:
        first = first or ts
        count += 1
        if count >= 3:
            score += int(25 * min(1.0, (ts - first) / PERSIST_SECONDS))
        else:
            reasons.append("Verifying - stay on this page")
    else:
        first, count = None, 0
    out["first"], out["count"] = first, count

    score = max(0, min(100, score - penalty))
    out["score"] = score
    bad_flag = any(k in ("teleport", "static_gps") for k, _ in flags)
    settled = count >= 3 and first is not None and (ts - first) >= PERSIST_SECONDS
    if score >= AI_AUTO and out["place_ok"] and not bad_flag:
        out["decision"] = "auto"
    elif score >= AI_REVIEW and (settled or bad_flag):
        out["decision"] = "review"      # evidence is mixed after a fair observation time -> faculty decides
    return out


def _state_row(sid, uid):
    return db.query_one("SELECT * FROM presence_state WHERE session_id=%s AND student_id=%s", (sid, uid))


def _save_state(sid, uid, dev_hash, res, ts, row):
    reasons = " | ".join(res["reasons"])[:400]
    lat, lon = res["lat"], res["lon"]
    if row is None:
        db.execute("INSERT INTO presence_state (session_id, student_id, device_hash, first_ok_ts, last_ts, ok_count, "
                   "same_count, jitter_count, last_lat, last_lon, score, decision, reasons) "
                   "VALUES (%s,%s,%s,%s,%s,%s,0,0,%s,%s,%s,%s,%s)",
                   (sid, uid, dev_hash, res.get("first"), ts, res.get("count", 0), lat, lon, res["score"],
                    res["decision"], reasons), commit=False)
        return
    same, jit = row["same_count"], row["jitter_count"]
    if lat is not None and row["last_lat"] is not None:
        if haversine_m(row["last_lat"], row["last_lon"], lat, lon) < 0.5:
            same += 1
        else:
            jit += 1
    db.execute("UPDATE presence_state SET device_hash=%s, first_ok_ts=%s, last_ts=%s, ok_count=%s, same_count=%s, "
               "jitter_count=%s, last_lat=%s, last_lon=%s, score=%s, decision=%s, reasons=%s "
               "WHERE session_id=%s AND student_id=%s",
               (dev_hash, res.get("first"), ts, res.get("count", 0), same, jit,
                lat if lat is not None else row["last_lat"], lon if lon is not None else row["last_lon"],
                res["score"], res["decision"], reasons, sid, uid), commit=False)


def session_view(sess):
    """Everything the faculty screen needs: rotating code, countdowns and the live roster."""
    ends = datetime.strptime(sess["ends_at"], "%Y-%m-%d %H:%M:%S")
    left = max(0, int((ends - datetime.now()).total_seconds()))
    status = sess["status"]
    marks = {r["student_id"]: r for r in db.query(
        "SELECT student_id, marked_at FROM session_marks WHERE session_id=%s", (sess["id"],))}
    att = {r["student_id"]: r for r in db.query(
        "SELECT student_id, status, method FROM attendance WHERE subject_id=%s AND att_date=%s",
        (sess["subject_id"], sess["att_date"]))}
    states = {r["student_id"]: r for r in db.query(
        "SELECT * FROM presence_state WHERE session_id=%s", (sess["id"],))}
    flags = {}
    for f in db.query("SELECT student_id, kind, detail FROM presence_flags WHERE session_id=%s ORDER BY id",
                      (sess["id"],)):
        flags.setdefault(f["student_id"], []).append(dict(kind=f["kind"], detail=f["detail"]))
    students, queue = [], []
    for st in class_students(sess):
        a = att.get(st["id"])
        m = marks.get(st["id"])
        ps = states.get(st["id"])
        fl = flags.get(st["id"], [])
        row = dict(id=st["id"], username=st["username"], name=st["name"],
                   status=a["status"] if a else None, method=a["method"] if a else None,
                   at=m["marked_at"][11:19] if m else None,
                   score=ps["score"] if ps else None, ai=ps["decision"] if ps else None)
        students.append(row)
        reviewed = ps["review"] if ps else None
        if not reviewed and ((ps and ps["decision"] in ("review", "blocked")) or fl):
            queue.append(dict(row, reasons=(ps["reasons"] if ps and ps["reasons"] else ""), flags=fl,
                              decision=ps["decision"] if ps else "flagged"))
    out = dict(id=sess["id"], status=status, ends_in=left, subject_id=sess["subject_id"],
               geofence=sess["lat"] is not None, radius=sess["radius_m"], students=students,
               present=sum(1 for x in students if x["status"] == "Present"), total=len(students),
               ai_auto=sum(1 for x in students if x["method"] == "ai"), queue=queue)
    if status == "open":
        out["code"] = code_for(sess["secret"], int(time.time() // CODE_STEP))
        out["code_ttl"] = CODE_STEP - int(time.time() % CODE_STEP)
    return out


# =========================================================================== FACULTY
@app.route("/faculty")
@role_required("faculty")
def faculty_dashboard():
    me = db.query_one("SELECT u.*, d.code AS dept_code, d.name AS dept_name FROM users u "
                      "JOIN departments d ON d.id=u.department_id WHERE u.id=%s", (session["uid"],))
    depts = db.query("SELECT id, code, name FROM departments ORDER BY name")
    st = db.query_one("SELECT COUNT(*) AS n, SUM(CASE WHEN att_date=%s THEN 1 ELSE 0 END) AS t "
                      "FROM class_sessions WHERE faculty_id=%s", (today(), me["id"]))
    return render_template("faculty/dashboard.html", me=me, depts=depts, today=today(),
                           total_sessions=st["n"] or 0, today_sessions=st["t"] or 0)


@app.route("/faculty/api/options")
@role_required("faculty")
def faculty_options():
    dept = request.args.get("dept", "")
    year = request.args.get("year", "")
    if not (dept.isdigit() and year.isdigit()):
        return bad("Select department and year.")
    secs = db.query("SELECT id, name FROM sections WHERE department_id=%s AND year_no=%s ORDER BY name",
                    (int(dept), int(year)))
    subs = db.query("SELECT id, code, name FROM subjects WHERE department_id=%s AND year_no=%s ORDER BY code",
                    (int(dept), int(year)))
    return jsonify(ok=True, sections=secs, subjects=subs)


@app.route("/faculty/api/roster")
@role_required("faculty")
def faculty_roster():
    a = request.args
    if not all(a.get(k, "").isdigit() for k in ("dept", "year", "section", "subject")):
        return bad("Select department, year, section and subject.")
    rows = db.query(
        "SELECT u.id, u.username, u.name FROM users u "
        "WHERE u.role='student' AND u.status='active' AND u.department_id=%s AND u.year_no=%s "
        "AND u.section_id=%s ORDER BY u.username",
        (int(a["dept"]), int(a["year"]), int(a["section"])))
    marked = {r["student_id"]: r for r in db.query(
        "SELECT student_id, status, method FROM attendance WHERE subject_id=%s AND att_date=%s",
        (int(a["subject"]), today()))}
    out = []
    for r in rows:
        m = marked.get(r["id"])
        out.append(dict(id=r["id"], username=r["username"], name=r["name"],
                        status=m["status"] if m else None, method=m["method"] if m else None))
    return jsonify(ok=True, students=out)


def _float(v, lo, hi):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) and lo <= f <= hi else None


@app.route("/faculty/api/session/start", methods=["POST"])
@role_required("faculty")
def faculty_session_start():
    d = request.get_json(silent=True) or {}
    try:
        dept, year, sec, sub = (int(d[k]) for k in ("dept", "year", "section", "subject"))
        minutes = min(60, max(2, int(d.get("minutes", 10))))
    except (KeyError, TypeError, ValueError):
        return bad("Select department, year, section and subject.")
    section = db.query_one("SELECT id FROM sections WHERE id=%s AND department_id=%s AND year_no=%s",
                           (sec, dept, year))
    subject = db.query_one("SELECT id FROM subjects WHERE id=%s AND department_id=%s AND year_no=%s",
                           (sub, dept, year))
    if not section or not subject:
        return bad("That class, section or subject combination does not exist.", 404)
    existing = db.query_one(
        "SELECT * FROM class_sessions WHERE subject_id=%s AND section_id=%s AND att_date=%s AND status='open'",
        (sub, sec, today()))
    if existing:
        if existing["faculty_id"] != session["uid"]:
            return bad("Another faculty member already has an open session for this class.", 409)
        return jsonify(ok=True, id=existing["id"], resumed=True)
    lat, lon = _float(d.get("lat"), -90, 90), _float(d.get("lon"), -180, 180)
    radius = None
    if lat is not None and lon is not None:
        radius = int(_float(d.get("radius"), 20, 1000) or 100)
    else:
        lat = lon = None
    sid = db.insert(
        "INSERT INTO class_sessions (faculty_id, subject_id, department_id, year_no, section_id, att_date, "
        "secret, started_at, ends_at, status, lat, lon, radius_m, faculty_ip) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'open',%s,%s,%s,%s)",
        (session["uid"], sub, dept, year, sec, today(), secrets.token_hex(24), now(),
         (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S"), lat, lon, radius,
         request.remote_addr))
    audit("session_start", f"session {sid} subject {sub} section {sec}")
    return jsonify(ok=True, id=sid)


def _own_session(sid):
    sess = db.query_one("SELECT * FROM class_sessions WHERE id=%s AND faculty_id=%s", (sid, session["uid"]))
    if not sess:
        abort(404)
    return sess


@app.route("/faculty/api/session/<int:sid>/live")
@role_required("faculty")
def faculty_session_live(sid):
    return jsonify(ok=True, **session_view(_own_session(sid)))


@app.route("/faculty/api/session/<int:sid>/extend", methods=["POST"])
@role_required("faculty")
def faculty_session_extend(sid):
    sess = _own_session(sid)
    if sess["status"] != "open":
        return bad("This session is already closed.")
    ends = max(datetime.strptime(sess["ends_at"], "%Y-%m-%d %H:%M:%S"), datetime.now()) + timedelta(minutes=5)
    db.execute("UPDATE class_sessions SET ends_at=%s WHERE id=%s", (ends.strftime("%Y-%m-%d %H:%M:%S"), sid))
    return jsonify(ok=True)


@app.route("/faculty/api/session/<int:sid>/close", methods=["POST"])
@role_required("faculty")
def faculty_session_close(sid):
    sess = _own_session(sid)
    n = finalize_session(sess)
    audit("session_close", f"session {sid}, {n} absent")
    return jsonify(ok=True, absent_marked=n)


@app.route("/faculty/api/session/<int:sid>/review", methods=["POST"])
@role_required("faculty")
def faculty_session_review(sid):
    """Faculty decision on a case the AI engine was not sure about."""
    sess = _own_session(sid)
    d = request.get_json(silent=True) or {}
    action = d.get("action")
    stu = db.query_one("SELECT id FROM users WHERE id=%s AND role='student' AND department_id=%s AND year_no=%s "
                       "AND section_id=%s", (d.get("student_id"), sess["department_id"], sess["year_no"],
                                             sess["section_id"]))
    if action not in ("approve", "reject") or not stu:
        return bad("Invalid review request.")
    status = "Present" if action == "approve" else "Absent"
    with db.transaction():
        upsert_attendance(stu["id"], sess["subject_id"], status, "review", session["username"], sess["att_date"])
        if _state_row(sid, stu["id"]):
            db.execute("UPDATE presence_state SET review=%s WHERE session_id=%s AND student_id=%s",
                       ("approved" if action == "approve" else "rejected", sid, stu["id"]), commit=False)
        else:
            db.execute("INSERT INTO presence_state (session_id, student_id, last_ts, review) VALUES (%s,%s,%s,%s)",
                       (sid, stu["id"], _now_ts(), "approved" if action == "approve" else "rejected"), commit=False)
    audit("review_" + action, f"session {sid} student {stu['id']}")
    return jsonify(ok=True)


@app.route("/faculty/api/session/open")
@role_required("faculty")
def faculty_session_open():
    """Lets the dashboard resume a running session after a page refresh."""
    sess = db.query_one("SELECT * FROM class_sessions WHERE faculty_id=%s AND status='open' "
                        "ORDER BY id DESC", (session["uid"],))
    if not sess:
        return jsonify(ok=True, session=None)
    return jsonify(ok=True, session=dict(id=sess["id"], dept=sess["department_id"], year=sess["year_no"],
                                         section=sess["section_id"], subject=sess["subject_id"]))


@app.route("/faculty/api/sessions")
@role_required("faculty")
def faculty_sessions():
    rows = db.query(
        "SELECT cs.id, cs.att_date, cs.started_at, cs.status, cs.year_no, sb.code AS subject, sc.name AS section, "
        "d.code AS dept, "
        "(SELECT COUNT(*) FROM attendance a WHERE a.subject_id=cs.subject_id AND a.att_date=cs.att_date "
        " AND a.status='Present' AND a.student_id IN (SELECT id FROM users WHERE section_id=cs.section_id)) AS present, "
        "(SELECT COUNT(*) FROM attendance a WHERE a.subject_id=cs.subject_id AND a.att_date=cs.att_date "
        " AND a.status='Absent' AND a.student_id IN (SELECT id FROM users WHERE section_id=cs.section_id)) AS absent "
        "FROM class_sessions cs JOIN subjects sb ON sb.id=cs.subject_id JOIN sections sc ON sc.id=cs.section_id "
        "JOIN departments d ON d.id=cs.department_id WHERE cs.faculty_id=%s ORDER BY cs.id DESC LIMIT 15",
        (session["uid"],))
    return jsonify(ok=True, rows=rows)


@app.route("/faculty/api/report")
@role_required("faculty")
def faculty_report():
    a = request.args
    if not all(a.get(k, "").isdigit() for k in ("dept", "year", "section", "subject")):
        return bad("Select department, year, section and subject.")
    rows = db.query(
        "SELECT u.username, u.name, "
        "SUM(CASE WHEN a.status='Present' THEN 1 ELSE 0 END) AS p, COUNT(a.id) AS t "
        "FROM users u LEFT JOIN attendance a ON a.student_id=u.id AND a.subject_id=%s "
        "WHERE u.role='student' AND u.status='active' AND u.department_id=%s AND u.year_no=%s AND u.section_id=%s "
        "GROUP BY u.id, u.username, u.name ORDER BY u.username",
        (int(a["subject"]), int(a["dept"]), int(a["year"]), int(a["section"])))
    for r in rows:
        r["p"] = r["p"] or 0
        r["pct"] = round(100.0 * r["p"] / r["t"], 1) if r["t"] else None
    return jsonify(ok=True, rows=rows, threshold=ATT_THRESHOLD)


@app.route("/faculty/api/mark", methods=["POST"])
@role_required("faculty")
def faculty_mark():
    """Manual correction by the faculty (e.g. a student whose phone is dead)."""
    d = request.get_json(silent=True) or {}
    status = d.get("status", "Present")
    if status not in ("Present", "Absent"):
        return bad("Invalid status.")
    stu = db.query_one("SELECT id FROM users WHERE id=%s AND role='student' AND status='active'",
                       (d.get("student_id"),))
    sub = db.query_one("SELECT id FROM subjects WHERE id=%s", (d.get("subject_id"),))
    if not stu or not sub:
        return bad("Student or subject not found.", 404)
    with db.transaction():
        upsert_attendance(stu["id"], sub["id"], status, "manual", session["username"])
    audit("manual_mark", f"student {stu['id']} subject {sub['id']} {status}")
    return jsonify(ok=True)


# =========================================================================== STUDENT
def student_report(uid, year_no, dept_id):
    subs = db.query("SELECT id, code, name FROM subjects WHERE department_id=%s AND year_no=%s ORDER BY code",
                    (dept_id, year_no or 0))
    known = {s["id"] for s in subs}
    extra = db.query("SELECT DISTINCT s.id, s.code, s.name FROM attendance a JOIN subjects s ON s.id=a.subject_id "
                     "WHERE a.student_id=%s", (uid,))
    subs += [s for s in extra if s["id"] not in known]
    att = db.query("SELECT subject_id, status, att_date, method FROM attendance WHERE student_id=%s "
                   "ORDER BY att_date DESC, id DESC", (uid,))
    mk = db.query("SELECT m.subject_id, m.exam_type, m.marks, m.max_marks FROM marks m WHERE m.student_id=%s "
                  "ORDER BY m.id", (uid,))
    per = []
    for s in subs:
        recs = [a for a in att if a["subject_id"] == s["id"]]
        p = sum(1 for a in recs if a["status"] == "Present")
        t = len(recs)
        marks = [m for m in mk if m["subject_id"] == s["id"]]
        got, mx = sum(m["marks"] for m in marks), sum(m["max_marks"] for m in marks)
        per.append(dict(id=s["id"], code=s["code"], name=s["name"], present=p, total=t,
                        pct=round(100.0 * p / t, 1) if t else None,
                        marks=marks, marks_pct=round(100.0 * got / mx, 1) if mx else None,
                        need=max(0, math.ceil(3 * t - 4 * p)) if t and 100.0 * p / t < ATT_THRESHOLD else 0))
    tp = sum(1 for a in att if a["status"] == "Present")
    tt = len(att)
    overall = round(100.0 * tp / tt, 1) if tt else None
    # cumulative trend (oldest -> newest)
    run_p = run_t = 0
    trend = []
    for a in reversed(att):
        run_t += 1
        run_p += a["status"] == "Present"
        trend.append(dict(date=a["att_date"], pct=round(100.0 * run_p / run_t, 1)))
    names = {s["id"]: s["code"] for s in subs}
    history = [dict(date=a["att_date"], subject=names.get(a["subject_id"], "-"), status=a["status"],
                    method=a["method"]) for a in att[:80]]
    return dict(subjects=per, overall=overall, present=tp, total=tt, trend=trend[-40:], history=history)


def recommendations(rep):
    tips = []
    ov = rep["overall"]
    if ov is None:
        tips.append(("info", "No attendance has been recorded yet. Your insights will appear after your first classes."))
    elif ov < ATT_THRESHOLD:
        tips.append(("danger", f"Your overall attendance is {ov}%, below the {int(ATT_THRESHOLD)}% requirement. "
                               "Attend every upcoming class and meet your faculty advisor."))
    elif ov < 80:
        tips.append(("warn", f"Overall attendance is {ov}% – close to the limit. Avoid any more absences."))
    else:
        tips.append(("good", f"Great consistency – overall attendance is {ov}%."))
    for s in rep["subjects"]:
        if s["pct"] is not None and s["pct"] < ATT_THRESHOLD:
            tips.append(("danger", f"{s['code']}: {s['pct']}% attendance. Attend the next {s['need']} class(es) "
                                   f"in a row to reach {int(ATT_THRESHOLD)}%."))
        elif s["pct"] is not None and s["pct"] < 80:
            tips.append(("warn", f"{s['code']}: {s['pct']}% is borderline – one or two absences could drop you below {int(ATT_THRESHOLD)}%."))
        if s["marks_pct"] is not None and s["marks_pct"] < 40:
            tips.append(("danger", f"{s['code']}: scoring {s['marks_pct']}%. Schedule revision sessions and "
                                   "practise previous question papers."))
        elif len(s["marks"]) >= 2:
            a, b = s["marks"][-2], s["marks"][-1]
            if b["marks"] / b["max_marks"] + 0.05 < a["marks"] / a["max_marks"]:
                tips.append(("warn", f"{s['code']}: your latest score ({b['exam_type']}) dropped compared with "
                                     f"{a['exam_type']}. Review the recent topics."))
    best = [s for s in rep["subjects"] if s["marks_pct"] is not None and s["marks_pct"] >= 75]
    if best:
        tips.append(("good", "Strong performance in " + ", ".join(s["code"] for s in best) + " – keep it up!"))
    return [dict(level=l, text=t) for l, t in tips]


_WRONG = {}   # student id -> timestamps of recent wrong codes (per process)


def _throttled(uid):
    now_t = time.time()
    hits = [t for t in _WRONG.get(uid, []) if now_t - t < 60]
    _WRONG[uid] = hits
    return len(hits) >= MAX_WRONG_CODES


def _student_me():
    return db.query_one(
        "SELECT u.*, d.name AS dept_name, d.code AS dept_code, s.name AS section_name "
        "FROM users u JOIN departments d ON d.id=u.department_id "
        "LEFT JOIN sections s ON s.id=u.section_id WHERE u.id=%s", (session["uid"],))


def _open_sessions_for(me):
    if not me["section_id"] or not me["year_no"]:
        return []
    return db.query(
        "SELECT cs.*, sb.code AS subject_code, sb.name AS subject_name FROM class_sessions cs "
        "JOIN subjects sb ON sb.id=cs.subject_id WHERE cs.status='open' AND cs.ends_at >= %s "
        "AND cs.department_id=%s AND cs.year_no=%s AND cs.section_id=%s ORDER BY cs.id",
        (now(), me["department_id"], me["year_no"], me["section_id"]))


@app.route("/student")
@role_required("student")
def student_dashboard():
    me = _student_me()
    rep = student_report(me["id"], me["year_no"], me["department_id"])
    tips = recommendations(rep)
    return render_template("student/dashboard.html", me=me, rep=rep, tips=tips, threshold=ATT_THRESHOLD)


def _stage(sess, me):
    if db.query_one("SELECT id FROM session_marks WHERE session_id=%s AND student_id=%s", (sess["id"], me["id"])):
        return "marked", ""
    ps = _state_row(sess["id"], me["id"])
    if ps and ps["review"] == "rejected":
        return "rejected", ""
    if ps and ps["decision"] == "blocked":
        return "blocked", (ps["reasons"] or "")
    if ps and ps["decision"] == "review":
        return "review", ""
    hint = ""
    if ps and ps["reasons"]:
        for r in ps["reasons"].split(" | "):
            if any(k in r for k in ("allow", "accurate", "Outside", "stay")):
                hint = r
                break
    return "verifying", hint


@app.route("/student/api/attendance/status")
@role_required("student")
def student_att_status():
    """Tells the student's page whether a class is open for check-in (never reveals the code)."""
    me = _student_me()
    out = []
    for s in _open_sessions_for(me):
        stage, hint = _stage(s, me)
        ends = datetime.strptime(s["ends_at"], "%Y-%m-%d %H:%M:%S")
        out.append(dict(id=s["id"], subject=f"{s['subject_code']} – {s['subject_name']}",
                        ends_in=max(0, int((ends - datetime.now()).total_seconds())),
                        needs_location=s["lat"] is not None, marked=stage == "marked", stage=stage, hint=hint))
    return jsonify(ok=True, sessions=out)


@app.route("/student/api/presence", methods=["POST"])
@role_required("student")
def student_presence():
    """Passive check-in: the student's open page sends a presence beacon every ~20 s and the AI engine
    decides (auto-mark / send to faculty review / nothing yet)."""
    d = request.get_json(silent=True) or {}
    device = str(d.get("device", ""))
    if not re.fullmatch(r"[A-Za-z0-9\-]{16,80}", device):
        return bad("This device could not be identified. Refresh the page and try again.")
    me = _student_me()
    results = []
    dev_hash = hashlib.sha256(device.encode()).hexdigest()
    ts = _now_ts()
    for sess in _open_sessions_for(me):
        stage, hint = _stage(sess, me)
        if stage in ("marked", "rejected", "blocked"):
            results.append(dict(id=sess["id"], stage=stage, hint=hint))
            continue
        row = _state_row(sess["id"], me["id"])
        if row and ts - row["last_ts"] < BEACON_GAP:
            results.append(dict(id=sess["id"], stage=stage, hint=hint))
            continue
        res = ai_evaluate(sess, me, dev_hash, d, request.remote_addr, row, ts)
        try:
            with db.transaction():
                for kind, detail in res["flags"]:
                    add_flag(sess["id"], me["id"], kind, detail)
                _save_state(sess["id"], me["id"], None if res["decision"] == "blocked" else dev_hash, res, ts, row)
                if res["decision"] == "auto":
                    existing = db.query_one(
                        "SELECT status FROM attendance WHERE student_id=%s AND subject_id=%s AND att_date=%s",
                        (me["id"], sess["subject_id"], sess["att_date"]))
                    if existing and existing["status"] == "Absent":
                        res["decision"] = "review"
                        db.execute("UPDATE presence_state SET decision='review' WHERE session_id=%s AND student_id=%s",
                                   (sess["id"], me["id"]), commit=False)
                    else:
                        if not db.query_one("SELECT device_hash FROM student_devices WHERE student_id=%s", (me["id"],)):
                            db.execute("INSERT INTO student_devices (student_id, device_hash, bound_at) VALUES (%s,%s,%s)",
                                       (me["id"], dev_hash, now()), commit=False)
                        db.execute("INSERT INTO session_marks (session_id, student_id, device_hash, distance_m, "
                                   "marked_at) VALUES (%s,%s,%s,%s,%s)",
                                   (sess["id"], me["id"], dev_hash,
                                    int(res["dist"]) if res["dist"] is not None else None, now()), commit=False)
                        upsert_attendance(me["id"], sess["subject_id"], "Present", "ai", f"session-{sess['id']}",
                                          sess["att_date"])
        except IntegrityViolation:
            add_flag(sess["id"], me["id"], "shared_device", "The same phone was used by two students in this class")
            results.append(dict(id=sess["id"], stage="blocked", hint="This phone is already used by another student"))
            continue
        if res["decision"] == "auto":
            audit("ai_auto_mark", f"session {sess['id']} score {res['score']}")
        stage, hint = _stage(sess, me)
        results.append(dict(id=sess["id"], stage=stage, hint=hint))
    return jsonify(ok=True, sessions=results)


@app.route("/student/api/attendance/mark", methods=["POST"])
@role_required("student")
def student_mark():
    d = request.get_json(silent=True) or {}
    code = str(d.get("code", "")).strip()
    device = str(d.get("device", ""))
    if not re.fullmatch(r"\d{6}", code):
        return bad("Enter the 6-digit code shown on your faculty's screen.")
    if not re.fullmatch(r"[A-Za-z0-9\-]{16,80}", device):
        return bad("This device could not be identified. Refresh the page and try again.")
    me = _student_me()
    if not me["section_id"] or not me["year_no"]:
        return bad("Your year/section is not set yet. Please contact the administrator.")
    if _throttled(me["id"]):
        return bad("Too many wrong codes. Wait one minute and try again.", 429)

    sessions = _open_sessions_for(me)
    if not sessions:
        return bad("No attendance session is open for your class right now.")
    sess = next((s for s in sessions if code_matches(s["secret"], code)), None)
    if not sess:
        _WRONG.setdefault(me["id"], []).append(time.time())
        audit("wrong_code", f"student {me['username']}")
        if _throttled(me["id"]):
            for s_ in sessions:
                add_flag(s_["id"], me["id"], "code_guessing", "Repeated wrong class codes")
        return bad("Invalid or expired code. Check the screen and enter the current code.")

    if db.query_one("SELECT id FROM session_marks WHERE session_id=%s AND student_id=%s", (sess["id"], me["id"])):
        return jsonify(ok=True, message="Your attendance is already marked for this class.", subject=sess["subject_code"])

    # --- device binding: one registered phone/browser per student, one student per phone
    dev_hash = hashlib.sha256(device.encode()).hexdigest()
    bound = db.query_one("SELECT device_hash FROM student_devices WHERE student_id=%s", (me["id"],))
    owner = db.query_one("SELECT student_id FROM student_devices WHERE device_hash=%s", (dev_hash,))
    if (bound and bound["device_hash"] != dev_hash) or (owner and owner["student_id"] != me["id"]):
        audit("device_mismatch", f"student {me['username']} session {sess['id']}")
        add_flag(sess["id"], me["id"], "device_mismatch", "Code entered from a phone registered to a different account")
        return bad("This is not the device registered for your account. Use your own phone, or ask the "
                   "administrator to reset your device.", 403)

    # --- geo-fence (only when the faculty locked the session to the classroom)
    distance = None
    if sess["lat"] is not None:
        lat, lon = _float(d.get("lat"), -90, 90), _float(d.get("lon"), -180, 180)
        acc = _float(d.get("accuracy"), 0, 100000)
        if lat is None or lon is None:
            return bad("Location is required for this class. Allow location access and try again.")
        acc = acc if acc is not None else 0
        if acc > max(150, sess["radius_m"]):
            return bad(f"Your location is not accurate enough (±{int(acc)} m). Turn on GPS and try again.")
        distance = haversine_m(sess["lat"], sess["lon"], lat, lon)
        if distance - acc > sess["radius_m"]:
            add_flag(sess["id"], me["id"], "code_far_away", f"Correct code entered {int(distance)} m from the classroom (code shared?)")
            return bad(f"You are about {int(distance)} m from the classroom. Attendance must be marked inside "
                       f"the class (within {sess['radius_m']} m).")

    existing = db.query_one("SELECT status FROM attendance WHERE student_id=%s AND subject_id=%s AND att_date=%s",
                            (me["id"], sess["subject_id"], sess["att_date"]))
    if existing and existing["status"] == "Absent":
        return bad("You were marked absent by your faculty for this class. Please contact them.")

    try:
        with db.transaction():
            if not bound:
                db.execute("INSERT INTO student_devices (student_id, device_hash, bound_at) VALUES (%s,%s,%s)",
                           (me["id"], dev_hash, now()), commit=False)
            db.execute("INSERT INTO session_marks (session_id, student_id, device_hash, distance_m, marked_at) "
                       "VALUES (%s,%s,%s,%s,%s)",
                       (sess["id"], me["id"], dev_hash, int(distance) if distance is not None else None, now()),
                       commit=False)
            upsert_attendance(me["id"], sess["subject_id"], "Present", "code", f"session-{sess['id']}",
                              sess["att_date"])
    except IntegrityViolation:
        return bad("This device was already used to mark attendance in this class.", 409)
    audit("attendance_marked", f"session {sess['id']}")
    return jsonify(ok=True, message="Attendance marked ✔", subject=sess["subject_code"])


# --------------------------------------------------------------------------- run
if __name__ == "__main__":
    try:
        bootstrap()
    except DatabaseError as exc:
        raise SystemExit(f"\nDatabase setup failed: {exc}\nCheck DB_HOST / DB_USER / DB_PASSWORD (see README.md).\n")
    print(f"\n Student portal : http://localhost:{os.getenv('PORT', '5000')}/student/login")
    print(f" Faculty portal : http://localhost:{os.getenv('PORT', '5000')}/faculty/login")
    print(f" ADMIN portal   : http://localhost:{os.getenv('PORT', '5000')}/{ADMIN_SLUG}   (secret - do not share)\n")
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")),
            debug=os.getenv("FLASK_DEBUG", "0") == "1")

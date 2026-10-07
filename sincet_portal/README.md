# SINCET – Smart Attendance & Student Performance Monitoring System

Flask + MySQL. **No camera, no face recognition, no extra hardware.**

## Three completely separate portals
| Portal | URL | Notes |
|---|---|---|
| Student | `/student/login` | sees only own profile, attendance, marks, insights |
| Faculty | `/faculty/login` | own profile, run attendance sessions, class reports |
| **Admin** | **secret URL** (printed when the server starts, stored in `.admin_path`) | never linked from any page; `/admin/...` returns 404 to everyone not signed in as admin |

Each portal has its own login page **and its own session cookie**, so a student, a faculty member and the admin can be
signed in at the same time in one browser without ever sharing a session. A faculty account cannot sign in on the student
page (and vice-versa).

Admin hardening: change the secret URL with `ADMIN_LOGIN_PATH=my-private-slug`, and optionally restrict to your office
network with `ADMIN_ALLOWED_IPS=192.168.1.10,192.168.1.11`. First run creates the admin from `ADMIN_USERNAME`
(default `admin`) / `ADMIN_PASSWORD`; if you don't set a password a random one is printed once in the console.

## How attendance works - the AI attendance engine (automatic, hardware-free)
Faculty presses **Start AI attendance** (Dept → Year → Section → Subject; optional classroom GPS lock). Students just sign in
on their own phone and keep the page open - nobody types anything. Every ~20 s the student page sends a presence beacon and the
engine produces an explainable **confidence score (0-100)**:

| Signal | Points |
|---|---|
| Registered phone (device binding) | 25 (15 for a brand-new phone, registered on first success) |
| Place proof: GPS inside the class area (50 if accurate, 35 if coarse) / same campus network as faculty (+20) / valid class code (+50) | up to 50 |
| Steady presence for 60 s (3+ beacons) | up to 25 |
| Penalties | impossible location jump -40, frozen/mock GPS -30 |

Decision: **≥ 90 → AI marks Present by itself** · **60-89 after a fair observation time, or any suspicious flag → faculty review
queue** · otherwise keep verifying. Hard blocks (never auto): attendance attempted from a phone registered to another student, or one
phone used by two students in the same class. Faculty only touches the **review queue** (Approve / Reject, even after the session
has closed). When the session ends (or its timer expires) everybody not marked is set to Absent automatically.

Proxy detection flags (shown to faculty with the reason): `device_mismatch`, `shared_device`, `teleport`, `static_gps`,
`outside_area`, `code_far_away`, `code_guessing`. A rotating 6-digit class code (changes every 30 s) remains as a backup for a student whose GPS fails.

Honest limits: this is a rule-based, explainable scoring engine (no camera/biometrics); a determined cheater with a spoofed GPS
and a cloned browser profile is *reduced*, not eliminated - which is why doubtful cases go to the faculty. The student's page must
stay open during the class. Browser GPS needs **HTTPS** (or localhost); without GPS only "same network" + registered phone are
available and those cases go to review.

## Run
1. Python 3.10+ and MySQL 8. `pip install -r requirements.txt`
2. Set DB login (database + tables are created automatically):
   - Windows CMD: `set DB_USER=root` / `set DB_PASSWORD=yourpassword`; PowerShell: `$env:DB_USER="root"; $env:DB_PASSWORD="yourpassword"`
   - Linux/Mac: `export DB_USER=root DB_PASSWORD=yourpassword`
3. `python app.py` – the three URLs (incl. the secret admin URL) are printed.
4. Optional demo data: `python seed_demo.py` (writes `demo_credentials.csv`).

Upgrading an existing database: just start the new version – new tables (`class_sessions`, `session_marks`,
`student_devices`, `presence_state`, `presence_flags`) are created automatically; old data is kept (the unused `face_descriptor` column is simply ignored).

## Admin features
Dashboard + charts, generate faculty/student accounts (hashed one-time passwords, forced change at first login), manage
users (search/filter/edit/deactivate/reset password/reset device/delete, CSV & PDF export), departments, sections, subjects,
attendance and marks records, generation history. Security: roles, CSRF, lock after 5 failed logins, 15-min idle timeout,
audit log, parameterised SQL.

Production: set `SECRET_KEY`, `COOKIE_SECURE=1` (HTTPS) and run with waitress/gunicorn (single process, as the wrong-code
throttle is in memory).

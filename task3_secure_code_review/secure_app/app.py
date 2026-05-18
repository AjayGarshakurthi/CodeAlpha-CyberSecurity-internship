"""
SECURE WEB APPLICATION — REMEDIATED VERSION
============================================
This is the fixed version of vulnerable_app/app.py.
Every vulnerability from the audit has been addressed.

CodeAlpha Cybersecurity Internship — Task 3
"""

import os
import datetime
import secrets
import logging

import bcrypt
from flask import (Flask, request, render_template, redirect,
                   session, url_for, abort, g)
from flask_wtf import CSRFProtect
from markupsafe import escape
from werkzeug.utils import secure_filename
import sqlite3

# ── App setup ─────────────────────────────────────────────────
app = Flask(__name__)

# FIX-01: Secret key loaded from environment variable, never hardcoded
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# FIX-02: CSRF protection on all POST forms
csrf = CSRFProtect(app)

# FIX-03: Secure session cookie settings
app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SECURE   = True,   # HTTPS only in production
    SESSION_COOKIE_SAMESITE = "Lax",
    PERMANENT_SESSION_LIFETIME = datetime.timedelta(hours=1),
    MAX_CONTENT_LENGTH      = 2 * 1024 * 1024,   # 2 MB upload limit
)

# FIX-04: Structured logging (no sensitive data)
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# FIX-05: Allowed upload extensions whitelist
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt"}
UPLOAD_FOLDER      = os.environ.get("UPLOAD_FOLDER", "/tmp/uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ── Database ──────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "/tmp/secure_app.db")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,   -- bcrypt hash
                role     TEXT NOT NULL DEFAULT 'user'
            )
        """)
        # FIX-06: Passwords hashed with bcrypt (salted, slow)
        admin_hash = bcrypt.hashpw(
            os.environ.get("ADMIN_PASSWORD", "change-me-in-env").encode(),
            bcrypt.gensalt(rounds=12)
        )
        db.execute(
            "INSERT OR IGNORE INTO users (id,username,password,role) VALUES (1,?,?,'admin')",
            ("admin", admin_hash.decode())
        )
        db.commit()


# ── Auth helpers ──────────────────────────────────────────────
def login_required(f):
    """Decorator: redirect to login if not authenticated."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator: 403 if not admin role (checked server-side)."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated

def allowed_file(filename: str) -> bool:
    return ("." in filename and
            filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS)


# ── Routes ────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    """FIX-07: Parameterised query + bcrypt verification + session regeneration."""
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # FIX-08: Parameterised query — no SQL injection possible
        db   = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # FIX-09: Constant-time bcrypt comparison
        if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
            # FIX-10: Regenerate session on login to prevent session fixation
            session.clear()
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            session.permanent   = True
            logger.info("Login success: user=%s", username)
            return redirect(url_for("dashboard"))
        else:
            # FIX-11: Generic error — don't reveal whether user exists
            error = "Invalid username or password."
            logger.warning("Login failure: user=%s", username)

    # FIX-12: Use a static template file with auto-escaping (no render_template_string)
    return render_template("login.html", error=error)


@app.route("/dashboard")
@login_required   # FIX-13: Authentication enforced via decorator
def dashboard():
    return render_template("dashboard.html", username=session["username"])


@app.route("/search")
@login_required
def search():
    """FIX-14: Parameterised LIKE query + Jinja2 auto-escaping."""
    query   = request.args.get("q", "").strip()
    results = []
    if query:
        db      = get_db()
        # Parameterised — safe from SQL injection
        results = db.execute(
            "SELECT username, role FROM users WHERE username LIKE ?",
            (f"%{query}%",)
        ).fetchall()
    return render_template("search.html", query=query, results=results)


@app.route("/ping")
@login_required
def ping():
    """FIX-15: No shell=True; input validated against strict allowlist."""
    import subprocess, re
    host = request.args.get("host", "").strip()

    # Strict allowlist: only valid hostnames/IPs
    if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
        abort(400, "Invalid host format.")

    # FIX-16: Command as list, shell=False — no injection possible
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True, text=True,
            timeout=5, shell=False
        )
        output = escape(result.stdout + result.stderr)
    except subprocess.TimeoutExpired:
        output = "Request timed out."
    return render_template("ping.html", host=escape(host), output=output)


@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    """FIX-17: IDOR fixed — users can only view their own profile; admins see all."""
    if session["role"] != "admin" and session["user_id"] != user_id:
        abort(403)
    db   = get_db()
    user = db.execute(
        "SELECT username, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not user:
        abort(404)
    return render_template("profile.html", user=user)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    """FIX-18: File type validation + secure_filename + size limit."""
    f = request.files.get("file")
    if not f or f.filename == "":
        abort(400, "No file provided.")

    # FIX-19: Validate extension
    if not allowed_file(f.filename):
        abort(400, f"File type not allowed. Permitted: {', '.join(ALLOWED_EXTENSIONS)}")

    # FIX-20: Sanitise filename — prevents path traversal
    safe_name = secure_filename(f.filename)
    save_path = os.path.join(UPLOAD_FOLDER, safe_name)

    # FIX-21: Confirm resolved path stays inside upload folder
    if not os.path.realpath(save_path).startswith(os.path.realpath(UPLOAD_FOLDER)):
        abort(400, "Invalid file path.")

    f.save(save_path)
    logger.info("File uploaded: %s by user_id=%s", safe_name, session["user_id"])
    return render_template("upload_ok.html", filename=safe_name)


@app.route("/export")
@login_required
def export():
    """FIX-22: No pickle deserialization; path traversal prevented."""
    # FIX-23: Whitelist allowed filenames — no user-controlled path
    ALLOWED_REPORTS = {"report.json", "summary.json"}
    filename = request.args.get("file", "report.json")

    if filename not in ALLOWED_REPORTS:
        abort(400, "Invalid report name.")

    data_dir = os.environ.get("DATA_DIR", "/var/data")
    filepath = os.path.join(data_dir, filename)

    # Double-check resolved path
    if not os.path.realpath(filepath).startswith(os.path.realpath(data_dir)):
        abort(400)

    try:
        with open(filepath) as fh:
            return fh.read(), 200, {"Content-Type": "application/json"}
    except FileNotFoundError:
        abort(404)


@app.route("/admin")
@login_required
@admin_required   # FIX-24: Role checked server-side from signed session
def admin_panel():
    db    = get_db()
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/reset_password", methods=["POST"])
@login_required
# CSRF token automatically validated by Flask-WTF (FIX-25)
def reset_password():
    """FIX-26: bcrypt hashing + CSRF protection."""
    new_pass = request.form.get("password", "")
    if len(new_pass) < 12:
        abort(400, "Password must be at least 12 characters.")

    hashed = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt(rounds=12)).decode()
    db     = get_db()
    db.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (hashed, session["user_id"])
    )
    db.commit()
    logger.info("Password changed for user_id=%s", session["user_id"])
    return render_template("password_ok.html")


@app.route("/redirect")
def safe_redirect():
    """FIX-27: Open redirect fixed — only allow relative paths."""
    url = request.args.get("url", "/")
    # Reject anything with a scheme (http://, https://, //)
    if url.startswith(("http://", "https://", "//", "javascript:")):
        url = "/"
    return redirect(url)


# FIX-28: No /debug endpoint in production
# FIX-29: Debug mode controlled by environment variable only
if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    # FIX-30: Bind to localhost only in development
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)

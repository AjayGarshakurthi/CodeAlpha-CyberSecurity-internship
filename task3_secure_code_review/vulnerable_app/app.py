"""
VULNERABLE WEB APPLICATION — AUDIT TARGET
==========================================
This file is INTENTIONALLY INSECURE for educational purposes.
It demonstrates common real-world vulnerabilities found in Python/Flask apps.
DO NOT deploy this in any real environment.

CodeAlpha Cybersecurity Internship — Task 3
"""

from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import os
import subprocess
import pickle
import hashlib

app = Flask(__name__)

# VULN-01: Hardcoded secret key — trivially guessable
app.secret_key = "secret123"

# VULN-02: Hardcoded credentials in source code
DB_PASSWORD = "admin:password123"
ADMIN_USER  = "admin"
ADMIN_PASS  = "password123"

# ── Database setup ────────────────────────────────────────────
def get_db():
    # VULN-03: Database file in web-accessible directory
    conn = sqlite3.connect("users.db")
    return conn

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users
                    (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)""")
    # VULN-04: Passwords stored as plain MD5 (no salt)
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','" +
                 hashlib.md5(b"password123").hexdigest() + "','admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','" +
                 hashlib.md5(b"alice123").hexdigest() + "','user')")
    conn.commit()
    conn.close()


# ── Routes ────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULN-05: SQL Injection — user input directly concatenated into query
        query = "SELECT * FROM users WHERE username='" + username + \
                "' AND password='" + hashlib.md5(password.encode()).hexdigest() + "'"
        conn = get_db()
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            session["user"]  = user[1]
            session["role"]  = user[3]
            # VULN-06: No session expiry / regeneration after login
            return redirect("/dashboard")
        else:
            error = "Invalid credentials"

    # VULN-07: Reflected XSS — error message rendered without escaping
    template = """
    <html><body>
    <h2>Login</h2>
    <form method="POST">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <input type="submit" value="Login">
    </form>
    <p style="color:red">""" + error + """</p>
    </body></html>
    """
    return render_template_string(template)


@app.route("/dashboard")
def dashboard():
    # VULN-08: Missing authentication check — anyone can access
    user = session.get("user", "Guest")
    return f"<h1>Welcome {user}</h1><a href='/search'>Search</a> | <a href='/ping'>Ping</a>"


@app.route("/search")
def search():
    query = request.args.get("q", "")
    conn  = get_db()

    # VULN-09: SQL Injection (GET parameter)
    results = conn.execute("SELECT username, role FROM users WHERE username LIKE '%" + query + "%'").fetchall()
    conn.close()

    # VULN-10: Stored/Reflected XSS — query reflected without escaping
    output = f"<h2>Results for: {query}</h2><ul>"
    for row in results:
        output += f"<li>{row[0]} ({row[1]})</li>"
    output += "</ul>"
    return output


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")

    # VULN-11: OS Command Injection — user input passed directly to shell
    result = subprocess.check_output("ping -c 1 " + host, shell=True,
                                     stderr=subprocess.STDOUT)
    return f"<pre>{result.decode()}</pre>"


@app.route("/profile/<username>")
def profile(username):
    # VULN-12: Insecure Direct Object Reference (IDOR) — no ownership check
    conn = get_db()
    user = conn.execute("SELECT username, role FROM users WHERE username=?",
                        (username,)).fetchone()
    conn.close()
    if user:
        return f"<p>User: {user[0]}, Role: {user[1]}</p>"
    return "Not found", 404


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if f:
        # VULN-13: Unrestricted file upload — no type/size validation
        # VULN-14: Path traversal — filename not sanitised
        f.save(os.path.join("/var/uploads", f.filename))
        return "Uploaded"
    return "No file", 400


@app.route("/export")
def export():
    fmt = request.args.get("format", "json")

    # VULN-15: Insecure deserialization — pickle from user-controlled data
    data = request.args.get("data", "")
    if data:
        obj = pickle.loads(bytes.fromhex(data))   # arbitrary code execution
        return str(obj)

    # VULN-16: Path traversal in file read
    filename = request.args.get("file", "report.json")
    filepath = "/var/data/" + filename            # no sanitisation
    with open(filepath) as fh:
        return fh.read()


@app.route("/admin")
def admin():
    # VULN-17: Broken access control — role check uses client-supplied cookie
    role = request.cookies.get("role", "user")
    if role != "admin":
        return "Forbidden", 403
    return "<h1>Admin Panel</h1>"


@app.route("/debug")
def debug():
    # VULN-18: Debug endpoint left in production — exposes env vars & config
    env_dump = dict(os.environ)
    return str(env_dump)


@app.route("/redirect")
def open_redirect():
    # VULN-19: Open redirect — destination not validated
    url = request.args.get("url", "/")
    return redirect(url)


@app.route("/reset_password", methods=["POST"])
def reset_password():
    # VULN-20: Missing CSRF protection on state-changing endpoint
    new_pass = request.form.get("password", "")
    user     = session.get("user")
    if user:
        conn = get_db()
        conn.execute("UPDATE users SET password=? WHERE username=?",
                     (hashlib.md5(new_pass.encode()).hexdigest(), user))
        conn.commit()
        conn.close()
        return "Password updated"
    return "Not logged in", 401


if __name__ == "__main__":
    init_db()
    # VULN-21: Debug mode enabled in production — exposes stack traces
    app.run(debug=True, host="0.0.0.0", port=5000)

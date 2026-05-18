# Task 3 — Secure Coding Review

## CodeAlpha Cybersecurity Internship

---

## Project Structure

```
task3_secure_code_review/
├── reviewer.py              ← Static analysis tool (run this)
├── findings_report.html     ← Pre-generated HTML findings report
├── vulnerable_app/
│   └── app.py               ← Intentionally vulnerable Flask app (audit target)
└── secure_app/
    ├── app.py               ← Fully remediated secure version
    └── requirements.txt     ← Dependencies for secure app
```

---

## What Was Audited

**Target:** `vulnerable_app/app.py` — a Python/Flask web application  
**Method:** Manual inspection + custom static analyzer (`reviewer.py`)  
**Language:** Python 3 / Flask

---

## Vulnerabilities Found: 21

| Severity | Count | Examples |
|----------|-------|---------|
| 🔴 CRITICAL | 5 | SQL Injection, Command Injection, Pickle RCE, Hardcoded Creds |
| 🟠 HIGH | 9 | SSTI, XSS, MD5 hashing, Path Traversal, Debug mode |
| 🟡 MEDIUM | 5 | CSRF, IDOR, Open Redirect, Unrestricted Upload |
| 🔵 LOW | 1 | Sensitive data in logs |
| ⚪ INFO | 1 | Security TODO comments |

---

## Running the Static Analyzer

```bash
# Install dependencies (none required for reviewer.py — stdlib only)
python reviewer.py

# Scan the vulnerable app (default)
python reviewer.py vulnerable_app/app.py

# Scan a directory
python reviewer.py vulnerable_app/

# Save HTML + JSON reports
python reviewer.py vulnerable_app/app.py --html my_report.html --json findings.json

# Show only HIGH and above
python reviewer.py vulnerable_app/app.py --min-severity HIGH
```

The tool outputs:
- Colour-coded terminal report with line numbers and fix recommendations
- `report.html` — full interactive HTML findings report
- Optional JSON export for CI/CD integration

---

## Vulnerability Summary

### CRITICAL

| ID | Vulnerability | CWE | Line |
|----|--------------|-----|------|
| SQL-01 | SQL Injection — login (string concat) | CWE-89 | 47 |
| SQL-02 | SQL Injection — search (GET param) | CWE-89 | 68 |
| CMD-01 | OS Command Injection (shell=True) | CWE-78 | 76 |
| CRED-01 | Hardcoded credentials + secret key | CWE-798 | 18–20 |
| DESER-01 | Insecure Deserialization — pickle RCE | CWE-502 | 97 |

### HIGH

| ID | Vulnerability | CWE | Line |
|----|--------------|-----|------|
| TMPL-01 | Server-Side Template Injection (SSTI) | CWE-94 | 55 |
| XSS-01 | Reflected XSS in search results | CWE-79 | 68 |
| CRYPT-01 | MD5 password hashing (no salt) | CWE-327 | 30 |
| PATH-01 | Path Traversal in file upload/export | CWE-22 | 86 |
| AUTH-01 | Role check from client cookie | CWE-284 | 110 |
| AUTH-02 | Missing authentication on dashboard | CWE-284 | 62 |
| CFG-01 | Debug mode enabled in production | CWE-94 | 130 |
| CRED-02 | Weak/guessable secret key | CWE-798 | 18 |
| CMD-02 | os.system() usage | CWE-78 | — |

### MEDIUM

| ID | Vulnerability | CWE | Line |
|----|--------------|-----|------|
| CSRF-01 | Missing CSRF on password reset | CWE-352 | 123 |
| AUTH-03 | IDOR on profile endpoint | CWE-639 | 80 |
| PATH-02 | Unrestricted file upload | CWE-22 | 86 |
| CFG-02 | Binding to 0.0.0.0 | CWE-605 | 130 |
| CFG-03 | /debug endpoint exposes env vars | CWE-215 | 115 |
| CFG-04 | Open redirect | CWE-601 | 120 |

---

## Key Fixes Applied in `secure_app/app.py`

| # | Vulnerable Code | Secure Code |
|---|----------------|-------------|
| 1 | `"SELECT ... WHERE user='" + username` | `db.execute("SELECT ... WHERE user=?", (username,))` |
| 2 | `subprocess.check_output("ping " + host, shell=True)` | `subprocess.run(["ping", "-c", "1", host], shell=False)` |
| 3 | `pickle.loads(bytes.fromhex(data))` | Removed — use JSON + pydantic |
| 4 | `app.secret_key = "secret123"` | `os.environ["FLASK_SECRET_KEY"]` |
| 5 | `hashlib.md5(password.encode())` | `bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))` |
| 6 | `render_template_string("..." + error)` | `render_template("login.html", error=error)` |
| 7 | `f.save(os.path.join(dir, f.filename))` | `secure_filename()` + `os.path.realpath()` check |
| 8 | `request.cookies.get("role")` | `session.get("role")` (server-side, signed) |
| 9 | `app.run(debug=True, host="0.0.0.0")` | `debug=False`, `host="127.0.0.1"` |
| 10 | No CSRF tokens | `CSRFProtect(app)` via Flask-WTF |

---

## Secure Coding Best Practices

1. **Never trust user input** — validate, sanitise, and parameterise everything
2. **Use parameterised queries** — the only reliable SQL injection defence
3. **Hash passwords with bcrypt/argon2** — never MD5/SHA1, never unsalted
4. **Load secrets from environment variables** — never hardcode in source
5. **Disable debug mode in production** — it's a remote code execution risk
6. **Use static templates** — never build HTML/templates from user strings
7. **Validate file uploads** — extension whitelist + size limit + path check
8. **Store roles server-side** — never read privilege levels from cookies
9. **Add CSRF tokens** to all state-changing forms
10. **Apply least privilege** — every route should check authentication and authorisation

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `reviewer.py` | Custom regex-based static analyzer (25 rules, 10 categories) |
| Manual inspection | Logic flaws, IDOR, missing auth checks |
| OWASP Top 10 | Vulnerability classification framework |
| CWE database | Weakness enumeration and categorisation |

---

## View the Report

Open `findings_report.html` in any browser for the full interactive findings report.

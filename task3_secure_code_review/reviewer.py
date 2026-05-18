"""
Static Security Code Reviewer
CodeAlpha Cybersecurity Internship - Task 3

Scans Python source files for common security vulnerabilities using
regex-based pattern matching. Generates a detailed findings report
in both terminal (colour) and HTML formats.
"""

import re
import os
import sys
import json
import argparse
import datetime
from pathlib import Path

# ── Colour helpers ────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    WHITE   = "\033[97m"

def col(text, color): return f"{color}{text}{C.RESET}"

# ── Severity levels ───────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEV_COLOR = {
    CRITICAL: C.RED,
    HIGH:     C.RED,
    MEDIUM:   C.YELLOW,
    LOW:      C.CYAN,
    INFO:     C.WHITE,
}

SEV_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

# ═══════════════════════════════════════════════════════════════
#  VULNERABILITY RULES
#  Each rule: (id, severity, name, regex_pattern, description,
#              recommendation, cwe)
# ═══════════════════════════════════════════════════════════════

RULES = [
    # ── Injection ──────────────────────────────────────────────
    (
        "SQL-01", CRITICAL, "SQL Injection (string concat)",
        r'execute\s*\(\s*["\'].*\+|execute\s*\(\s*f["\'].*\{',
        "User-controlled data concatenated directly into SQL query string.",
        "Use parameterised queries: cursor.execute('SELECT ... WHERE x=?', (val,))",
        "CWE-89"
    ),
    (
        "SQL-02", HIGH, "SQL Injection (% formatting)",
        r'execute\s*\(.*%\s*[(\w]',
        "SQL query built with % string formatting — injectable.",
        "Replace with parameterised queries using ? or %s placeholders.",
        "CWE-89"
    ),
    (
        "CMD-01", CRITICAL, "OS Command Injection",
        r'(subprocess\.(call|run|check_output|Popen)|os\.system)\s*\(.*shell\s*=\s*True',
        "shell=True with dynamic input allows arbitrary command execution.",
        "Pass commands as a list (no shell=True). Validate/whitelist all inputs.",
        "CWE-78"
    ),
    (
        "CMD-02", HIGH, "os.system() usage",
        r'\bos\.system\s*\(',
        "os.system() is vulnerable to shell injection and should be avoided.",
        "Use subprocess with a list of arguments and shell=False.",
        "CWE-78"
    ),
    (
        "TMPL-01", HIGH, "Server-Side Template Injection",
        r'render_template_string\s*\(.*\+|render_template_string\s*\(.*%|render_template_string\s*\(.*f["\']',
        "Dynamic string passed to render_template_string() — SSTI risk.",
        "Never build templates from user input. Use static template files with context variables.",
        "CWE-94"
    ),

    # ── Cryptography ───────────────────────────────────────────
    (
        "CRYPT-01", HIGH, "Weak Hash — MD5",
        r'\bhashlib\.md5\b',
        "MD5 is cryptographically broken and unsuitable for password hashing.",
        "Use bcrypt, argon2-cffi, or hashlib.scrypt with a random salt.",
        "CWE-327"
    ),
    (
        "CRYPT-02", HIGH, "Weak Hash — SHA1",
        r'\bhashlib\.sha1\b',
        "SHA-1 is deprecated for security use.",
        "Use SHA-256 minimum for integrity checks; bcrypt/argon2 for passwords.",
        "CWE-327"
    ),
    (
        "CRYPT-03", MEDIUM, "Hardcoded secret key",
        r'secret_key\s*=\s*["\'][^"\']{1,30}["\']',
        "Hardcoded Flask/Django secret key found in source.",
        "Load secret keys from environment variables or a secrets manager.",
        "CWE-321"
    ),

    # ── Sensitive Data ─────────────────────────────────────────
    (
        "CRED-01", CRITICAL, "Hardcoded Password",
        r'(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']',
        "Plaintext password hardcoded in source code.",
        "Use environment variables (os.environ) or a vault (HashiCorp Vault, AWS Secrets Manager).",
        "CWE-798"
    ),
    (
        "CRED-02", HIGH, "Hardcoded API Key / Token",
        r'(api_key|apikey|token|secret)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']',
        "Hardcoded API key or token found.",
        "Store secrets in environment variables or a secrets manager, never in source.",
        "CWE-798"
    ),

    # ── Deserialization ────────────────────────────────────────
    (
        "DESER-01", CRITICAL, "Insecure Deserialization — pickle",
        r'\bpickle\.(loads|load)\b',
        "pickle.loads() on untrusted data allows arbitrary code execution.",
        "Never deserialize untrusted data with pickle. Use JSON or a safe schema validator.",
        "CWE-502"
    ),
    (
        "DESER-02", HIGH, "Insecure Deserialization — yaml.load",
        r'\byaml\.load\s*\([^,)]+\)',
        "yaml.load() without Loader= is unsafe.",
        "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
        "CWE-502"
    ),

    # ── Path Traversal ─────────────────────────────────────────
    (
        "PATH-01", HIGH, "Path Traversal",
        r'open\s*\(\s*[^)]*\+|os\.path\.join\s*\([^)]*request\.',
        "File path constructed from user input without sanitisation.",
        "Use os.path.basename(), validate against an allowed directory with os.path.realpath().",
        "CWE-22"
    ),
    (
        "PATH-02", MEDIUM, "Unsafe file save (user-supplied filename)",
        r'\.save\s*\(\s*os\.path\.join\s*\([^)]*\.filename',
        "File saved using client-supplied filename — path traversal risk.",
        "Use werkzeug.utils.secure_filename() and validate file extension and size.",
        "CWE-22"
    ),

    # ── Access Control ─────────────────────────────────────────
    (
        "AUTH-01", HIGH, "Auth check from client-supplied cookie",
        r'request\.cookies\.get\s*\(["\']role["\']',
        "Role/privilege read directly from a client cookie — trivially forgeable.",
        "Store roles server-side in the session (signed) or database, never in plain cookies.",
        "CWE-284"
    ),
    (
        "AUTH-02", MEDIUM, "Open Redirect",
        r'redirect\s*\(\s*request\.(args|form|values)\.get',
        "Redirect destination taken from user input without validation.",
        "Validate redirect URLs against an allowlist of trusted domains.",
        "CWE-601"
    ),

    # ── Configuration ──────────────────────────────────────────
    (
        "CFG-01", HIGH, "Debug mode enabled",
        r'app\.run\s*\(.*debug\s*=\s*True',
        "Flask debug mode exposes an interactive debugger and stack traces.",
        "Set debug=False in production. Use environment variable: DEBUG=False.",
        "CWE-94"
    ),
    (
        "CFG-02", MEDIUM, "Binding to all interfaces (0.0.0.0)",
        r'app\.run\s*\(.*host\s*=\s*["\']0\.0\.0\.0["\']',
        "App bound to all network interfaces — exposed beyond localhost.",
        "Bind to 127.0.0.1 in development. Use a reverse proxy (nginx) in production.",
        "CWE-605"
    ),
    (
        "CFG-03", MEDIUM, "Debug/info endpoint exposed",
        r'@app\.route\s*\(["\']\/debug|@app\.route\s*\(["\']\/env|@app\.route\s*\(["\']\/config',
        "Debug or configuration endpoint accessible via HTTP.",
        "Remove debug endpoints before deployment or protect with strong authentication.",
        "CWE-215"
    ),

    # ── XSS ────────────────────────────────────────────────────
    (
        "XSS-01", HIGH, "Reflected XSS — unescaped f-string in response",
        r'return\s+f["\'].*\{.*request\.(args|form|values)',
        "User input from request reflected directly into HTTP response.",
        "Use Jinja2 templates with auto-escaping, or escape() from markupsafe.",
        "CWE-79"
    ),

    # ── CSRF ───────────────────────────────────────────────────
    (
        "CSRF-01", MEDIUM, "Missing CSRF protection (POST route)",
        r'@app\.route\s*\([^)]*methods.*POST.*\)\s*\ndef\s+\w+[^:]*:\s*\n(?!.*csrf)',
        "POST endpoint with no CSRF token validation detected.",
        "Use Flask-WTF or implement CSRF tokens manually on all state-changing forms.",
        "CWE-352"
    ),

    # ── Logging ────────────────────────────────────────────────
    (
        "LOG-01", LOW, "Sensitive data in print/log statement",
        r'print\s*\(.*(?:password|token|secret|key)',
        "Potentially sensitive value passed to print() — may appear in logs.",
        "Never log credentials. Redact sensitive fields before logging.",
        "CWE-532"
    ),

    # ── Misc ───────────────────────────────────────────────────
    (
        "MISC-01", LOW, "Use of assert for security checks",
        r'\bassert\b.*(?:auth|role|admin|permission)',
        "assert statements are stripped in optimised Python (-O flag).",
        "Replace security-critical asserts with explicit if/raise checks.",
        "CWE-617"
    ),
    (
        "MISC-02", INFO, "TODO / FIXME security note",
        r'#\s*(TODO|FIXME|HACK|XXX).*(?:security|auth|sql|inject|vuln)',
        "Developer left a security-related TODO comment.",
        "Resolve all security TODOs before deployment.",
        "CWE-1164"
    ),
]


# ═══════════════════════════════════════════════════════════════
#  SCANNER
# ═══════════════════════════════════════════════════════════════

class Finding:
    def __init__(self, rule_id, severity, name, cwe, file, line_no, line, description, recommendation):
        self.rule_id        = rule_id
        self.severity       = severity
        self.name           = name
        self.cwe            = cwe
        self.file           = file
        self.line_no        = line_no
        self.line           = line.strip()
        self.description    = description
        self.recommendation = recommendation

    def to_dict(self):
        return {
            "id":             self.rule_id,
            "severity":       self.severity,
            "name":           self.name,
            "cwe":            self.cwe,
            "file":           self.file,
            "line":           self.line_no,
            "code":           self.line,
            "description":    self.description,
            "recommendation": self.recommendation,
        }


def scan_file(filepath: str) -> list[Finding]:
    findings = []
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as e:
        print(col(f"[!] Cannot read {filepath}: {e}", C.RED))
        return findings

    compiled = [(rid, sev, name, re.compile(pat, re.IGNORECASE), desc, rec, cwe)
                for rid, sev, name, pat, desc, rec, cwe in RULES]

    for lineno, line in enumerate(lines, 1):
        # Skip comment-only lines for most rules
        stripped = line.strip()
        if stripped.startswith("#"):
            # Still check MISC-02 (TODO comments)
            for rid, sev, name, pattern, desc, rec, cwe in compiled:
                if rid == "MISC-02" and pattern.search(line):
                    findings.append(Finding(rid, sev, name, cwe, filepath, lineno, line, desc, rec))
            continue

        for rid, sev, name, pattern, desc, rec, cwe in compiled:
            if rid == "MISC-02":
                continue
            if pattern.search(line):
                findings.append(Finding(rid, sev, name, cwe, filepath, lineno, line, desc, rec))

    return findings


def scan_path(target: str) -> list[Finding]:
    all_findings = []
    p = Path(target)
    if p.is_file():
        all_findings = scan_file(str(p))
    elif p.is_dir():
        for py_file in sorted(p.rglob("*.py")):
            all_findings.extend(scan_file(str(py_file)))
    else:
        print(col(f"[!] Path not found: {target}", C.RED))
    return all_findings


# ═══════════════════════════════════════════════════════════════
#  TERMINAL REPORT
# ═══════════════════════════════════════════════════════════════

def print_terminal_report(findings: list[Finding], target: str):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"""
{col('╔══════════════════════════════════════════════════════════╗', C.CYAN)}
{col('║        SECURE CODE REVIEW — STATIC ANALYZER             ║', C.CYAN)}
{col('║        CodeAlpha Cybersecurity Internship — Task 3       ║', C.CYAN)}
{col('╚══════════════════════════════════════════════════════════╝', C.CYAN)}
  Target  : {col(target, C.WHITE)}
  Scanned : {col(ts, C.WHITE)}
  Rules   : {col(str(len(RULES)), C.WHITE)}
""")

    if not findings:
        print(col("  ✅  No issues found.", C.GREEN))
        return

    # Sort by severity then file/line
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], f.file, f.line_no))

    # Counts
    counts = {s: 0 for s in [CRITICAL, HIGH, MEDIUM, LOW, INFO]}
    for f in findings:
        counts[f.severity] += 1

    print(col("  SUMMARY", C.BOLD))
    print("  " + "─" * 50)
    for sev, cnt in counts.items():
        if cnt:
            bar = col("█" * min(cnt * 3, 30), SEV_COLOR[sev])
            print(f"  {col(f'{sev:<10}', SEV_COLOR[sev])} {cnt:>3}  {bar}")
    print(f"\n  {col('TOTAL', C.BOLD)}      {len(findings)}\n")

    # Detailed findings
    print(col("  FINDINGS", C.BOLD))
    print("  " + "═" * 60)

    for i, f in enumerate(findings, 1):
        sev_label = col(f"[{f.severity}]", SEV_COLOR[f.severity])
        print(f"\n  {col(str(i).zfill(2), C.BLUE)}. {sev_label} {col(f.name, C.BOLD)}")
        print(f"      {col('Rule        :', C.CYAN)} {f.rule_id}  ({f.cwe})")
        print(f"      {col('Location    :', C.CYAN)} {f.file}:{f.line_no}")
        print(f"      {col('Code        :', C.YELLOW)} {f.line[:100]}")
        print(f"      {col('Description :', C.WHITE)} {f.description}")
        print(f"      {col('Fix         :', C.GREEN)} {f.recommendation}")

    print(f"\n  {'═' * 60}")
    print(f"  {col('Scan complete.', C.BOLD)} {len(findings)} issue(s) found.\n")


# ═══════════════════════════════════════════════════════════════
#  HTML REPORT
# ═══════════════════════════════════════════════════════════════

SEV_HTML_COLOR = {
    CRITICAL: "#f85149",
    HIGH:     "#ff7b72",
    MEDIUM:   "#d29922",
    LOW:      "#58a6ff",
    INFO:     "#8b949e",
}

def generate_html_report(findings: list[Finding], target: str, out_path: str):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {s: 0 for s in [CRITICAL, HIGH, MEDIUM, LOW, INFO]}
    for f in findings:
        counts[f.severity] += 1

    findings_sorted = sorted(findings, key=lambda f: (SEV_ORDER[f.severity], f.file, f.line_no))

    rows = ""
    for i, f in enumerate(findings_sorted, 1):
        color = SEV_HTML_COLOR[f.severity]
        rows += f"""
        <tr>
          <td>{i}</td>
          <td><span class="badge" style="background:{color}">{f.severity}</span></td>
          <td><strong>{f.name}</strong></td>
          <td><code>{f.rule_id}</code></td>
          <td><a href="https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-','')}.html"
                 target="_blank">{f.cwe}</a></td>
          <td>{os.path.basename(f.file)}:{f.line_no}</td>
          <td><code class="code-snippet">{f.line[:120].replace('<','&lt;').replace('>','&gt;')}</code></td>
          <td>{f.description}</td>
          <td class="fix-cell">{f.recommendation}</td>
        </tr>"""

    summary_bars = ""
    for sev, cnt in counts.items():
        if cnt:
            color = SEV_HTML_COLOR[sev]
            pct   = round(cnt / max(len(findings), 1) * 100)
            summary_bars += f"""
            <div class="sev-row">
              <span class="sev-label" style="color:{color}">{sev}</span>
              <div class="sev-bar-track">
                <div class="sev-bar-fill" style="width:{pct}%;background:{color}"></div>
              </div>
              <span class="sev-count">{cnt}</span>
            </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Code Review Report</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif;
          background: var(--bg); color: var(--text); padding: 2rem; }}
  h1 {{ font-size: 1.8rem; color: var(--accent); margin-bottom: .25rem; }}
  .meta {{ color: var(--muted); font-size: .9rem; margin-bottom: 2rem; }}
  .summary-grid {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .stat-card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; padding: 1rem 1.5rem; min-width: 120px; text-align: center;
  }}
  .stat-num {{ font-size: 2rem; font-weight: 800; }}
  .stat-lbl {{ font-size: .8rem; color: var(--muted); }}
  .sev-row {{ display: flex; align-items: center; gap: .75rem; margin-bottom: .5rem; }}
  .sev-label {{ width: 80px; font-weight: 700; font-size: .85rem; }}
  .sev-bar-track {{ flex: 1; height: 10px; background: var(--border); border-radius: 99px; overflow: hidden; }}
  .sev-bar-fill  {{ height: 100%; border-radius: 99px; transition: width .6s; }}
  .sev-count {{ width: 30px; text-align: right; font-size: .85rem; }}
  .chart-card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; padding: 1.5rem; margin-bottom: 2rem; max-width: 500px;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th {{
    background: #21262d; padding: .6rem .75rem; text-align: left;
    border-bottom: 2px solid var(--border); color: var(--muted);
    font-size: .75rem; text-transform: uppercase; letter-spacing: .05em;
  }}
  td {{ padding: .6rem .75rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: rgba(88,166,255,.05); }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 99px;
    font-size: .75rem; font-weight: 700; color: #000;
  }}
  code {{ font-family: 'Consolas', monospace; font-size: .8rem; }}
  .code-snippet {{
    background: #21262d; padding: 2px 6px; border-radius: 4px;
    display: block; max-width: 300px; overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap;
  }}
  .fix-cell {{ color: #3fb950; font-size: .82rem; }}
  a {{ color: var(--accent); }}
  .table-wrap {{ overflow-x: auto; }}
  footer {{ margin-top: 3rem; color: var(--muted); font-size: .8rem; text-align: center; }}
</style>
</head>
<body>
<h1>🔍 Secure Code Review Report</h1>
<div class="meta">
  Target: <strong>{target}</strong> &nbsp;|&nbsp;
  Scanned: <strong>{ts}</strong> &nbsp;|&nbsp;
  Total Issues: <strong>{len(findings)}</strong>
</div>

<div class="summary-grid">
  <div class="stat-card">
    <div class="stat-num" style="color:#f85149">{counts[CRITICAL]}</div>
    <div class="stat-lbl">CRITICAL</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:#ff7b72">{counts[HIGH]}</div>
    <div class="stat-lbl">HIGH</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:#d29922">{counts[MEDIUM]}</div>
    <div class="stat-lbl">MEDIUM</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:#58a6ff">{counts[LOW]}</div>
    <div class="stat-lbl">LOW</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:#8b949e">{counts[INFO]}</div>
    <div class="stat-lbl">INFO</div>
  </div>
</div>

<div class="chart-card">
  <h3 style="margin-bottom:1rem;font-size:1rem">Severity Distribution</h3>
  {summary_bars}
</div>

<div class="table-wrap">
<table>
  <thead>
    <tr>
      <th>#</th><th>Severity</th><th>Vulnerability</th><th>Rule</th>
      <th>CWE</th><th>Location</th><th>Code</th>
      <th>Description</th><th>Recommendation</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
</div>

<footer>
  CodeAlpha Cybersecurity Internship — Task 3: Secure Coding Review &nbsp;|&nbsp;
  Generated by reviewer.py
</footer>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(col(f"\n  📄 HTML report saved → {out_path}", C.GREEN))


# ═══════════════════════════════════════════════════════════════
#  JSON EXPORT
# ═══════════════════════════════════════════════════════════════

def save_json(findings: list[Finding], out_path: str):
    data = {
        "scan_time": datetime.datetime.now().isoformat(),
        "total":     len(findings),
        "findings":  [f.to_dict() for f in findings],
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(col(f"  📄 JSON report saved → {out_path}", C.GREEN))


# ═══════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Static Security Code Reviewer — CodeAlpha Task 3",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target", nargs="?",
                        default="vulnerable_app/app.py",
                        help="Python file or directory to scan (default: vulnerable_app/app.py)")
    parser.add_argument("--html", default="report.html",
                        help="Output HTML report path (default: report.html)")
    parser.add_argument("--json", default=None,
                        help="Also save a JSON report to this path")
    parser.add_argument("--min-severity", default="INFO",
                        choices=[CRITICAL, HIGH, MEDIUM, LOW, INFO],
                        help="Only show findings at or above this severity")
    args = parser.parse_args()

    findings = scan_path(args.target)

    # Filter by minimum severity
    min_order = SEV_ORDER[args.min_severity]
    findings  = [f for f in findings if SEV_ORDER[f.severity] <= min_order]

    print_terminal_report(findings, args.target)
    generate_html_report(findings, args.target, args.html)
    if args.json:
        save_json(findings, args.json)

    # Exit code: non-zero if critical/high found
    critical_high = sum(1 for f in findings if f.severity in (CRITICAL, HIGH))
    sys.exit(1 if critical_high else 0)


if __name__ == "__main__":
    main()

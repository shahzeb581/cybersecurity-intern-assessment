# 🔐 Cybersecurity Internship – Week 1: Vulnerable Web App Security Assessment

**Student:** Muhammad Shahzaib  
**ID:** DHC-3811  
**Date:** March 2, 2026  
**Target App:** User Management System (Flask/Python)

---

## 📌 Project Overview

This repository documents my **Week 1 security assessment** of an intentionally vulnerable Flask web application. The goal was to identify, exploit, and remediate real-world web vulnerabilities using both manual testing and automated scanning (OWASP ZAP).

The repo includes:
- The original vulnerable application (`app.py`)
- A fully patched version (`app_fixed.py`) with all vulnerabilities remediated
- All payloads used during testing
- OWASP ZAP scan report
- Evidence screenshots
- A full written security report

---

## 🗂️ Repository Structure

```
📁 security-repo/
├── app.py                         # Original vulnerable application
├── app_fixed.py                   # Patched/remediated version
├── payloads.txt                   # SQL injection & XSS payloads used
├── OWASP_ZAP_Report.html          # Full automated scan results
├── Week1_Report_Muhammad_Shahzaib_DHC-3811.docx  # Full written report
├── VULNERABILITIES.md             # Detailed vulnerability breakdown
├── FIXES.md                       # Explanation of every fix applied
├── /screenshots/                  # Evidence screenshots
│   ├── 01_sqli_login_bypass.png
│   ├── 02_sqli_search_error.png
│   ├── 03_admin_panel_disclosure.png
│   ├── 04_error_message_disclosure.png
│   ├── 05_zap_scan_results.png
│   ├── 06_broken_password_reset.png
│   └── 07_xss_test.png
└── /fake_reports/                 # Dummy files for IDOR testing
    ├── admin_notes.txt
    ├── payroll.csv
    └── top-secret-company-strategy-2024.doc
```

---

## 🔍 Vulnerabilities Found

| # | Severity | Vulnerability | Location | CVE Category |
|---|----------|--------------|----------|--------------|
| 1 | 🔴 Critical | SQL Injection | `/login` | CWE-89 |
| 2 | 🔴 Critical | SQL Injection | `/search` | CWE-89 |
| 3 | 🔴 Critical | Remote Code Execution (File Upload) | `/account` | CWE-434 |
| 4 | 🔴 Critical | OS Command Injection | `/system_info` | CWE-78 |
| 5 | 🟠 High | Path Traversal | `/os_info` | CWE-22 |
| 6 | 🟠 High | Privilege Escalation via Registration | `/register` | CWE-269 |
| 7 | 🟠 Medium | Missing CSRF Tokens | All Forms | CWE-352 |
| 8 | 🟠 Medium | Information Disclosure | Error Messages, Admin Panel | CWE-200 |
| 9 | 🟠 Medium | Insecure Direct Object Reference (IDOR) | `/admin/download/<id>` | CWE-639 |
| 10 | 🟡 Low | Plaintext Password Storage | Database | CWE-256 |
| 11 | 🟡 Low | Insecure Session Cookies | App Config | CWE-614 |
| 12 | 🟡 Low | Hardcoded Weak Secret Key | App Config | CWE-321 |
| 13 | 🟡 Low | Missing Security Headers | Whole App | CWE-693 |
| 14 | 🟡 Low | Debug Mode Enabled in Production | App Config | CWE-489 |

---

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| Browser DevTools (F12) | Manual request inspection |
| OWASP ZAP | Automated vulnerability scanning |
| Manual SQL Injection Testing | Login & search bypass |
| Manual XSS Testing | Chat & input fields |
| Burp Suite (optional) | Request interception |

---

## 🔑 Key Findings

### 1. SQL Injection – Login Bypass
Using `' OR '1'='1' --` in the username field bypassed authentication entirely and logged in as admin without a valid password.

### 2. SQL Injection – Search Bar
The search endpoint reflected raw SQL errors, confirming injection. Dumping the users table was possible via UNION-based injection.

### 3. Remote Code Execution – File Upload
The profile picture upload accepted `.py` files and executed them via `subprocess.run()`. Uploading a reverse shell script would give full server access.

### 4. OS Command Injection – `/system_info`
The `cmd` GET parameter was passed directly to `os.popen()`. Any OS command (e.g., `whoami`, `cat /etc/passwd`) was executed on the server.

---

## ✅ How Vulnerabilities Were Fixed

See [`FIXES.md`](./FIXES.md) for a full breakdown. Summary:

- **SQL Injection** → Parameterized queries (`?` placeholders)
- **RCE via Upload** → Strict extension whitelist, execution code removed
- **Command Injection** → Endpoint removed entirely
- **Path Traversal** → `os.path.realpath()` with boundary check
- **Privilege Escalation** → Role hardcoded to `'user'` on registration
- **CSRF** → Token generated per session, validated on all POST routes
- **Plaintext Passwords** → `werkzeug` `generate_password_hash` / `check_password_hash`
- **Insecure Cookies** → `HTTPONLY=True`, `SECURE=True`, `SAMESITE=Lax`
- **Weak Secret Key** → `secrets.token_hex(32)` loaded from environment variable

---

## ⚠️ Disclaimer

> This project was created **strictly for educational purposes** as part of a cybersecurity internship training program. All testing was performed on a **local, intentionally vulnerable application** in a controlled environment. The vulnerabilities and payloads documented here should **never** be used against real systems without explicit written authorization.

---

## 📄 License

This project is for educational use only. No license is granted for offensive use.
Update README with full security assessment

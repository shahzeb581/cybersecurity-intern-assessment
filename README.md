# Cybersecurity Internship - Week 1 Security Assessment

**Student:** Muhammad Shahzaib  
**ID:** DHC-3811  
**Date:** March 2, 2026  
**Application Tested:** User Management System (http://localhost:3000)

## 📋 Project Overview

This repository contains my Week 1 security assessment of a vulnerable User Management System. The assessment included manual vulnerability testing and automated scanning using OWASP ZAP.

## 🔍 Vulnerabilities Found

| Severity | Vulnerability | Location |
|----------|---------------|----------|
| 🔴 CRITICAL | SQL Injection | Login Form |
| 🔴 CRITICAL | SQL Injection | Search Bar |
| 🟠 MEDIUM | Information Disclosure | Admin Panel |
| 🟠 MEDIUM | Information Disclosure | Error Messages |
| 🟠 MEDIUM | Missing Anti-CSRF Tokens | All Forms |
| 🟡 LOW | Missing Security Headers | Whole Application |
| 🟡 LOW | Broken Password Reset | Profile Page |

## 🛠️ Tools Used

- Manual SQL Injection Testing
- Manual XSS Testing
- Browser Developer Tools (F12)
- OWASP ZAP (Automated Scanner)

## 📁 Repository Contents

| File/Folder | Description |
|-------------|-------------|
| `Week1_Report_Muhammad_Shahzaib_DHC-3811.docx` | Detailed security assessment report |
| `/screenshots/` | Evidence screenshots of all findings |
| `payloads.txt` | List of XSS and SQL injection payloads tested |
| `OWASP_ZAP_Report.html` | Full OWASP ZAP scan results |

## 📸 Key Findings Screenshots

Screenshots are available in the `/screenshots` folder showing:
- SQL Injection successful admin login
- SQL error traceback from search bar
- Admin panel showing usernames and emails
- Error message disclosure
- OWASP ZAP scan results (9 alerts)
- Broken password reset functionality
- XSS testing results

## 🎯 Summary

This assessment identified **12 security issues** including critical SQL injection vulnerabilities, information disclosure, missing security headers, and broken functionality. Detailed findings and remediation recommendations are in the full report.

---

*This project is part of my cybersecurity internship training.*
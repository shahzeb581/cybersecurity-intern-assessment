# ✅ FIXES.md — Remediation Summary

All fixes are implemented in `app_fixed.py`.

---

## FIX-01 & 02 — SQL Injection (Login + Search)

**Before:**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
db.execute(query)
```

**After:**
```python
user = db.execute(
    "SELECT * FROM users WHERE username = ?", (username,)
).fetchone()
```

**Why it works:** Parameterized queries pass user input as data, not as part of the SQL string. The database driver handles escaping, so injection characters like `'` or `--` are treated literally.

---

## FIX-03 — Remote Code Execution via File Upload

**Before:**
```python
# Accepted any file, executed .py files
if filename.endswith('.py'):
    subprocess.run(['python', file_path], ...)
```

**After:**
```python
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if not allowed_file(file.filename):
    flash("Only image files are allowed.", "danger")
    return redirect(url_for('account'))
# No execution logic at all
```

**Why it works:** Only image extensions are accepted. The execution code is completely removed — there is no safe way to execute uploaded files.

---

## FIX-04 — OS Command Injection

**Before:**
```python
cmd = request.args.get('cmd', '')
result = os.popen(cmd).read()
```

**After:** The `/system_info` endpoint is **removed entirely**.

**Why:** There is no safe way to let users run arbitrary OS commands. If diagnostic info is genuinely needed, implement a fixed allowlist of specific, pre-approved commands behind strong authentication.

---

## FIX-05 — Path Traversal

**Before:**
```python
filename = request.args.get('filename', 'testing.txt')
file_path = os.path.join(STATIC_FOLDER, filename)
with open(file_path, 'r') as file: ...
```

**After:**
```python
SAFE_DIR = os.path.realpath(STATIC_FOLDER)
requested_path = os.path.realpath(os.path.join(SAFE_DIR, filename))

if not requested_path.startswith(SAFE_DIR + os.sep):
    return jsonify({"error": "Access denied"}), 403
```

**Why it works:** `os.path.realpath()` resolves `../` sequences. Checking that the result starts with the safe directory ensures the file is always within bounds.

---

## FIX-06 — Privilege Escalation via Registration

**Before:**
```python
role = request.form['role']
decoded_role = base64.b64decode(role).decode('utf-8')
# trusted and inserted into DB
```

**After:**
```python
role = 'user'  # Always hardcoded — never from user input
```

**Why it works:** User role is never accepted from client input. Role elevation must be done by an existing admin through the admin panel only.

---

## FIX-07 — CSRF Tokens

**Added:**
```python
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf(token):
    return token and token == session.get('csrf_token')
```

All state-changing POST routes now call `validate_csrf()` and abort with 403 if it fails. Templates include `{{ csrf_token() }}` as a hidden field.

---

## FIX-08 — Information Disclosure

- Generic error messages returned (`"Invalid credentials"` instead of specific field errors)
- Exception details never returned to the client
- `debug=False` in production

---

## FIX-09 — IDOR on File Download

Added `@login_required` and `@admin_required` decorators to the download route:
```python
@app.route('/admin/download/<int:file_id>')
@login_required
@admin_required
def download(file_id): ...
```

---

## FIX-10 — Plaintext Password Storage

**Before:**
```python
db.execute("INSERT INTO users (...) VALUES (?, ?, ?, ?)", (username, password, ...))
```

**After:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

hashed_pw = generate_password_hash(password)
db.execute("INSERT INTO users (...) VALUES (?, ?, ?, ?)", (username, hashed_pw, ...))

# On login:
if user and check_password_hash(user['password'], password):
    ...
```

**Why it works:** Passwords are stored as salted hashes (PBKDF2-SHA256 by default). Even if the database is leaked, plaintext passwords cannot be recovered directly.

---

## FIX-11 — Insecure Session Cookies

**Before:**
```python
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SECURE'] = False
```

**After:**
```python
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

---

## FIX-12 — Hardcoded Weak Secret Key

**Before:**
```python
app.secret_key = 'your_secret_key'
```

**After:**
```python
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
```

In production, set the `SECRET_KEY` environment variable to a long random string and never hardcode it.

---

## FIX-13 — Security Headers (Recommended Addition)

Add Flask-Talisman or manually set headers:
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

---

## FIX-14 — Debug Mode

**Before:**
```python
app.run(debug=True)
```

**After:**
```python
app.run(host='0.0.0.0', port=3000, debug=False)
```

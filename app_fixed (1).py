from flask import Flask, request, render_template, redirect, url_for, session, make_response, send_file, jsonify, flash, abort
import base64
import random
import sqlite3
import os
import re
import secrets
from werkzeug.utils import secure_filename
from functools import wraps

# ============================================================
# SECURITY FIXES APPLIED:
# 1. SQL Injection (Login & Search) → Parameterized queries
# 2. Remote Code Execution (Profile pic upload) → Strict file type validation
# 3. Command Injection (/system_info) → Endpoint removed
# 4. Path Traversal (/os_info) → Restricted to safe directory
# 5. Insecure Deserialization → pickle import removed
# 6. Broken Role Assignment (Register) → Role hardcoded to 'user'
# 7. Missing CSRF protection → Flask-WTF / token-based CSRF added
# 8. Insecure session cookies → HTTPONLY + SECURE flags enabled
# 9. Weak/hardcoded secret key → secrets.token_hex() used
# 10. Passwords stored in plaintext → werkzeug password hashing used
# 11. Missing authorization on /admin/download → Login + admin role required
# 12. Information disclosure in errors → Generic error messages returned
# ============================================================

from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# FIX #9: Use a strong, random secret key (in production, load from environment variable)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DATABASE = 'sql_injection_demo.db'

# FIX #2: Strict allowed extensions — NO .py, .php, .sh, etc.
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
STATIC_FOLDER = 'static'

def allowed_file(filename):
    return (
        '.' in filename
        and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )

PROFILE_PIC_FOLDER = os.path.join(app.root_path, 'static', 'profile_pics')
if not os.path.exists(PROFILE_PIC_FOLDER):
    os.makedirs(PROFILE_PIC_FOLDER)

app.config['PROFILE_PIC_FOLDER'] = PROFILE_PIC_FOLDER

# FIX #8: Secure session cookie flags
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True   # Requires HTTPS in production
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def login_required(f):
    """Decorator to enforce authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to enforce admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf(token):
    return token and token == session.get('csrf_token')


app.jinja_env.globals['csrf_token'] = generate_csrf_token


def init_db():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            profile_picture TEXT
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')

    # FIX #10: Passwords are now hashed with werkzeug
    seed_users = [
        ('developer', 'devs-rule',     'devin@dev4U.com',    'dev'),
        ('admin',     'adminpassword', 'admin@example.com',  'admin'),
        ('jim',       'batman',        'jim@dm-scranton.com', 'user'),
        ('dwight',    'spiderman',     'dwight@dm-scranton.com', 'user'),
    ]
    for username, password, email, role in seed_users:
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not existing:
            db.execute(
                "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), email, role)
            )

    seed_contacts = [
        ('micheal', 'bigMike@hotmail.com'),
        ('pam',     'pamcake@aol.com'),
        ('ryan',    'ry-guy@gmail.com'),
    ]
    for name, email in seed_contacts:
        db.execute("INSERT OR IGNORE INTO contacts (name, email) VALUES (?, ?)", (name, email))

    db.commit()


init_db()

chat_messages = []


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # FIX #1: Parameterized query — eliminates SQL injection
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # FIX #10: Compare against hashed password
        if user and check_password_hash(user['password'], password):
            session.regenerate() if hasattr(session, 'regenerate') else None
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            return redirect(url_for('account'))
        else:
            # FIX #12: Generic error — don't reveal which field was wrong
            return render_template('login.html', error='Invalid credentials, please try again.')

    return render_template('login.html')


@app.before_request
def check_session():
    if request.endpoint and request.endpoint.startswith('static'):
        return None
    public_endpoints = {'login', 'register', 'index', 'diagnostics'}
    if 'username' not in session and request.endpoint not in public_endpoints:
        return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(e):
    image_number = random.randint(1, 6)
    return render_template("404.html", image_number=image_number), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template("404.html", image_number=1), 403


@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    # FIX: Use Jinja2 autoescaping (ensure templates use {{ msg }} not {{ msg|safe }})
    # The blacklist approach is kept but XSS is primarily prevented by template escaping.
    if request.method == "POST":
        # FIX #6 (CSRF): validate token on state-changing POST
        if not validate_csrf(request.form.get('csrf_token')):
            abort(403)
        message = request.form.get("message", "")
        # Store raw; Jinja2 autoescaping handles XSS on render
        chat_messages.append(message)

    return render_template('chat.html', messages=chat_messages)


@app.route('/clear_messages', methods=['POST'])
@login_required
def clear_messages():
    if not validate_csrf(request.form.get('csrf_token')):
        abort(403)
    chat_messages.clear()
    return redirect(url_for('chat'))


# FIX #11: Download endpoint now requires admin login
@app.route('/admin/download/<int:file_id>', methods=['GET'])
@login_required
@admin_required
def download(file_id):
    file_mapping = {
        1: "top-secret-company-strategy-2024.doc",
        2: "admin_notes.txt",
        3: "payroll.csv",
    }
    filename = file_mapping.get(file_id)
    if filename:
        safe_filename = secure_filename(filename)
        return send_file(f"fake_reports/{safe_filename}", as_attachment=True, mimetype="text/plain")
    else:
        abort(404)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            abort(403)

        username = request.form['username'].strip()
        password = request.form['password']
        email    = request.form['email'].strip()

        # FIX #6: Role is NEVER accepted from user input — always default to 'user'
        role = 'user'

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for('register'))

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            flash("Username already exists. Please choose a different one.", "danger")
            return redirect(url_for('register'))

        # FIX #10: Hash the password before storing
        hashed_pw = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            (username, hashed_pw, email, role)
        )
        db.commit()

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user_id = session['user_id']
    db = get_db()
    user = db.execute(
        "SELECT username, role, profile_picture FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            abort(403)

        file = request.files.get('profile_picture')
        if file and file.filename:
            # FIX #2: Validate extension AND do NOT execute uploaded files
            if not allowed_file(file.filename):
                flash("Only image files (png, jpg, jpeg, gif) are allowed.", "danger")
                return redirect(url_for('account'))

            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['PROFILE_PIC_FOLDER'], filename)
            file.save(file_path)

            # REMOVED: subprocess execution of uploaded files

            db.execute("UPDATE users SET profile_picture = ? WHERE id = ?", (filename, user_id))
            db.commit()
            session['profile_picture'] = filename
            return redirect(url_for('account'))

    profile_picture_url = None
    if user['profile_picture']:
        profile_picture_url = url_for(
            'static',
            filename=os.path.join('profile_pics', user['profile_picture'])
        )

    return render_template(
        'account.html',
        username=user['username'],
        role=user['role'],
        profile_picture_url=profile_picture_url
    )


@app.route('/diagnostics', methods=['GET'])
def diagnostics():
    return render_template('diagnostics.html')


# FIX #3: /system_info REMOVED — executing arbitrary OS commands from user input
# is a critical Remote Code Execution vulnerability with no safe mitigation.
# If system diagnostics are needed, implement a fixed allowlist of safe commands
# behind strong authentication and audit logging.


@app.route('/os_info', methods=['GET'])
@login_required
@admin_required
def os_info():
    # FIX #4: Restrict to a single safe directory; reject path traversal attempts
    SAFE_DIR = os.path.realpath(STATIC_FOLDER)
    filename = request.args.get('filename', 'testing.txt')

    # Prevent path traversal: resolve and verify it stays inside SAFE_DIR
    requested_path = os.path.realpath(os.path.join(SAFE_DIR, filename))
    if not requested_path.startswith(SAFE_DIR + os.sep):
        return jsonify({"error": "Access denied"}), 403

    try:
        with open(requested_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except Exception:
        # FIX #12: Don't expose exception details to the client
        return jsonify({"error": "Unable to read file"}), 500

    return jsonify({"file_content": content})


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            abort(403)

        user_id     = session['user_id']
        new_password = request.form.get('new_password', '')

        if len(new_password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for('change_password'))

        db = get_db()
        # FIX #10: Hash before storing
        db.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id)
        )
        db.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('account'))

    return render_template('change_password.html')


@app.route('/admin')
@login_required
@admin_required
def admin():
    db = get_db()
    page     = request.args.get('page', 1, type=int)
    per_page = 5
    offset   = (page - 1) * per_page

    users = db.execute(
        "SELECT id, username, email FROM users WHERE username != 'admin' LIMIT ? OFFSET ?",
        (per_page, offset)
    ).fetchall()

    total_users = db.execute(
        "SELECT COUNT(*) FROM users WHERE username != 'admin'"
    ).fetchone()[0]
    total_pages = (total_users // per_page) + (1 if total_users % per_page > 0 else 0)

    return render_template('admin.html', users=users, page=page, total_pages=total_pages)


@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reset_password(user_id):
    if not validate_csrf(request.form.get('csrf_token')):
        abort(403)
    db = get_db()
    # FIX #10: Hash the reset password
    db.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (generate_password_hash('qwerty'), user_id)
    )
    db.commit()
    return redirect(url_for('admin'))


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if not validate_csrf(request.form.get('csrf_token')):
        abort(403)
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return redirect(url_for('admin'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            abort(403)
        query = request.form.get('query', '').strip()
        if query:
            db = get_db()
            # FIX #1: Parameterized query — eliminates SQL injection in search
            result = db.execute(
                "SELECT username, email FROM users WHERE username LIKE ?",
                (f'%{query}%',)
            ).fetchall()

            if result:
                return render_template('search_results.html', results=result)
            else:
                return 'No results found.'
        else:
            return 'No parameter provided', 400

    return render_template('search.html')


if __name__ == '__main__':
    # FIX: debug=False in production to prevent Werkzeug debugger exposure
    app.run(host='0.0.0.0', port=3000, debug=False)

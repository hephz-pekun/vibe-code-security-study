#!/usr/bin/env python3
"""
Cookie-based session system for Flask (single file, self-contained).

How it works
------------
* The browser only holds an opaque, HMAC-signed session ID in a cookie.
* Session data lives server-side in SQLite. Only a SHA-256 hash of the ID is
  stored, so a leaked database cannot be used to hijack sessions.
* Sessions have an idle timeout and an absolute timeout. "Remember me" gives
  a persistent cookie with longer limits; otherwise it is a browser-session cookie.
* The session ID is rotated on login/logout (prevents session fixation).
* Built-in CSRF protection for all POST/PUT/PATCH/DELETE requests.
* Cookie flags: HttpOnly, SameSite=Lax, Secure (+ __Host- prefix) in production.
* Users can list their active sessions, revoke one, or log out everywhere else.
* Anonymous visitors don't create DB rows unless something is stored.

Run
---
    pip install flask
    python cookie_sessions.py                  # dev, http://127.0.0.1:5000
    SECRET_KEY=... COOKIE_SECURE=1 python cookie_sessions.py   # behind HTTPS

Set SECRET_KEY in the environment for production so cookies survive restarts.
Session data must be JSON-serializable.
"""

import functools
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict
from collections.abc import MutableMapping
from datetime import datetime

from flask import (Flask, abort, current_app, g, redirect, render_template,
                   request, url_for)
from itsdangerous import BadSignature, URLSafeSerializer
from jinja2 import DictLoader
from werkzeug.local import LocalProxy
from werkzeug.security import check_password_hash, generate_password_hash


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    DATABASE = os.environ.get("DATABASE", "app.db")

    COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
    COOKIE_SAMESITE = "Lax"

    IDLE_TIMEOUT = 30 * 60                  # 30 min of inactivity
    ABSOLUTE_TIMEOUT = 12 * 60 * 60         # 12 h hard limit
    REMEMBER_IDLE_TIMEOUT = 14 * 86400      # 14 days inactivity ("remember me")
    REMEMBER_ABSOLUTE_TIMEOUT = 30 * 86400  # 30 days hard limit
    TOUCH_INTERVAL = 60                     # write last_seen at most once/minute
    BIND_USER_AGENT = True                  # drop session if User-Agent changes

    LOGIN_MAX_FAILURES = 5                  # per IP ...
    LOGIN_WINDOW = 300                      # ... per 5 minutes


# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    sid_hash   TEXT PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
    data       TEXT NOT NULL,
    created    REAL NOT NULL,
    last_seen  REAL NOT NULL,
    expires    REAL NOT NULL,
    remember   INTEGER NOT NULL DEFAULT 0,
    ip         TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_sid(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Session object (dict-like, tracks modifications)
# --------------------------------------------------------------------------- #
class Session(MutableMapping):
    def __init__(self, sid=None, data=None, user_id=None, created=None,
                 last_seen=None, expires=None, remember=False):
        now = time.time()
        self.sid = sid
        self._data = data or {}
        self.user_id = user_id
        self.created = created or now
        self.last_seen = last_seen or now
        self.expires = expires
        self.remember = remember
        self.modified = False
        self.rotate_requested = False
        self.invalid_cookie = False   # request carried a bad/expired cookie

    # --- mapping interface ---------------------------------------------------
    def __getitem__(self, key):
        return self._data[key]

    def __setitem__(self, key, value):
        self._data[key] = value
        self.modified = True

    def __delitem__(self, key):
        del self._data[key]
        self.modified = True

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    # --- auth ----------------------------------------------------------------
    @property
    def sid_hash(self):
        return hash_sid(self.sid) if self.sid else None

    def login(self, user_id, remember=False):
        """Attach a user and rotate the session ID (anti session-fixation)."""
        self.user_id = user_id
        self.remember = bool(remember)
        self._data.pop("_csrf", None)
        self.rotate_requested = True
        self.modified = True

    def logout(self):
        """Wipe everything and rotate; a fresh anonymous session follows."""
        self._data.clear()
        self.user_id = None
        self.remember = False
        self.rotate_requested = True
        self.modified = True

    # --- flash messages ------------------------------------------------------
    def flash(self, message, category="info"):
        flashes = list(self._data.get("_flashes", []))
        flashes.append([category, message])
        self["_flashes"] = flashes

    def pop_flashes(self):
        if "_flashes" in self._data:
            flashes = self._data["_flashes"]
            del self["_flashes"]
            return flashes
        return []

    # --- CSRF ----------------------------------------------------------------
    def csrf_token(self):
        token = self._data.get("_csrf")
        if not token:
            token = secrets.token_urlsafe(32)
            self["_csrf"] = token
        return token


sess = LocalProxy(lambda: g.sess)


# --------------------------------------------------------------------------- #
# Session manager: loads session before request, saves after
# --------------------------------------------------------------------------- #
class CookieSessions:
    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        cfg = app.config
        if not cfg.get("SECRET_KEY"):
            cfg["SECRET_KEY"] = secrets.token_hex(32)
            app.logger.warning("SECRET_KEY not set: using a random key. "
                               "Sessions will be invalid after restart.")
        self.cfg = cfg
        self.signer = URLSafeSerializer(cfg["SECRET_KEY"], salt="session-cookie-v1")
        self.cookie_name = "__Host-sid" if cfg["COOKIE_SECURE"] else "sid"
        app.before_request(self._load)
        app.after_request(self._save)
        app.teardown_appcontext(close_db)

    # --- helpers -------------------------------------------------------------
    def _cookie_kwargs(self):
        return dict(path="/", httponly=True, secure=self.cfg["COOKIE_SECURE"],
                    samesite=self.cfg["COOKIE_SAMESITE"])

    def _delete_row(self, sid):
        db = get_db()
        db.execute("DELETE FROM sessions WHERE sid_hash = ?", (hash_sid(sid),))
        db.commit()

    # --- before_request ------------------------------------------------------
    def _load(self):
        g.sess = self._load_session()

    def _load_session(self):
        raw = request.cookies.get(self.cookie_name)
        if not raw:
            return Session()

        s = Session()
        s.invalid_cookie = True
        try:
            sid = self.signer.loads(raw)
        except BadSignature:
            return s

        db = get_db()
        row = db.execute("SELECT * FROM sessions WHERE sid_hash = ?",
                         (hash_sid(sid),)).fetchone()
        if row is None:
            return s

        now = time.time()
        idle = (self.cfg["REMEMBER_IDLE_TIMEOUT"] if row["remember"]
                else self.cfg["IDLE_TIMEOUT"])
        expired = now >= row["expires"] or now - row["last_seen"] >= idle
        ua_mismatch = (self.cfg["BIND_USER_AGENT"]
                       and (row["user_agent"] or "") != self._ua())
        if expired or ua_mismatch:
            self._delete_row(sid)
            return s

        try:
            data = json.loads(row["data"])
        except ValueError:
            data = {}
        return Session(sid=sid, data=data, user_id=row["user_id"],
                       created=row["created"], last_seen=row["last_seen"],
                       expires=row["expires"], remember=bool(row["remember"]))

    @staticmethod
    def _ua():
        return (request.headers.get("User-Agent") or "")[:300]

    # --- after_request -------------------------------------------------------
    def _save(self, response):
        s = g.get("sess")
        if s is None:
            return response

        db = get_db()
        now = time.time()
        has_content = bool(s._data) or s.user_id is not None

        # Rotation: drop the old row, issue a new ID below.
        if s.sid and (s.rotate_requested or not has_content):
            self._delete_row(s.sid)
            s.sid = None
            s.created = now

        if not has_content:
            if request.cookies.get(self.cookie_name):
                response.delete_cookie(self.cookie_name, **self._cookie_kwargs())
            return response

        payload = json.dumps(s._data, separators=(",", ":"))

        if s.sid is None:                                   # create
            s.sid = secrets.token_urlsafe(32)
            s.created = s.last_seen = now
            lifetime = (self.cfg["REMEMBER_ABSOLUTE_TIMEOUT"] if s.remember
                        else self.cfg["ABSOLUTE_TIMEOUT"])
            s.expires = now + lifetime
            db.execute(
                "INSERT INTO sessions (sid_hash, user_id, data, created, last_seen,"
                " expires, remember, ip, user_agent) VALUES (?,?,?,?,?,?,?,?,?)",
                (hash_sid(s.sid), s.user_id, payload, s.created, now, s.expires,
                 int(s.remember), request.remote_addr, self._ua()))
            db.commit()
            response.set_cookie(
                self.cookie_name, self.signer.dumps(s.sid),
                max_age=int(lifetime) if s.remember else None,
                **self._cookie_kwargs())
        elif s.modified or now - s.last_seen >= self.cfg["TOUCH_INTERVAL"]:  # update
            db.execute("UPDATE sessions SET data = ?, user_id = ?, last_seen = ?"
                       " WHERE sid_hash = ?",
                       (payload, s.user_id, now, hash_sid(s.sid)))
            db.commit()
        elif s.invalid_cookie:
            response.delete_cookie(self.cookie_name, **self._cookie_kwargs())

        # Occasional cleanup of dead sessions (~1% of requests)
        if secrets.randbelow(100) == 0:
            db.execute("DELETE FROM sessions WHERE expires < ? OR last_seen < ?",
                       (now, now - self.cfg["REMEMBER_IDLE_TIMEOUT"]))
            db.commit()

        response.vary.add("Cookie")
        return response


# --------------------------------------------------------------------------- #
# Auth helpers
# --------------------------------------------------------------------------- #
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
DUMMY_HASH = generate_password_hash("dummy-password-for-timing")
_failures = defaultdict(list)   # in-memory; use Redis or similar in production


def rate_limited(ip):
    cutoff = time.time() - Config.LOGIN_WINDOW
    _failures[ip] = [t for t in _failures[ip] if t > cutoff]
    return len(_failures[ip]) >= Config.LOGIN_MAX_FAILURES


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//") \
            and "\\" not in target:
        return target
    return url_for("dashboard")


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            sess.flash("Please log in first.", "error")
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)
    return wrapped


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #
TEMPLATES = {
    "base.html": """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}{% endblock %} · Session Demo</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#222}
 nav{display:flex;gap:1rem;align-items:center;border-bottom:1px solid #ddd;padding-bottom:.75rem;margin-bottom:1.5rem}
 nav .sp{flex:1} nav form{margin:0}
 input,button{font:inherit;padding:.45rem .6rem;margin:.2rem 0}
 input[type=text],input[type=password]{width:100%;box-sizing:border-box}
 button{cursor:pointer} .link{background:none;border:0;color:#06c;text-decoration:underline;padding:0}
 .flash{padding:.6rem .8rem;border-radius:6px;margin-bottom:1rem;background:#eef}
 .flash.error{background:#fee;color:#900} .flash.success{background:#efe;color:#060}
 table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid #eee;padding:.4rem;text-align:left;font-size:.9rem}
 code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}
</style></head><body>
<nav>
 <a href="{{ url_for('index') }}">Home</a>
 {% if user %}<a href="{{ url_for('dashboard') }}">Dashboard</a>{% endif %}
 <span class="sp"></span>
 {% if user %}
  <span>{{ user.username }}</span>
  <form method="post" action="{{ url_for('logout') }}">
   <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
   <button class="link">Log out</button></form>
 {% else %}
  <a href="{{ url_for('login') }}">Log in</a>
  <a href="{{ url_for('register') }}">Register</a>
 {% endif %}
</nav>
{% for category, message in get_flashed_messages() %}
 <div class="flash {{ category }}">{{ message }}</div>
{% endfor %}
{% block body %}{% endblock %}
</body></html>""",

    "index.html": """{% extends "base.html" %}{% block title %}Home{% endblock %}
{% block body %}
<h1>Cookie session demo</h1>
<p>Page views in this session: <strong>{{ views }}</strong></p>
{% if user %}<p>Welcome back, {{ user.username }}.</p>
{% else %}<p>You are browsing anonymously. <a href="{{ url_for('register') }}">Create an account</a>
or <a href="{{ url_for('login') }}">log in</a>.</p>{% endif %}
{% endblock %}""",

    "auth.html": """{% extends "base.html" %}{% block title %}{{ title }}{% endblock %}
{% block body %}
<h1>{{ title }}</h1>
<form method="post">
 <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
 <label>Username<input type="text" name="username" value="{{ username or '' }}" required autofocus></label>
 <label>Password<input type="password" name="password" required minlength="8"></label>
 {% if mode == 'login' %}
  <label><input type="checkbox" name="remember"> Remember me for 30 days</label>
 {% endif %}
 <button>{{ title }}</button>
</form>
{% endblock %}""",

    "dashboard.html": """{% extends "base.html" %}{% block title %}Dashboard{% endblock %}
{% block body %}
<h1>Dashboard</h1>
<p>Hello, <strong>{{ user.username }}</strong>. Visits to this page: <strong>{{ visits }}</strong>
 (stored in your server-side session).</p>
<h2>Active sessions</h2>
<table>
 <tr><th>Device</th><th>IP</th><th>Last active</th><th>Expires</th><th></th></tr>
 {% for s in sessions %}
 <tr>
  <td>{{ s.user_agent[:40] or 'unknown' }}{% if s.sid_hash == current %} <em>(this one)</em>{% endif %}</td>
  <td>{{ s.ip }}</td><td>{{ s.last_seen|ts }}</td><td>{{ s.expires|ts }}</td>
  <td>{% if s.sid_hash != current %}
   <form method="post" action="{{ url_for('revoke') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input type="hidden" name="sid_hash" value="{{ s.sid_hash }}">
    <button class="link">Revoke</button></form>{% endif %}</td>
 </tr>
 {% endfor %}
</table>
<form method="post" action="{{ url_for('revoke_others') }}">
 <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
 <button>Log out all other sessions</button>
</form>
{% endblock %}""",
}


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #
def create_app(config=None):
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)
    if config:
        app.config.update(config)
    app.jinja_loader = DictLoader(TEMPLATES)

    CookieSessions(app)

    with app.app_context():
        db = sqlite3.connect(app.config["DATABASE"])
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(SCHEMA)
        db.close()

    # ---- request hooks (registered after the session loader) ---------------
    @app.before_request
    def load_user_and_check_csrf():
        g.user = None
        if sess.user_id is not None:
            g.user = get_db().execute("SELECT id, username FROM users WHERE id = ?",
                                      (sess.user_id,)).fetchone()
            if g.user is None:          # user was deleted
                sess.logout()

        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            expected = sess.get("_csrf", "")
            if not expected or not sent or not secrets.compare_digest(
                    sent.encode(), expected.encode()):
                abort(400, "Invalid or missing CSRF token.")

    @app.context_processor
    def inject():
        return dict(user=g.get("user"), csrf_token=sess.csrf_token,
                    get_flashed_messages=sess.pop_flashes)

    @app.template_filter("ts")
    def fmt_ts(value):
        return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M")

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    # ---- routes -------------------------------------------------------------
    @app.route("/")
    def index():
        sess["views"] = sess.get("views", 0) + 1
        return render_template("index.html", views=sess["views"])

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user:
            return redirect(url_for("dashboard"))
        username = request.form.get("username", "").strip()
        if request.method == "POST":
            password = request.form.get("password", "")
            error = None
            if not USERNAME_RE.match(username):
                error = "Username must be 3-32 letters, digits or underscores."
            elif len(password) < 8:
                error = "Password must be at least 8 characters."
            if not error:
                db = get_db()
                try:
                    cur = db.execute(
                        "INSERT INTO users (username, password_hash, created) VALUES (?,?,?)",
                        (username, generate_password_hash(password), time.time()))
                    db.commit()
                except sqlite3.IntegrityError:
                    error = "That username is taken."
                else:
                    sess.login(cur.lastrowid)
                    sess.flash("Account created. Welcome!", "success")
                    return redirect(url_for("dashboard"))
            sess.flash(error, "error")
        return render_template("auth.html", title="Register", mode="register",
                               username=username)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
        username = request.form.get("username", "").strip()
        if request.method == "POST":
            ip = request.remote_addr or "?"
            if rate_limited(ip):
                sess.flash("Too many failed attempts. Try again later.", "error")
                return render_template("auth.html", title="Log in", mode="login",
                                       username=username), 429
            password = request.form.get("password", "")
            row = get_db().execute(
                "SELECT id, password_hash FROM users WHERE username = ?",
                (username,)).fetchone()
            # Always run a hash check so timing doesn't reveal valid usernames
            ok = check_password_hash(row["password_hash"] if row else DUMMY_HASH, password)
            if row and ok:
                _failures.pop(ip, None)
                sess.login(row["id"], remember=bool(request.form.get("remember")))
                sess.flash("Logged in.", "success")
                return redirect(safe_next(request.args.get("next")))
            _failures[ip].append(time.time())
            sess.flash("Invalid username or password.", "error")
        return render_template("auth.html", title="Log in", mode="login",
                               username=username)

    @app.post("/logout")
    def logout():
        sess.logout()
        sess.flash("You have been logged out.", "success")
        return redirect(url_for("index"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        sess["visits"] = sess.get("visits", 0) + 1
        rows = get_db().execute(
            "SELECT sid_hash, ip, user_agent, last_seen, expires FROM sessions"
            " WHERE user_id = ? ORDER BY last_seen DESC", (g.user["id"],)).fetchall()
        return render_template("dashboard.html", visits=sess["visits"],
                               sessions=rows, current=sess.sid_hash)

    @app.post("/sessions/revoke")
    @login_required
    def revoke():
        db = get_db()
        target = request.form.get("sid_hash", "")
        if target != sess.sid_hash:
            db.execute("DELETE FROM sessions WHERE sid_hash = ? AND user_id = ?",
                       (target, g.user["id"]))
            db.commit()
            sess.flash("Session revoked.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/sessions/revoke-others")
    @login_required
    def revoke_others():
        db = get_db()
        db.execute("DELETE FROM sessions WHERE user_id = ? AND sid_hash != ?",
                   (g.user["id"], sess.sid_hash))
        db.commit()
        sess.flash("All other sessions were logged out.", "success")
        return redirect(url_for("dashboard"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
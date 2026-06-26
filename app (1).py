"""
Password manager web app.

Session/key handling, the part most worth reading carefully:

- The master password is NEVER stored anywhere, not even temporarily on disk.
- On login we derive a 32-byte AES key from the master password (Argon2id +
  per-user salt) and keep that key ONLY in server-side process memory
  (`SESSION_KEYS`), indexed by a random opaque session token.
- The browser only ever receives that random token, set as an httponly
  cookie with no embedded expiry. It never sees the encryption key.
- Sessions expire after SESSION_TIMEOUT of inactivity, checked against a
  server-side timestamp on every request (not anything read from the
  cookie). The key is dropped from memory at that point and the user must
  re-enter their master password (which is the only thing that can
  re-derive the key).
- This is single-process by design: SESSION_KEYS lives in one process's
  memory, so running multiple worker processes (e.g. `gunicorn -w 4`) would
  split sessions across workers that can't see each other's memory. Restart
  the process and every session is also gone. Both are deliberate
  simplicity trade-offs for a small app, called out in the README. A
  multi-worker deployment would need to move this to something shared,
  like Redis, keeping the same access pattern.
"""

import json
import os
import secrets
import time
from functools import wraps

from flask import Flask, request, redirect, url_for, render_template, session, flash, g
from cryptography.exceptions import InvalidTag

import db
import crypto_utils as crypto

app = Flask(__name__)

# Signs the (non-sensitive) Flask session cookie. Set FLASK_SECRET_KEY in the
# environment for any deployment with more than one worker process: each
# worker would otherwise generate its own random key at startup, and cookies
# signed by one worker would fail to validate on another.
_secret_key = os.environ.get("FLASK_SECRET_KEY")
if not _secret_key:
    _secret_key = secrets.token_hex(32)
    print(
        "WARNING: FLASK_SECRET_KEY not set, using a random key for this process. "
        "Fine for local single-process dev. Set FLASK_SECRET_KEY explicitly for "
        "anything multi-worker or anything you want to survive a restart."
    )
app.secret_key = _secret_key

# token -> {"key": bytearray, "user_id": int, "username": str, "last_active": float}
SESSION_KEYS: dict[str, dict] = {}
SESSION_TIMEOUT = 15 * 60  # seconds


def _touch_or_expire(token: str):
    entry = SESSION_KEYS.get(token)
    if entry is None:
        return None
    if time.time() - entry["last_active"] > SESSION_TIMEOUT:
        crypto.wipe(entry["key"])  # zero the key buffer, not just drop the reference
        SESSION_KEYS.pop(token, None)
        return None
    entry["last_active"] = time.time()
    return entry


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = session.get("token")
        entry = _touch_or_expire(token) if token else None
        if entry is None:
            session.clear()
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for("login"))
        g.key = entry["key"]
        g.user_id = entry["user_id"]
        g.username = entry["username"]
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    return redirect(url_for("vault") if session.get("token") else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")
        if len(password) < 8:
            flash("Master password must be at least 8 characters.", "error")
            return render_template("register.html")
        if db.get_user_by_username(username):
            flash("That username is already taken.", "error")
            return render_template("register.html")

        password_hash = crypto.hash_password(password)
        enc_salt = crypto.new_salt()
        db.create_user(username, password_hash, enc_salt)
        # Drop our reference now that we're done with the plaintext. CPython's
        # refcounting frees it immediately, no GC cycle wait needed, since a
        # plain str has no reference cycle. But the freed memory isn't
        # zeroed, so remnants could still be read by something that scans
        # freed memory directly (e.g. a core dump). See README "Known
        # limitations" for what this does and doesn't protect against.
        del password

        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.get_user_by_username(username)
        if user is None or not crypto.verify_password(password, user["password_hash"]):
            flash("Invalid username or master password.", "error")
            return render_template("login.html")

        key = crypto.derive_key(password, user["enc_salt"])
        del password  # see register() comment: drops our reference promptly
        token = secrets.token_urlsafe(32)
        SESSION_KEYS[token] = {
            "key": key,
            "user_id": user["id"],
            "username": user["username"],
            "last_active": time.time(),
        }
        session.clear()
        session["token"] = token
        return redirect(url_for("vault"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    token = session.get("token")
    if token:
        entry = SESSION_KEYS.pop(token, None)
        if entry is not None:
            crypto.wipe(entry["key"])
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


@app.route("/vault")
@login_required
def vault():
    rows = db.get_entries(g.user_id)
    entries = []
    for row in rows:
        try:
            data = json.loads(crypto.decrypt(g.key, row["blob"]).decode("utf-8"))
        except InvalidTag:
            # Wrong key or corrupted/tampered row; skip rather than crash the page.
            continue
        entries.append(
            {
                "id": row["id"],
                "site": data.get("site", ""),
                "username": data.get("username", ""),
                "password": data.get("password", ""),
                "notes": data.get("notes", ""),
                "updated_at": row["updated_at"],
            }
        )
    return render_template("vault.html", entries=entries, username=g.username)


@app.route("/entry/add", methods=["GET", "POST"])
@login_required
def add_entry():
    if request.method == "POST":
        payload = {
            "site": request.form.get("site", "").strip(),
            "username": request.form.get("entry_username", "").strip(),
            "password": request.form.get("entry_password", ""),
            "notes": request.form.get("notes", "").strip(),
        }
        if not payload["site"] or not payload["password"]:
            flash("Site and password are required.", "error")
            return render_template("entry_form.html", mode="add", entry=None)

        blob = crypto.encrypt(g.key, json.dumps(payload).encode("utf-8"))
        db.add_entry(g.user_id, blob)
        flash("Entry saved.", "success")
        return redirect(url_for("vault"))

    return render_template("entry_form.html", mode="add", entry=None)


@app.route("/entry/<int:entry_id>/edit", methods=["GET", "POST"])
@login_required
def edit_entry(entry_id):
    row = db.get_entry(entry_id, g.user_id)
    if row is None:
        flash("Entry not found.", "error")
        return redirect(url_for("vault"))

    if request.method == "POST":
        payload = {
            "site": request.form.get("site", "").strip(),
            "username": request.form.get("entry_username", "").strip(),
            "password": request.form.get("entry_password", ""),
            "notes": request.form.get("notes", "").strip(),
        }
        if not payload["site"] or not payload["password"]:
            flash("Site and password are required.", "error")
            return redirect(url_for("edit_entry", entry_id=entry_id))

        blob = crypto.encrypt(g.key, json.dumps(payload).encode("utf-8"))
        db.update_entry(entry_id, g.user_id, blob)
        flash("Entry updated.", "success")
        return redirect(url_for("vault"))

    try:
        data = json.loads(crypto.decrypt(g.key, row["blob"]).decode("utf-8"))
    except InvalidTag:
        flash("Could not decrypt entry.", "error")
        return redirect(url_for("vault"))

    entry = {"id": entry_id, **data}
    return render_template("entry_form.html", mode="edit", entry=entry)


@app.route("/entry/<int:entry_id>/delete", methods=["POST"])
@login_required
def delete_entry(entry_id):
    db.delete_entry(entry_id, g.user_id)
    flash("Entry deleted.", "success")
    return redirect(url_for("vault"))


if __name__ == "__main__":
    db.init_db()
    # Off by default. Debug mode's interactive debugger shows local variables
    # on unhandled exceptions, which in this app can include decrypted vault
    # entries sitting in memory mid-request. Only enable for local dev where
    # you trust everyone who can reach the port.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug)

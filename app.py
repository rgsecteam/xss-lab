"""
RGSecurityTeam - Cookie / Session Hijacking Lab
------------------------------------------------
EDUCATIONAL USE ONLY. Run this only inside the provided Docker container,
on your own machine, isolated from the internet. It contains INTENTIONAL
vulnerabilities (reflected XSS -> cookie theft -> account takeover) for
teaching purposes. Do NOT deploy this publicly. Do NOT reuse this code
for anything except a local, offline classroom / video demo.
"""

import os
import re
import sqlite3
import secrets
from flask import Flask, request, redirect, url_for, session, render_template, g, make_response

APP_DB = os.path.join(os.path.dirname(__file__), "lab.db")

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # only used for flash/login-state, NOT the vulnerable cookie

# In-memory "comments" board per level (reset when container restarts)
COMMENTS = {"low": [], "medium": [], "high": []}

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(APP_DB)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    if not os.path.exists(APP_DB):
        conn = sqlite3.connect(APP_DB)
        conn.execute(
            """CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                auth_token TEXT
            )"""
        )
        conn.commit()
        conn.close()


# ---------------------------------------------------------------------------
# Intentionally weak sanitisation filters (this is the point of the lab!)
# ---------------------------------------------------------------------------

def filter_low(payload: str) -> str:
    """LOW: no filtering at all. Anything goes."""
    return payload


def filter_medium(payload: str) -> str:
    """MEDIUM: strips a literal <script>...</script> block, single pass,
    case-insensitive. Doesn't think about other HTML event-handlers."""
    return re.sub(r"<script.*?>.*?</script>", "", payload, flags=re.I | re.S)


HIGH_BLACKLIST = [
    "<script>", "</script>", "onerror=", "onload=", "onclick=", "onmouseover=", "onfocus=",
]


def filter_high(payload: str) -> str:
    """HIGH: blacklist-based, single (non-recursive) pass over a few
    dangerous substrings. Classic 'strip once, don't rescan' filter-evasion
    weakness: removing an inner match can cause the surrounding leftovers
    to re-form a blocked pattern, and the filter never checks again."""
    for bad in HIGH_BLACKLIST:
        payload = re.sub(re.escape(bad), "", payload, flags=re.I)
    return payload


FILTERS = {"low": filter_low, "medium": filter_medium, "high": filter_high}
LEVELS = ["low", "medium", "high"]


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("levels"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            error = "Username / password khali rakha jabe na."
        else:
            db = get_db()
            try:
                # NOTE: plaintext password storage is ALSO intentional here,
                # to keep the lab focused purely on cookie/session hijacking.
                db.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, password),
                )
                db.commit()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Ei username age theke ache."
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?", (username, password)
        ).fetchone()
        if user:
            token = secrets.token_hex(16)
            db.execute("UPDATE users SET auth_token=? WHERE id=?", (token, user["id"]))
            db.commit()
            session["username"] = username
            resp = make_response(redirect(url_for("levels")))
            # INTENTIONALLY VULNERABLE COOKIE:
            # httponly=False -> readable by JavaScript -> stealable via XSS
            resp.set_cookie("auth_token", token, httponly=False, samesite="Lax")
            return resp
        error = "Username ba password bhul."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("home")))
    resp.delete_cookie("auth_token")
    return resp


def current_user_from_token():
    token = request.cookies.get("auth_token")
    if not token:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE auth_token=?", (token,)).fetchone()


def require_login():
    user = current_user_from_token()
    return user


# ---------------------------------------------------------------------------
# Level selection
# ---------------------------------------------------------------------------

@app.route("/levels")
def levels():
    user = require_login()
    if not user:
        return redirect(url_for("login"))
    return render_template("levels.html", username=user["username"])


# ---------------------------------------------------------------------------
# Vulnerable dashboard (search bar / comment button / category dropdown)
# ---------------------------------------------------------------------------

@app.route("/dashboard/<level>", methods=["GET", "POST"])
def dashboard(level):
    if level not in LEVELS:
        return redirect(url_for("levels"))

    user = require_login()
    if not user:
        return redirect(url_for("login"))

    flt = FILTERS[level]

    # Vector 1: search bar (GET, reflected)
    raw_q = request.args.get("q", "")
    q_result = flt(raw_q) if raw_q else ""

    # Vector 2: category dropdown (GET, reflected) - value can be tampered
    # via the URL even though the UI only offers a fixed <select> list.
    raw_cat = request.args.get("cat", "")
    cat_result = flt(raw_cat) if raw_cat else ""

    # Vector 3: comment box + "Post" button (POST, stored for this level)
    if request.method == "POST":
        raw_comment = request.form.get("comment", "")
        if raw_comment.strip():
            COMMENTS[level].append({"user": user["username"], "text": flt(raw_comment)})
        return redirect(url_for("dashboard", level=level))

    return render_template(
        "dashboard.html",
        level=level,
        username=user["username"],
        q_raw=raw_q,
        q_result=q_result,
        cat_raw=raw_cat,
        cat_result=cat_result,
        comments=COMMENTS[level],
    )


# ---------------------------------------------------------------------------
# "Attacker" side: session hijack simulator
# ---------------------------------------------------------------------------

@app.route("/hijack", methods=["GET", "POST"])
def hijack():
    """Lets the viewer paste a stolen auth_token cookie value and get logged
    in as that victim, closing the loop from XSS -> stolen cookie -> full
    account takeover, entirely inside this offline lab."""
    result = None
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE auth_token=?", (token,)).fetchone()
        if user:
            resp = make_response(redirect(url_for("levels")))
            session["username"] = user["username"]
            resp.set_cookie("auth_token", token, httponly=False, samesite="Lax")
            return resp
        result = "Token match korlo na."
    return render_template("hijack.html", result=result)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)

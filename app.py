from flask import Flask, render_template, request, redirect, url_for, make_response
import base64
import json
import os
import re

app = Flask(__name__)

FLAG = "Securinets{c00k13s_4nd_b4s364_4r3_n0t_s3cur3}"

# In-memory user store (resets on restart — fine for CTF)
USERS = {}


def encode_cookie(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":"))
    return base64.b64encode(raw.encode()).decode()


def decode_cookie(token: str):
    try:
        raw = base64.b64decode(token.encode()).decode()
        return json.loads(raw)
    except Exception:
        return None


def get_current_user():
    token = request.cookies.get("auth")
    if not token:
        return None
    return decode_cookie(token)


@app.route("/", methods=["GET", "POST"])
def index():
    """Login / Register page (this is the homepage)"""
    user = get_current_user()
    if user:
        return redirect(url_for("home"))

    error = None
    mode = request.args.get("mode", "login")  # login | register

    if request.method == "POST":
        action = request.form.get("action", "login")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "Username and password are required."
            mode = action
        elif not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
            error = "Username must be 3-20 characters (letters, numbers, underscore)."
            mode = action
        elif action == "register":
            if username in USERS:
                error = "Username already taken."
                mode = "register"
            else:
                USERS[username] = password
                cookie_data = {"username": username, "role": "user"}
                token = encode_cookie(cookie_data)
                resp = make_response(redirect(url_for("home")))
                resp.set_cookie("auth", token, httponly=False, samesite="Lax")
                return resp
        else:  # login
            if username not in USERS or USERS[username] != password:
                error = "Invalid username or password."
                mode = "login"
            else:
                cookie_data = {"username": username, "role": "user"}
                token = encode_cookie(cookie_data)
                resp = make_response(redirect(url_for("home")))
                resp.set_cookie("auth", token, httponly=False, samesite="Lax")
                return resp

    return render_template("index.html", error=error, mode=mode)


@app.route("/home")
def home():
    user = get_current_user()
    if not user:
        return redirect(url_for("index"))
    return render_template("home.html", user=user)


@app.route("/admin")
def admin():
    user = get_current_user()
    if not user:
        return redirect(url_for("index"))

    if user.get("role") == "admin":
        return render_template("admin.html", flag=FLAG, user=user)

    return render_template("denied.html", user=user)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("auth")
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

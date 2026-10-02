from flask import Flask, render_template, request, redirect, url_for, make_response
import base64
import json
import os

app = Flask(__name__)

# Simple credentials for the challenge
VALID_USER = "guest"
VALID_PASS = "guest"

FLAG = "Securinets{c00k13s_4nd_b4s364_4r3_n0t_s3cur3}"


def encode_cookie(data: dict) -> str:
    """Encode a dict as base64(JSON)"""
    raw = json.dumps(data, separators=(",", ":"))
    return base64.b64encode(raw.encode()).decode()


def decode_cookie(token: str):
    """Decode base64 cookie back to dict. Returns None on failure."""
    try:
        raw = base64.b64decode(token.encode()).decode()
        return json.loads(raw)
    except Exception:
        return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == VALID_USER and password == VALID_PASS:
            # Set a cookie containing user info (base64 encoded JSON)
            cookie_data = {
                "username": username,
                "role": "user"
            }
            token = encode_cookie(cookie_data)

            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie(
                "auth",
                token,
                httponly=False,   # intentionally readable by JS / easy to inspect
                samesite="Lax"
            )
            return resp

        error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    token = request.cookies.get("auth")
    if not token:
        return redirect(url_for("login"))

    data = decode_cookie(token)
    if not data:
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=data)


@app.route("/admin")
def admin():
    token = request.cookies.get("auth")
    if not token:
        return redirect(url_for("login"))

    data = decode_cookie(token)
    if not data:
        return redirect(url_for("login"))

    # Weak check: only looks at the role inside the cookie
    if data.get("role") == "admin":
        return render_template("admin.html", flag=FLAG, user=data)

    return render_template("denied.html", user=data)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("auth")
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

import os, secrets, time
from collections import defaultdict, deque
from flask import Flask, render_template, request, session, abort
from analyzer import analyze, load_model

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=16 * 1024)

model = load_model()
MIN_LEN, MAX_LEN = 5, 1000
RATE_LIMIT, WINDOW = 20, 60            # 20 checks per minute per IP
hits = defaultdict(deque)

def rate_limited(ip):
    now = time.time()
    q = hits[ip]
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False

@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.route("/", methods=["GET", "POST"])
def index():
    error, result, text = None, None, ""
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
            abort(400)                                   # CSRF check failed
        if rate_limited(request.remote_addr):
            return render_template("index.html", error="Too many checks. Please wait a minute.", result=None, text="", csrf=session["csrf"]), 429
        text = request.form.get("message", "").strip()
        if not (MIN_LEN <= len(text) <= MAX_LEN):
            error = f"Please paste a message between {MIN_LEN} and {MAX_LEN} characters."
        else:
            result = analyze(text, model)                # message is analysed in memory and never stored or logged
    session["csrf"] = session.get("csrf") or secrets.token_hex(16)
    return render_template("index.html", error=error, result=result, text=text, csrf=session["csrf"])

if __name__ == "__main__":
    app.run(debug=False)

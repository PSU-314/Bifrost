"""
auth2fa — Two-Factor Authentication demo with X25519 key exchange.
"""

import logging
import os
import random
import time

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from utils import x25519, totp

# ---------------------------------------------------------------------------
# App & Database setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

# Use SQLite for development
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "bifrost.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---------------------------------------------------------------------------
# Database Models
# ---------------------------------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    shared_secret_hex = db.Column(db.String(64), nullable=True) # Populated after 1 successful exchange

class ExchangeToken(db.Model):
    pin = db.Column(db.String(6), primary_key=True)
    username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    server_priv_hex = db.Column(db.String(64), nullable=False)
    server_pub_hex = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.Float, nullable=False)

# Initialize database tables
with app.app_context():
    db.create_all()

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Tokens expire after this many seconds even if unused.
TOKEN_TTL = 300   # 5 minutes

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _purge_expired_tokens() -> None:
    """Remove all tokens that have passed their TTL."""
    now = time.time()
    expired_tokens = ExchangeToken.query.filter(ExchangeToken.created_at < now - TOKEN_TTL).all()
    for t in expired_tokens:
        db.session.delete(t)
        log.info("Purged expired exchange token %s.", t.pin)
    db.session.commit()

def _get_shared_secret() -> bytes | None:
    """Retrieve the shared secret from the session, or None if absent."""
    raw = session.get("shared_secret_hex")
    return bytes.fromhex(raw) if raw else None

def _generate_pin() -> str:
    """Return a cryptographically random 6-digit PIN string (zero-padded)."""
    return f"{random.SystemRandom().randint(0, 999_999):06d}"

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def page_1():
    """Landing page — entry point."""
    return render_template("page1.html")


@app.route("/signup", methods=["GET"])
def page_2():
    username = request.args.get("username", "").strip()
    password = request.args.get("password", "").strip()

    if username and password:
        if len(username) < 3 or len(password) < 6:
            return render_template("page2.html", error="Username must be ≥ 3 chars and password ≥ 6 chars.")

        # Check if user already exists
        user = User.query.filter_by(username=username).first()
        
        # Enforce: Exchange happens only once per user
        if user and user.shared_secret_hex:
            return render_template("page2.html", error="An account with this username has already completed the exchange. Please log in.")

        if not user:
            user = User(username=username, password_hash=generate_password_hash(password))
            db.session.add(user)
        else:
            # If user exists but hasn't completed exchange, allow password update
            user.password_hash = generate_password_hash(password)
        
        db.session.commit()
        session["saved_username"] = username

        server_priv = x25519.generate_private_key()
        server_pub  = x25519.public_key(server_priv)

        _purge_expired_tokens()

        # Clean up any existing orphaned endpoints for this specific username
        ExchangeToken.query.filter_by(username=username).delete()
        db.session.commit()

        pin = _generate_pin()

        # Save the new token in the database
        token_entry = ExchangeToken(
            pin=pin,
            username=username,
            server_priv_hex=server_priv.hex(),
            server_pub_hex=server_pub.hex(),
            created_at=time.time()
        )
        db.session.add(token_entry)
        db.session.commit()

        exchange_url = url_for("exchange_endpoint", pin=pin, _external=True)
        log.info("Signup: endpoint created for user '%s' at /signup/%s", username, pin)

        return render_template(
            "page2.html",
            show_token=True,
            server_pub=server_pub.hex(),
            exchange_url=exchange_url,
            pin=pin,
        )

    return render_template("page2.html")


@app.route("/signup/<pin>", methods=["GET", "POST"])
def exchange_endpoint(pin: str):
    """
    Single-use key-exchange endpoint.
    URL format: /signup/<pin>
    """
    token_entry = db.session.get(ExchangeToken, pin)

    if token_entry is None:
        log.warning("Exchange attempt with unknown/used PIN %s.", pin)
        if request.is_json:
             return jsonify({"error": "Endpoint not found or already used."}), 404
        return render_template("page_exchange.html", expired=True), 404

    if time.time() - token_entry.created_at > TOKEN_TTL:
        db.session.delete(token_entry)
        db.session.commit()
        log.warning("Exchange endpoint %s expired.", pin)
        if request.is_json:
             return jsonify({"error": "Endpoint expired."}), 410
        return render_template("page_exchange.html", expired=True), 410

    # ---- GET: fallback if visited in browser ----
    if request.method == "GET":
        return render_template(
            "page_exchange.html",
            server_pub=token_entry.server_pub_hex,
            token=pin, 
        )

    # ---- POST: perform the exchange from Authenticator ----
    if request.is_json:
        body = request.get_json(silent=True) or {}
        client_pub_hex = str(body.get("bifrost-public-key", "")).strip()
    else:
        client_pub_hex = request.form.get("bifrost-public-key", "").strip()

    if not client_pub_hex:
        return jsonify({"error": "Missing bifrost-public-key parameter"}), 400

    user = User.query.filter_by(username=token_entry.username).first()
    
    if not user:
        return jsonify({"error": "User associated with token no longer exists"}), 400

    # Strict enforcement: Cannot exchange if already completed
    if user.shared_secret_hex:
        db.session.delete(token_entry)
        db.session.commit()
        return jsonify({"error": "Key exchange already completed for this user."}), 403

    try:
        server_priv = bytes.fromhex(token_entry.server_priv_hex)
        client_pub  = bytes.fromhex(client_pub_hex)

        if len(client_pub) != 32:
            raise ValueError("Public key must be exactly 32 bytes (64 hex chars).")

        secret = x25519.diffie_hellman(server_priv, client_pub)

    except (ValueError, Exception) as exc:
        log.warning("Key exchange failed on endpoint %s: %s", pin, exc)
        return jsonify({"error": f"Key exchange failed: {exc}"}), 400

    # --- SUCCESS: Update user, burn the endpoint immediately ---
    server_pub_hex = token_entry.server_pub_hex
    
    # Save the secret permanently to the User database model
    user.shared_secret_hex = secret.hex()
    db.session.delete(token_entry)
    db.session.commit()
    
    log.info("Endpoint /signup/%s used and destroyed. Secret securely saved.", pin)

    return jsonify({
        "status": "success",
        "server-public-key": server_pub_hex,
        "message": "Key exchange complete"
    }), 200


@app.route("/login", methods=["GET"])
def page_3():
    """
    Login page.
    """
    username = request.args.get("username", "").strip()
    password = request.args.get("password", "").strip()

    if username and password:
        user = User.query.filter_by(username=username).first()

        # Secure password hash comparison
        if user and check_password_hash(user.password_hash, password):
            log.info("Credentials verified for '%s'.", username)
            session["saved_username"] = user.username
            
            # Load the shared secret from the database into the browser session
            session["shared_secret_hex"] = user.shared_secret_hex
            return redirect(url_for("page_4"))

        log.warning("Failed login attempt for '%s'.", username)
        return render_template("page3.html", error="Invalid username or password.")

    return render_template("page3.html")


@app.route("/2fa", methods=["GET"])
def page_4():
    """2FA verification page."""
    user_code = request.args.get("code", "").strip()

    if user_code:
        shared_secret = _get_shared_secret()
        if not shared_secret:
            return render_template(
                "page4.html",
                error="No shared secret — please complete sign-up exchange first.",
            )

        if totp.verify_otp(shared_secret, user_code):
            log.info("2FA verified.")
            session["authenticated"] = True
            return redirect(url_for("page_5"))

        log.warning("Invalid 2FA code submitted.")
        return render_template("page4.html", error="Incorrect code. Please try again.")

    return render_template("page4.html")


@app.route("/success")
def page_5():
    """Success — only reachable after full authentication."""
    if not session.get("authenticated"):
        return redirect(url_for("page_1"))
    return render_template("page5.html", username=session.get("saved_username", "User"))


@app.route("/logout")
def logout():
    """Clear the session and return to the landing page."""
    session.clear()
    log.info("User logged out.")
    return redirect(url_for("page_1"))


if __name__ == "__main__":
    app.run(debug=True)
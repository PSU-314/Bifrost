import hashlib
import hmac
import math
import time
from datetime import datetime

import x25519
from flask import Flask, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = "dh_secret_key_for_session"

# User storage  (all kept as bytes)
saved_username: bytes = None
saved_password: bytes = None
shared_secret: bytes = None

# Constants from C++ logic
TIME_WINDOW = 30
OTP_SIZE = 6


# --- TRANSLATED C++ TOTP LOGIC ---


def genSample(key_bytes: bytes, time_val):
    """Translated from uint32_t genSample(std::string &key, std::time_t time)"""
    # HMAC-SHA1: key is the raw shared-secret bytes; message is the time window
    msg_bytes = str(time_val).encode("utf-8")
    key_hex = key_bytes.hex().encode("utf-8")

    hash_result = hmac.new(key_hex, msg_bytes, hashlib.sha1).digest()
    print(hash_result.hex())
    # Byte offset = hash.back() & 0x0F;
    offset = hash_result[-1] & 0x0F

    # Manual byte shifting: (hash[offset] << 24) | (hash[offset + 1] << 16)...
    sample = (
        (hash_result[offset] << 24)
        | (hash_result[offset + 1] << 16)
        | (hash_result[offset + 2] << 8)
        | hash_result[offset + 3]
    )

    # sample &= 0x7FFFFFFF;
    sample &= 0x7FFFFFFF
    return sample


def generateOTP(shared_secret_val: bytes):
    """Translated from uint32_t generateOTP(std::string &key)"""
    if shared_secret_val is None:
        return None

    epoch = int(datetime.now().timestamp())
    curtime1 = epoch // TIME_WINDOW
    curtime2 = curtime1 + 1
    curtime3 = curtime1 - 1

    # Log details to console (matching the C++ couts)
    print(f"Key: {shared_secret_val.hex()}")
    print(f"Time: {epoch}")
    print(f"Expires in: {TIME_WINDOW - (epoch % TIME_WINDOW)}\n")

    # genSample(key, curtime) % (uint32_t)std::pow(10, OTP_SIZE);
    otp1 = genSample(shared_secret_val, curtime1) % int(math.pow(10, OTP_SIZE))
    otp2 = genSample(shared_secret_val, curtime2) % int(math.pow(10, OTP_SIZE))
    otp3 = genSample(shared_secret_val, curtime3) % int(math.pow(10, OTP_SIZE))
    print("OTP 1: ", otp1)
    print("OTP 2: ", otp2)
    print("OTP 3: ", otp3)
    return [f"{otp1:06d}", f"{otp2:06d}", f"{otp3:06d}"]


# --- ROUTES ---


@app.route("/")
def page_1():
    return render_template("page1.html")


@app.route("/signup_input")
def page_2():
    global saved_username, saved_password
    user = request.args.get("username")
    pw = request.args.get("password")

    if user and pw:
        saved_username = user.encode("utf-8")
        saved_password = pw.encode("utf-8")

        # Generate an X25519 keypair for this session.
        # Private key stored server-side in the session (hex-encoded for JSON
        # serialisability); public key forwarded to the exchange page.
        server_priv = x25519.generate_private_key()
        server_pub = x25519.public_key(server_priv)

        session["server_private"] = server_priv.hex()
        return redirect(url_for("page_exchange", magic_num=server_pub.hex()))

    return render_template("page2.html", step="input")


@app.route("/exchange")
def page_exchange():
    global shared_secret

    # The server's public key is shown to the user so they (or their client)
    # can complete the X25519 handshake on their side.
    magic_num = request.args.get("magic_num")

    # 'verify' carries the client's X25519 public key (hex-encoded, 64 chars).
    client_pub_hex = request.args.get("verify")

    if client_pub_hex:
        server_priv_hex = session.get("server_private")
        if server_priv_hex:
            try:
                server_priv = bytes.fromhex(server_priv_hex)
                client_pub = bytes.fromhex(client_pub_hex)

                # Store the raw 32-byte secret — used directly as the HMAC key.
                shared_secret = x25519.diffie_hellman(server_priv, client_pub)
                print("shared secret: ", shared_secret.hex())

                return "Secret Established! <br><a href='/login_input'>Proceed to Login</a>"

            except (ValueError, Exception) as e:
                return f"Key exchange failed: {e}", 400

    return render_template("page_exchange.html", magic_num=magic_num)


@app.route("/login_input")
def page_3():
    user = request.args.get("username")
    pw = request.args.get("password")

    if (
        user is not None
        and user.encode("utf-8") == saved_username
        and pw.encode("utf-8") == saved_password
    ):
        return redirect(url_for("page_4"))

    return render_template("page3.html")


@app.route("/2fa_input")
def page_4():
    global shared_secret
    user_code = request.args.get("code")

    if user_code:
        # Using the translated C++ logic
        expected_code = generateOTP(shared_secret)

        if user_code in expected_code:
            return redirect(url_for("page_5"))
        else:
            print("Correct 2FA Code: ", expected_code)
            return "Invalid 2FA Code. <a href='/2fa_input'>Try again</a>"

    return render_template("page4.html")


@app.route("/success")
def page_5():
    return render_template("page5.html")


if __name__ == "__main__":
    app.run(debug=True)

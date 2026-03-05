from flask import Flask, render_template, request, redirect, url_for, session
import secrets
import hmac
import hashlib
from datetime import datetime
import math
import time

app = Flask(__name__)
app.secret_key = 'dh_secret_key_for_session'

# Global Shared Constants
p = 775145549137931
g = 23

# User storage
saved_username = None
saved_password = None
shared_secret = None

# Constants from C++ logic
TIME_WINDOW = 30
OTP_SIZE = 6

def create_keypair(p, g):
    priv = secrets.randbelow(p - 2) + 2
    pub = pow(g, priv, p)
    return priv, pub

def calculate_shared_secret(remote_public, local_private, p):
    return pow(int(remote_public), int(local_private), p)

# --- TRANSLATED C++ TOTP LOGIC ---

def genSample(key_str, time_val):
    """Translated from uint32_t genSample(std::string &key, std::time_t time)"""
    # HMAC-SHA1 using the string representation of time as the message
    key_bytes = key_str.encode('utf-8')
    msg_bytes = str(time_val).encode('utf-8')
    
    hash_result = hmac.new(key_bytes, msg_bytes, hashlib.sha1).digest()
    print(hash_result)
    # Byte offset = hash.back() & 0x0F;
    offset = hash_result[-1] & 0x0F
    
    # Manual byte shifting: (hash[offset] << 24) | (hash[offset + 1] << 16)...
    sample = (hash_result[offset] << 24) | \
             (hash_result[offset + 1] << 16) | \
             (hash_result[offset + 2] << 8) | \
             hash_result[offset + 3]
    
    # sample &= 0x7FFFFFFF;
    sample &= 0x7FFFFFFF
    return sample

def generateOTP(shared_secret_val):
    """Translated from uint32_t generateOTP(std::string &key)"""
    if shared_secret_val is None:
        return None
        
    key_str = str(shared_secret_val)
    epoch = int(datetime.now().timestamp())
    curtime1 = epoch // TIME_WINDOW
    curtime2 = curtime1 + 1
    curtime3 = curtime1 - 1
    
    # Log details to console (matching the C++ couts)
    print(f"Key: {key_str}")
    print(f"Time: {epoch}")
    print(f"Expires in: {TIME_WINDOW - (epoch % TIME_WINDOW)}\n")
    
    # genSample(key, curtime) % (uint32_t)std::pow(10, OTP_SIZE);
    otp1 = genSample(key_str, curtime1) % int(math.pow(10, OTP_SIZE))
    otp2 = genSample(key_str, curtime2) % int(math.pow(10, OTP_SIZE))
    otp3 = genSample(key_str, curtime3) % int(math.pow(10, OTP_SIZE))
    print('OTP 1: ', otp1)
    print('OTP 2: ', otp2)
    print('OTP 3: ', otp3)
    return [f"{otp1:06d}", f"{otp2:06d}", f"{otp3:06d}"]

# --- ROUTES ---

@app.route('/')
def page_1():
    return render_template('page1.html')

@app.route('/signup_input')
def page_2():
    global saved_username, saved_password
    user = request.args.get('username')
    pw = request.args.get('password')
    
    if user and pw:
        saved_username = user
        saved_password = pw
        priv, pub = create_keypair(p, g)
        session['server_private'] = priv
        return redirect(url_for('page_exchange', magic_num=pub))
    return render_template('page2.html', step='input')

@app.route('/exchange')
def page_exchange():
    global shared_secret
    magic_num = request.args.get('magic_num')
    other_public_key = request.args.get('verify')
    
    if other_public_key:
        server_priv = session.get('server_private')
        if server_priv:
            shared_secret = calculate_shared_secret(other_public_key, server_priv, p)
            print("shared secret: ", shared_secret)
            return f"Secret Established! <br><a href='/login_input'>Proceed to Login</a>"
            
    return render_template('page_exchange.html', magic_num=magic_num)

@app.route('/login_input')
def page_3():
    user = request.args.get('username')
    pw = request.args.get('password')
    
    if user == saved_username and pw == saved_password and user is not None:
        return redirect(url_for('page_4'))
    
    return render_template('page3.html')

@app.route('/2fa_input')
def page_4():
    global shared_secret
    user_code = request.args.get('code')
    
    if user_code:
        # Using the translated C++ logic

        expected_code = generateOTP(shared_secret)
        
        if user_code in expected_code:
            return redirect(url_for('page_5'))
        else:
            print("Correct 2FA Code: ", expected_code)
            return "Invalid 2FA Code. <a href='/2fa_input'>Try again</a>"
            
    return render_template('page4.html')

@app.route('/success')
def page_5():
    return render_template('page5.html')

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import secrets
import hmac
import hashlib
from datetime import datetime
import math
import time

app = Flask(__name__)
app.secret_key = 'dh_secret_key_for_session'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    shared_secret = db.Column(db.String(255), nullable=True)

with app.app_context():
    db.create_all()

p = 775145549137931
g = 23

saved_username = None
saved_password = None
shared_secret = None

TIME_WINDOW = 30
OTP_SIZE = 6

def create_keypair(p, g):
    priv = secrets.randbelow(p - 2) + 2
    pub = pow(g, priv, p)
    return priv, pub

def calculate_shared_secret(remote_public, local_private, p):
    return pow(int(remote_public), int(local_private), p)

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
    user = request.args.get('username')
    pw = request.args.get('password')
    
    if user and pw:
        
        if User.query.filter_by(username=user).first():
            return "User already exists!"
            
        new_user = User(username=user, password=pw)
        db.session.add(new_user)
        db.session.commit()
        
        session['temp_user'] = user 
        
        priv, pub = create_keypair(p, g)
        session['server_private'] = priv
        return redirect(url_for('page_exchange', magic_num=pub))
    return render_template('page2.html', step='input')

@app.route('/exchange')
def page_exchange():
    magic_num = request.args.get('magic_num')
    other_public_key = request.args.get('verify')
    
    if other_public_key:
        server_priv = session.get('server_private')
        username = session.get('temp_user')
        
        user = User.query.filter_by(username=username).first()
        if server_priv and user:
            secret = calculate_shared_secret(other_public_key, server_priv, p)
            user.shared_secret = str(secret)
            db.session.commit()
            return f"Secret Established! <br><a href='/login_input'>Proceed to Login</a>"
        
            
    return render_template('page_exchange.html', magic_num=magic_num)

@app.route('/login_input')
def page_3():
    user_input = request.args.get('username')
    pw_input = request.args.get('password')
    
    if not user_input or not pw_input:
        return render_template('page3.html')

    # 1. Find the user in the database
    user = User.query.filter_by(username=user_input, password=pw_input).first()
    
    if user:
        # 2. Check if they ever finished the key exchange
        if user.shared_secret is None:
            # They have an account but no 2FA setup! 
            # We must restart the exchange process for them.
            session['temp_user'] = user.username 
            priv, pub = create_keypair(p, g)
            session['server_private'] = priv
            
            # Send them back to the exchange step
            return redirect(url_for('page_exchange', magic_num=pub))
        
        # 3. Everything is normal, proceed to 2FA
        session['logged_in_user'] = user.username
        return redirect(url_for('page_4'))
    
    return "Invalid credentials. <a href='/login_input'>Try again</a>"

@app.route('/2fa_input')
def page_4():
    user_code = request.args.get('code')
    username = session.get('logged_in_user')
    
    user = User.query.filter_by(username=username).first()
    
    # Safety Check: Does the user even have a secret?
    if user and user.shared_secret:
        if user_code:
            expected_codes = generateOTP(user.shared_secret)
            if user_code in expected_codes:
                return redirect(url_for('page_5'))
            else:
                return "Invalid 2FA Code. <a href='/2fa_input'>Try again</a>"
    else:
        # If they don't have a secret or aren't logged in, boot them back to login
        return redirect(url_for('page_3'))
            
    return render_template('page4.html')

@app.route('/success')
def page_5():
    return render_template('page5.html')

@app.route('/logout')
def logout():
    # This wipes everything in the session: 
    # the logged-in user, the temp user, and the server private keys.
    session.clear() 
    return redirect(url_for('page_1'))

if __name__ == '__main__':
    app.run(debug=True)
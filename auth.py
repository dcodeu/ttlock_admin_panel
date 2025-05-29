# --- Add to auth.py ---
import hashlib
import requests
import logging
import time
import pprint
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required
from .models import db, User
from .api_requests import get_token, refresh_tocken

log = logging.getLogger(__name__)
auth = Blueprint('auth', __name__)

# Configuration from config.ini
import os, configparser
config_path = os.path.join(os.path.dirname(__file__), 'config.ini')
config = configparser.ConfigParser()
config.read(config_path)
client_id = config['ttlock_admin_panel']['client_id']
client_secret = config['ttlock_admin_panel']['client_secret']

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not email or not password or not confirm:
            flash("All fields are required", "danger")
            return redirect(url_for('auth.register'))

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for('auth.register'))

        session['pending_email'] = email
        session['pending_password'] = password

        r = requests.post("https://euapi.ttlock.com/v3/user/sendRegisterVerificationCode", data={
            'clientId': client_id,
            'username': email
        })
        log.debug(f"[sendVerification] Response: {r.text}")
        print("[DEBUG] API Response to sendRegisterVerificationCode:", r.status_code, r.text)

        try:
            response_data = r.json()
        except Exception as e:
            log.error(f"[sendVerification] Failed to parse JSON: {e}")
            flash("API error — invalid response format.", "danger")
            return redirect(url_for('auth.register'))

        if r.ok and response_data.get('errcode') == 0:
            return redirect(url_for('auth.verify'))
        else:
            flash(response_data.get('errmsg', 'Failed to send code'), 'danger')
            return redirect(url_for('auth.register'))


    return render_template('register.html')


@auth.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        email = session.get('pending_email')
        raw_password = session.get('pending_password')
        code = request.form.get('code', '')

        if not email or not raw_password or not code:
            flash("Missing verification information.", "danger")
            return redirect(url_for('auth.verify'))

        hashed_pw = hashlib.md5(raw_password.encode()).hexdigest()

        r = requests.post("https://api.ttlock.com/v3/user/register", data={
            'clientId': client_id,
            'clientSecret': client_secret,
            'username': email,
            'password': hashed_pw,
            'code': code,
            'date': int(time.time() * 1000)
        })
        log.debug(f"[register] Response: {r.text}")

        if r.ok and r.json().get('errcode') == 0:
            new_user = User(username=email, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash("Registered! You may now login.", "success")
            return redirect(url_for('auth.login'))
        else:
            flash(r.json().get('errmsg', 'Registration failed'), 'danger')

    return render_template('verify.html')


@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('email', '').strip()
    password_raw = request.form.get('password', '')
    remember = True if request.form.get('remember') else False

    if not username or not password_raw:
        flash("Email and password are required.")
        return redirect(url_for('auth.login'))

    password = hashlib.md5(password_raw.encode('utf-8')).hexdigest()
    print(f"\n[DEBUG] Username: {username}")
    print(f"[DEBUG] MD5 Password: {password}")

    request_user_ttlock = get_token(username, password)
    try:
        tt_response = request_user_ttlock.json()
    except Exception as e:
        flash("Could not decode TTLock response.")
        print("[ERROR] Invalid JSON response from TTLock:", e)
        return redirect(url_for('auth.login'))

    print("\n[DEBUG] TTLock API Response:")
    pprint.pprint(tt_response)

    if 'errcode' in tt_response:
        flash(f"TTLock Error: {tt_response.get('errmsg', 'Unknown error')}")
        return redirect(url_for('auth.login'))

    expires_in = tt_response.get('expires_in')
    access_token = tt_response.get('access_token')
    refresh_token = tt_response.get('refresh_token')
    uid = tt_response.get('uid')
    openid = tt_response.get('openid')
    scope = tt_response.get('scope')

    if not all([access_token, uid, refresh_token]):
        flash("TTLock did not return all required credentials.")
        return redirect(url_for('auth.login'))

    check_username = User.query.filter_by(username=username).first()
    if check_username:
        if expires_in and expires_in < 432000:
            refreshed = refresh_tocken(refresh_token).json()
            print("[DEBUG] Refresh Token Response:")
            pprint.pprint(refreshed)

            check_username.access_token = refreshed.get('access_token', access_token)
            check_username.expires_in = refreshed.get('expires_in', expires_in)
            check_username.refresh_token = refreshed.get('refresh_token', refresh_token)
            db.session.commit()
    else:
        new_user = User(
            username=username,
            uid=uid,
            password=password_raw,
            access_token=access_token,
            openid=openid,
            scope=scope,
            refresh_token=refresh_token
        )
        db.session.add(new_user)
        db.session.commit()

    user = User.query.filter_by(username=username).first()
    login_user(user, remember=remember)
    return redirect(url_for('main.index'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
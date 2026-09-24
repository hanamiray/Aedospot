import hashlib
import os
import uuid
import traceback
import requests
from flask import Flask, request, jsonify, session, render_template, send_from_directory, redirect, send_file
from flask_cors import CORS
from datetime import timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time
from dotenv import load_dotenv
from db import get_db_connection
import json 
import csv
from io import BytesIO, StringIO
from datetime import datetime
from zoneinfo import ZoneInfo
import base64
from html import escape

# Environmental Data's per-day boundary must be Manila wall-clock midnight
# (12:00 AM-11:59 PM PHT), not UTC. datetime.utcnow().date() is 8 hours
# behind Manila, so anything polled between 12:00 AM-7:59 AM PHT would land
# under the *previous* day's row instead of today's — this is the
# Manila-aware replacement used by archive_device_daily_readings's caller.
MANILA_TZ = ZoneInfo('Asia/Manila')


def manila_today_str():
    return datetime.now(MANILA_TZ).date().isoformat()

load_dotenv()

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'   
app.permanent_session_lifetime = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB cap, mainly for avatar uploads
CORS(app, supports_credentials=True)

# Where uploaded profile pictures are stored, and what's allowed.
AVATAR_UPLOAD_FOLDER = os.path.join('static', 'avatars')
ALLOWED_AVATAR_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def to_iso_ts(value):
    """Normalize a SQLite TIMESTAMP value into a consistent 'YYYY-MM-DDTHH:MM:SS'
    string before it goes into a JSON response.

    Depending on how the sqlite3 connection is configured, a TIMESTAMP column can come
    back either as a plain 'YYYY-MM-DD HH:MM:SS' string OR as a Python datetime object.
    When it's a datetime object, Flask's default JSON encoder serializes it as an RFC
    1123 string ('Wed, 03 Sep 2026 10:41:13 GMT') instead — a completely different shape
    than every frontend page expects. Each page does `value.replace(' ', 'T')` and feeds
    that into `new Date(...)`, assuming the SQLite string shape; the RFC 1123 shape has
    extra spaces/commas that break that replace and the date fails to parse, which is
    what was showing up to users as "Invalid Date" (e.g. the Joined column on the
    Residents page). Routing every outgoing created_at/timestamp through this function
    guarantees the frontend always receives the same predictable shape.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%dT%H:%M:%S')
    s = str(value).strip()
    if ' ' in s and 'T' not in s:
        s = s.replace(' ', 'T', 1)
    return s


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

def is_password_strong(password):
    import re
    return (
        len(password) >= 8
        and re.search(r'[A-Z]', password)
        and re.search(r'[a-z]', password)
        and re.search(r'[0-9]', password)
        and re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\];\'`~/\\]', password)
    )

def normalize_answer(answer):
    # Case/whitespace-insensitive so "Fluffy" and " fluffy " match the same answer
    return answer.strip().lower()

def hash_answer(answer):
    return hashlib.sha256(normalize_answer(answer).encode()).hexdigest()

def verify_answer(answer, hashed):
    return hash_answer(answer) == hashed

DEFAULT_RESET_PASSWORD = 'reset'  

# The only 4 accounts allowed to have admin access.
DEFAULT_ADMIN_ACCOUNTS = [
    {'email': 'miraberonhannah@gmail.com', 'password': 'admin1', 'fullname': 'admin1'},
    {'email': 'ryanregistos@gmail.com',    'password': 'admin2', 'fullname': 'admin2'},
    {'email': 'salinasjancee@gmail.com',   'password': 'admin3', 'fullname': 'admin3'},
    {'email': 'beasistina44@gmail.com',    'password': 'admin4', 'fullname': 'admin4'},
]

# Keep this list in sync with the <option value="..."> entries in
# resident_signup.html (the 8 barangays of Morong, Rizal).
BARANGAYS = [
    'Bombongan',
    'Caniogan-Calero-Lanang',
    'Lagundi',
    'Maybancal',
    'San Guillermo',
    'San Jose',
    'San Juan',
    'San Pedro',
]

# Keep these values in sync with the <option value="..."> entries in signup.html
SECURITY_QUESTIONS = {
    'first_pet': 'What was the name of your first pet?',
    'maiden_name': "What is your mother's maiden name?",
    'birth_city': 'What city were you born in?',
    'crush': 'Who is your crush?',
    'favorite_teacher': 'Who was your favorite childhood teacher?',
    'childhood_nickname': 'What was your childhood nickname?',
}

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT,
            barangay TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS risk_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            alert_message TEXT,
            risk_level TEXT,
            barangay TEXT,
            email_sent INTEGER DEFAULT 1,
            sms_sent INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            level TEXT DEFAULT 'info',
            created_by INTEGER,
            barangay TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scheduled_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            risk_alert_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            channel TEXT NOT NULL,
            risk_level TEXT,
            temperature REAL,
            humidity REAL,
            rainfall_mm REAL,
            ph_level REAL,
            wind_speed REAL,
            scheduled_for TIMESTAMP NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sent_at TIMESTAMP,
            UNIQUE (risk_alert_id, user_id, channel),
            FOREIGN KEY (risk_alert_id) REFERENCES risk_alerts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dismissed_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            notification_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, notification_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_dismissed_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            alert_id INTEGER NOT NULL,
            dismissed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(source, alert_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            sensor_refresh_rate INTEGER NOT NULL DEFAULT 1,
            global_notif_freq TEXT DEFAULT '15',
            moderate_advice_message TEXT,
            high_advice_message TEXT,
            moderate_sms_message TEXT,
            high_sms_message TEXT,
            moderate_app_message TEXT,
            high_app_message TEXT,
            updated_by INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute("PRAGMA table_info(app_settings)")
    app_settings_cols = [col[1] for col in cursor.fetchall()]
    if 'global_notif_freq' not in app_settings_cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN global_notif_freq TEXT DEFAULT '15'")
    if 'moderate_advice_message' not in app_settings_cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN moderate_advice_message TEXT")
    if 'high_advice_message' not in app_settings_cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN high_advice_message TEXT")
    if 'moderate_sms_message' not in app_settings_cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN moderate_sms_message TEXT")
    if 'high_sms_message' not in app_settings_cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN high_sms_message TEXT")
    if 'moderate_app_message' not in app_settings_cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN moderate_app_message TEXT")
    if 'high_app_message' not in app_settings_cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN high_app_message TEXT")
    if 'lstm_deployed_device_id' not in app_settings_cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN lstm_deployed_device_id INTEGER")
    if 'lstm_forecast_horizon' not in app_settings_cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN lstm_forecast_horizon INTEGER DEFAULT 7")
    if 'lstm_confidence_display' not in app_settings_cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN lstm_confidence_display INTEGER DEFAULT 1")

    cursor.execute("SELECT id FROM app_settings WHERE id = 1")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO app_settings (id, sensor_refresh_rate, global_notif_freq) VALUES (1, 1, '15')")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hotspot_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            lat REAL NOT NULL,
            lng REAL NOT NULL,
            temperature REAL,
            humidity REAL,
            rainfall_mm REAL,
            ph_level REAL,
            wind_speed REAL,
            risk_level TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            lat REAL NOT NULL,
            lng REAL NOT NULL,
            status TEXT DEFAULT 'offline',
            temperature REAL,
            humidity REAL,
            rainfall_mm REAL,
            ph_level REAL,
            wind_speed REAL,
            risk_level TEXT DEFAULT 'low',
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sensor_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor_name TEXT NOT NULL UNIQUE,
            device_id INTEGER,
            updated_by INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES device_deployments(id),
            FOREIGN KEY (updated_by) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hotspot_device_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hotspot_id INTEGER NOT NULL UNIQUE,
            device_id INTEGER,
            updated_by INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (hotspot_id) REFERENCES hotspot_locations(id),
            FOREIGN KEY (device_id) REFERENCES device_deployments(id),
            FOREIGN KEY (updated_by) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sensor_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            temperature REAL,
            humidity REAL,
            rainfall_mm REAL,
            ph_level REAL,
            wind_speed REAL,
            wind_direction TEXT,
            risk_level INTEGER,
            risk_bucket TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_daily_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            reading_date TEXT NOT NULL,
            temperature REAL,
            humidity REAL,
            rainfall_mm REAL,
            ph_level REAL,
            wind_speed REAL,
            risk_level TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES device_deployments(id),
            UNIQUE(device_id, reading_date)
        )
    ''')

    # device_daily_readings used to get overwritten by whichever poll landed
    # last each day (temperature = excluded.temperature, etc.) — an early
    # morning Low reading would be silently replaced by an afternoon
    # Moderate one. These extra columns let one row per device per day still
    # represent the WHOLE day: temperature/humidity/rainfall_mm/ph_level/
    # wind_speed become a running AVERAGE across every poll that day
    # (sample_count is the divisor), and risk_level becomes the most
    # frequent ("mode") risk bucket seen that day, tracked via the three
    # risk_*_count tallies — see archive_device_daily_readings().
    cursor.execute("PRAGMA table_info(device_daily_readings)")
    ddr_columns = [col[1] for col in cursor.fetchall()]
    if 'sample_count' not in ddr_columns:
        cursor.execute("ALTER TABLE device_daily_readings ADD COLUMN sample_count INTEGER DEFAULT 1")
    if 'risk_low_count' not in ddr_columns:
        cursor.execute("ALTER TABLE device_daily_readings ADD COLUMN risk_low_count INTEGER DEFAULT 0")
    if 'risk_moderate_count' not in ddr_columns:
        cursor.execute("ALTER TABLE device_daily_readings ADD COLUMN risk_moderate_count INTEGER DEFAULT 0")
    if 'risk_high_count' not in ddr_columns:
        cursor.execute("ALTER TABLE device_daily_readings ADD COLUMN risk_high_count INTEGER DEFAULT 0")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS lstm_weekly_archive (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            week_start TEXT NOT NULL,
            week_end TEXT NOT NULL,
            risk_level TEXT,
            confidence REAL,
            note TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(week_start, week_end)
        )
    ''')


    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gis_boundary_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            override_key TEXT UNIQUE NOT NULL,
            geojson TEXT NOT NULL,
            updated_by INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (updated_by) REFERENCES users(id)
        )
    ''')

    # Check existing columns
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    
    # Add missing columns if not exist
    if 'phone' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    if 'is_admin' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    if 'must_setup' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN must_setup INTEGER DEFAULT 0")
    if 'security_question' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN security_question TEXT")
    if 'security_answer' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN security_answer TEXT")
    if 'email_enabled' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN email_enabled INTEGER DEFAULT 1")
    if 'notif_freq' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN notif_freq INTEGER DEFAULT 15")

    cursor.execute("ALTER TABLE users ALTER COLUMN notif_freq TYPE TEXT USING notif_freq::TEXT")

    if 'sms_enabled' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN sms_enabled INTEGER DEFAULT 0")
    if 'in_app_enabled' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN in_app_enabled INTEGER DEFAULT 1")


    if 'sms_notif_freq' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN sms_notif_freq TEXT DEFAULT '15'")
    cursor.execute("ALTER TABLE users ALTER COLUMN sms_notif_freq TYPE TEXT USING sms_notif_freq::TEXT")
    cursor.execute("UPDATE users SET sms_notif_freq = 15 WHERE sms_notif_freq IS NULL AND (is_admin = 0 OR is_admin IS NULL)")

    # One-time repair: some residents may have been created with NULL
    # email_enabled / notif_freq / in_app_enabled because those columns' stored
    # DEFAULT was stale on this DB at the time they signed up (see /api/register).
    # A NULL here isn't a deliberate "turned off" choice — nobody can set NULL from
    # the UI — so it's safe to backfill it to the intended defaults. Residents who
    # actually turned notifications off themselves have real 0 / 'off' values, which
    # this does not touch.
    cursor.execute("UPDATE users SET email_enabled = 1 WHERE email_enabled IS NULL AND (is_admin = 0 OR is_admin IS NULL)")
    cursor.execute("UPDATE users SET notif_freq = 15 WHERE notif_freq IS NULL AND (is_admin = 0 OR is_admin IS NULL)")
    cursor.execute("UPDATE users SET in_app_enabled = 1 WHERE in_app_enabled IS NULL AND (is_admin = 0 OR is_admin IS NULL)")

    # Same repair for is_admin / must_setup / created_at — confirmed via the Supabase
    # table editor that at least one resident row had all three sitting at NULL
    # (nobody can produce NULL for these from the UI either). is_admin NULL can only
    # mean "not an admin" (the 4 seeded admin accounts always set is_admin=1
    # explicitly), so it's safe to backfill to 0. must_setup NULL just means "not
    # mid-password-reset", so 0 is correct there too. created_at NULL can't be
    # recovered to the real signup date since it was never recorded, so this backfills
    # it to now — later than the true join date, but far better than showing blank
    # forever on the Residents page.
    cursor.execute("UPDATE users SET is_admin = 0 WHERE is_admin IS NULL")
    cursor.execute("UPDATE users SET must_setup = 0 WHERE must_setup IS NULL")
    cursor.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
        
    # ── IDINAGDAG KO ITO ──
    if 'data_refresh_rate' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN data_refresh_rate INTEGER DEFAULT 1")
    if 'barangay' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN barangay TEXT")
    if 'avatar_url' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT")
    if 'near_hotspot_id' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN near_hotspot_id INTEGER")

    # Same migration for risk_alerts
    cursor.execute("PRAGMA table_info(risk_alerts)")
    risk_alert_columns = [col[1] for col in cursor.fetchall()]
    if 'barangay' not in risk_alert_columns:
        cursor.execute("ALTER TABLE risk_alerts ADD COLUMN barangay TEXT")
    if 'email_subject' not in risk_alert_columns:
        cursor.execute("ALTER TABLE risk_alerts ADD COLUMN email_subject TEXT")
    if 'email_body' not in risk_alert_columns:
        cursor.execute("ALTER TABLE risk_alerts ADD COLUMN email_body TEXT")
    # email_sent / sms_sent freeze, at the moment each alert was created, whether it
    # actually went out over that channel. Older rows predate this column: every one
    # of them was only ever inserted after a successful email send (see
    # risk_monitor_loop), so backfilling them as email_sent=1 is accurate; SMS sending
    # didn't exist yet at that point, so they backfill as sms_sent=0.
    if 'email_sent' not in risk_alert_columns:
        cursor.execute("ALTER TABLE risk_alerts ADD COLUMN email_sent INTEGER DEFAULT 1")
    if 'sms_sent' not in risk_alert_columns:
        cursor.execute("ALTER TABLE risk_alerts ADD COLUMN sms_sent INTEGER DEFAULT 0")
    # Backfill any existing rows whose created_at came back NULL (this table's
    # DEFAULT CURRENT_TIMESTAMP wasn't firing on inserts — see the explicit
    # created_at now passed in risk_monitor_loop's INSERT). Can't recover the
    # real detection time since it was never recorded, so this sets it to now —
    # later than the true detection time, but far better than "—" forever on
    # the resident Alerts page.
    cursor.execute("UPDATE risk_alerts SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")

    cursor.execute("PRAGMA table_info(notifications)")
    notification_columns = [col[1] for col in cursor.fetchall()]
    if 'barangay' not in notification_columns:
        cursor.execute("ALTER TABLE notifications ADD COLUMN barangay TEXT")
    if 'admin_only' not in notification_columns:
        # Distinguishes internal/admin-facing notices (e.g. sensor refresh
        # rate changes) from resident-facing broadcasts. Both types live in
        # the same table and both have barangay = NULL ("everyone"), so
        # without this flag an admin-only notice would incorrectly also show
        # up on every resident's own Alerts page.
        cursor.execute("ALTER TABLE notifications ADD COLUMN admin_only INTEGER DEFAULT 0")
    # Backfill: any "Sensor Data Setting Changed" row already sitting in the
    # table from before admin_only existed (or from any other gap) defaulted
    # to admin_only = 0, which is exactly what was leaking these internal
    # notices onto residents' own Alerts page. Re-tag them by title so the
    # fix also cleans up rows that already exist, not just new ones going
    # forward.
    cursor.execute(
        "UPDATE notifications SET admin_only = 1 "
        "WHERE title = 'Sensor Data Setting Changed' AND COALESCE(admin_only, 0) = 0"
    )
    # Same NULL-created_at issue as risk_alerts above — backfill any rows
    # stuck with NULL (from before created_at was passed explicitly) so they
    # sort correctly instead of always falling to the bottom of Recent Alerts.
    cursor.execute("UPDATE notifications SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")

    # Same migration for hotspot_locations / device_deployments
    cursor.execute("PRAGMA table_info(hotspot_locations)")
    hotspot_columns = [col[1] for col in cursor.fetchall()]
    if 'temperature' not in hotspot_columns:
        cursor.execute("ALTER TABLE hotspot_locations ADD COLUMN temperature REAL")
    if 'humidity' not in hotspot_columns:
        cursor.execute("ALTER TABLE hotspot_locations ADD COLUMN humidity REAL")
    if 'rainfall_mm' not in hotspot_columns:
        cursor.execute("ALTER TABLE hotspot_locations ADD COLUMN rainfall_mm REAL")
    if 'ph_level' not in hotspot_columns:
        cursor.execute("ALTER TABLE hotspot_locations ADD COLUMN ph_level REAL")
    if 'wind_speed' not in hotspot_columns:
        cursor.execute("ALTER TABLE hotspot_locations ADD COLUMN wind_speed REAL")
    if 'risk_level' not in hotspot_columns:
        cursor.execute("ALTER TABLE hotspot_locations ADD COLUMN risk_level TEXT")
    if 'created_by' not in hotspot_columns:
        cursor.execute("ALTER TABLE hotspot_locations ADD COLUMN created_by INTEGER")
    if 'updated_at' not in hotspot_columns:
        cursor.execute("ALTER TABLE hotspot_locations ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

    cursor.execute("PRAGMA table_info(device_deployments)")
    device_columns = [col[1] for col in cursor.fetchall()]
    if 'status' not in device_columns:
        cursor.execute("ALTER TABLE device_deployments ADD COLUMN status TEXT DEFAULT 'offline'")
    if 'temperature' not in device_columns:
        cursor.execute("ALTER TABLE device_deployments ADD COLUMN temperature REAL")
    if 'humidity' not in device_columns:
        cursor.execute("ALTER TABLE device_deployments ADD COLUMN humidity REAL")
    if 'rainfall_mm' not in device_columns:
        cursor.execute("ALTER TABLE device_deployments ADD COLUMN rainfall_mm REAL")
    if 'ph_level' not in device_columns:
        cursor.execute("ALTER TABLE device_deployments ADD COLUMN ph_level REAL")
    if 'wind_speed' not in device_columns:
        cursor.execute("ALTER TABLE device_deployments ADD COLUMN wind_speed REAL")
    if 'risk_level' not in device_columns:
        cursor.execute("ALTER TABLE device_deployments ADD COLUMN risk_level TEXT DEFAULT 'low'")
    if 'created_by' not in device_columns:
        cursor.execute("ALTER TABLE device_deployments ADD COLUMN created_by INTEGER")
    if 'updated_at' not in device_columns:
        cursor.execute("ALTER TABLE device_deployments ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

    # One-time data correction
    cursor.execute("UPDATE device_deployments SET status = 'offline' WHERE status = 'online'")

    # Seed the 4 fixed admin accounts if they don't exist yet.
    for admin in DEFAULT_ADMIN_ACCOUNTS:
        cursor.execute("SELECT id FROM users WHERE email = ?", (admin['email'],))
        if not cursor.fetchone():
            # created_at set explicitly (see note above the notification-defaults
            # backfill): this DB's column defaults aren't reliably applied on insert,
            # so every column that needs a real value gets one written here instead
            # of being left to fall back on the schema's DEFAULT clause.
            cursor.execute(
                "INSERT INTO users (fullname, email, password, phone, is_admin, must_setup, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                (admin['fullname'], admin['email'], hash_password(admin['password']), None, 1, 1)
            )
            print(f"Admin account created — email: '{admin['email']}', password: '{admin['password']}' (please change this!)")
    
    conn.commit()
    conn.close()
    print("Database initialized successfully!")


def admin_required(f):
    """Guards JSON/API endpoints."""
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Please login first'}), 401
        if not session.get('is_admin'):
            return jsonify({'success': False, 'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return wrapper


def login_required(f):
    """Any logged-in user (admin or resident) may view this page."""
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return wrapper


def api_login_required(f):
    """Guards JSON/API endpoints that any logged-in user may call."""
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Please login first'}), 401
        return f(*args, **kwargs)
    return wrapper


def admin_page_required(f):
    """Only admins may view this page."""
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/admin')
        if not session.get('is_admin'):
            return redirect('/resident/home')
        return f(*args, **kwargs)
    return wrapper


def resident_page_required(f):
    """Only residents may view this page."""
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        if session.get('is_admin'):
            return redirect('/admin/home')
        return f(*args, **kwargs)
    return wrapper


def role_redirect(admin_path, resident_path):
    if 'user_id' not in session:
        return redirect('/login')
    return redirect(admin_path) if session.get('is_admin') else redirect(resident_path)


# ── PAGE ROUTES ──────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('shared_main.html')

@app.route('/login')
def login_page():
    if session.get('is_admin'):
        return redirect('/admin/home')
    if 'user_id' in session:
        return redirect('/resident/home')
    return render_template('resident_login.html')

@app.route('/admin')
def admin_login_page():
    if session.get('is_admin'):
        return redirect('/admin/home')
    if 'user_id' in session:
        return redirect('/resident/home')
    return render_template('admin_login.html')

@app.route('/signup')
def signup_page():
    return render_template('resident_signup.html')

@app.route('/reset-password')
def reset_password_page():
    return render_template('shared_reset_password.html')


# ── ADMIN PAGES ──────────────────────────────────────────────────────
@app.route('/admin/home')
@admin_page_required
def admin_home():
    return render_template('admin_home.html')

@app.route('/admin/account')
@admin_page_required
def admin_account():
    return render_template('admin_account.html')

@app.route('/admin/alerts')
@admin_page_required
def admin_alerts():
    return render_template('admin_alerts.html')

@app.route('/admin/risk_map')
@admin_page_required
def admin_risk_map():
    return render_template('admin_risk_map.html')

@app.route('/admin/settings')
@admin_page_required
def admin_settings():
    return render_template('admin_settings.html')

@app.route('/admin_user_residents')
@admin_page_required
def admin_user_residents():
    return render_template('admin_user_residents.html')

@app.route('/admin_reports')
@admin_page_required
def admin_reports():
    return render_template('admin_reports.html')


# ── RESIDENT PAGES ───────────────────────────────────────────────────
@app.route('/resident/home')
@resident_page_required
def resident_home():
    return render_template('resident_home.html')

@app.route('/resident/account')
@resident_page_required
def resident_account():
    return render_template('resident_account.html')

@app.route('/resident/alerts')
@resident_page_required
def resident_alerts():
    return render_template('resident_alerts.html')

@app.route('/resident/risk_map')
@resident_page_required
def resident_risk_map():
    return render_template('resident_risk_map.html')

@app.route('/resident/settings')
@resident_page_required
def resident_settings():
    return render_template('resident_settings.html')


# ── LEGACY / SHARED URLS ─────────────────────────────────────────────
@app.route('/home')
def home():
    return role_redirect('/admin/home', '/resident/home')

@app.route('/monitoring')
def monitoring():
    return role_redirect('/admin/home', '/resident/home')

@app.route('/account')
def account():
    return role_redirect('/admin/account', '/resident/account')

@app.route('/alerts')
def alerts():
    return role_redirect('/admin/alerts', '/resident/alerts')

@app.route('/risk_map')
def risk_map():
    return role_redirect('/admin/risk_map', '/resident/risk_map')

@app.route('/settings')
def settings():
    return role_redirect('/admin/settings', '/resident/settings')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    fullname = f"{first_name} {last_name}"
    email = data.get('email', '').strip().lower()
    phone = data.get('phone', '').strip()
    barangay = data.get('barangay', '').strip()
    password = data.get('password', '')
    security_question = data.get('security_question', '').strip()
    security_answer = data.get('security_answer', '').strip()

    if not fullname or not email or not phone or not password:
        return jsonify({
            'success': False,
            'message': 'All fields are required'
        }), 400

    if not barangay or barangay not in BARANGAYS:
        return jsonify({
            'success': False,
            'message': 'Please select a valid barangay'
        }), 400

    if not security_question or security_question not in SECURITY_QUESTIONS:
        return jsonify({
            'success': False,
            'message': 'Please select a valid security question'
        }), 400

    if not security_answer:
        return jsonify({
            'success': False,
            'message': 'Please provide an answer to your security question'
        }), 400

    if len(password) < 4:
        return jsonify({
            'success': False,
            'message': 'Password must be at least 4 characters'
        }), 400

    # Format phone number with +63 prefix
    digits_only = ''.join(filter(str.isdigit, phone))
    if len(digits_only) == 10:
        formatted_phone = f"+63{digits_only}"
    else:
        formatted_phone = phone

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if email already exists
    cursor.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    )

    if cursor.fetchone():
        conn.close()
        return jsonify({
            'success': False,
            'message': 'Email already registered'
        }), 409

    hashed_pw = hash_password(password)
    hashed_answer = hash_answer(security_answer)

    # NOTE: notification defaults are set explicitly here instead of relying on the
    # `ALTER TABLE ... DEFAULT` fallback. Once a column already exists in an installed
    # DB, re-running init_db() with an updated DEFAULT value does NOT retroactively
    # change that column's stored default — so a deployed database created before
    # these defaults were correct could silently create new residents with
    # notifications turned off. Being explicit here guarantees every new resident
    # starts with email on, notification frequency at 15 minutes, and in-app on,
    # regardless of whatever the DB's column default happens to be. Same reasoning
    # for is_admin/must_setup/created_at: confirmed via the Supabase table editor
    # that rows inserted without these columns explicitly set were landing as NULL
    # instead of falling back to the schema default, so every column that needs a
    # real value on signup is written here explicitly rather than left to chance.
    cursor.execute(
        "INSERT INTO users (fullname, email, password, phone, barangay, security_question, security_answer, "
        "email_enabled, notif_freq, sms_enabled, in_app_enabled, is_admin, must_setup, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, 15, 0, 1, 0, 0, CURRENT_TIMESTAMP)",
        (fullname, email, hashed_pw, formatted_phone, barangay, security_question, hashed_answer)
    )

    conn.commit()

    session['user_id'] = cursor.lastrowid
    session['user_name'] = fullname
    session['user_email'] = email
    session['user_phone'] = formatted_phone
    session['user_barangay'] = barangay
    session['is_admin'] = False

    conn.close()

    return jsonify({
        'success': True,
        'message': f'Welcome, {fullname}!',
        'user': {
            'name': fullname,
            'email': email,
            'phone': formatted_phone,
            'barangay': barangay,
            'is_admin': False
        }
    })

@app.route('/api/login', methods=['POST'])
def login():
    """Resident login only."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, fullname, email, password, is_admin, must_setup FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    
    if verify_password(password, user[3]):
        is_admin = bool(user[4])
        if is_admin:
            return jsonify({
                'success': False,
                'message': 'This is an admin account. Please use the admin login page instead.'
            }), 403
        must_setup = bool(user[5])
        session['user_id'] = user[0]
        session['user_name'] = user[1]
        session['user_email'] = user[2]
        session['is_admin'] = False
        return jsonify({
            'success': True,
            'message': f'Welcome back, {user[1]}!',
            'user': {'id': user[0], 'name': user[1], 'email': user[2], 'is_admin': False, 'must_setup': must_setup}
        })
    else:
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401


@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Admin login only."""
    data = request.get_json()
    username = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, fullname, email, password, is_admin, must_setup FROM users WHERE email = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_password(password, user[3]):
        return jsonify({'success': False, 'message': 'Invalid admin credentials'}), 401

    if not user[4]:
        return jsonify({'success': False, 'message': 'This account does not have admin access'}), 403

    session['user_id'] = user[0]
    session['user_name'] = user[1]
    session['user_email'] = user[2]
    session['is_admin'] = True
    return jsonify({
        'success': True,
        'message': f'Welcome back, {user[1]}!',
        'user': {'id': user[0], 'name': user[1], 'email': user[2], 'is_admin': True, 'must_setup': bool(user[5])}
    })
    
@app.route('/api/get_security_question', methods=['POST'])
def get_security_question():
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT security_question FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()

    # Deliberately vague message on failure so this endpoint can't be used
    # to enumerate which emails are registered.
    if not row or not row[0]:
        return jsonify({'success': False, 'message': 'No security question found for that email'}), 404

    question_text = SECURITY_QUESTIONS.get(row[0], row[0])
    return jsonify({'success': True, 'question': question_text})


@app.route('/api/verify_security_answer', methods=['POST'])
def verify_security_answer():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    answer = data.get('answer', '')

    if not email or not answer:
        return jsonify({'success': False, 'message': 'Answer is required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT security_answer FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()

    if not row or not row[0] or not verify_answer(answer, row[0]):
        return jsonify({'success': False, 'message': 'Incorrect answer'}), 401

    return jsonify({'success': True, 'message': 'Answer verified'})


@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    new_password = data.get('new_password', '')
    security_answer = data.get('security_answer', '')

    if not email or not new_password or not security_answer:
        return jsonify({
            'success': False,
            'message': 'All fields are required'
        }), 400

    if len(new_password) < 4:
        return jsonify({
            'success': False,
            'message': 'Password must be at least 4 characters'
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, security_answer, fullname, is_admin FROM users WHERE email = ?",
        (email,)
    )

    user = cursor.fetchone()

    if not user:
        conn.close()

        return jsonify({
            'success': False,
            'message': 'Email not found'
        }), 404

    if not user[1] or not verify_answer(security_answer, user[1]):
        conn.close()
        return jsonify({
            'success': False,
            'message': 'Security answer is incorrect'
        }), 401

    hashed_pw = hash_password(new_password)
    cursor.execute(
        "UPDATE users SET password = ? WHERE email = ?",
        (hashed_pw, email)
    )
    conn.commit()
    conn.close()

    # Log the user straight in after a successful reset
    session.permanent = True
    session['user_id'] = user[0]
    session['user_name'] = user[2]
    session['user_email'] = email
    session['is_admin'] = bool(user[3])

    return jsonify({
        'success': True,
        'message': 'Password updated successfully'
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/check_session', methods=['GET'])
def check_session():
    if 'user_id' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT phone, is_admin, must_setup, created_at, barangay, avatar_url, near_hotspot_id FROM users WHERE id = ?", (session['user_id'],))
        user_data = cursor.fetchone()
        conn.close()
        
        return jsonify({
            'logged_in': True,
            'user': {
                'id': session['user_id'],
                'name': session.get('user_name'),
                'email': session.get('user_email'),
                'phone': user_data[0] if user_data else None,
                'is_admin': bool(user_data[1]) if user_data else bool(session.get('is_admin')),
                'must_setup': bool(user_data[2]) if user_data else False,
                'created_at': to_iso_ts(user_data[3]) if user_data else None,
                'barangay': user_data[4] if user_data else session.get('user_barangay'),
                'avatar_url': user_data[5] if user_data else None,
                'near_hotspot_id': user_data[6] if user_data else None
            }
        })
    return jsonify({'logged_in': False})

@app.route('/api/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    barangay = data.get('barangay', '').strip()
    phone = data.get('phone', '').strip() 
    
    if not first_name or not last_name:
        return jsonify({'success': False, 'message': 'First name and last name are required'}), 400

    if barangay and barangay not in BARANGAYS:
        return jsonify({'success': False, 'message': 'Please select a valid barangay'}), 400
    
    # ── PHONE VALIDATION (same as signup) ──
    if phone:
        digits_only = ''.join(filter(str.isdigit, phone))
        # Remove +63 prefix if present before validation
        if digits_only.startswith('63') and len(digits_only) == 12:
            digits_only = digits_only[2:]
        if len(digits_only) != 10:
            return jsonify({
                'success': False,
                'message': 'Please enter exactly 10 digits (e.g., 9123456789)'
            }), 400
        formatted_phone = f"+63{digits_only}"
    else:
        formatted_phone = None
    
    user_id = session['user_id']
    fullname = f"{first_name} {last_name}"
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Update user profile (name, barangay, and phone)
    if barangay and formatted_phone:
        cursor.execute(
            "UPDATE users SET fullname = ?, barangay = ?, phone = ? WHERE id = ?",
            (fullname, barangay, formatted_phone, user_id)
        )
    elif barangay:
        cursor.execute(
            "UPDATE users SET fullname = ?, barangay = ? WHERE id = ?",
            (fullname, barangay, user_id)
        )
    elif formatted_phone:
        cursor.execute(
            "UPDATE users SET fullname = ?, phone = ? WHERE id = ?",
            (fullname, formatted_phone, user_id)
        )
    else:
        cursor.execute(
            "UPDATE users SET fullname = ? WHERE id = ?",
            (fullname, user_id)
        )
    conn.commit()
    
    # Get updated user data
    cursor.execute("SELECT email, phone, barangay FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    # Update session
    session['user_name'] = fullname
    if barangay:
        session['user_barangay'] = barangay
    if formatted_phone:
        session['user_phone'] = formatted_phone
    
    return jsonify({
        'success': True,
        'message': 'Profile updated successfully',
        'user': {
            'name': fullname,
            'email': user_data[0] if user_data else None,
            'phone': user_data[1] if user_data else None,
            'barangay': user_data[2] if user_data else None
        }
    })

@app.route('/api/upload_avatar', methods=['POST'])
def upload_avatar():
    """Lets any logged-in user (admin or resident) replace their profile picture."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    if 'avatar' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400

    file = request.files['avatar']
    if not file or file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_AVATAR_EXTENSIONS:
        return jsonify({
            'success': False,
            'message': 'Unsupported file type. Please upload a PNG, JPG, GIF, or WEBP image.'
        }), 400

    user_id = session['user_id']

    base_dir = os.path.dirname(os.path.abspath(__file__))
    avatar_folder = os.path.join(base_dir, 'static', 'avatars')
    
    os.makedirs(avatar_folder, exist_ok=True)
    
    # Generate unique filename
    filename = f"user_{user_id}_{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(avatar_folder, filename)
    
    # Save the file
    file.save(filepath)
    print(f"📁 Avatar saved to: {filepath}")

    # URL path for the client
    avatar_url = f"/static/avatars/{filename}"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT avatar_url FROM users WHERE id = ?", (user_id,))
    old_row = cursor.fetchone()
    if old_row and old_row[0]:
        old_path = old_row[0].lstrip('/')
        full_old_path = os.path.join(base_dir, old_path)
        if os.path.exists(full_old_path):
            try:
                os.remove(full_old_path)
                print(f"🗑️ Deleted old avatar: {full_old_path}")
            except OSError as e:
                print(f"⚠️ Could not delete old avatar: {e}")

    cursor.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar_url, user_id))
    conn.commit()
    conn.close()

    session['user_avatar'] = avatar_url

    return jsonify({
        'success': True,
        'message': 'Profile picture updated',
        'avatar_url': avatar_url
    })

@app.route('/api/complete_setup', methods=['POST'])
def complete_setup():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    data = request.get_json()
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    new_password = data.get('new_password', '')

    if not new_password:
        return jsonify({'success': False, 'message': 'A new password is required'}), 400

    if not is_password_strong(new_password):
        return jsonify({
            'success': False,
            'message': 'Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character'
        }), 400

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    if first_name and last_name:
        fullname = f"{first_name} {last_name}"
        cursor.execute(
            "UPDATE users SET fullname = ?, password = ?, must_setup = 0 WHERE id = ?",
            (fullname, hash_password(new_password), user_id)
        )
        session['user_name'] = fullname
    else:
        cursor.execute(
            "UPDATE users SET password = ?, must_setup = 0 WHERE id = ?",
            (hash_password(new_password), user_id)
        )

    conn.commit()

    cursor.execute("SELECT fullname, email, phone, is_admin FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()

    return jsonify({
        'success': True,
        'message': 'Profile set up successfully!',
        'user': {
            'name': user_data[0] if user_data else None,
            'email': user_data[1] if user_data else None,
            'phone': user_data[2] if user_data else None,
            'is_admin': bool(user_data[3]) if user_data else False,
            'must_setup': False
        }
    })


@app.route('/api/update_password', methods=['POST'])
def update_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    data = request.get_json()
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if not current_password or not new_password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    if len(new_password) < 4:
        return jsonify({'success': False, 'message': 'New password must be at least 4 characters'}), 400

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()

    if not row or not verify_password(current_password, row[0]):
        conn.close()
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 401

    cursor.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (hash_password(new_password), user_id)
    )
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Password updated successfully'})


@app.route('/api/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({'success': True, 'message': 'Password reset link sent to your email (demo feature)'})
    else:
        return jsonify({'success': False, 'message': 'Email not found'}), 404
    

@app.route('/api/get_notification_settings', methods=['GET'])
def get_notification_settings():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    user_id = session['user_id']

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Kunin ang BOTH settings: notif_freq (para sa email), sms_notif_freq
            # (para sa SMS, independent from email's) at data_refresh_rate
            # para sa user settings
            cursor.execute(
                "SELECT email_enabled, notif_freq, data_refresh_rate, sms_enabled, phone, in_app_enabled, sms_notif_freq "
                "FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()

            # Kunin din ang admin-controlled global frequency
            cursor.execute("SELECT global_notif_freq FROM app_settings WHERE id = 1")
            global_row = cursor.fetchone()

        if row:
            # IMPORTANT: Kunin ang raw value from DB. Ang DB ay naka-store as integer (15, 30, 60)
            # o kaya 'off' (kung minsan string). I-convert para sa frontend.
            raw_freq = row[1]
            
            # Para sa display, siguraduhing integer ito kung hindi 'off'
            if raw_freq == 'off' or raw_freq == 0:
                freq_val = 'off'
            else:
                # Convert to int para sa dropdown
                try:
                    freq_val = int(raw_freq) if raw_freq is not None else 15
                except (ValueError, TypeError):
                    freq_val = 15

            # Same normalization as above, but for SMS's own independent
            # frequency (sms_notif_freq) — kept entirely separate so Email
            # and SMS can be set to different cadences.
            raw_sms_freq = row[6]
            if raw_sms_freq == 'off' or raw_sms_freq == 0:
                sms_freq_val = 'off'
            else:
                try:
                    sms_freq_val = int(raw_sms_freq) if raw_sms_freq is not None else 15
                except (ValueError, TypeError):
                    sms_freq_val = 15

            resp = jsonify({
                'success': True,
                'email_enabled': bool(row[0]),
                'notif_freq': freq_val,
                'sms_notif_freq': sms_freq_val,
                'data_refresh_rate': row[2],
                'sms_enabled': bool(row[3]),
                'phone': row[4],
                # In-app notifications are no longer a resident-facing toggle — they're
                # always on, so this always reports True regardless of what's stored.
                'in_app_enabled': True,
                'global_notif_freq': global_row[0] if global_row and global_row[0] is not None else '15',
                'is_admin': bool(session.get('is_admin'))
            })
            resp.headers['Cache-Control'] = 'no-store'
            return resp
        return jsonify({'success': False, 'message': 'User not found'}), 404
    except Exception as e:
        print(f"❌ get_notification_settings DB error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Could not load notification settings. Please try again.'}), 500


@app.route('/api/update_notification_settings', methods=['POST'])
@api_login_required
def update_notification_settings():
    if session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Email notification settings are only available for resident accounts.'}), 403

    data = request.get_json() or {}
    email_enabled = data.get('email_enabled')
    notif_freq = data.get('notif_freq')
    sms_enabled = data.get('sms_enabled', False)
    # Email and SMS now share ONE combined Notification Frequency (the
    # resident sets a single delivery time in the UI that applies to both
    # channels). sms_notif_freq is always mirrored from notif_freq here —
    # never taken independently from the request — so the two columns can
    # never drift apart, even if an older/other client still sends a
    # separate value for it.
    sms_notif_freq = notif_freq
    # In-app notifications can no longer be turned off by the resident — always store
    # it as enabled, regardless of what (if anything) the client sends.
    in_app_enabled = True

    if email_enabled is None or notif_freq is None:
        return jsonify({'success': False, 'message': 'email_enabled and notif_freq are required'}), 400

    def _normalize_freq(value, field_name):
        """Shared validator for notif_freq/sms_notif_freq. No silent fallback:
        if the value isn't exactly 'off', 15, 30, or 60, this raises instead of
        quietly coercing it to 15 and reporting success."""
        if value == 'off':
            return 'off', None
        try:
            freq_val = int(value)
        except (ValueError, TypeError):
            return None, f'Invalid {field_name}'
        if freq_val not in (15, 30, 60):
            return None, f'Invalid {field_name}: {freq_val}'
        return freq_val, None

    freq_val, err = _normalize_freq(notif_freq, 'notification frequency')
    if err:
        return jsonify({'success': False, 'message': err}), 400

    sms_freq_val, err = _normalize_freq(sms_notif_freq, 'SMS notification frequency')
    if err:
        return jsonify({'success': False, 'message': err}), 400

    user_id = session['user_id']
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Note: Pag 'off' ang freq, set as 'off'. 
            # Pag number, set as number.
            # notif_freq = Email's own delay, sms_notif_freq = SMS's own
            # delay — independent columns so the two channels can be set to
            # different cadences (e.g. Email every 30 min, SMS every hour).
            cursor.execute(
                "UPDATE users SET email_enabled = ?, notif_freq = ?, sms_enabled = ?, "
                "sms_notif_freq = ?, in_app_enabled = ? WHERE id = ?",
                (1 if email_enabled else 0, freq_val, 1 if sms_enabled else 0,
                 sms_freq_val, 1 if in_app_enabled else 0, user_id)
            )
            conn.commit()
    except Exception as e:
        print(f"❌ update_notification_settings DB error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Could not save notification settings. Please try again.'}), 500

    resp = jsonify({'success': True, 'message': 'Notification settings saved.'})
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/api/delete_account', methods=['DELETE'])
def delete_own_account():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if row[0]:
        conn.close()
        return jsonify({'success': False, 'message': 'Admin accounts cannot be deleted this way'}), 400

    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    cursor.execute("DELETE FROM risk_alerts WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

    session.clear()
    return jsonify({'success': True, 'message': 'Your account has been deleted.'})


# ── ADMIN: ACCOUNT MONITORING ──────────────────────────────────────

# ── ADMIN: CREATE RESIDENT (ADMIN OVERRIDE) ──
@app.route('/api/admin/users', methods=['POST'])
@admin_required
def admin_create_user():
    data = request.get_json()

    fullname = data.get('fullname', '').strip()
    email = data.get('email', '').strip().lower()
    phone = data.get('phone', '').strip()
    barangay = data.get('barangay', '').strip()
    password = data.get('password', '')
    security_question = data.get('security_question', '').strip()
    security_answer = data.get('security_answer', '').strip()

    if not fullname or not email or not phone or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    if not barangay or barangay not in BARANGAYS:
        return jsonify({'success': False, 'message': 'Please select a valid barangay'}), 400

    if not security_question or security_question not in SECURITY_QUESTIONS:
        return jsonify({'success': False, 'message': 'Please select a valid security question'}), 400

    if not security_answer:
        return jsonify({'success': False, 'message': 'Please provide an answer to your security question'}), 400

    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400

    # Format phone number with +63 prefix
    digits_only = ''.join(filter(str.isdigit, phone))
    if len(digits_only) == 10:
        formatted_phone = f"+63{digits_only}"
    else:
        formatted_phone = phone

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if email already exists
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Email already registered'}), 409

    hashed_pw = hash_password(password)
    hashed_answer = hash_answer(security_answer)

    # Same reasoning as /api/register: set notification defaults explicitly instead
    # of relying on the users table's column default, since that default can be
    # stale on an already-migrated database.
    cursor.execute(
        """INSERT INTO users 
           (fullname, email, password, phone, barangay, security_question, security_answer, is_admin, must_setup,
            email_enabled, notif_freq, sms_enabled, in_app_enabled, created_at) 
           VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1, 1, 15, 0, 1, CURRENT_TIMESTAMP)""",
        (fullname, email, hashed_pw, formatted_phone, barangay, security_question, hashed_answer)
    )

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': f'Resident {fullname} created successfully!'})


# ── ADMIN: UPDATE RESIDENT ──
@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def admin_update_user(user_id):
    if user_id == session.get('user_id'):
        return jsonify({'success': False, 'message': "Use the Account page to edit your own profile"}), 400

    data = request.get_json()
    fullname = data.get('fullname', '').strip()
    phone = data.get('phone', '').strip()
    barangay = data.get('barangay', '').strip()
    new_password = data.get('password', '')
    security_question = data.get('security_question', '').strip()
    security_answer = data.get('security_answer', '').strip()

    if not fullname:
        return jsonify({'success': False, 'message': 'Full name is required'}), 400

    if barangay and barangay not in BARANGAYS:
        return jsonify({'success': False, 'message': 'Please select a valid barangay'}), 400

    if phone:
        digits_only = ''.join(filter(str.isdigit, phone))
        if len(digits_only) == 10:
            formatted_phone = f"+63{digits_only}"
        else:
            formatted_phone = phone
    else:
        formatted_phone = None

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        return jsonify({'success': False, 'message': 'User not found'}), 404
    if target[0]:
        conn.close()
        return jsonify({'success': False, 'message': 'Cannot edit admin accounts'}), 400

    updates = ["fullname = ?"]
    params = [fullname]

    if formatted_phone:
        updates.append("phone = ?")
        params.append(formatted_phone)

    if barangay:
        updates.append("barangay = ?")
        params.append(barangay)

    if new_password and len(new_password) >= 8:
        updates.append("password = ?")
        params.append(hash_password(new_password))
        updates.append("must_setup = 1")

    if security_question and security_question in SECURITY_QUESTIONS:
        updates.append("security_question = ?")
        params.append(security_question)

    if security_answer:
        updates.append("security_answer = ?")
        params.append(hash_answer(security_answer))

    params.append(user_id)
    query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"

    cursor.execute(query, params)
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Resident updated successfully!'})

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT u.id, u.fullname, u.email, u.phone, u.is_admin, u.created_at, u.barangay, u.avatar_url, "
        "u.email_enabled, u.sms_enabled, u.notif_freq, u.near_hotspot_id, h.name "
        "FROM users u LEFT JOIN hotspot_locations h ON h.id = u.near_hotspot_id "
        "ORDER BY u.created_at DESC"
    )
    rows = cursor.fetchall()
    conn.close()

    users = [{
        'id': r[0],
        'fullname': r[1],
        'email': r[2],
        'phone': r[3],
        'is_admin': bool(r[4]),
        'created_at': to_iso_ts(r[5]),
        'barangay': r[6],
        'avatar_url': r[7],
        'email_enabled': bool(r[8]),
        'sms_enabled': bool(r[9]),
        'notif_freq': r[10],
        'near_hotspot_id': r[11],
        'near_hotspot_name': r[12]
    } for r in rows]

    return jsonify({'success': True, 'users': users})


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        return jsonify({'success': False, 'message': "You can't delete your own account while logged in"}), 400

    conn = get_db_connection()

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, is_admin FROM users WHERE id = ?", (user_id,))
        target = cursor.fetchone()

        if not target:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        if target[1]:
            return jsonify({'success': False, 'message': 'Admin accounts cannot be deleted'}), 400

        # This was the actual bug: `users` was being deleted BEFORE its
        # child rows, and scheduled_notifications wasn't touched at all.
        # risk_alerts.user_id and scheduled_notifications.user_id both have
        # a FOREIGN KEY on users(id) (see init_db above), so deleting the
        # users row first — while those rows still point at it — violates
        # the constraint and the whole request fails with a 500, which is
        # why the Delete button looked broken for any resident who'd
        # actually received an alert. Child rows now go first, then the
        # user itself.
        cursor.execute("DELETE FROM scheduled_notifications WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM risk_alerts WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM dismissed_notifications WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"❌ admin_delete_user DB error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Could not delete resident. Please try again.'}), 500
    finally:
        conn.close()

    return jsonify({'success': True, 'message': 'Account deleted successfully'})


@app.route('/api/admin/users/<int:user_id>/reset_password', methods=['POST'])
@admin_required
def admin_reset_user_password(user_id):
    if user_id == session.get('user_id'):
        return jsonify({'success': False, 'message': "Use the Security tab to change your own password"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    target = cursor.fetchone()

    if not target:
        conn.close()
        return jsonify({'success': False, 'message': 'User not found'}), 404

    cursor.execute(
        "UPDATE users SET password = ?, must_setup = 1 WHERE id = ?",
        (hash_password(DEFAULT_RESET_PASSWORD), user_id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'message': f'Password reset. Temporary password: {DEFAULT_RESET_PASSWORD}',
        'temporary_password': DEFAULT_RESET_PASSWORD
    })

# ── GLOBAL NOTIFICATION SETTINGS (ADMIN CONTROLS FOR ALL RESIDENTS) ──
@app.route('/api/get_global_notification_settings', methods=['GET'])
@admin_required
def get_global_notification_settings():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT global_notif_freq FROM app_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    
    freq = row[0] if row and row[0] is not None else '15'
    resp = jsonify({'success': True, 'notif_freq': freq})
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/api/update_global_notification_settings', methods=['POST'])
@admin_required
def update_global_notification_settings():
    data = request.get_json() or {}
    notif_freq = data.get('notif_freq')

    # NOTE: '30' was missing here — admins couldn't set the global frequency
    # to "every 30 minutes" even though residents can. Added it back.
    if notif_freq not in ('0', '15', '30', '60', 'off'):
        return jsonify({'success': False, 'message': 'Invalid notification frequency'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE app_settings SET global_notif_freq = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        (notif_freq,)
    )
    conn.commit()
    conn.close()

    resp = jsonify({'success': True, 'message': 'Global notification frequency updated successfully'})
    resp.headers['Cache-Control'] = 'no-store'
    return resp

# ── WEATHER API (OPENWEATHERMAP) ──
def get_live_weather_reading():
    API_KEY = '9d6b7b1cb940813da990bd4166045b25'
    LAT = 14.5170
    LON = 121.2370
    UNITS = 'metric'

    url = f'https://api.openweathermap.org/data/2.5/weather?lat={LAT}&lon={LON}&appid={API_KEY}&units={UNITS}'

    try:
        response = requests.get(url, timeout=8)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f'Weather service unreachable: {e}')
    if response.status_code != 200:
        raise RuntimeError('Failed to fetch weather data')
    data = response.json()

    temp = data['main']['temp']
    humidity = data['main']['humidity']
    wind_speed = data['wind']['speed']
    wind_deg = data['wind'].get('deg', 0)
    rain_mm = data.get('rain', {}).get('1h', 0)

    dirs = ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW']
    wind_dir = dirs[round(wind_deg / 45) % 8]

    risk_score = 0
    if temp >= 29:
        risk_score += 25
    if humidity >= 80:
        risk_score += 25
    if rain_mm > 0:
        risk_score += 30
    if wind_speed < 1.5:
        risk_score += 20

    risk_score = min(risk_score, 100)
    risk_bucket = 'low' if risk_score < 33 else 'moderate' if risk_score < 66 else 'high'

    return {
        'temperature': temp,
        'humidity': humidity,
        'rainfall_mm': rain_mm,
        'ph_level': 6.5,
        'wind_speed': wind_speed,
        'wind_direction': wind_dir,
        'risk_level': risk_score,
        'risk_bucket': risk_bucket,
    }


def archive_device_daily_readings(reading_date, temp, humidity, rain_mm, ph_level, wind_speed, current_risk):
    """Folds one new poll into that device's ONE row for `reading_date` in
    device_daily_readings — but instead of overwriting with just this poll
    (which erased the morning reading the moment an afternoon one came in),
    temperature/humidity/rainfall_mm/ph_level/wind_speed are updated as a
    running AVERAGE across every poll so far today, and risk_level is kept
    as whichever bucket (low/moderate/high) has shown up most often today
    (ties favor the more severe bucket). device_deployments (the live map
    pins) is intentionally NOT averaged here — it should keep showing the
    latest live reading, not a running average.
    """
    risk_bucket = (current_risk or 'low').lower()
    if risk_bucket not in ('low', 'moderate', 'high'):
        risk_bucket = 'low'

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM device_deployments')
        device_ids = [r[0] for r in cursor.fetchall()]

        for did in device_ids:
            cursor.execute('''
                UPDATE device_deployments
                SET temperature = ?, humidity = ?, rainfall_mm = ?, ph_level = ?,
                    wind_speed = ?, risk_level = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (temp, humidity, rain_mm, ph_level, wind_speed, current_risk, did))

            cursor.execute('''
                SELECT sample_count, temperature, humidity, rainfall_mm, ph_level, wind_speed,
                       risk_low_count, risk_moderate_count, risk_high_count
                FROM device_daily_readings
                WHERE device_id = ? AND reading_date = ?
            ''', (did, reading_date))
            existing = cursor.fetchone()

            if existing:
                n = existing['sample_count'] or 1
                new_n = n + 1
                new_temp = (existing['temperature'] * n + temp) / new_n
                new_hum = (existing['humidity'] * n + humidity) / new_n
                new_rain = (existing['rainfall_mm'] * n + rain_mm) / new_n
                new_ph = (existing['ph_level'] * n + ph_level) / new_n
                new_wind = (existing['wind_speed'] * n + wind_speed) / new_n

                low_c = existing['risk_low_count'] or 0
                mod_c = existing['risk_moderate_count'] or 0
                high_c = existing['risk_high_count'] or 0
                if risk_bucket == 'low':
                    low_c += 1
                elif risk_bucket == 'moderate':
                    mod_c += 1
                else:
                    high_c += 1
                # Mode across the day so far; ties resolved toward the more
                # severe bucket (high > moderate > low) so a day that's evenly
                # split doesn't quietly default to "Low".
                dominant = max((('high', high_c), ('moderate', mod_c), ('low', low_c)), key=lambda kv: kv[1])[0]

                cursor.execute('''
                    UPDATE device_daily_readings
                    SET temperature = ?, humidity = ?, rainfall_mm = ?, ph_level = ?, wind_speed = ?,
                        sample_count = ?, risk_low_count = ?, risk_moderate_count = ?, risk_high_count = ?,
                        risk_level = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE device_id = ? AND reading_date = ?
                ''', (new_temp, new_hum, new_rain, new_ph, new_wind, new_n,
                      low_c, mod_c, high_c, dominant, did, reading_date))
            else:
                low_c = 1 if risk_bucket == 'low' else 0
                mod_c = 1 if risk_bucket == 'moderate' else 0
                high_c = 1 if risk_bucket == 'high' else 0
                cursor.execute('''
                    INSERT INTO device_daily_readings
                        (device_id, reading_date, temperature, humidity, rainfall_mm, ph_level, wind_speed,
                         risk_level, sample_count, risk_low_count, risk_moderate_count, risk_high_count, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (did, reading_date, temp, humidity, rain_mm, ph_level, wind_speed,
                      risk_bucket, low_c, mod_c, high_c))
        conn.commit()
    finally:
        conn.close()


@app.route('/api/get_sensor_data', methods=['GET'])
def get_sensor_data():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT temperature, humidity, rainfall_mm, ph_level, wind_speed,
                       wind_direction, risk_level, risk_bucket
                FROM sensor_readings
                ORDER BY id DESC
                LIMIT 1
            ''')
            row = cursor.fetchone()

        if row:
            return jsonify({
                'temperature': row['temperature'],
                'humidity': row['humidity'],
                'rainfall_mm': row['rainfall_mm'],
                'ph_level': row['ph_level'],
                'wind_speed': row['wind_speed'],
                'wind_direction': row['wind_direction'],
                'risk_level': row['risk_level'],
                'risk_bucket': row['risk_bucket'],
            })

        return jsonify(get_live_weather_reading())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


SENSOR_HISTORY_MAX_ROWS = 240


@app.route('/api/get_sensor_history', methods=['GET'])
@api_login_required
def get_sensor_history():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT temperature, humidity, rainfall_mm, ph_level, wind_speed, created_at
                FROM sensor_readings
                ORDER BY id DESC
                LIMIT ?
            ''', (SENSOR_HISTORY_MAX_ROWS,))
            rows = cursor.fetchall()

        readings = [
            {
                'temperature': r['temperature'],
                'humidity': r['humidity'],
                'rainfall_mm': r['rainfall_mm'],
                'ph_level': r['ph_level'],
                'wind_speed': r['wind_speed'],
                # to_iso_ts() handles both None and datetime-object timestamps
                # safely — calling .replace() directly on r['created_at'] (the
                # old code) crashes with a 500 the moment any row has a NULL
                # or non-string created_at value.
                'timestamp': (lambda ts: (ts + 'Z') if ts else None)(to_iso_ts(r['created_at']))
            }
            for r in reversed(rows)
        ]

        return jsonify({'success': True, 'readings': readings})
    except Exception as e:
        print(f"❌ get_sensor_history DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load sensor history. Please try again.'}), 500


# ── GLOBAL SENSOR REFRESH RATE ──
@app.route('/api/get_sensor_refresh_rate', methods=['GET'])
@api_login_required
def get_sensor_refresh_rate():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sensor_refresh_rate FROM app_settings WHERE id = 1")
            row = cursor.fetchone()

        return jsonify({'success': True, 'refresh_rate': row[0] if row else 1})
    except Exception as e:
        print(f"❌ get_sensor_refresh_rate DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load refresh rate. Please try again.'}), 500



# Message shown in Admin > Alerts whenever the "Getting data from sensors"
# rate is changed, keyed by the new refresh_rate value.
SENSOR_REFRESH_RATE_MESSAGES = {
    0: 'Getting data from sensors turned off',
    1: 'Getting data from sensors set in real-time',
    15: 'Getting data from sensors set every 15 minutes',
    60: 'Getting data from sensors set every 1 hour',
}


@app.route('/api/update_sensor_refresh_rate', methods=['POST'])
@admin_required
def update_sensor_refresh_rate():
    data = request.get_json() or {}
    refresh_rate = data.get('refresh_rate')

    if refresh_rate not in (0, 1, 15, 60):
        return jsonify({'success': False, 'message': 'Invalid refresh rate'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE app_settings SET sensor_refresh_rate = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        (refresh_rate, session['user_id'])
    )

    # Log the change as a notification so it shows up in Admin > Alerts
    # (admin_alerts.html), the same way risk alerts and other notices do.
    # admin_only=1 keeps this OUT of residents' own Alerts page (see
    # get_notifications) — this is an internal/operational notice, not
    # something residents need to see.
    # created_at is set explicitly (not relying on the column's SQL DEFAULT
    # CURRENT_TIMESTAMP) — same reason as risk_alerts above: the DEFAULT
    # silently never fires on this DB, so the row would come back with
    # created_at = NULL and sort to the bottom of Recent Alerts instead of
    # the top.
    admin_name = session.get('user_name') or 'Unknown'
    notif_message = f"{SENSOR_REFRESH_RATE_MESSAGES[refresh_rate]} changes made by admin {admin_name}"
    now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute(
        "INSERT INTO notifications (title, message, level, created_by, barangay, admin_only, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ('Sensor Data Setting Changed', notif_message, 'info', session['user_id'], None, 1, now_ts)
    )

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'refresh_rate': refresh_rate})


# ── NOTIFICATIONS ──
@app.route('/api/notifications', methods=['GET'])
@api_login_required
def get_notifications():
    try:
        user_id = session['user_id']
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT barangay FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            user_barangay = row[0] if row else None

            # The in-app sensor alert is its own permanent notification — it
            # is read straight off risk_alerts, independent of email_sent/
            # sms_sent, and it never mutates into (or gets replaced by) an
            # Email/SMS delivery line. This is what keeps "Moderate/High
            # Risk Detected" visible exactly as it first appeared, even
            # after that resident's Email/SMS eventually go out.
            cursor.execute('''
                SELECT ra.id, ra.alert_message, ra.risk_level, ra.barangay, ra.created_at
                FROM risk_alerts ra
                WHERE ra.user_id = ?
                ORDER BY ra.created_at DESC
                LIMIT 100
            ''', (user_id,))
            risk_rows = cursor.fetchall()

            # Each Email/SMS delivery is its OWN separate notification,
            # sourced straight from scheduled_notifications, and only ever
            # appears once status = 'sent' — i.e. once
            # dispatch_scheduled_notifications has genuinely sent it. There
            # is no "scheduled"/"pending" row shown here at all: a row simply
            # doesn't exist in this result set until the send has actually
            # happened, so there's nothing to display in the meantime and
            # nothing that later "changes into" sent — it just appears once,
            # already sent, right when it happens.
            cursor.execute('''
                SELECT sn.id, sn.channel, sn.risk_level, sn.sent_at,
                       ra.alert_message, ra.barangay
                FROM scheduled_notifications sn
                LEFT JOIN risk_alerts ra ON ra.id = sn.risk_alert_id
                WHERE sn.user_id = ? AND sn.status = 'sent'
                ORDER BY sn.sent_at DESC
                LIMIT 100
            ''', (user_id,))
            delivery_rows = cursor.fetchall()

            # Exclude notifications this resident already dismissed from their own
            # view — see the note above dismissed_notifications' CREATE TABLE.
            # Also exclude admin_only=1 rows — those are internal/operational
            # notices (e.g. sensor refresh rate changes) meant for Admin > Alerts
            # only, not for residents.
            if user_barangay:
                cursor.execute('''
                    SELECT n.id, n.title, n.message, n.level, n.barangay, n.created_at
                    FROM notifications n
                    WHERE (n.barangay = ? OR n.barangay IS NULL)
                      AND COALESCE(n.admin_only, 0) = 0
                      AND n.id NOT IN (SELECT notification_id FROM dismissed_notifications WHERE user_id = ?)
                    ORDER BY n.created_at DESC
                    LIMIT 100
                ''', (user_barangay, user_id))
            else:
                cursor.execute('''
                    SELECT n.id, n.title, n.message, n.level, n.barangay, n.created_at
                    FROM notifications n
                    WHERE n.barangay IS NULL
                      AND COALESCE(n.admin_only, 0) = 0
                      AND n.id NOT IN (SELECT notification_id FROM dismissed_notifications WHERE user_id = ?)
                    ORDER BY n.created_at DESC
                    LIMIT 100
                ''', (user_id,))
            notif_rows = cursor.fetchall()

        items = []
        for (alert_id, alert_message, risk_level, barangay, created_at) in risk_rows:
            level = (risk_level or 'moderate').lower()
            items.append({
                'source': 'risk_alert',
                'id': alert_id,
                'title': f"{level.capitalize()} Risk Detected",
                'message': alert_message,
                'level': level,
                'barangay': barangay,
                'created_at': to_iso_ts(created_at),
                # None = this is the immediate in-app alert itself, not a
                # channel delivery — it always renders as "Sent via In-App
                # Notification" and never changes.
                'delivery_channel': None,
            })

        for (sn_id, channel, risk_level, sent_at, alert_message, barangay) in delivery_rows:
            level = (risk_level or 'moderate').lower()
            items.append({
                'source': 'channel_delivery',
                'id': sn_id,
                'title': f"{level.capitalize()} Risk Detected",
                'message': alert_message,
                'level': level,
                'barangay': barangay,
                # This IS the moment the send actually happened — not the
                # original sensor-trigger time, so "time ago" reflects the
                # real Email/SMS delivery moment, separately from the
                # in-app alert's own timestamp above.
                'created_at': to_iso_ts(sent_at),
                'delivery_channel': channel,  # 'email' or 'sms'
            })

        for notif_id, title, message, level, barangay, created_at in notif_rows:
            items.append({
                'source': 'notification',
                'id': notif_id,
                'title': title,
                'message': message,
                'level': (level or 'info').lower(),
                'barangay': barangay,
                'created_at': to_iso_ts(created_at),
                # Manual/admin notifications are in-app only — they were never
                # emailed or texted, so there's no delivery line for these.
                'delivery_channel': None,
            })

        items.sort(key=lambda x: x['created_at'] or '', reverse=True)
        return jsonify({'success': True, 'notifications': items[:150]})
    except Exception as e:
        print(f"❌ get_notifications DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load notifications. Please try again.'}), 500


@app.route('/api/notifications', methods=['DELETE'])
@api_login_required
def delete_notifications():
    """Handles both 'Clear All' and 'remove selected' from the resident Alerts
    page. risk_alerts rows are personal (have user_id) and get hard-deleted.
    notifications rows are shared across a barangay, so they're never deleted
    here — instead we record a per-user dismissal so they disappear only from
    this resident's own list (see dismissed_notifications above)."""
    try:
        user_id = session['user_id']
        data = request.get_json(silent=True) or {}
        clear_all = bool(data.get('clear_all'))
        items = data.get('items') or []

        with get_db_connection() as conn:
            cursor = conn.cursor()

            if clear_all:
                cursor.execute("DELETE FROM risk_alerts WHERE user_id = ?", (user_id,))
                # Email/SMS deliveries are now their own separate rows (in
                # scheduled_notifications) from the in-app alert above — a
                # "Clear All" has to hit both tables, or a sent delivery
                # would reappear on refresh even after the alert was cleared.
                cursor.execute("DELETE FROM scheduled_notifications WHERE user_id = ?", (user_id,))

                cursor.execute("SELECT barangay FROM users WHERE id = ?", (user_id,))
                row = cursor.fetchone()
                user_barangay = row[0] if row else None
                if user_barangay:
                    cursor.execute(
                        "SELECT id FROM notifications WHERE barangay = ? OR barangay IS NULL",
                        (user_barangay,)
                    )
                else:
                    cursor.execute("SELECT id FROM notifications WHERE barangay IS NULL")
                for (notif_id,) in cursor.fetchall():
                    cursor.execute(
                        "INSERT OR IGNORE INTO dismissed_notifications (user_id, notification_id) VALUES (?, ?)",
                        (user_id, notif_id)
                    )
            else:
                for item in items:
                    source = item.get('source')
                    item_id = item.get('id')
                    if item_id is None:
                        continue
                    if source == 'risk_alert':
                        cursor.execute(
                            "DELETE FROM risk_alerts WHERE id = ? AND user_id = ?",
                            (item_id, user_id)
                        )
                    elif source == 'channel_delivery':
                        cursor.execute(
                            "DELETE FROM scheduled_notifications WHERE id = ? AND user_id = ?",
                            (item_id, user_id)
                        )
                    elif source == 'notification':
                        cursor.execute(
                            "INSERT OR IGNORE INTO dismissed_notifications (user_id, notification_id) VALUES (?, ?)",
                            (user_id, item_id)
                        )

            conn.commit()

        return jsonify({'success': True})
    except Exception as e:
        print(f"❌ delete_notifications DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not remove notifications. Please try again.'}), 500


# ── ADMIN ALERTS FEED ──
@app.route('/api/admin/alerts', methods=['GET'])
@admin_required
def get_admin_alerts():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # The in-app sensor alert is read straight off risk_alerts,
            # independent of email_sent/sms_sent — it never mutates into (or
            # gets replaced by) an Email/SMS delivery line, and it never
            # disappears once one of those channels is sent. Each channel's
            # delivery is queried separately below, as its own row.
            cursor.execute('''
                SELECT ra.id, ra.alert_message, ra.risk_level, ra.created_at
                FROM risk_alerts ra
                WHERE ra.id NOT IN (
                    SELECT alert_id FROM admin_dismissed_alerts WHERE source = 'risk_alert'
                )
                ORDER BY ra.created_at DESC
                LIMIT 400
            ''')
            risk_rows = cursor.fetchall()

            # Each Email/SMS delivery is its OWN separate row, sourced
            # straight from scheduled_notifications, and only ever appears
            # once status = 'sent' — i.e. once dispatch_scheduled_notifications
            # has genuinely sent it. A row simply doesn't exist in this
            # result set while it's still 'pending' (counting down to its
            # own scheduled_for), so there is nothing "scheduled" to display
            # and nothing that later mutates into "sent" — it appears once,
            # already sent, exactly when the send happens.
            cursor.execute('''
                SELECT sn.id, sn.channel, sn.risk_level, sn.sent_at,
                       ra.alert_message, ra.email_subject, ra.email_body,
                       u.fullname, u.email, u.phone
                FROM scheduled_notifications sn
                LEFT JOIN risk_alerts ra ON ra.id = sn.risk_alert_id
                JOIN users u ON u.id = sn.user_id
                WHERE sn.status = 'sent'
                  AND sn.id NOT IN (
                      SELECT alert_id FROM admin_dismissed_alerts WHERE source = 'channel_delivery'
                  )
                ORDER BY sn.sent_at DESC
                LIMIT 400
            ''')
            delivery_rows = cursor.fetchall()

            cursor.execute('''
                SELECT id, title, message, level, barangay, created_at
                FROM notifications
                WHERE id NOT IN (
                    SELECT alert_id FROM admin_dismissed_alerts WHERE source = 'notification'
                )
                ORDER BY created_at DESC
                LIMIT 100
            ''')
            notif_rows = cursor.fetchall()

        items = []
        # Every risk_alerts row is each resident's own copy of the SAME
        # fixed-cadence "Always On" In-App tick — not an individual delivery.
        # Logged per-resident so each resident's own Alerts page has their
        # copy, they'd otherwise show up here as one near-identical
        # "<level> Risk Detected from sensors" line per resident every tick.
        # Bucket them by (minute, level, message) and collapse each tick into
        # a single "Sent to all resident via In-App Notifications" row. This
        # bucket is now built UNCONDITIONALLY (not gated on whether Email/SMS
        # have gone out) — the in-app line never waits for, or gets replaced
        # by, a channel delivery; those are handled entirely separately below.
        broadcast_groups = {}
        for (alert_id, alert_message, risk_level, created_at) in risk_rows:
            level = (risk_level or 'moderate').lower()
            created_iso = to_iso_ts(created_at)
            minute_bucket = (created_iso or '')[:16]  # 'YYYY-MM-DDTHH:MM'
            key = (minute_bucket, level, alert_message)
            group = broadcast_groups.setdefault(key, {
                'ids': [], 'message': alert_message, 'level': level, 'created_at': created_iso or ''
            })
            group['ids'].append(alert_id)
            if (created_iso or '') > group['created_at']:
                group['created_at'] = created_iso or ''

        # Personal Email/SMS deliveries (which DO name a specific recipient)
        # are their own individual rows, one per channel per send — never
        # merged with the in-app broadcast above, and never shown before
        # sn.status is actually 'sent'.
        for (sn_id, channel, risk_level, sent_at, alert_message, email_subject, email_body,
             recipient_name, recipient_email, recipient_phone) in delivery_rows:
            level = (risk_level or 'moderate').lower()
            items.append({
                'id': sn_id,
                'title': f"{level.capitalize()} Risk Detected",
                'message': alert_message,
                'level': level,
                'barangay': None,
                # This IS the moment the send actually happened, not the
                # original sensor-trigger time — so "time ago" and the
                # displayed date/time reflect the real Email/SMS delivery
                # moment, kept separate from the in-app alert's own timestamp.
                'created_at': to_iso_ts(sent_at),
                'source': 'channel_delivery',
                'delivery_channel': channel,  # 'email' or 'sms'
                'recipient_name': recipient_name,
                'recipient_email': recipient_email if channel == 'email' else None,
                'recipient_contact_number': recipient_phone if channel == 'sms' else None,
                'email_subject': email_subject if channel == 'email' else None,
                'email_body': email_body if channel == 'email' else None,
                'broadcast_inapp': False,
            })

        for (minute_bucket, level, alert_message), group in broadcast_groups.items():
            items.append({
                'id': max(group['ids']),
                'group_ids': group['ids'],
                'title': f"{level.capitalize()} Risk Detected",
                'message': group['message'],
                'level': level,
                'barangay': None,
                'created_at': group['created_at'],
                'source': 'risk_alert',
                'recipient_name': None,
                'recipient_email': None,
                'recipient_contact_number': None,
                'email_subject': None,
                'email_body': None,
                'broadcast_inapp': True,
            })

        for notif_id, title, message, level, barangay, created_at in notif_rows:
            items.append({
                'id': notif_id,
                'title': title,
                'message': message,
                'level': (level or 'info').lower(),
                'barangay': barangay,
                'created_at': to_iso_ts(created_at),
                'source': 'notification',
            })

        # Newest minute first; within the same minute, that tick's individual
        # "Sent to <resident>" email/SMS deliveries are listed ABOVE the
        # collapsed "sensors → everyone via In-App" broadcast line — the
        # broadcast is what triggered them, so it reads as having happened
        # first (comes below), with its actual per-channel deliveries above it.
        def sort_key(x):
            minute = (x['created_at'] or '')[:16]
            is_individual_delivery = 1 if not x.get('broadcast_inapp') else 0
            return (minute, is_individual_delivery, x['created_at'] or '')

        items.sort(key=sort_key, reverse=True)
        return jsonify({'success': True, 'alerts': items[:80]})
    except Exception as e:
        print(f"❌ get_admin_alerts DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load alerts. Please try again.'}), 500


@app.route('/api/admin/alerts', methods=['DELETE'])
@admin_required
def delete_admin_alerts():
    try:
        data = request.get_json(silent=True) or {}
        clear_all = bool(data.get('clear_all'))
        items = data.get('items') or []

        with get_db_connection() as conn:
            cursor = conn.cursor()

            if clear_all:
                # Hide every alert/notification currently in existence from the
                # admin dashboard, WITHOUT deleting the actual rows — residents'
                # own Alerts pages read those same rows directly and must keep
                # showing their own history untouched.
                cursor.execute(
                    "INSERT INTO admin_dismissed_alerts (source, alert_id) "
                    "SELECT 'risk_alert', id FROM risk_alerts "
                    "ON CONFLICT (source, alert_id) DO NOTHING"
                )
                # Email/SMS deliveries are now their own separate rows,
                # sourced from scheduled_notifications — "Clear All" needs to
                # dismiss those independently too, or a sent delivery would
                # keep reappearing after the in-app alert above is cleared.
                cursor.execute(
                    "INSERT INTO admin_dismissed_alerts (source, alert_id) "
                    "SELECT 'channel_delivery', id FROM scheduled_notifications WHERE status = 'sent' "
                    "ON CONFLICT (source, alert_id) DO NOTHING"
                )
                cursor.execute(
                    "INSERT INTO admin_dismissed_alerts (source, alert_id) "
                    "SELECT 'notification', id FROM notifications "
                    "ON CONFLICT (source, alert_id) DO NOTHING"
                )
                conn.commit()
                return jsonify({'success': True, 'cleared_all': True})

            if not items:
                return jsonify({'success': False, 'message': 'No alerts selected.'}), 400

            deleted = 0
            for item in items:
                source = item.get('source')
                alert_id = item.get('id')
                if source not in ('risk_alert', 'notification', 'channel_delivery'):
                    continue
                # A collapsed "Sent to all resident via In-App Notifications"
                # row stands in for several underlying risk_alerts rows (one
                # per resident, same tick) — dismiss all of them together so
                # the row doesn't reappear (with a smaller count) on refresh.
                ids_to_dismiss = item.get('group_ids') or ([alert_id] if alert_id is not None else [])
                for gid in ids_to_dismiss:
                    cursor.execute(
                        "INSERT INTO admin_dismissed_alerts (source, alert_id) VALUES (?, ?) "
                        "ON CONFLICT (source, alert_id) DO NOTHING",
                        (source, gid)
                    )
                    deleted += cursor.rowcount

            conn.commit()
        return jsonify({'success': True, 'deleted': deleted})
    except Exception as e:
        print(f"❌ delete_admin_alerts DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not delete alerts. Please try again.'}), 500


# ── HOTSPOT LOCATIONS ──
def _hotspot_row_to_dict(row):
    return {
        'id': row[0], 'name': row[1], 'lat': row[2], 'lng': row[3],
        'temp': row[4], 'hum': row[5], 'rain': row[6], 'ph': row[7],
        'wind': row[8], 'risk': row[9], 'updated_at': row[10]
    }


@app.route('/api/hotspots', methods=['GET'])
@api_login_required
def get_hotspots():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, name, lat, lng, temperature, humidity, rainfall_mm, ph_level,
                       wind_speed, risk_level, updated_at
                FROM hotspot_locations
                ORDER BY created_at ASC
            ''')
            rows = cursor.fetchall()
            return jsonify({'success': True, 'hotspots': [_hotspot_row_to_dict(r) for r in rows]})
    except Exception as e:
        print(f"❌ get_hotspots DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load locations. Please try again.'}), 500


# ── GIS BARANGAY BOUNDARIES (admin "Edit Trace" edits, shared with residents) ──
GIS_BOUNDARY_KEYS = ('barangay_boundaries', 'manual_trace')


def _get_gis_boundary_row(cursor, key):
    cursor.execute(
        'SELECT geojson, updated_at FROM gis_boundary_overrides WHERE override_key = ?',
        (key,)
    )
    return cursor.fetchone()


@app.route('/api/gis_boundaries', methods=['GET'])
@api_login_required
def get_gis_boundaries():
    """Any logged-in user (admin or resident) can read the current saved
    boundaries — this is what lets the resident map mirror whatever the
    admin last saved, instead of each browser having its own copy."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            result = {'success': True}
            for key in GIS_BOUNDARY_KEYS:
                row = _get_gis_boundary_row(cursor, key)
                if row:
                    try:
                        result[key] = json.loads(row[0])
                    except (TypeError, ValueError):
                        result[key] = None
                    result[f'{key}_updated_at'] = to_iso_ts(row[1])
                else:
                    result[key] = None
                    result[f'{key}_updated_at'] = None
            return jsonify(result)
    except Exception as e:
        print(f"❌ get_gis_boundaries DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load the barangay boundaries. Please try again.'}), 500


@app.route('/api/gis_boundaries/<key>', methods=['PUT'])
@admin_required
def save_gis_boundary(key):
    """Only admins may write — residents' maps are view-only."""
    if key not in GIS_BOUNDARY_KEYS:
        return jsonify({'success': False, 'message': 'Unknown boundary type.'}), 404

    data = request.get_json(silent=True) or {}
    geojson_data = data.get('geojson')
    if not geojson_data or not isinstance(geojson_data, dict):
        return jsonify({'success': False, 'message': 'Missing GeoJSON data.'}), 400

    try:
        geojson_text = json.dumps(geojson_data)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Invalid GeoJSON data.'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO gis_boundary_overrides (override_key, geojson, updated_by, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(override_key) DO UPDATE SET
                    geojson = excluded.geojson,
                    updated_by = excluded.updated_by,
                    updated_at = CURRENT_TIMESTAMP
            ''', (key, geojson_text, session['user_id']))
            conn.commit()

            row = _get_gis_boundary_row(cursor, key)
            return jsonify({
                'success': True,
                'key': key,
                'geojson': geojson_data,
                'updated_at': to_iso_ts(row[1]) if row else None
            })
    except Exception as e:
        print(f"❌ save_gis_boundary DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not save the boundary changes. Please try again.'}), 500


@app.route('/api/gis_boundaries/<key>', methods=['DELETE'])
@admin_required
def delete_gis_boundary(key):
    """Restores the default/official trace by clearing the saved override."""
    if key not in GIS_BOUNDARY_KEYS:
        return jsonify({'success': False, 'message': 'Unknown boundary type.'}), 404

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM gis_boundary_overrides WHERE override_key = ?', (key,))
            conn.commit()
            return jsonify({'success': True, 'key': key})
    except Exception as e:
        print(f"❌ delete_gis_boundary DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not restore the default boundary. Please try again.'}), 500


# ── NEAR MONITORED LOCATION ──
@app.route('/api/user/near_location', methods=['GET'])
@api_login_required
def get_near_location():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT h.id, h.name, h.risk_level
                FROM users u
                LEFT JOIN hotspot_locations h ON h.id = u.near_hotspot_id
                WHERE u.id = ?
            ''', (session['user_id'],))
            row = cursor.fetchone()

            near_location = None
            if row and row[0] is not None:
                near_location = {'id': row[0], 'name': row[1], 'risk': row[2]}

            return jsonify({'success': True, 'near_location': near_location})
    except Exception as e:
        print(f"❌ get_near_location DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load your location. Please try again.'}), 500


@app.route('/api/user/near_location', methods=['POST'])
@api_login_required
def set_near_location():
    data = request.get_json() or {}
    hotspot_id = data.get('hotspot_id')

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            if hotspot_id is not None:
                cursor.execute("SELECT id, name, risk_level FROM hotspot_locations WHERE id = ?", (hotspot_id,))
                hotspot = cursor.fetchone()
                if not hotspot:
                    return jsonify({'success': False, 'message': 'That location no longer exists.'}), 404

            cursor.execute(
                "UPDATE users SET near_hotspot_id = ? WHERE id = ?",
                (hotspot_id, session['user_id'])
            )
            conn.commit()

            near_location = None
            if hotspot_id is not None:
                near_location = {'id': hotspot[0], 'name': hotspot[1], 'risk': hotspot[2]}

            return jsonify({'success': True, 'near_location': near_location})
    except Exception as e:
        print(f"❌ set_near_location DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not save your location. Please try again.'}), 500


# ── ADMIN: SET A RESIDENT'S NEAR MONITORED LOCATION ──
@app.route('/api/admin/users/<int:user_id>/near_location', methods=['PUT'])
@admin_required
def admin_set_near_location(user_id):
    data = request.get_json() or {}
    hotspot_id = data.get('hotspot_id')

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT id, is_admin FROM users WHERE id = ?", (user_id,))
            target = cursor.fetchone()
            if not target:
                return jsonify({'success': False, 'message': 'User not found'}), 404
            if target[1]:
                return jsonify({'success': False, 'message': "Admin accounts don't have a near location"}), 400

            hotspot = None
            if hotspot_id is not None:
                cursor.execute("SELECT id, name, risk_level FROM hotspot_locations WHERE id = ?", (hotspot_id,))
                hotspot = cursor.fetchone()
                if not hotspot:
                    return jsonify({'success': False, 'message': 'That location no longer exists.'}), 404

            cursor.execute(
                "UPDATE users SET near_hotspot_id = ? WHERE id = ?",
                (hotspot_id, user_id)
            )
            conn.commit()

            near_location = None
            if hotspot_id is not None:
                near_location = {'id': hotspot[0], 'name': hotspot[1], 'risk': hotspot[2]}

            return jsonify({'success': True, 'near_location': near_location})
    except Exception as e:
        print(f"❌ admin_set_near_location DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not save the location. Please try again.'}), 500


@app.route('/api/hotspots', methods=['POST'])
@admin_required
def add_hotspot():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    lat = data.get('lat')
    lng = data.get('lng')

    if not name:
        return jsonify({'success': False, 'message': 'Location name is required'}), 400
    if lat is None or lng is None:
        return jsonify({'success': False, 'message': 'Map coordinates are required'}), 400

    try:
        lat = float(lat)
        lng = float(lng)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Invalid coordinates'}), 400

    try:
        reading = get_live_weather_reading()
    except Exception as e:
        print(f"⚠️ add_hotspot: weather fetch failed, using fallback reading: {e}")
        reading = {'temperature': None, 'humidity': None, 'rainfall_mm': None,
                   'ph_level': None, 'wind_speed': None}

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO hotspot_locations
                    (name, lat, lng, temperature, humidity, rainfall_mm, ph_level, wind_speed, risk_level, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                name, lat, lng,
                reading['temperature'], reading['humidity'], reading['rainfall_mm'],
                reading['ph_level'], reading['wind_speed'], 'low',
                session['user_id']
            ))
            new_id = cursor.lastrowid
            conn.commit()

            cursor.execute('''
                SELECT id, name, lat, lng, temperature, humidity, rainfall_mm, ph_level,
                       wind_speed, risk_level, updated_at
                FROM hotspot_locations WHERE id = ?
            ''', (new_id,))
            row = cursor.fetchone()
            return jsonify({'success': True, 'hotspot': _hotspot_row_to_dict(row)})
    except Exception as e:
        print(f"❌ add_hotspot DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not save location. Please try again.'}), 500


@app.route('/api/hotspots/<int:hotspot_id>', methods=['PUT'])
@admin_required
def update_hotspot(hotspot_id):
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()

    if not name:
        return jsonify({'success': False, 'message': 'Location name is required'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE hotspot_locations SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (name, hotspot_id)
            )
            conn.commit()
            updated = cursor.rowcount

            if not updated:
                return jsonify({'success': False, 'message': 'Location not found'}), 404

            cursor.execute('''
                SELECT id, name, lat, lng, temperature, humidity, rainfall_mm, ph_level,
                       wind_speed, risk_level, updated_at
                FROM hotspot_locations WHERE id = ?
            ''', (hotspot_id,))
            row = cursor.fetchone()

            if not row:
                return jsonify({'success': False, 'message': 'Location not found'}), 404

            hotspot_data = _hotspot_row_to_dict(row)
            return jsonify({'success': True, 'hotspot': hotspot_data})

    except Exception as e:
        print(f"❌ update_hotspot DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not save changes. Please try again.'}), 500


@app.route('/api/hotspots/<int:hotspot_id>', methods=['DELETE'])
@admin_required
def delete_hotspot(hotspot_id):
    # Phase 1: the actual deletion. This is the operation the admin asked
    # for, and its outcome (found/deleted vs. not found vs. genuine DB
    # failure) is what the response reflects. Committed immediately so it
    # can never be undone or masked by anything that happens afterward.
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM hotspot_locations WHERE id = ?', (hotspot_id,))
            deleted = cursor.rowcount
            conn.commit()
    except Exception as e:
        print(f"❌ delete_hotspot DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not remove location. Please try again.'}), 500

    if not deleted:
        return jsonify({'success': False, 'message': 'Location not found'}), 404

    # Phase 2: best-effort cleanup of references to this hotspot elsewhere
    # (device links, residents' "near location" setting). The hotspot is
    # already gone at this point — a hiccup here (locked row, transient DB
    # error, etc.) is logged but must NEVER be reported back to the frontend
    # as a failed deletion, since the deletion itself already succeeded.
    # This was the actual bug: previously these statements shared a
    # transaction/response with the deletion above, so a failure here alone
    # was enough to return success:false / 500 even though the location had
    # already been removed from the database.
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM hotspot_device_links WHERE hotspot_id = ?', (hotspot_id,))
            cursor.execute('UPDATE users SET near_hotspot_id = NULL WHERE near_hotspot_id = ?', (hotspot_id,))
            conn.commit()
    except Exception as e:
        print(f"⚠️ delete_hotspot cleanup warning (location {hotspot_id} was still deleted): {e}")

    return jsonify({'success': True})


# ── DEVICE DEPLOYMENTS ──
def _device_row_to_dict(row):
    return {
        'id': row[0], 'name': row[1], 'lat': row[2], 'lng': row[3],
        'status': row[4], 'temp': row[5], 'hum': row[6], 'rain': row[7],
        'ph': row[8], 'wind': row[9], 'risk': row[10], 'updated_at': row[11]
    }


@app.route('/api/devices', methods=['GET'])
@api_login_required
def get_devices():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, name, lat, lng, status, temperature, humidity, rainfall_mm,
                       ph_level, wind_speed, risk_level, updated_at
                FROM device_deployments
                ORDER BY created_at ASC
            ''')
            rows = cursor.fetchall()
            return jsonify({'success': True, 'devices': [_device_row_to_dict(r) for r in rows]})
    except Exception as e:
        print(f"❌ get_devices DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load devices. Please try again.'}), 500


@app.route('/api/devices', methods=['POST'])
@admin_required
def add_device():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    lat = data.get('lat')
    lng = data.get('lng')

    if not name:
        return jsonify({'success': False, 'message': 'Device name is required'}), 400
    if lat is None or lng is None:
        return jsonify({'success': False, 'message': 'Map coordinates are required'}), 400

    try:
        lat = float(lat)
        lng = float(lng)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Invalid coordinates'}), 400

    try:
        reading = get_live_weather_reading()
    except Exception as e:
        print(f"⚠️ add_device: weather fetch failed, using fallback reading: {e}")
        reading = {'temperature': None, 'humidity': None, 'rainfall_mm': None,
                   'ph_level': None, 'wind_speed': None}

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO device_deployments
                    (name, lat, lng, status, temperature, humidity, rainfall_mm, ph_level, wind_speed, risk_level, created_by)
                VALUES (?, ?, ?, 'offline', ?, ?, ?, ?, ?, 'low', ?)
            ''', (
                name, lat, lng,
                reading['temperature'], reading['humidity'], reading['rainfall_mm'],
                reading['ph_level'], reading['wind_speed'],
                session['user_id']
            ))
            new_id = cursor.lastrowid
            conn.commit()

            cursor.execute('''
                SELECT id, name, lat, lng, status, temperature, humidity, rainfall_mm,
                       ph_level, wind_speed, risk_level, updated_at
                FROM device_deployments WHERE id = ?
            ''', (new_id,))
            row = cursor.fetchone()
            return jsonify({'success': True, 'device': _device_row_to_dict(row)})
    except Exception as e:
        print(f"❌ add_device DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not save device. Please try again.'}), 500


@app.route('/api/devices/<int:device_id>', methods=['PUT'])
@admin_required
def update_device(device_id):
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()

    if not name:
        return jsonify({'success': False, 'message': 'Device name is required'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE device_deployments SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (name, device_id)
            )
            conn.commit()
            updated = cursor.rowcount

            if not updated:
                return jsonify({'success': False, 'message': 'Device not found'}), 404

            cursor.execute('''
                SELECT id, name, lat, lng, status, temperature, humidity, rainfall_mm,
                       ph_level, wind_speed, risk_level, updated_at
                FROM device_deployments WHERE id = ?
            ''', (device_id,))
            row = cursor.fetchone()

            if not row:
                return jsonify({'success': False, 'message': 'Device not found'}), 404

            device_data = _device_row_to_dict(row)
            return jsonify({'success': True, 'device': device_data})

    except Exception as e:
        print(f"❌ update_device DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not save changes. Please try again.'}), 500


@app.route('/api/devices/<int:device_id>', methods=['DELETE'])
@admin_required
def delete_device(device_id):
    # Phase 1: the actual deletion, committed immediately (see delete_hotspot
    # above for why this is split from the cleanup below).
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM device_deployments WHERE id = ?', (device_id,))
            deleted = cursor.rowcount
            conn.commit()
    except Exception as e:
        print(f"❌ delete_device DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not remove device. Please try again.'}), 500

    if not deleted:
        return jsonify({'success': False, 'message': 'Device not found'}), 404

    # Phase 2: best-effort cleanup of references to this device elsewhere.
    # A failure here is logged but never reported as a failed deletion —
    # the device itself is already gone.
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE sensor_assignments SET device_id = NULL WHERE device_id = ?', (device_id,))
            cursor.execute('UPDATE hotspot_device_links SET device_id = NULL WHERE device_id = ?', (device_id,))
            cursor.execute('UPDATE app_settings SET lstm_deployed_device_id = NULL WHERE lstm_deployed_device_id = ?', (device_id,))
            conn.commit()
    except Exception as e:
        print(f"⚠️ delete_device cleanup warning (device {device_id} was still deleted): {e}")

    return jsonify({'success': True})


# ── SENSOR ↔ DEVICE-LOCATION ASSIGNMENTS ──
def _sensor_assignment_row_to_dict(row):
    return {
        'sensor_name': row[0],
        'device_id': row[1],
        'device_name': row[2],
        'device_lat': row[3],
        'device_lng': row[4],
        'device_status': row[5],
        'updated_at': row[6],
    }


@app.route('/api/sensor_assignments', methods=['GET'])
@api_login_required
def get_sensor_assignments():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT sa.sensor_name, sa.device_id, d.name, d.lat, d.lng, d.status, sa.updated_at
                FROM sensor_assignments sa
                LEFT JOIN device_deployments d ON d.id = sa.device_id
            ''')
            rows = cursor.fetchall()
            return jsonify({'success': True, 'assignments': [_sensor_assignment_row_to_dict(r) for r in rows]})
    except Exception as e:
        print(f"❌ get_sensor_assignments DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load sensor assignments. Please try again.'}), 500


@app.route('/api/sensor_assignments', methods=['POST'])
@admin_required
def set_sensor_assignment():
    data = request.get_json() or {}
    sensor_name = (data.get('sensor_name') or '').strip()
    device_id = data.get('device_id')

    if not sensor_name:
        return jsonify({'success': False, 'message': 'Sensor name is required'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            if device_id is not None:
                cursor.execute('SELECT id FROM device_deployments WHERE id = ?', (device_id,))
                if not cursor.fetchone():
                    return jsonify({'success': False, 'message': 'Selected device was not found. It may have been removed.'}), 404

            cursor.execute('''
                INSERT INTO sensor_assignments (sensor_name, device_id, updated_by, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(sensor_name) DO UPDATE SET
                    device_id = excluded.device_id,
                    updated_by = excluded.updated_by,
                    updated_at = CURRENT_TIMESTAMP
            ''', (sensor_name, device_id, session['user_id']))
            conn.commit()

            cursor.execute('''
                SELECT sa.sensor_name, sa.device_id, d.name, d.lat, d.lng, d.status, sa.updated_at
                FROM sensor_assignments sa
                LEFT JOIN device_deployments d ON d.id = sa.device_id
                WHERE sa.sensor_name = ?
            ''', (sensor_name,))
            row = cursor.fetchone()
            return jsonify({'success': True, 'assignment': _sensor_assignment_row_to_dict(row)})
    except Exception as e:
        print(f"❌ set_sensor_assignment DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not save the sensor location. Please try again.'}), 500


# ── HOTSPOT ↔ NEAREST-DEVICE LINKS ──
def _hotspot_device_link_row_to_dict(row):
    return {
        'hotspot_id': row[0],
        'device_id': row[1],
        'device_name': row[2],
        'device_lat': row[3],
        'device_lng': row[4],
        'device_status': row[5],
        'updated_at': row[6],
    }


@app.route('/api/hotspot_device_links', methods=['GET'])
@api_login_required
def get_hotspot_device_links():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT hdl.hotspot_id, hdl.device_id, d.name, d.lat, d.lng, d.status, hdl.updated_at
                FROM hotspot_device_links hdl
                LEFT JOIN device_deployments d ON d.id = hdl.device_id
            ''')
            rows = cursor.fetchall()
            return jsonify({'success': True, 'links': [_hotspot_device_link_row_to_dict(r) for r in rows]})
    except Exception as e:
        print(f"❌ get_hotspot_device_links DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load near-device links. Please try again.'}), 500


@app.route('/api/hotspot_device_links', methods=['POST'])
@admin_required
def set_hotspot_device_link():
    data = request.get_json() or {}
    hotspot_id = data.get('hotspot_id')
    device_id = data.get('device_id')

    if hotspot_id is None:
        return jsonify({'success': False, 'message': 'Location is required'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT id FROM hotspot_locations WHERE id = ?', (hotspot_id,))
            if not cursor.fetchone():
                return jsonify({'success': False, 'message': 'Location not found'}), 404

            if device_id is not None:
                cursor.execute('SELECT id FROM device_deployments WHERE id = ?', (device_id,))
                if not cursor.fetchone():
                    return jsonify({'success': False, 'message': 'Selected device was not found. It may have been removed.'}), 404

            cursor.execute('''
                INSERT INTO hotspot_device_links (hotspot_id, device_id, updated_by, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(hotspot_id) DO UPDATE SET
                    device_id = excluded.device_id,
                    updated_by = excluded.updated_by,
                    updated_at = CURRENT_TIMESTAMP
            ''', (hotspot_id, device_id, session['user_id']))
            conn.commit()

            cursor.execute('''
                SELECT hdl.hotspot_id, hdl.device_id, d.name, d.lat, d.lng, d.status, hdl.updated_at
                FROM hotspot_device_links hdl
                LEFT JOIN device_deployments d ON d.id = hdl.device_id
                WHERE hdl.hotspot_id = ?
            ''', (hotspot_id,))
            row = cursor.fetchone()
            return jsonify({'success': True, 'link': _hotspot_device_link_row_to_dict(row)})
    except Exception as e:
        print(f"❌ set_hotspot_device_link DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not save the near-device link. Please try again.'}), 500


# ── LSTM PREDICTION ──
def _ensure_lstm_device_archive_table(cursor):
    """Per-location LSTM archive: one row per (device, week). Created on demand so it
    also exists when the server was already running before this feature was added."""
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS lstm_device_weekly_archive (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            week_start TEXT NOT NULL,
            week_end TEXT NOT NULL,
            risk_level TEXT,
            confidence REAL,
            note TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(device_id, week_start, week_end)
        )
    ''')


LSTM_ANCHOR_DATE = datetime(2026, 7, 26).date()


def get_lstm_week_bounds(for_date=None):
    d = for_date or datetime.utcnow().date()
    days_since_anchor = (d - LSTM_ANCHOR_DATE).days
    if days_since_anchor < 0:
        return LSTM_ANCHOR_DATE, LSTM_ANCHOR_DATE + timedelta(days=6)
    week_index = days_since_anchor // 7
    week_start = LSTM_ANCHOR_DATE + timedelta(days=week_index * 7)
    week_end = week_start + timedelta(days=6)
    return week_start, week_end


def generate_lstm_forecast():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT temperature, humidity, rainfall_mm, risk_level, created_at
        FROM sensor_readings
        ORDER BY created_at DESC
        LIMIT 7
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    if not rows or len(rows) < 3:
        return {
            'forecast': [
                {'day': 'Mon', 'temp': 28, 'humidity': 72, 'risk': 45, 'rainfall': 2.1},
                {'day': 'Tue', 'temp': 29, 'humidity': 74, 'risk': 55, 'rainfall': 1.8},
                {'day': 'Wed', 'temp': 30, 'humidity': 76, 'risk': 68, 'rainfall': 3.2},
                {'day': 'Thu', 'temp': 31, 'humidity': 78, 'risk': 72, 'rainfall': 4.5},
                {'day': 'Fri', 'temp': 30, 'humidity': 77, 'risk': 65, 'rainfall': 2.9},
                {'day': 'Sat', 'temp': 29, 'humidity': 75, 'risk': 58, 'rainfall': 1.5},
                {'day': 'Sun', 'temp': 28, 'humidity': 73, 'risk': 50, 'rainfall': 1.2}
            ],
            'overall_risk': 'moderate',
            'confidence': 87,
            'hotspots': ['Sector 3', 'Sector 7']
        }
    
    recent_data = list(reversed(rows))
    days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    
    avg_temp = sum(r['temperature'] for r in recent_data) / len(recent_data)
    avg_hum = sum(r['humidity'] for r in recent_data) / len(recent_data)
    avg_rain = sum(r['rainfall_mm'] for r in recent_data) / len(recent_data)
    
    forecast = []
    for i, day in enumerate(days):
        variation = (i - 3) * 0.3
        temp = avg_temp + variation + (i % 3 - 1) * 0.5
        hum = avg_hum + variation * 0.5 + (i % 2) * 2
        rain = max(0, avg_rain + (i - 3) * 0.2 + (i % 4) * 0.5)
        risk = min(100, max(0, 40 + (i * 5) + (temp - 28) * 3 + (hum - 70) * 0.5))
        
        forecast.append({
            'day': day,
            'temp': round(temp, 1),
            'humidity': round(hum, 1),
            'risk': round(risk, 0),
            'rainfall': round(rain, 1)
        })
    
    avg_risk = sum(f['risk'] for f in forecast) / len(forecast)
    if avg_risk < 33:
        overall_risk = 'low'
    elif avg_risk < 66:
        overall_risk = 'moderate'
    else:
        overall_risk = 'high'
    
    hotspots = ['Sector 3', 'Sector 7'] if avg_risk > 50 else ['Sector 5']
    
    return {
        'forecast': forecast,
        'overall_risk': overall_risk,
        'confidence': round(85 + (len(rows) / 10), 0),
        'hotspots': hotspots
    }


@app.route('/api/lstm_forecast', methods=['GET'])
@api_login_required
def get_lstm_forecast():
    start_str = request.args.get('start')
    end_str = request.args.get('end')
    device_id = request.args.get('device_id')

    if start_str and end_str:
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                if device_id:
                    # Saved LSTM data for one Monitored Device Location
                    _ensure_lstm_device_archive_table(cursor)
                    cursor.execute('''
                        SELECT risk_level, confidence, note
                        FROM lstm_device_weekly_archive
                        WHERE device_id = ? AND week_start = ? AND week_end = ?
                    ''', (device_id, start_str, end_str))
                    row = cursor.fetchone()
                    if not row:
                        # Weeks saved before per-location archiving existed live in lstm_weekly_archive.
                        # Show them for the location currently set as the LSTM Deployed Device.
                        _ensure_lstm_deployed_column(cursor)
                        cursor.execute('SELECT lstm_deployed_device_id FROM app_settings WHERE id = 1')
                        dep = cursor.fetchone()
                        if dep and dep[0] is not None and str(dep[0]) == str(device_id):
                            cursor.execute('''
                                SELECT risk_level, confidence, note
                                FROM lstm_weekly_archive
                                WHERE week_start = ? AND week_end = ?
                            ''', (start_str, end_str))
                            row = cursor.fetchone()
                    if not row:
                        return jsonify({'success': False, 'message': 'No LSTM data archived for this week yet'})
                    return jsonify({'success': True, 'data': {
                        'risk': row[0], 'confidence': row[1], 'note': row[2]
                    }})
                else:
                    cursor.execute('''
                        SELECT risk_level, confidence, note
                        FROM lstm_weekly_archive
                        WHERE week_start = ? AND week_end = ?
                    ''', (start_str, end_str))
                row = cursor.fetchone()
                if not row:
                    return jsonify({'success': False, 'message': 'No LSTM data archived for this week yet'})
                return jsonify({'success': True, 'data': {
                    'risk': row[0], 'confidence': row[1], 'note': row[2]
                }})
        except Exception as e:
            print(f"❌ LSTM archive lookup error: {e}")
            return jsonify({'success': False, 'message': 'Could not load archived forecast'}), 500

    try:
        forecast_data = generate_lstm_forecast()
        return jsonify({'success': True, 'data': forecast_data})
    except Exception as e:
        print(f"❌ LSTM forecast error: {e}")
        return jsonify({'success': False, 'message': 'Could not generate forecast'}), 500


# ── LSTM MODEL SETTINGS: FORECAST HORIZON ──
# Display-only: controls how many days the Risk Map's LSTM chart shows.
# Reports & Data stay on the fixed 7-day weekly archive regardless of this value.
LSTM_DEFAULT_HORIZON = 7
LSTM_MIN_HORIZON = 1
LSTM_MAX_HORIZON = 30


def _ensure_lstm_horizon_column(cursor):
    """Makes sure the LSTM setting columns exist (init_db only runs on a full server start)."""
    cursor.execute("PRAGMA table_info(app_settings)")
    cols = [col[1] for col in cursor.fetchall()]
    if 'lstm_forecast_horizon' not in cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN lstm_forecast_horizon INTEGER DEFAULT 7")
    if 'lstm_confidence_display' not in cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN lstm_confidence_display INTEGER DEFAULT 1")


def _read_lstm_settings(cursor):
    cursor.execute("SELECT lstm_forecast_horizon, lstm_confidence_display FROM app_settings WHERE id = 1")
    row = cursor.fetchone()
    horizon = int(row[0]) if row and row[0] is not None else LSTM_DEFAULT_HORIZON
    confidence = bool(row[1]) if row and row[1] is not None else True   # default ON
    return {'forecast_horizon': horizon, 'confidence_display': confidence}


@app.route('/api/lstm_settings', methods=['GET'])
@api_login_required
def get_lstm_settings():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            _ensure_lstm_horizon_column(cursor)
            return jsonify({'success': True, 'settings': _read_lstm_settings(cursor)})
    except Exception as e:
        print(f"❌ get_lstm_settings DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load LSTM settings.'}), 500


@app.route('/api/lstm_settings', methods=['POST'])
@admin_required
def set_lstm_settings():
    data = request.get_json() or {}
    sets, params = [], []

    if 'forecast_horizon' in data:
        try:
            horizon = int(data.get('forecast_horizon'))
        except (TypeError, ValueError):
            return jsonify({'success': False, 'message': 'Forecast horizon must be a number of days.'}), 400
        if horizon < LSTM_MIN_HORIZON or horizon > LSTM_MAX_HORIZON:
            return jsonify({'success': False, 'message': f'Forecast horizon must be between {LSTM_MIN_HORIZON} and {LSTM_MAX_HORIZON} days.'}), 400
        sets.append('lstm_forecast_horizon = ?')
        params.append(horizon)

    if 'confidence_display' in data:
        raw = data.get('confidence_display')
        show = raw if isinstance(raw, bool) else str(raw).strip().lower() in ('1', 'true', 'on', 'yes')
        sets.append('lstm_confidence_display = ?')
        params.append(1 if show else 0)

    if not sets:
        return jsonify({'success': False, 'message': 'Nothing to save.'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            _ensure_lstm_horizon_column(cursor)
            cursor.execute(
                "UPDATE app_settings SET " + ", ".join(sets) + ", updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
                tuple(params) + (session['user_id'],)
            )
            conn.commit()
            return jsonify({'success': True, 'settings': _read_lstm_settings(cursor)})
    except Exception as e:
        print(f"❌ set_lstm_settings DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not save LSTM settings. Please try again.'}), 500


# ── LSTM DEPLOYED DEVICE (which Monitored Device Location the LSTM uses) ──
def _ensure_lstm_deployed_column(cursor):
    """init_db() only runs on a full server start, so if the server was already
    running when this feature was added the column won't exist yet. Add it on demand."""
    cursor.execute("PRAGMA table_info(app_settings)")
    cols = [col[1] for col in cursor.fetchall()]
    if 'lstm_deployed_device_id' not in cols:
        cursor.execute("ALTER TABLE app_settings ADD COLUMN lstm_deployed_device_id INTEGER")


def _lstm_deployed_device_payload(cursor):
    cursor.execute('''
        SELECT s.lstm_deployed_device_id, d.name, d.lat, d.lng, d.status
        FROM app_settings s
        LEFT JOIN device_deployments d ON d.id = s.lstm_deployed_device_id
        WHERE s.id = 1
    ''')
    row = cursor.fetchone()
    if not row or row[0] is None or row[1] is None:
        return {'device_id': None, 'device_name': None}
    return {
        'device_id': row[0],
        'device_name': row[1],
        'device_lat': row[2],
        'device_lng': row[3],
        'device_status': row[4],
    }


@app.route('/api/lstm_deployed_device', methods=['GET'])
@api_login_required
def get_lstm_deployed_device():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            _ensure_lstm_deployed_column(cursor)
            return jsonify({'success': True, 'deployed': _lstm_deployed_device_payload(cursor)})
    except Exception as e:
        print(f"❌ get_lstm_deployed_device DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load the LSTM deployed device.'}), 500


@app.route('/api/lstm_deployed_device', methods=['POST'])
@admin_required
def set_lstm_deployed_device():
    data = request.get_json() or {}
    device_id = data.get('device_id')  # None = clear the selection

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            _ensure_lstm_deployed_column(cursor)

            if device_id is not None:
                cursor.execute('SELECT id FROM device_deployments WHERE id = ?', (device_id,))
                if not cursor.fetchone():
                    return jsonify({'success': False, 'message': 'Selected device was not found. It may have been removed.'}), 404

            cursor.execute(
                "UPDATE app_settings SET lstm_deployed_device_id = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
                (device_id, session['user_id'])
            )
            conn.commit()
            return jsonify({'success': True, 'deployed': _lstm_deployed_device_payload(cursor)})
    except Exception as e:
        print(f"❌ set_lstm_deployed_device DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not save the deployed device. Please try again.'}), 500


@app.route('/api/environmental_data', methods=['GET'])
@admin_required
def get_environmental_data():
    device_id = request.args.get('device_id')
    year = request.args.get('year')
    month = request.args.get('month')

    if not device_id or not year or not month:
        return jsonify({'success': False, 'message': 'device_id, year and month are required'}), 400

    try:
        device_id = int(device_id)
        year = int(year)
        month = int(month)
        if not (1 <= month <= 12):
            raise ValueError('month out of range')
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Invalid device_id, year or month'}), 400

    month_prefix = f'{year:04d}-{month:02d}'

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM device_deployments WHERE id = ?', (device_id,))
            device_row = cursor.fetchone()
            if not device_row:
                return jsonify({'success': False, 'message': 'Device not found'}), 404

            cursor.execute('''
                SELECT reading_date, temperature, humidity, rainfall_mm, ph_level, wind_speed, risk_level, updated_at
                FROM device_daily_readings
                WHERE device_id = ? AND reading_date LIKE ?
                ORDER BY reading_date ASC
            ''', (device_id, month_prefix + '%'))
            rows = cursor.fetchall()

            data = [{
                'date': r[0], 'temp': r[1], 'hum': r[2], 'rain': r[3],
                'ph': r[4], 'wind': r[5], 'risk': r[6],
                # updated_at is naive but already Manila wall-clock time —
                # db.py's get_db_connection() runs SET TIME ZONE 'Asia/Manila'
                # on every session, and this column is `timestamp without
                # time zone`, so CURRENT_TIMESTAMP was written using that
                # session tz already. No conversion needed here.
                'time': r[7].strftime('%H:%M:%S') if r[7] else None,
            } for r in rows]

            return jsonify({'success': True, 'device_name': device_row[0], 'data': data})
    except Exception as e:
        print(f"❌ get_environmental_data DB error: {e}")
        return jsonify({'success': False, 'message': 'Could not load environmental data'}), 500


@app.route('/api/reports/generate', methods=['POST'])
@admin_required
def generate_report():
    data = request.get_json() or {}
    report_type = data.get('type', 'daily')
    format_type = data.get('format', 'pdf')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if report_type == 'daily':
        cursor.execute('''
            SELECT temperature, humidity, rainfall_mm, ph_level, wind_speed, risk_bucket, created_at
            FROM sensor_readings
            WHERE created_at >= datetime('now', '-1 day')
            ORDER BY created_at DESC
        ''')
    else:
        cursor.execute('''
            SELECT temperature, humidity, rainfall_mm, ph_level, wind_speed, risk_bucket, created_at
            FROM sensor_readings
            WHERE created_at >= datetime('now', '-7 days')
            ORDER BY created_at DESC
        ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        return jsonify({'success': False, 'message': 'No data available for the selected period'}), 404
    
    report_data = []
    for row in rows:
        report_data.append({
            'temperature': row['temperature'],
            'humidity': row['humidity'],
            'rainfall_mm': row['rainfall_mm'],
            'ph_level': row['ph_level'],
            'wind_speed': row['wind_speed'],
            'risk_level': row['risk_bucket'],
            'timestamp': row['created_at']
        })
    
    if format_type == 'csv':
        return generate_csv_report(report_data)
    else:
        return jsonify({
            'success': True,
            'data': report_data,
            'count': len(report_data),
            'type': report_type,
            'format': format_type
        })


def generate_csv_report(data):
    si = StringIO()
    writer = csv.writer(si)
    
    writer.writerow(['Temperature (°C)', 'Humidity (%)', 'Rainfall (mm)', 'pH Level', 'Wind Speed (m/s)', 'Risk Level', 'Timestamp'])
    
    for row in data:
        writer.writerow([
            row['temperature'],
            row['humidity'],
            row['rainfall_mm'],
            row['ph_level'],
            row['wind_speed'],
            row['risk_level'],
            row['timestamp']
        ])
    
    output = si.getvalue()
    si.close()
    
    return send_file(
        BytesIO(output.encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'risk_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )


@app.route('/api/reports/history', methods=['GET'])
@admin_required
def get_report_history():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 
            date(created_at) as date,
            AVG(temperature) as avg_temp,
            AVG(humidity) as avg_humidity,
            AVG(rainfall_mm) as avg_rainfall,
            AVG(risk_level) as avg_risk
        FROM sensor_readings
        WHERE created_at >= datetime('now', '-30 days')
        GROUP BY date(created_at)
        ORDER BY date ASC
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    history_data = []
    for row in rows:
        history_data.append({
            'date': row['date'],
            'avg_temp': round(row['avg_temp'], 1) if row['avg_temp'] else None,
            'avg_humidity': round(row['avg_humidity'], 1) if row['avg_humidity'] else None,
            'avg_rainfall': round(row['avg_rainfall'], 1) if row['avg_rainfall'] else None,
            'avg_risk': round(row['avg_risk'], 0) if row['avg_risk'] else None
        })
    
    return jsonify({'success': True, 'history': history_data})


# ── RISK MONITOR LOOP ──
# Fixed cadence for the "Always On" In-App Notifications channel — independent
# of whatever the resident has set for Email/SMS/Notification Frequency.
IN_APP_INTERVAL_SECONDS = 15 * 60


def dispatch_scheduled_notifications():
    """Sends any Email/SMS notifications whose per-resident delay has come due.

    Called once per tick of risk_monitor_loop's own while-loop, BEFORE the
    sensor-refresh-rate gating below — a resident's scheduled delay must keep
    counting down and firing even while sensor polling itself is paused/slow,
    and even while the admin page is closed or refreshed, since the schedule
    lives in scheduled_notifications (the database), not in this thread's
    memory. That's also what makes it survive a full server restart: the
    scheduled_for time was computed once, at alert-creation time, and stored —
    there's no per-user countdown sitting only in a Python dict that a
    restart would reset or need to re-arm.

    Duplicate sends are prevented by the atomic UPDATE ... WHERE status =
    'pending' below: only the request that actually flips a row from
    'pending' to 'sending' (rowcount == 1) is allowed to send it. Anything
    else that saw the same row as "due" on this tick (or a retried/overlapping
    call) gets rowcount 0 and skips it.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            "SELECT sn.id, sn.user_id, sn.channel, sn.risk_level, sn.temperature, sn.humidity, "
            "sn.rainfall_mm, sn.ph_level, sn.wind_speed, sn.risk_alert_id, u.email, u.phone "
            "FROM scheduled_notifications sn "
            "JOIN users u ON u.id = sn.user_id "
            "WHERE sn.status = 'pending' AND sn.scheduled_for <= ?",
            (now_ts,)
        )
        due_rows = cursor.fetchall()
        conn.close()
    except Exception as e:
        print(f"⚠️ Failed to poll scheduled_notifications: {e}")
        return

    for (sched_id, user_id, channel, risk_level, temp, humidity, rain_mm, ph_level,
         wind_speed, risk_alert_id, email, phone) in due_rows:

        # ── ATOMIC CLAIM: pending -> sending ──
        try:
            claim_conn = get_db_connection()
            claim_cursor = claim_conn.cursor()
            claim_cursor.execute(
                "UPDATE scheduled_notifications SET status = 'sending' WHERE id = ? AND status = 'pending'",
                (sched_id,)
            )
            claimed = claim_cursor.rowcount == 1
            claim_conn.commit()
            claim_conn.close()
        except Exception as e:
            print(f"⚠️ Failed to claim scheduled_notification {sched_id}: {e}")
            continue

        if not claimed:
            continue

        sent_ok = False
        subject = body = None
        try:
            if channel == 'email' and email:
                sent_ok, subject, body = send_risk_email(
                    email, risk_level, temp, humidity, rain_mm, ph_level, wind_speed
                )
            elif channel == 'sms' and phone:
                # No standalone SMS gateway is wired up in this codebase yet —
                # SMS delivery has always been represented as riding along
                # with the resident's email send. Only the delay/scheduling
                # behavior is new here.
                sent_ok = True
        except Exception as e:
            print(f"⚠️ Failed to send scheduled {channel} to user {user_id}: {e}")

        try:
            final_conn = get_db_connection()
            final_cursor = final_conn.cursor()
            final_cursor.execute(
                "UPDATE scheduled_notifications SET status = ?, sent_at = CURRENT_TIMESTAMP WHERE id = ?",
                ('sent' if sent_ok else 'failed', sched_id)
            )
            if sent_ok and risk_alert_id:
                # Reflect the real delivery outcome on the alert once it
                # actually happens — until then, the alert's own row still
                # shows email_sent/sms_sent = 0, which is correct: it hasn't
                # been sent yet, it's still waiting out the resident's delay.
                if channel == 'email':
                    final_cursor.execute(
                        "UPDATE risk_alerts SET email_sent = 1, "
                        "email_subject = COALESCE(?, email_subject), "
                        "email_body = COALESCE(?, email_body) WHERE id = ?",
                        (subject, body, risk_alert_id)
                    )
                elif channel == 'sms':
                    final_cursor.execute(
                        "UPDATE risk_alerts SET sms_sent = 1 WHERE id = ?",
                        (risk_alert_id,)
                    )
            final_conn.commit()
            final_conn.close()
        except Exception as e:
            print(f"⚠️ Failed to finalize scheduled_notification {sched_id}: {e}")


def risk_monitor_loop():
    # Guards against duplicate/"tripled" alerts when more than one AEDOSPOT
    # server process ends up running at the same time (e.g. an old
    # `python app.py` from a previous debug session that never fully exited).
    # Each process's monitor thread would otherwise call the live weather API
    # and INSERT its own risk_alerts row on its own independent timers,
    # producing several near-identical "Just now" alerts with slightly
    # different sensor values for what should be a single event. A Postgres
    # advisory lock is visible across *every* connection to the same Supabase
    # database, not just within this one process, so only the process that
    # actually holds the lock is allowed to run the monitoring work below —
    # any other process just waits (rechecking every minute) until it can.
    lock_conn = None
    while lock_conn is None:
        try:
            candidate = get_db_connection()
            lock_cur = candidate.cursor()
            lock_cur.execute("SELECT pg_try_advisory_lock(hashtext('aedospot_risk_monitor'))")
            got_lock = lock_cur.fetchone()[0]
            if got_lock:
                lock_conn = candidate  # kept open for the life of this thread — closing it releases the lock
            else:
                candidate.close()
                print("ℹ️ Another AEDOSPOT process already owns the risk monitor — waiting...")
                time.sleep(60)
        except Exception as e:
            print(f"⚠️ Could not acquire risk monitor lock, retrying: {e}")
            time.sleep(60)

    last_risk_level = None
    last_inapp_time_per_user = {}  # user_id -> timestamp of last in-app alert logged for that user
    first_iteration = True  # so a fresh thread (e.g. after a restart) doesn't treat "no prior state" as a risk change
    last_sensor_fetch_time = None  # gates how often we actually pull a fresh reading, per admin's "Getting data from sensors" setting

    while True:
        try:
            # Runs every tick, independent of the sensor-refresh-rate gating
            # right below — a resident's Email/SMS delay must keep counting
            # down (and fire) even on a tick where sensor polling itself is
            # skipped. See dispatch_scheduled_notifications for why.
            dispatch_scheduled_notifications()

            # ── RESPETUHIN ANG ADMIN'S "GETTING DATA FROM SENSORS" SETTING ──
            # app_settings.sensor_refresh_rate: 0 = off (no polling, no risk
            # checks, nothing sent — not even In-App), 1 = real-time (every
            # tick, ~60s), 15 = every 15 min, 60 = every hour. This is what
            # actually paces WHEN a fresh reading (and therefore a possible
            # risk_changed / in-app notification) can happen at all — the
            # in-app alert still fires immediately once a change IS detected,
            # but detection itself only happens as often as this setting allows.
            settings_conn = get_db_connection()
            settings_cursor = settings_conn.cursor()
            settings_cursor.execute("SELECT sensor_refresh_rate FROM app_settings WHERE id = 1")
            settings_row = settings_cursor.fetchone()
            settings_conn.close()
            sensor_refresh_rate = settings_row[0] if settings_row and settings_row[0] is not None else 1

            if sensor_refresh_rate == 0:
                # Turned off — don't fetch, don't check risk, don't send anything.
                time.sleep(60)
                continue

            refresh_interval_seconds = float(sensor_refresh_rate) * 60
            now_tick = time.time()
            if last_sensor_fetch_time is not None and (now_tick - last_sensor_fetch_time) < refresh_interval_seconds:
                # Not due for a fresh reading yet under the admin's configured cadence.
                time.sleep(60)
                continue
            last_sensor_fetch_time = now_tick

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, email, notif_freq, email_enabled, barangay, sms_enabled, phone, sms_notif_freq FROM users "
                "WHERE is_admin = 0 OR is_admin IS NULL"
            )
            users = cursor.fetchall()
            conn.close()

            # ── KUHA NG DATA SA OPENWEATHERMAP ──
            try:
                reading = get_live_weather_reading()
            except Exception:
                time.sleep(60)
                continue

            temp = reading['temperature']
            humidity = reading['humidity']
            wind_speed = reading['wind_speed']
            rain_mm = reading['rainfall_mm']
            ph_level = reading['ph_level']
            current_risk = reading['risk_bucket']

            # ── I-LOG ANG READING PARA SA CHART ──
            try:
                hist_conn = get_db_connection()
                hist_cursor = hist_conn.cursor()
                hist_cursor.execute(
                    '''INSERT INTO sensor_readings
                       (temperature, humidity, rainfall_mm, ph_level, wind_speed, wind_direction, risk_level, risk_bucket)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (temp, humidity, rain_mm, ph_level, wind_speed,
                     reading.get('wind_direction'), reading.get('risk_level'), current_risk)
                )
                hist_cursor.execute(
                    '''DELETE FROM sensor_readings WHERE id NOT IN (
                           SELECT id FROM sensor_readings ORDER BY id DESC LIMIT ?
                       )''',
                    (SENSOR_HISTORY_MAX_ROWS,)
                )
                hist_conn.commit()
                hist_conn.close()
            except Exception as e:
                print(f"⚠️ Failed to log sensor_reading: {e}")

            # ── I-REFRESH ANG BAWAT DEVICE PIN + I-ARCHIVE PARA SA "ENVIRONMENTAL DATA" ──
            try:
                today_str = manila_today_str()  # Manila 12:00 AM-11:59 PM boundary, not UTC
                archive_device_daily_readings(
                    today_str, temp, humidity, rain_mm, ph_level, wind_speed, current_risk
                )
            except Exception as e:
                print(f"⚠️ Failed to archive device_daily_readings: {e}")

            # ── I-ARCHIVE ANG LSTM SNAPSHOT PARA SA KASALUKUYANG LINGGO ──
            try:
                forecast = generate_lstm_forecast()
                week_start, week_end = get_lstm_week_bounds()
                hotspots = forecast.get('hotspots') or []
                note = f"LSTM predicts elevated breeding risk in {' & '.join(hotspots)} over the next 72h." if hotspots else None
                lstm_conn = get_db_connection()
                lstm_cursor = lstm_conn.cursor()
                lstm_cursor.execute('''
                    INSERT INTO lstm_weekly_archive (week_start, week_end, risk_level, confidence, note, updated_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(week_start, week_end) DO UPDATE SET
                        risk_level = excluded.risk_level,
                        confidence = excluded.confidence,
                        note = excluded.note,
                        updated_at = CURRENT_TIMESTAMP
                ''', (week_start.isoformat(), week_end.isoformat(), forecast.get('overall_risk'), forecast.get('confidence'), note))

                lstm_conn.commit()
                lstm_conn.close()
            except Exception as e:
                print(f"⚠️ Failed to archive lstm_weekly_archive: {e}")

            # ── I-SAVE DIN SA LOCATION NA NAKA "SET DEPLOYED DEVICE" SA LSTM DASHBOARD ──
            # Separate connection/try so a problem here can never block the global archive above.
            try:
                dev_conn = get_db_connection()
                dev_cursor = dev_conn.cursor()
                _ensure_lstm_deployed_column(dev_cursor)
                _ensure_lstm_device_archive_table(dev_cursor)
                dev_cursor.execute('SELECT lstm_deployed_device_id FROM app_settings WHERE id = 1')
                dep_row = dev_cursor.fetchone()
                deployed_id = dep_row[0] if dep_row else None
                if deployed_id is not None:
                    dev_cursor.execute('SELECT id FROM device_deployments WHERE id = ?', (deployed_id,))
                    if dev_cursor.fetchone():
                        dev_cursor.execute('''
                            INSERT INTO lstm_device_weekly_archive (device_id, week_start, week_end, risk_level, confidence, note, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                            ON CONFLICT(device_id, week_start, week_end) DO UPDATE SET
                                risk_level = excluded.risk_level,
                                confidence = excluded.confidence,
                                note = excluded.note,
                                updated_at = CURRENT_TIMESTAMP
                        ''', (deployed_id, week_start.isoformat(), week_end.isoformat(), forecast.get('overall_risk'), forecast.get('confidence'), note))
                dev_conn.commit()
                dev_conn.close()
            except Exception as e:
                print(f"⚠️ Failed to archive lstm_device_weekly_archive: {e}")

            # Only count an actual moderate<->high<->low transition as a "risk changed" trigger
            # once we have a real prior reading. On the very first iteration of a fresh thread
            # (e.g. right after a server restart / ctrl+F5) there is no real prior state yet —
            # treating that as a "change" was what caused an immediate nag email on every restart,
            # ignoring each user's configured Notification Frequency entirely.
            risk_changed = (not first_iteration) and (current_risk != last_risk_level)

            # One shared timestamp for this whole detection tick — captured
            # ONCE here, before looping over residents, rather than calling
            # datetime.now() again inside the per-user loop below. Every
            # resident's risk_alerts row (and the Email/SMS schedule derived
            # from it) must carry the exact same detected-at time, so that
            # admin_alerts' "Sent to all residents via In-App Notification"
            # broadcast line (which groups by minute) always reflects the
            # same moment shown on every individual resident's own Alerts
            # page — not a slightly different timestamp per resident that
            # drifted while the loop below was running (or that crossed a
            # minute boundary partway through a large resident list).
            trigger_now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # ── I-LOOP ANG BAWAT USER ──
            for user_id, email, freq_minutes, enabled, barangay, sms_enabled, phone, sms_freq_minutes in users:
                current_time = time.time()

                # ── IN-APP: this is the "Always On" channel promised in the
                # resident's Delivery Channels settings — it must keep working
                # on its own fixed 15-minute cadence no matter what the
                # resident has done to Email/SMS/Notification Frequency below
                # (including turning both off entirely). It gets its own
                # independent timer, separate from the Email/SMS scheduling below.
                last_inapp_sent = last_inapp_time_per_user.get(user_id)
                should_inapp = False
                if risk_changed:
                    should_inapp = True
                elif last_inapp_sent is None:
                    # Fresh thread (restart/ctrl+F5/deploy) — baseline the
                    # clock instead of firing immediately.
                    last_inapp_time_per_user[user_id] = current_time
                elif (current_time - last_inapp_sent) >= IN_APP_INTERVAL_SECONDS:
                    should_inapp = True

                if not should_inapp or current_risk not in ('moderate', 'high'):
                    continue

                if should_inapp:
                    last_inapp_time_per_user[user_id] = current_time

                # ── AN ALERT IS BEING CREATED FOR THIS RESIDENT ──
                # In-App is the "immediate" channel — the alert row itself IS
                # the in-app notification, so it's written right here, right
                # now. email_sent/sms_sent start at 0: whether those channels
                # actually go out is decided below, on each resident's own
                # delay, and the flags get flipped later (by
                # dispatch_scheduled_notifications) once that delay elapses
                # and the send genuinely happens — never before.
                try:
                    alert_message = (
                        f"{current_risk.capitalize()} mosquito breeding risk detected — "
                        f"Temp {temp}°C, Humidity {humidity}%, Rainfall {rain_mm}mm, "
                        f"pH {ph_level}, Wind {wind_speed} m/s."
                    )
                    log_conn = get_db_connection()
                    log_cursor = log_conn.cursor()
                    # created_at is set explicitly here (to the ONE shared
                    # trigger_now_ts captured before this per-user loop began)
                    # rather than relying on the column's SQL DEFAULT
                    # CURRENT_TIMESTAMP or re-reading the clock per user — on a
                    # DB whose risk_alerts table predates that default (or has
                    # any other schema drift), the DEFAULT silently never
                    # fires and the column comes back NULL, which is what was
                    # breaking the "time ago" display on the Alerts page.
                    # Using the shared timestamp (instead of a fresh
                    # datetime.now() per user) is what guarantees every
                    # resident's copy of this alert — and admin_alerts'
                    # broadcast line for it — shows the exact same detected
                    # date/time.
                    now_ts = trigger_now_ts
                    # email_sent/sms_sent are explicitly forced to 0 here — the
                    # risk_alerts.email_sent column defaults to 1 (a backfill
                    # default for pre-existing rows that predate this column,
                    # see the migration above), which would otherwise make a
                    # brand-new alert look like its email already went out
                    # before the resident's delay has even started.
                    log_cursor.execute(
                        "INSERT INTO risk_alerts (user_id, alert_message, risk_level, barangay, "
                        "email_sent, sms_sent, created_at) "
                        "VALUES (?, ?, ?, ?, 0, 0, ?)",
                        (user_id, alert_message, current_risk, barangay, now_ts)
                    )
                    risk_alert_id = log_cursor.lastrowid
                    log_conn.commit()
                    log_conn.close()
                except Exception as e:
                    print(f"⚠️ Failed to log risk_alert for user {user_id}: {e}")
                    continue

                # ── SCHEDULE EMAIL AND SMS, EACH DELAYED BY ITS OWN
                # INDEPENDENT NOTIFICATION FREQUENCY ──
                # Email uses resident_alert.notif_freq, SMS uses its own
                # sms_notif_freq column — the two are never mixed. Each is
                # computed from the SAME base moment (trigger_ts, this exact
                # sensor alert's own created_at, captured above as now_ts) so
                # e.g. Email=30min/SMS=1hr against an 11:00 AM alert always
                # lands on 11:30 AM and 12:00 PM respectively, never on each
                # other's delay. 'off' (stored as the literal string, not a
                # number) means that channel is fully disabled — excluded up
                # front so freq_minutes * 60 never gets attempted against it.
                trigger_ts = datetime.strptime(now_ts, '%Y-%m-%d %H:%M:%S')

                def _channel_delay_minutes(freq_value):
                    if freq_value == 'off' or freq_value is None:
                        return None
                    try:
                        return float(freq_value)
                    except (TypeError, ValueError):
                        return 15.0  # unexpected stored value — fall back to the default cadence

                channel_schedule = []  # list of (channel, scheduled_for)
                if enabled:  # email_enabled
                    email_delay = _channel_delay_minutes(freq_minutes)
                    if email_delay is not None:
                        channel_schedule.append((
                            'email',
                            (trigger_ts + timedelta(minutes=email_delay)).strftime('%Y-%m-%d %H:%M:%S')
                        ))
                if sms_enabled and phone:
                    sms_delay = _channel_delay_minutes(sms_freq_minutes)
                    if sms_delay is not None:
                        channel_schedule.append((
                            'sms',
                            (trigger_ts + timedelta(minutes=sms_delay)).strftime('%Y-%m-%d %H:%M:%S')
                        ))

                if channel_schedule:
                    try:
                        sched_conn = get_db_connection()
                        sched_cursor = sched_conn.cursor()
                        for channel, scheduled_for in channel_schedule:
                            # ON CONFLICT DO NOTHING (keyed on risk_alert_id +
                            # user_id + channel) is the safety net that stops
                            # this exact alert from ever getting scheduled
                            # twice for the same resident/channel.
                            sched_cursor.execute(
                                "INSERT INTO scheduled_notifications "
                                "(risk_alert_id, user_id, channel, risk_level, temperature, humidity, "
                                "rainfall_mm, ph_level, wind_speed, scheduled_for) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                                "ON CONFLICT (risk_alert_id, user_id, channel) DO NOTHING",
                                (risk_alert_id, user_id, channel, current_risk, temp, humidity,
                                 rain_mm, ph_level, wind_speed, scheduled_for)
                            )
                        sched_conn.commit()
                        sched_conn.close()
                    except Exception as e:
                        print(f"⚠️ Failed to schedule notifications for user {user_id}: {e}")
                # If both Email and SMS are disabled (or their frequency is
                # 'off'), channel_schedule is empty and nothing gets
                # scheduled — the alert stays In-App only, exactly as configured.

            last_risk_level = current_risk
            first_iteration = False

        except Exception as e:
            print(f"⚠️ Monitor error: {e}")

        time.sleep(60)


@app.route('/api/update_data_refresh_rate', methods=['POST'])
def update_data_refresh_rate():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    data = request.get_json()
    refresh_rate = data.get('refresh_rate', 1)

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'data_refresh_rate' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN data_refresh_rate INTEGER DEFAULT 1")
    
    cursor.execute(
        "UPDATE users SET data_refresh_rate = ? WHERE id = ?",
        (refresh_rate, user_id)
    )
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Data refresh rate updated!'})


@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)


@app.errorhandler(Exception)
def handle_unexpected_error(e):
    if request.path.startswith('/api/'):
        print(f"❌ Unhandled error on {request.path}: {e}")
        return jsonify({'success': False, 'message': 'Something went wrong on our end. Please try again.'}), 500
    raise e


DEFAULT_MODERATE_ADVICE_MESSAGE = (
    "Moderate dengue risk detected. Increase mosquito prevention measures and "
    "monitor for possible symptoms. Remove stagnant water around your home, use "
    "mosquito repellent, wear long sleeves, and keep doors/windows screened. If "
    "symptoms such as fever, severe headache, body aches, nausea, or rash develop, "
    "seek medical advice promptly."
)

DEFAULT_HIGH_ADVICE_MESSAGE = (
    "High dengue risk detected. Take immediate precautions to prevent mosquito bites "
    "and eliminate all stagnant water around your home. Use mosquito repellent, wear "
    "long sleeves, and keep your surroundings clean. Monitor for dengue symptoms such "
    "as high fever, severe headache, body pain, rash, or bleeding. If symptoms develop, "
    "seek medical attention immediately."
)


def get_risk_advice(risk_level):
    if risk_level not in ('moderate', 'high'):
        return ''

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT moderate_advice_message, high_advice_message FROM app_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    if risk_level == 'moderate':
        custom = row['moderate_advice_message'] if row else None
        return custom if custom else DEFAULT_MODERATE_ADVICE_MESSAGE
    else:
        custom = row['high_advice_message'] if row else None
        return custom if custom else DEFAULT_HIGH_ADVICE_MESSAGE


@app.route('/api/get_email_messages', methods=['GET'])
@admin_required
def get_email_messages():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT moderate_advice_message, high_advice_message FROM app_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    moderate_msg = (row['moderate_advice_message'] if row else None) or DEFAULT_MODERATE_ADVICE_MESSAGE
    high_msg = (row['high_advice_message'] if row else None) or DEFAULT_HIGH_ADVICE_MESSAGE

    return jsonify({
        'success': True,
        'moderate_message': moderate_msg,
        'high_message': high_msg
    })


@app.route('/api/update_email_messages', methods=['POST'])
@admin_required
def update_email_messages():
    data = request.get_json() or {}
    moderate_message = (data.get('moderate_message') or '').strip()
    high_message = (data.get('high_message') or '').strip()

    if len(moderate_message) > 2000 or len(high_message) > 2000:
        return jsonify({'success': False, 'message': 'Message is too long (2000 character max).'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE app_settings SET moderate_advice_message = ?, high_advice_message = ?, "
        "updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        (moderate_message or None, high_message or None, session['user_id'])
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'moderate_message': moderate_message or DEFAULT_MODERATE_ADVICE_MESSAGE,
        'high_message': high_message or DEFAULT_HIGH_ADVICE_MESSAGE
    })


DEFAULT_MODERATE_SMS_MESSAGE = (
    "Moderate dengue risk detected in your area. Remove stagnant water, use "
    "mosquito repellent, and watch for fever, headache, or rash. Stay safe!"
)

DEFAULT_HIGH_SMS_MESSAGE = (
    "HIGH dengue risk detected in your area. Eliminate stagnant water now and "
    "use mosquito protection. Seek medical help right away if symptoms occur."
)

SMS_CHAR_LIMIT = 320  # ~2 SMS segments (GSM-7, 153 chars/segment when concatenated)


def get_risk_sms_advice(risk_level):
    if risk_level not in ('moderate', 'high'):
        return ''

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT moderate_sms_message, high_sms_message FROM app_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    if risk_level == 'moderate':
        custom = row['moderate_sms_message'] if row else None
        return custom if custom else DEFAULT_MODERATE_SMS_MESSAGE
    else:
        custom = row['high_sms_message'] if row else None
        return custom if custom else DEFAULT_HIGH_SMS_MESSAGE


@app.route('/api/get_sms_messages', methods=['GET'])
@admin_required
def get_sms_messages():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT moderate_sms_message, high_sms_message FROM app_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    moderate_msg = (row['moderate_sms_message'] if row else None) or DEFAULT_MODERATE_SMS_MESSAGE
    high_msg = (row['high_sms_message'] if row else None) or DEFAULT_HIGH_SMS_MESSAGE

    return jsonify({
        'success': True,
        'moderate_message': moderate_msg,
        'high_message': high_msg,
        'char_limit': SMS_CHAR_LIMIT
    })


@app.route('/api/update_sms_messages', methods=['POST'])
@admin_required
def update_sms_messages():
    data = request.get_json() or {}
    moderate_message = (data.get('moderate_message') or '').strip()
    high_message = (data.get('high_message') or '').strip()

    if len(moderate_message) > SMS_CHAR_LIMIT or len(high_message) > SMS_CHAR_LIMIT:
        return jsonify({'success': False, 'message': f'Message is too long ({SMS_CHAR_LIMIT} character max).'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE app_settings SET moderate_sms_message = ?, high_sms_message = ?, "
        "updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        (moderate_message or None, high_message or None, session['user_id'])
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'moderate_message': moderate_message or DEFAULT_MODERATE_SMS_MESSAGE,
        'high_message': high_message or DEFAULT_HIGH_SMS_MESSAGE
    })


DEFAULT_MODERATE_APP_MESSAGE = "Moderate mosquito breeding risk detected"
DEFAULT_HIGH_APP_MESSAGE = "High mosquito breeding risk detected"
APP_MESSAGE_CHAR_LIMIT = 300


def get_risk_app_message(risk_level):
    """The admin-configurable headline shown on the resident's Alerts page
    (and in the admin's In-App Notification detail view) for a given risk
    level — falls back to the default headline when nothing custom is set.
    This is the single source of truth: callers must not hardcode or copy
    this text elsewhere, since an admin edit here needs to be reflected
    immediately anywhere it's read from."""
    if risk_level not in ('moderate', 'high'):
        return ''

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT moderate_app_message, high_app_message FROM app_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    if risk_level == 'moderate':
        custom = row['moderate_app_message'] if row else None
        return custom if custom else DEFAULT_MODERATE_APP_MESSAGE
    else:
        custom = row['high_app_message'] if row else None
        return custom if custom else DEFAULT_HIGH_APP_MESSAGE


@app.route('/api/get_app_messages', methods=['GET'])
@admin_required
def get_app_messages():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT moderate_app_message, high_app_message FROM app_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    moderate_msg = (row['moderate_app_message'] if row else None) or DEFAULT_MODERATE_APP_MESSAGE
    high_msg = (row['high_app_message'] if row else None) or DEFAULT_HIGH_APP_MESSAGE

    return jsonify({
        'success': True,
        'moderate_message': moderate_msg,
        'high_message': high_msg,
        'char_limit': APP_MESSAGE_CHAR_LIMIT
    })


@app.route('/api/get_current_app_message', methods=['GET'])
@api_login_required
def get_current_app_message():
    """Read-only, resident-facing counterpart to /api/get_app_messages.
    Residents (and admins) can look up the CURRENT headline for a risk level
    here, but only an admin can change it (via /api/update_app_messages).
    This is what resident_alerts.html reads from when it opens the In-App
    Notification detail view — the message itself is never stored or
    duplicated on the resident side, only fetched live from here."""
    risk_level = (request.args.get('risk_level') or 'moderate').lower().strip()
    if risk_level not in ('moderate', 'high'):
        risk_level = 'moderate'

    return jsonify({
        'success': True,
        'risk_level': risk_level,
        'message': get_risk_app_message(risk_level)
    })


@app.route('/api/update_app_messages', methods=['POST'])
@admin_required
def update_app_messages():
    data = request.get_json() or {}
    moderate_message = (data.get('moderate_message') or '').strip()
    high_message = (data.get('high_message') or '').strip()

    if len(moderate_message) > APP_MESSAGE_CHAR_LIMIT or len(high_message) > APP_MESSAGE_CHAR_LIMIT:
        return jsonify({'success': False, 'message': f'Message is too long ({APP_MESSAGE_CHAR_LIMIT} character max).'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE app_settings SET moderate_app_message = ?, high_app_message = ?, "
        "updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        (moderate_message or None, high_message or None, session['user_id'])
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'moderate_message': moderate_message or DEFAULT_MODERATE_APP_MESSAGE,
        'high_message': high_message or DEFAULT_HIGH_APP_MESSAGE
    })


@app.route('/api/app_message_preview', methods=['POST'])
@admin_required
def app_message_preview():
    try:
        data = request.get_json(silent=True) or {}
        risk_level = (data.get('risk_level') or 'moderate').lower().strip()
        if risk_level not in ('moderate', 'high'):
            risk_level = 'moderate'

        headline = data.get('headline')
        if headline is None:
            headline = get_risk_app_message(risk_level)
        headline = (headline or '').strip() or (
            DEFAULT_HIGH_APP_MESSAGE if risk_level == 'high' else DEFAULT_MODERATE_APP_MESSAGE
        )

        # Use the same latest sensor row used by the dashboards/email preview.
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT temperature, humidity, rainfall_mm, ph_level, wind_speed FROM sensor_readings ORDER BY id DESC LIMIT 1"
            )
            row = cursor.fetchone()

        if row:
            temp = row['temperature']
            humidity = row['humidity']
            rain = row['rainfall_mm']
            ph = row['ph_level']
            wind = row['wind_speed']
        else:
            live = get_live_weather_reading() or {}
            temp = live.get('temperature', '--')
            humidity = live.get('humidity', '--')
            rain = live.get('rainfall_mm', live.get('rainfall', '--'))
            ph = live.get('ph_level', '--')
            wind = live.get('wind_speed', '--')

        # The message is returned exactly as given — nothing is appended to
        # it — and the sensor readings are returned in their own "env"
        # object. Keeping them separate here means the frontend never has to
        # parse them back apart, and the preview can't drift from the actual
        # editable message value.
        return jsonify({
            'success': True,
            'message': headline,
            'char_count': len(headline),
            'risk_level': risk_level,
            'env': {
                'temperature': temp,
                'humidity': humidity,
                'rainfall': rain,
                'ph': ph,
                'wind': wind
            }
        })
    except Exception as e:
        print(f"❌ In-app message preview error: {e}")
        return jsonify({'success': False, 'message': 'Could not generate in-app message preview.'}), 500


def render_risk_sms_text(risk_level, temp, humidity, advice_text=None):
    """Plain-text SMS body — mirrors render_risk_email_html but kept short,
    since this is what actually gets sent thru the SMS gateway/app."""
    risk_level = (risk_level or 'moderate').lower().strip()
    if risk_level not in ('moderate', 'high'):
        risk_level = 'moderate'

    if advice_text is None:
        advice_text = get_risk_sms_advice(risk_level)

    tag = 'HIGH' if risk_level == 'high' else 'MODERATE'
    return (
        f"[AEDOSPOT] {tag} dengue risk detected (Temp {temp}°C, Humidity {humidity}%). "
        f"{advice_text or ''}".strip()
    )


@app.route('/api/sms_preview', methods=['POST'])
@admin_required
def sms_preview():
    try:
        data = request.get_json(silent=True) or {}
        risk_level = (data.get('risk_level') or 'moderate').lower().strip()
        if risk_level not in ('moderate', 'high'):
            risk_level = 'moderate'

        advice_text = data.get('advice_text')
        if advice_text is None:
            advice_text = get_risk_sms_advice(risk_level)

        # Use the same latest sensor row used by the dashboards/email preview.
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT temperature, humidity FROM sensor_readings ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()

        if row:
            temp = row['temperature']
            humidity = row['humidity']
        else:
            live = get_live_weather_reading() or {}
            temp = live.get('temperature', '--')
            humidity = live.get('humidity', '--')

        text = render_risk_sms_text(risk_level, temp, humidity, advice_text)

        return jsonify({
            'success': True,
            'text': text,
            'char_count': len(text),
            'risk_level': risk_level
        })
    except Exception as e:
        print(f"❌ SMS preview error: {e}")
        return jsonify({'success': False, 'message': 'Could not generate SMS preview.'}), 500


def render_risk_email_html(risk_level, temp, humidity, rain, ph, wind, advice_text=None):
    risk_level = (risk_level or 'moderate').lower().strip()
    if risk_level not in ('moderate', 'high'):
        risk_level = 'moderate'

    if risk_level == 'high':
        accent = '#e74c3c'
    else:
        accent = '#f39c12'

    safe_risk = escape(risk_level.upper())
    safe_temp = escape(str(temp))
    safe_humidity = escape(str(humidity))
    safe_rain = escape(str(rain))
    safe_ph = escape(str(ph))
    safe_wind = escape(str(wind))
    safe_detected = escape(datetime.now().strftime('%B %d, %Y at %I:%M %p'))

    if advice_text is None:
        advice_text = get_risk_advice(risk_level)

    safe_advice = escape(advice_text or '')
    safe_advice = safe_advice.replace('\r\n', '\n').replace('\r', '\n').replace('\n', '<br>')
    fallback_advice = 'Please continue following dengue prevention measures and monitor the latest AEDOSPOT risk status.'

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEDOSPOT Dengue Risk Alert</title>
</head>
<body style="margin:0; padding:0; background:#f4f7f5; font-family:Arial, Helvetica, sans-serif; color:#193025;">
    <div style="width:100%; padding:28px 12px; box-sizing:border-box; background:#f4f7f5;">
        <div style="max-width:600px; margin:0 auto; background:#ffffff; border:1px solid #dfe8e2; border-radius:12px; overflow:hidden;">
            <div style="padding:26px 20px 22px; text-align:center; background:#ffffff;">
                <div style="font-size:25px; line-height:1.15; font-weight:800; color:#20d978; letter-spacing:0.3px;">
                    AEDOSPOT DENGUE<br>MONITOR
                </div>
                <div style="margin-top:8px; font-size:12px; color:#789086;">Automated Dengue Risk Alert</div>
            </div>
            <div style="padding:0 28px 28px;">
                <div style="padding:18px 14px; border-radius:12px; background:{accent}; color:#ffffff; text-align:center;">
                    <div style="font-size:11px; line-height:1.2; font-weight:700; letter-spacing:0.5px;">CURRENT RISK LEVEL</div>
                    <div style="margin-top:6px; font-size:24px; line-height:1.1; font-weight:800;">{safe_risk}</div>
                </div>
                <div style="margin-top:18px; padding:18px 14px; border:1px solid #dce7e0; border-radius:10px; background:#f8fbf9;">
                    <div style="font-size:14px; font-weight:800; color:#193025;">Real-Time Monitoring Data</div>
                    <div style="margin-top:6px; font-size:11px; color:#71857b;">Monitored area: Morong, Rizal</div>
                    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse; margin-top:12px; font-size:12px;">
                        <tr><td style="padding:9px 0; color:#63766d; border-bottom:1px solid #e1e9e4;">Temperature</td><td align="right" style="padding:9px 0; font-weight:700; color:#193025; border-bottom:1px solid #e1e9e4;">{safe_temp}°C</td></tr>
                        <tr><td style="padding:9px 0; color:#63766d; border-bottom:1px solid #e1e9e4;">Humidity</td><td align="right" style="padding:9px 0; font-weight:700; color:#193025; border-bottom:1px solid #e1e9e4;">{safe_humidity}%</td></tr>
                        <tr><td style="padding:9px 0; color:#63766d; border-bottom:1px solid #e1e9e4;">Rainfall</td><td align="right" style="padding:9px 0; font-weight:700; color:#193025; border-bottom:1px solid #e1e9e4;">{safe_rain} mm</td></tr>
                        <tr><td style="padding:9px 0; color:#63766d; border-bottom:1px solid #e1e9e4;">pH Level</td><td align="right" style="padding:9px 0; font-weight:700; color:#193025; border-bottom:1px solid #e1e9e4;">{safe_ph}</td></tr>
                        <tr><td style="padding:9px 0; color:#63766d;">Wind Speed</td><td align="right" style="padding:9px 0; font-weight:700; color:#193025;">{safe_wind} m/s</td></tr>
                    </table>
                    <div style="margin-top:10px; font-size:10px; color:#82938b;">Detected: {safe_detected}</div>
                </div>
                <div style="margin-top:22px; padding:0 2px;">
                    <div style="font-size:15px; font-weight:800; color:#193025; margin-bottom:10px;">Recommended Actions</div>
                    <div style="font-size:13px; line-height:1.75; color:#40554b;">{safe_advice or fallback_advice}</div>
                </div>
            </div>
            <div style="padding:16px 24px; border-top:1px solid #e2e8e4; background:#fafcfb; text-align:center; font-size:11px; color:#788880;">
                AEDOSPOT Dengue Monitor — Morong, Rizal<br>
                This is an automated message. Please do not reply to this email.
            </div>
        </div>
    </div>
</body>
</html>
"""


def send_risk_email(to_email, risk_level, temp, humidity, rain, ph, wind):
    try:
        risk_level = (risk_level or 'moderate').lower().strip()
        if risk_level not in ('moderate', 'high'):
            print(f"ℹ️ No risk email sent to {to_email} (Risk: {risk_level})")
            return False, None, None

        risk_icon = '🔴' if risk_level == 'high' else '🟡'
        safe_risk = escape(risk_level.upper())
        safe_temp = escape(str(temp))
        safe_humidity = escape(str(humidity))
        safe_rain = escape(str(rain))
        safe_ph = escape(str(ph))
        safe_wind = escape(str(wind))
        advice_text = get_risk_advice(risk_level)
        plain_body = f"""AEDOSPOT DENGUE MONITOR

{risk_icon} CURRENT RISK LEVEL: {safe_risk}

Real-Time Monitoring Data
Monitored area: Morong, Rizal

Temperature: {safe_temp}°C
Humidity: {safe_humidity}%
Rainfall: {safe_rain} mm
pH Level: {safe_ph}
Wind Speed: {safe_wind} m/s
Detected: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}

Recommended Actions
{advice_text or 'Please continue following dengue prevention measures and monitor the latest AEDOSPOT risk status.'}

This is an automated message from AEDOSPOT Dengue Monitor. Please do not reply to this email.
"""
        body = render_risk_email_html(risk_level, temp, humidity, rain, ph, wind, advice_text)
        subject = f"AEDOSPOT Alert: {risk_level.capitalize()} Dengue Risk Detected"

        msg = MIMEMultipart('alternative')
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(plain_body, 'plain', 'utf-8'))
        msg.attach(MIMEText(body, 'html', 'utf-8'))

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)

        print(f"✅ Email sent to {to_email} (Risk: {risk_level})")
        return True, subject, plain_body
    except Exception as e:
        print(f"❌ Failed to send email: {str(e)}")
        return False, None, None


@app.route('/api/email_preview', methods=['POST'])
@admin_required
def email_preview():
    try:
        data = request.get_json(silent=True) or {}
        risk_level = (data.get('risk_level') or 'moderate').lower().strip()
        if risk_level not in ('moderate', 'high'):
            risk_level = 'moderate'

        advice_text = data.get('advice_text')
        if advice_text is None:
            advice_text = get_risk_advice(risk_level)

        # Use the same latest sensor row used by the dashboards.
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT temperature, humidity, rainfall_mm, ph_level, wind_speed FROM sensor_readings ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            # <--- REMOVED: row = cursor.fetchone() (This caused a blank row iteration bug)

        if row:
            temp = row['temperature']
            humidity = row['humidity']
            rain = row['rainfall_mm']
            ph = row['ph_level']
            wind = row['wind_speed']
        else:
            live = get_live_weather_reading() or {}
            temp = live.get('temperature', '--')
            humidity = live.get('humidity', '--')
            rain = live.get('rainfall_mm', live.get('rainfall', '--'))
            ph = live.get('ph_level', '--')
            wind = live.get('wind_speed', '--')

        return jsonify({
            'success': True,
            'subject': f"AEDOSPOT Alert: {risk_level.capitalize()} Dengue Risk Detected",
            'html': render_risk_email_html(risk_level, temp, humidity, rain, ph, wind, advice_text),
            'risk_level': risk_level
        })
    except Exception as e:
        print(f"❌ Email preview error: {e}")
        return jsonify({'success': False, 'message': 'Could not generate email preview.'}), 500


if __name__ == '__main__':
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        init_db()
        monitor_thread = threading.Thread(target=risk_monitor_loop, daemon=True)
        monitor_thread.start()

    print("\n" + "="*50)
    print("🦟 AEDOSPOT Server Running!")
    print("="*50 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)
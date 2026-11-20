import io
import zipfile
import shutil
import stat
import os
import hmac
import json
import secrets
import sqlite3
import subprocess
import sys
import requests
import time

from pathlib import Path, PurePosixPath
from functools import wraps
from urllib.parse import urlencode

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, abort, flash
)


# ---------------- ENV ----------------

BASE = Path(__file__).resolve().parent
BOT_DIR = BASE / "bots"
CONFIG_FILE = BASE / "bots.json"
DB_FILE = BASE / "nexora.db"

MAX_ZIP_SIZE = 25 * 1024 * 1024
MAX_EXTRACTED_SIZE = 50 * 1024 * 1024
MAX_ZIP_FILES = 100

ALLOWED_EXTENSIONS = {
    ".py", ".txt", ".json", ".md", ".toml",
    ".yaml", ".yml", ".cfg", ".ini"
}


def load_env_file(path):
    if not path.exists():
        return

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(
            key.strip(),
            value.strip().strip('"').strip("'")
        )


load_env_file(BASE / ".env")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "")

if len(app.secret_key) < 32:
    raise RuntimeError(
        "ضع FLASK_SECRET_KEY بطول 32 حرفاً على الأقل في .env"
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=MAX_ZIP_SIZE + 1024 * 1024
)

CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "").strip()
ADMIN_DISCORD_ID = os.getenv("ADMIN_DISCORD_ID", "").strip()

REDIRECT_URI = os.getenv(
    "DISCORD_REDIRECT_URI",
    "http://127.0.0.1:5000/callback"
)

DISCORD_API = "https://discord.com/api/v10"
processes = {}


# ---------------- DATABASE ----------------

def get_db():
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with get_db() as con:
        columns = con.execute("PRAGMA table_info(users)").fetchall()

        if not columns:
            con.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    discord_id TEXT UNIQUE NOT NULL,
                    discord_username TEXT NOT NULL,
                    discord_avatar TEXT,
                    role TEXT DEFAULT 'user',
                    created_at REAL
                )
            """)
        else:
            column_names = {row["name"] for row in columns}

            if "email" in column_names:
                con.execute("DROP TABLE IF EXISTS users_new")
                con.execute("""
                    CREATE TABLE users_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        discord_id TEXT UNIQUE NOT NULL,
                        discord_username TEXT NOT NULL,
                        discord_avatar TEXT,
                        role TEXT DEFAULT 'user',
                        created_at REAL
                    )
                """)

                if "discord_id" in column_names:
                    con.execute("""
                        INSERT OR IGNORE INTO users_new
                        (id, discord_id, discord_username,
                         discord_avatar, role, created_at)
                        SELECT
                            id,
                            discord_id,
                            COALESCE(discord_username, 'Discord User'),
                            discord_avatar,
                            CASE WHEN discord_id = ? THEN 'owner'
                                 ELSE 'user' END,
                            COALESCE(created_at, 0)
                        FROM users
                        WHERE discord_id IS NOT NULL
                          AND discord_id != ''
                    """, (ADMIN_DISCORD_ID,))

                con.execute("DROP TABLE users")
                con.execute("ALTER TABLE users_new RENAME TO users")


init_db()


def get_user_by_discord(discord_id):
    with get_db() as con:
        return con.execute(
            "SELECT * FROM users WHERE discord_id = ?",
            (discord_id,)
        ).fetchone()


def get_user_by_id(user_id):
    with get_db() as con:
        return con.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()


# ---------------- CURRENT USER ----------------

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    row = get_user_by_id(user_id)
    if not row:
        session.clear()
        return None

    return {
        "id": row["id"],
        "email": "",
        "username": row["discord_username"],
        "avatar": row["discord_avatar"],
        "discord_id": row["discord_id"],
        "is_owner": row["role"] == "owner"
    }


def login_user(row):
    session.clear()
    session["user_id"] = row["id"]


# ---------------- CSRF ----------------

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}


@app.before_request
def check_csrf():
    if request.method == "POST":
        expected = session.get("_csrf")
        supplied = (
            request.form.get("_csrf_token")
            or request.headers.get("X-CSRF-Token")
        )

        if not expected or not supplied:
            abort(400, "CSRF validation failed")

        if not hmac.compare_digest(expected, supplied):
            abort(400, "CSRF validation failed")


# ---------------- ACCESS CONTROL ----------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper


def owner_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("index"))
        if not user["is_owner"]:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


# ---------------- HOME ----------------

@app.get("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("welcome.html")


# ---------------- OLD EMAIL ROUTES ----------------

@app.route("/register", methods=["GET", "POST"])
@app.route("/email-login", methods=["GET", "POST"])
@app.route("/verify", methods=["GET", "POST"])
@app.route("/resend-code", methods=["GET", "POST"])
def old_email_routes():
    return redirect(url_for("discord_login"))


# ---------------- DISCORD LOGIN ----------------

@app.get("/discord/login")
def discord_login():
    if not CLIENT_ID or not CLIENT_SECRET:
        return "إعدادات Discord غير مكتملة في .env", 503

    state = secrets.token_urlsafe(32)
    session["discord_state"] = state

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": state
    }

    authorization_url = (
        "https://discord.com/oauth2/authorize?" + urlencode(params)
    )
    return redirect(authorization_url)


# ---------------- DISCORD CALLBACK ----------------

@app.get("/callback")
def discord_callback():
    if request.args.get("error"):
        flash("تم إلغاء تسجيل الدخول عبر Discord.")
        return redirect(url_for("index"))

    state = request.args.get("state", "")
    expected = session.pop("discord_state", None)

    if not state or not expected or not hmac.compare_digest(state, expected):
        abort(400, "OAuth state mismatch")

    code = request.args.get("code")
    if not code:
        abort(400, "Authorization code missing")

    try:
        token_response = requests.post(
            f"{DISCORD_API}/oauth2/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=20
        )

        if not token_response.ok:
            app.logger.error(
                "Discord token error: %s", token_response.status_code
            )
            flash("تعذر تسجيل الدخول عبر Discord.")
            return redirect(url_for("index"))

        access_token = token_response.json().get("access_token")
        if not access_token:
            flash("لم يتم استلام تصريح Discord.")
            return redirect(url_for("index"))

        user_response = requests.get(
            f"{DISCORD_API}/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=20
        )

        if not user_response.ok:
            flash("تعذر قراءة حساب Discord.")
            return redirect(url_for("index"))

        discord_user = user_response.json()

    except requests.RequestException:
        app.logger.exception("Discord connection failed")
        flash("تعذر الاتصال بخوادم Discord.")
        return redirect(url_for("index"))

    discord_id = str(discord_user["id"])
    username = (
        discord_user.get("global_name")
        or discord_user.get("username")
        or "Discord User"
    )
    avatar = discord_user.get("avatar")

    role = (
        "owner"
        if ADMIN_DISCORD_ID and discord_id == ADMIN_DISCORD_ID
        else "user"
    )

    with get_db() as con:
        con.execute("""
            INSERT INTO users (
                discord_id, discord_username, discord_avatar,
                role, created_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(discord_id)
            DO UPDATE SET
                discord_username = excluded.discord_username,
                discord_avatar = excluded.discord_avatar,
                role = excluded.role
        """, (
            discord_id, username, avatar, role, time.time()
        ))

    row = get_user_by_discord(discord_id)
    if not row:
        flash("تعذر إنشاء حساب NEXORA.")
        return redirect(url_for("index"))

    login_user(row)
    return redirect(url_for("dashboard"))


# ---------------- LOGOUT ----------------

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------- BOTS ----------------

def load_bots():
    if not CONFIG_FILE.exists():
        return []

    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        app.logger.exception("Could not read bots.json")
        return []


def save_bots(items):
    temporary = CONFIG_FILE.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(items, ensure_ascii=False, indent=4),
        encoding="utf-8"
    )
    temporary.replace(CONFIG_FILE)


# ---------------- ADD BOT FROM EXISTING FILE ----------------

@app.post("/library/add")
@owner_required
def add_bot():
    name = request.form.get("name", "").strip()
    bot_type = request.form.get("type", "").strip()
    icon = request.form.get("icon", "🤖").strip()
    description = request.form.get("description", "").strip()
    script_name = request.form.get("script", "").strip()
    features_text = request.form.get("features", "").strip()

    if not name or not bot_type or not script_name:
        flash("يرجى تعبئة الاسم والنوع واسم ملف Python.")
        return redirect(url_for("bot_library"))

    if Path(script_name).name != script_name or not script_name.endswith(".py"):
        flash("اسم ملف التشغيل غير صالح.")
        return redirect(url_for("bot_library"))

    script_path = (BOT_DIR / script_name).resolve()
    try:
        script_path.relative_to(BOT_DIR.resolve())
    except ValueError:
        flash("مسار ملف التشغيل غير صالح.")
        return redirect(url_for("bot_library"))

    if not script_path.is_file():
        flash("ملف Python غير موجود داخل مجلد bots.")
        return redirect(url_for("bot_library"))

    items = load_bots()
    if any(x.get("script") == script_name for x in items):
        flash("هذا الملف مسجل بالفعل في المكتبة.")
        return redirect(url_for("bot_library"))

    features = [
        line.strip() for line in features_text.splitlines() if line.strip()
    ]

    items.append({
        "key": "bot-" + secrets.token_hex(6),
        "name": name,
        "type": bot_type,
        "icon": icon or "🤖",
        "script": script_name,
        "description": description,
        "features": features,
        "env": {}
    })

    try:
        save_bots(items)
    except OSError:
        app.logger.exception("Could not save new bot")
        flash("تعذر حفظ البوت. تحقق من صلاحيات الملفات.")
        return redirect(url_for("bot_library"))

    flash("تمت إضافة البوت إلى المكتبة بنجاح.")
    return redirect(url_for("bot_library"))


# ---------------- UPLOAD BOT ZIP ----------------

@app.post("/library/upload")
@owner_required
def upload_bot_zip():
    uploaded = request.files.get("zip_file")
    name = request.form.get("name", "").strip()
    bot_type = request.form.get("type", "").strip()
    icon = request.form.get("icon", "🤖").strip()
    description = request.form.get("description", "").strip()
    main_script = request.form.get("main_script", "").strip().replace("\\", "/")

    if not uploaded or not uploaded.filename:
        flash("اختر ملف ZIP أولاً.")
        return redirect(url_for("bot_library"))

    if not name or not bot_type or not main_script:
        flash("أكمل اسم البوت والنوع ومسار ملف التشغيل.")
        return redirect(url_for("bot_library"))

    if Path(uploaded.filename).suffix.lower() != ".zip":
        flash("يسمح برفع ملفات ZIP فقط.")
        return redirect(url_for("bot_library"))

    main_path = PurePosixPath(main_script)
    if (
        main_path.is_absolute()
        or not main_path.parts
        or ".." in main_path.parts
        or main_path.suffix.lower() != ".py"
    ):
        flash("مسار ملف التشغيل غير صالح. مثال: main.py أو src/main.py")
        return redirect(url_for("bot_library"))

    archive_data = uploaded.stream.read(MAX_ZIP_SIZE + 1)
    if len(archive_data) > MAX_ZIP_SIZE:
        flash("حجم ZIP أكبر من 25 ميجابايت.")
        return redirect(url_for("bot_library"))

    items = load_bots()
    key = "bot-" + secrets.token_hex(6)
    target_dir = BOT_DIR / key
    created_dir = False

    try:
        BOT_DIR.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
            members = archive.infolist()

            if not members or len(members) > MAX_ZIP_FILES:
                raise ValueError("عدد الملفات داخل ZIP غير صالح.")

            safe_files = []
            seen_paths = set()
            declared_total = 0

            for member in members:
                raw_name = member.filename.replace("\\", "/")
                relative = PurePosixPath(raw_name)

                if (
                    not raw_name
                    or relative.is_absolute()
                    or ".." in relative.parts
                    or ":" in raw_name
                    or "\x00" in raw_name
                ):
                    raise ValueError("ZIP يحتوي على مسار غير آمن.")

                mode = (member.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise ValueError("ZIP يحتوي على رابط رمزي.")

                if member.is_dir():
                    continue

                if raw_name in seen_paths:
                    raise ValueError("ZIP يحتوي على أسماء ملفات مكررة.")
                seen_paths.add(raw_name)

                if relative.name.lower() == ".env":
                    raise ValueError("لا يسمح برفع ملفات .env.")

                suffix = Path(relative.name).suffix.lower()
                if suffix not in ALLOWED_EXTENSIONS:
                    raise ValueError(
                        "ZIP يحتوي على نوع ملف غير مسموح: " + suffix
                    )

                if member.file_size < 0:
                    raise ValueError("حجم ملف غير صالح.")

                declared_total += member.file_size
                if declared_total > MAX_EXTRACTED_SIZE:
                    raise ValueError("حجم الملفات بعد الاستخراج كبير جداً.")

                safe_files.append((member, relative))

            if not safe_files:
                raise ValueError("لم يتم العثور على ملفات صالحة.")

            if main_script not in seen_paths:
                raise ValueError(
                    "مسار ملف التشغيل غير موجود داخل ZIP."
                )

            target_dir.mkdir(parents=True, exist_ok=False)
            created_dir = True
            actual_total = 0

            for member, relative in safe_files:
                destination = (target_dir / Path(*relative.parts)).resolve()

                try:
                    destination.relative_to(target_dir.resolve())
                except ValueError:
                    raise ValueError("مسار ملف غير آمن.")

                destination.parent.mkdir(parents=True, exist_ok=True)

                # نسخ محدود الحجم لتقليل خطر ZIP bomb أو metadata مزورة
                file_written = 0
                with archive.open(member, "r") as source:
                    with destination.open("xb") as output:
                        while True:
                            chunk = source.read(64 * 1024)
                            if not chunk:
                                break

                            file_written += len(chunk)
                            actual_total += len(chunk)

                            if (
                                file_written > member.file_size
                                or actual_total > MAX_EXTRACTED_SIZE
                            ):
                                raise ValueError(
                                    "حجم الملفات الفعلي تجاوز الحد المسموح."
                                )

                            output.write(chunk)

                if file_written != member.file_size:
                    raise ValueError("حجم أحد الملفات لا يطابق بيانات ZIP.")

        if any(x.get("key") == key for x in items):
            raise ValueError("حدث تعارض في معرف البوت.")

        items.append({
            "key": key,
            "name": name,
            "type": bot_type,
            "icon": icon or "🤖",
            "script": f"{key}/{main_script}",
            "description": description,
            "features": [],
            "env": {}
        })

        save_bots(items)

    except (zipfile.BadZipFile, ValueError, OSError, RuntimeError) as error:
        if created_dir and target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)

        app.logger.warning("ZIP upload rejected: %s", error)
        flash("تعذر رفع ZIP: " + str(error))
        return redirect(url_for("bot_library"))

    flash("تم رفع البوت وإضافته للمكتبة. لم يتم تشغيله.")
    return redirect(url_for("bot_library"))


# ---------------- DASHBOARD ----------------

@app.get("/dashboard")
@login_required
def dashboard():
    user = current_user()
    items = load_bots() if user["is_owner"] else []
    view = []

    for item in items:
        proc = processes.get(item.get("key"))
        view.append({
            **item,
            "running": bool(proc and proc.poll() is None)
        })

    return render_template(
        "dashboard.html",
        user=user,
        bots=view
    )


# ---------------- START / STOP BOT ----------------

@app.post("/bots/<key>/toggle")
@owner_required
def toggle_bot(key):
    items = load_bots()
    item = next((x for x in items if x.get("key") == key), None)

    if not item:
        abort(404)

    script_value = item.get("script", "")
    if not isinstance(script_value, str) or not script_value:
        abort(400, "Invalid bot script configuration")

    script = (BOT_DIR / script_value).resolve()

    try:
        script.relative_to(BOT_DIR.resolve())
    except ValueError:
        abort(400, "Invalid bot script configuration")

    if not script.is_file() or script.suffix.lower() != ".py":
        abort(400, "Invalid bot script configuration")

    proc = processes.get(key)

    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)

        processes.pop(key, None)
        action = "stopped"
    else:
        env = os.environ.copy()
        bot_env = item.get("env", {})
        if isinstance(bot_env, dict):
            env.update({
                str(k): str(v) for k, v in bot_env.items()
                if isinstance(k, str)
            })

        processes[key] = subprocess.Popen(
            [sys.executable, str(script)],
            cwd=str(script.parent),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        action = "started"

    return jsonify({"ok": True, "action": action})


# ---------------- BOT LIBRARY ----------------

@app.get("/library")
@login_required
def bot_library():
    items = load_bots()
    view = []

    for item in items:
        proc = processes.get(item.get("key"))
        view.append({
            **item,
            "running": bool(proc and proc.poll() is None)
        })

    return render_template(
        "library.html",
        user=current_user(),
        bots=view
    )


@app.get("/library/<key>")
@login_required
def bot_details(key):
    items = load_bots()
    item = next((x for x in items if x.get("key") == key), None)

    if not item:
        abort(404)

    proc = processes.get(key)
    bot = {
        **item,
        "running": bool(proc and proc.poll() is None)
    }

    return render_template(
        "bot_details.html",
        user=current_user(),
        bot=bot
    )


# ---------------- ERRORS ----------------

@app.errorhandler(403)
def forbidden(_):
    return render_template(
        "error.html",
        message="ليس لديك صلاحية الوصول إلى هذه الصفحة."
    ), 403


@app.errorhandler(413)
def too_large(_):
    return "حجم الطلب أكبر من الحد المسموح.", 413


# ---------------- RUN ----------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", "5000")),
        debug=False
    )

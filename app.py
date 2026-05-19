from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import json
import requests
import jwt
import urllib3
from urllib.parse import parse_qs, urlparse, unquote
import my_pb2
import output_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
MAJOR_LOGIN_URL = "https://loginbp.ggpolarbear.com/MajorLogin"
PLATFORM_MAP = {3: "Facebook", 4: "Guest", 5: "VK", 6: "Huawei", 8: "Google", 11: "X (Twitter)", 13: "AppleId"}
DEFAULT_PLATFORMS = [8, 3, 4, 6, 5, 11, 13]

WEB_HTML = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>JWT API</title>
<style>body{margin:0;background:#0b0f17;color:#e8eef8;font-family:Arial,sans-serif}.wrap{max-width:860px;margin:0 auto;padding:28px 16px}code,pre{background:#111827;border:1px solid #253247;border-radius:8px;padding:10px;display:block;overflow:auto}a{color:#4ea1ff}</style></head>
<body><main class="wrap"><h1>JWT API</h1><pre>/token?access_token=ACCESS_TOKEN
/token?access_token=ACCESS_TOKEN&open_id=OPEN_ID
/eat?eat_token=EAT_TOKEN_OR_URL
/guest?uid=UID&password=PASSWORD
/bulk_guest POST {"accounts":"uid:password\nuid:password"}</pre></main></body></html>
"""


def encrypt_message(plaintext):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(plaintext, AES.block_size))


def decode_jwt_payload(token_value):
    try:
        return jwt.decode(token_value, options={"verify_signature": False})
    except Exception:
        payload_b64 = token_value.split(".")[1]
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")))


def decode_ff_name(b64_str):
    try:
        if not b64_str:
            return ""
        key = b"1e5898ccb8dfdd921f9bdea848768b64a201"
        b64_str = b64_str.strip() + "=" * ((4 - len(b64_str) % 4) % 4)
        encrypted_bytes = base64.b64decode(b64_str)
        return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(encrypted_bytes)).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def pb_varint(value):
    output = bytearray()
    value = int(value)
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            output.append(byte | 0x80)
        else:
            output.append(byte)
            break
    return bytes(output)


def pb_key(field_number, wire_type):
    return pb_varint((field_number << 3) | wire_type)


def pb_int(field_number, value):
    return pb_key(field_number, 0) + pb_varint(value)


def read_varint(data, index):
    shift = 0
    value = 0
    while index < len(data):
        byte = data[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index
        shift += 7
    return None, index


def parse_pb_fields(data):
    fields = {}
    index = 0
    while index < len(data):
        key, index = read_varint(data, index)
        if key is None:
            break
        field_number = key >> 3
        wire_type = key & 7
        if wire_type == 0:
            value, index = read_varint(data, index)
        elif wire_type == 1:
            value = data[index:index + 8]
            index += 8
        elif wire_type == 2:
            length, index = read_varint(data, index)
            if length is None:
                break
            value = data[index:index + length]
            index += length
        elif wire_type == 5:
            value = data[index:index + 4]
            index += 4
        else:
            break
        fields.setdefault(field_number, []).append(value)
    return fields


def extract_eat_token(user_input):
    if not user_input:
        return None
    user_input = str(user_input).strip()
    if "http" in user_input or "?" in user_input:
        query_params = parse_qs(urlparse(user_input).query)
        return query_params.get("eat", [None])[0] or query_params.get("eat_token", [None])[0]
    return user_input


def get_access_token_from_eat(eat_token):
    api_url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
    headers = {"User-Agent": "Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 Chrome/114.0.0.0 Mobile"}
    try:
        response = requests.get(api_url, headers=headers, allow_redirects=True, timeout=10)
        final_params = parse_qs(urlparse(response.url).query)
        return final_params.get("access_token", [None])[0]
    except Exception:
        return None


def fetch_open_id(access_token):
    try:
        uid_headers = {
            "authority": "prod-api.reward.ff.garena.com",
            "accept": "application/json, text/plain, */*",
            "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "access-token": access_token,
            "origin": "https://reward.ff.garena.com",
            "referer": "https://reward.ff.garena.com/",
            "sec-ch-ua": '"Not-A.Brand";v="99", "Chromium";v="124"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        }
        uid_res = requests.get("https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/", headers=uid_headers, verify=False, timeout=10)
        try:
            uid_data = uid_res.json()
        except Exception:
            return None, f"Failed to extract UID: inspect_http_{uid_res.status_code}"
        uid = uid_data.get("uid")
        if not uid:
            detail = uid_data.get("message") or uid_data.get("error") or "empty_uid"
            return None, f"Failed to extract UID: inspect_http_{uid_res.status_code}:{detail}"

        payload = {"app_id": 100067, "login_id": str(uid)}
        shop_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ar-MA,ar;q=0.9,en-US;q=0.8,en;q=0.7,ar-AE;q=0.6,fr-FR;q=0.5,fr;q=0.4",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Cookie": "source=mb; region=MA; language=ar",
            "Origin": "https://shop2game.com",
            "Referer": "https://shop2game.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
        }
        topup_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Origin": "https://topup.pk",
            "Referer": "https://topup.pk/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
        }
        attempts = [
            ("shop2game", "https://shop2game.com/api/auth/player_id_login", shop_headers),
            ("topup", "https://topup.pk/api/auth/player_id_login", topup_headers),
        ]
        errors = []
        for label, url, headers in attempts:
            openid_res = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
            try:
                openid_data = openid_res.json()
            except Exception:
                openid_data = {}
            open_id = openid_data.get("open_id") or openid_data.get("openId")
            if open_id:
                return open_id, None
            detail = openid_data.get("error") or openid_data.get("message") or openid_res.text[:80]
            errors.append(f"{label}_http_{openid_res.status_code}:{detail}")
        return None, "Failed to extract open_id: " + " | ".join(errors)
    except Exception as exc:
        return None, f"Exception occurred: {str(exc)}"


def get_profile_url(region):
    if str(region).upper() in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    return "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"


def fetch_profile_stats(account_id, region, token_value):
    try:
        payload = encrypt_message(pb_int(1, int(account_id)) + pb_int(2, 1))
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Authorization": f"Bearer {token_value}",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
        }
        response = requests.post(get_profile_url(region), data=payload, headers=headers, verify=False, timeout=8)
        if response.status_code != 200:
            return {}
        account_info = parse_pb_fields(response.content).get(1, [None])[0]
        if not isinstance(account_info, (bytes, bytearray)):
            return {}
        info = parse_pb_fields(account_info)
        return {"level": info.get(6, [None])[0], "likes": info.get(21, [None])[0]}
    except Exception:
        return {}


def make_success_response(access_token, open_id, token_value):
    decoded = decode_jwt_payload(token_value)
    external_type = decoded.get("external_type")
    raw_nickname = decoded.get("nickname", "")
    account_name = decode_ff_name(raw_nickname) or unquote(raw_nickname)
    account_id = decoded.get("account_id")
    region = decoded.get("lock_region")
    result = {
        "access_token": access_token,
        "account_id": account_id,
        "account_name": account_name,
        "open_id": open_id,
        "platform": PLATFORM_MAP.get(external_type, f"Unknown ({external_type})"),
        "platform_type": external_type,
        "region": region,
        "status": "success",
        "token": token_value,
    }
    if account_id:
        result.update(fetch_profile_stats(account_id, region, token_value))
    return result


def major_login(access_token, open_id, platform_type):
    try:
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
        }
        game_data = my_pb2.GameData()
        game_data.timestamp = "2024-12-05 18:15:32"
        game_data.game_name = "free fire"
        game_data.game_version = 1
        game_data.version_code = "1.108.3"
        game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        game_data.device_type = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type = "WIFI"
        game_data.screen_width = 1280
        game_data.screen_height = 960
        game_data.dpi = "240"
        game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        game_data.total_ram = 5951
        game_data.gpu_name = "Adreno (TM) 640"
        game_data.gpu_version = "OpenGL ES 3.0"
        game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        game_data.ip_address = "172.190.111.97"
        game_data.language = "en"
        game_data.open_id = open_id
        game_data.access_token = access_token
        game_data.platform_type = int(platform_type)
        game_data.field_99 = str(platform_type)
        game_data.field_100 = str(platform_type)
        response = requests.post(MAJOR_LOGIN_URL, data=encrypt_message(game_data.SerializeToString()), headers=headers, verify=False, timeout=8)
        if response.status_code != 200:
            return None
        msg = output_pb2.Garena_420()
        msg.ParseFromString(response.content)
        return getattr(msg, "token", None)
    except Exception:
        return None


def generate_jwt_from_access(access_token, open_id=None):
    if not open_id:
        open_id, error = fetch_open_id(access_token)
        if error:
            return {"status": "error", "message": error}, 400
    for platform_type in DEFAULT_PLATFORMS:
        token = major_login(access_token, open_id, platform_type)
        if token:
            return make_success_response(access_token, open_id, token), 200
    return {"status": "error", "message": "No valid platform found"}, 400


def generate_guest_account(uid, password):
    try:
        payload = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067",
        }
        headers = {"User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)", "Connection": "Keep-Alive", "Accept-Encoding": "gzip"}
        oauth = requests.post("https://100067.connect.garena.com/oauth/guest/token/grant", data=payload, headers=headers, timeout=8)
        if oauth.status_code != 200:
            return {"uid": uid, "status": "error", "message": f"oauth_http_{oauth.status_code}"}
        data = oauth.json()
        access_token = data.get("access_token")
        open_id = data.get("open_id")
        if not access_token or not open_id:
            return {"uid": uid, "status": "error", "message": "missing_access_token_or_open_id"}
        token = major_login(access_token, open_id, 4)
        if not token:
            return {"uid": uid, "status": "error", "message": "no_jwt_token"}
        result = make_success_response(access_token, open_id, token)
        result["uid"] = str(uid)
        return result
    except Exception as exc:
        return {"uid": uid, "status": "error", "message": str(exc)}


def parse_accounts(raw):
    accounts = []
    for line in str(raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            accounts.append({"raw": line, "status": "error", "message": "invalid_format"})
            continue
        uid, password = line.split(":", 1)
        uid = uid.strip()
        password = password.strip()
        if not uid or not password:
            accounts.append({"raw": line, "status": "error", "message": "invalid_format"})
            continue
        accounts.append({"uid": uid, "password": password})
    return accounts


def get_request_param(param_name):
    data = request.get_json(silent=True) if request.is_json else None
    if isinstance(data, dict) and param_name in data:
        return data.get(param_name)
    if request.form and param_name in request.form:
        return request.form.get(param_name)
    return request.args.get(param_name)


def docs_response():
    return jsonify({
        "status": "success",
        "web": "/web",
        "endpoints": {
            "/token": "GET or POST /token?access_token=ACCESS_TOKEN[&open_id=OPEN_ID]",
            "/eat": "GET or POST /eat?eat_token=EAT_TOKEN_OR_URL",
            "/guest": "GET or POST /guest?uid=UID&password=PASSWORD",
            "/bulk_guest": "POST /bulk_guest with JSON {accounts: 'uid:password\\nuid:password'}",
        },
        "platforms": PLATFORM_MAP,
    })


@app.route("/", methods=["GET"])
def index():
    return docs_response()


@app.route("/api", methods=["GET"])
def api_docs():
    return docs_response()


@app.route("/web", methods=["GET"])
def web():
    return render_template_string(WEB_HTML)


@app.route("/token", methods=["GET", "POST"])
def token_endpoint():
    access_token = get_request_param("access_token")
    open_id = get_request_param("open_id")
    if not access_token or not str(access_token).strip():
        return jsonify({"status": "error", "message": "access_token required"}), 400
    result, status_code = generate_jwt_from_access(str(access_token).strip(), str(open_id).strip() if open_id else None)
    return jsonify(result), status_code


@app.route("/eat", methods=["GET", "POST"])
def eat_endpoint():
    eat_input = get_request_param("eat_token") or get_request_param("eat") or get_request_param("url")
    if not eat_input or not str(eat_input).strip():
        return jsonify({"status": "error", "message": "eat_token required"}), 400
    eat_token = extract_eat_token(eat_input)
    if not eat_token:
        return jsonify({"status": "error", "message": "invalid eat_token"}), 400
    access_token = get_access_token_from_eat(eat_token)
    if not access_token:
        return jsonify({"status": "error", "message": "failed to resolve access_token"}), 400
    result, status_code = generate_jwt_from_access(access_token)
    if isinstance(result, dict):
        result["eat_token"] = eat_token
    return jsonify(result), status_code


@app.route("/guest", methods=["GET", "POST"])
def guest_endpoint():
    uid = get_request_param("uid")
    password = get_request_param("password")
    if not uid or not password:
        return jsonify({"status": "error", "message": "uid and password required"}), 400
    result = generate_guest_account(uid, password)
    return jsonify(result), 200 if result.get("status") == "success" else 400


@app.route("/bulk_guest", methods=["POST"])
def bulk_guest_endpoint():
    raw = get_request_param("accounts")
    parsed = parse_accounts(raw)
    if not parsed:
        return jsonify({"status": "error", "message": "accounts list is empty", "results": []}), 400
    invalid = [item for item in parsed if item.get("status") == "error"]
    valid = [item for item in parsed if item.get("uid") and item.get("password")]
    results = list(invalid)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(generate_guest_account, item["uid"], item["password"]) for item in valid]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: int(item.get("uid", "0")) if str(item.get("uid", "0")).isdigit() else 0)
    success = sum(1 for item in results if item.get("status") == "success")
    return jsonify({"total": len(results), "success": success, "failed": len(results) - success, "results": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1080, debug=False)

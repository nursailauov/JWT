from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import jwt
import urllib3
import base64
import json
from urllib.parse import urlparse, parse_qs
import my_pb2
import output_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
MAJOR_LOGIN_URL = "https://loginbp.ggpolarbear.com/MajorLogin"

PLATFORM_MAP = {
    3: "Facebook",
    4: "Guest",
    5: "VK",
    6: "Huawei",
    8: "Google",
    11: "X (Twitter)",
    13: "AppleId",
}
DEFAULT_PLATFORMS = [3, 4, 5, 6, 8, 11, 13]


def decode_ff_name(b64_str):
    try:
        if not b64_str:
            return ""
        key = b"1e5898ccb8dfdd921f9bdea848768b64a201"
        b64_str = b64_str.strip()
        b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
        encrypted_bytes = base64.b64decode(b64_str)
        decrypted_bytes = bytearray()
        for i, byte in enumerate(encrypted_bytes):
            decrypted_bytes.append(byte ^ key[i % len(key)])
        return decrypted_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def decode_jwt_payload(token_value):
    try:
        return jwt.decode(token_value, options={"verify_signature": False})
    except Exception:
        payload_b64 = token_value.split(".")[1]
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")))


def extract_eat_token(user_input):
    if "http" in user_input or "?" in user_input:
        parsed_url = urlparse(user_input)
        query_params = parse_qs(parsed_url.query)
        return query_params.get("eat", [None])[0]
    return user_input.strip()


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
        uid_url = "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/"
        uid_headers = {
            "accept": "application/json, text/plain, */*",
            "access-token": access_token,
            "origin": "https://reward.ff.garena.com",
            "referer": "https://reward.ff.garena.com/",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        }
        uid_res = requests.get(uid_url, headers=uid_headers, verify=False, timeout=10)
        uid_data = uid_res.json()
        uid = uid_data.get("uid")
        if not uid:
            return None, "Failed to extract UID from token"

        openid_url = "https://topup.pk/api/auth/player_id_login"
        openid_headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://topup.pk",
            "Referer": "https://topup.pk/",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; RMX5070 Build/UKQ1.231108.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.157 Mobile Safari/537.36",
        }
        payload = {"app_id": 100067, "login_id": str(uid)}
        openid_res = requests.post(openid_url, headers=openid_headers, json=payload, verify=False, timeout=10)
        openid_data = openid_res.json()
        open_id = openid_data.get("open_id")
        if not open_id:
            return None, "Failed to extract open_id"
        return open_id, None
    except Exception as exc:
        return None, str(exc)


def build_game_data(access_token, open_id, platform_type):
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
    return game_data.SerializeToString()


def internal_generate_jwt(access_token):
    open_id, error = fetch_open_id(access_token)
    if error:
        return {"status": "error", "message": error}, 400

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

    for platform_type in DEFAULT_PLATFORMS:
        try:
            encrypted_data = encrypt_message(build_game_data(access_token, open_id, platform_type))
            response = requests.post(MAJOR_LOGIN_URL, data=encrypted_data, headers=headers, verify=False, timeout=8)
            if response.status_code != 200:
                continue

            example_msg = output_pb2.Garena_420()
            example_msg.ParseFromString(response.content)
            token_value = getattr(example_msg, "token", None)
            if not token_value:
                continue

            decoded_token = decode_jwt_payload(token_value)
            external_type = decoded_token.get("external_type")
            raw_nickname = decoded_token.get("nickname", "")
            account_name = decode_ff_name(raw_nickname)
            if not account_name:
                import urllib.parse
                account_name = urllib.parse.unquote(raw_nickname)

            return {
                "access_token": access_token,
                "account_id": decoded_token.get("account_id"),
                "account_name": account_name,
                "open_id": open_id,
                "platform": PLATFORM_MAP.get(external_type, f"Unknown ({external_type})"),
                "platform_type": external_type,
                "region": decoded_token.get("lock_region"),
                "status": "success",
                "token": token_value,
            }, 200
        except Exception:
            continue

    return {"status": "error", "message": "No valid platform found."}, 400


def get_request_param(param_name):
    if request.is_json and request.json and param_name in request.json:
        return request.json.get(param_name)
    if request.form and param_name in request.form:
        return request.form.get(param_name)
    return request.args.get(param_name)


@app.route("/", methods=["GET"])
@app.route("/api", methods=["GET"])
def api_docs():
    return jsonify({
        "status": "success",
        "endpoints": {
            "/token": "/token?access_token=YOUR_ACCESS_TOKEN",
            "/guest": "/guest?uid=UID&password=PASSWORD",
            "/eat": "/eat?eat_token=EAT_TOKEN_OR_URL",
        },
        "platforms": PLATFORM_MAP,
    }), 200


@app.route("/token", methods=["GET", "POST"])
def token_endpoint():
    access_token = get_request_param("access_token")
    if not access_token or access_token.strip() == "":
        return jsonify({"status": "error", "message": "access_token required"}), 400
    result, status_code = internal_generate_jwt(access_token.strip())
    return jsonify(result), status_code


@app.route("/guest", methods=["GET", "POST"])
def guest_endpoint():
    uid = get_request_param("uid")
    password = get_request_param("password")
    if not uid or not password:
        return jsonify({"status": "error", "message": "uid and password required"}), 400

    oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }

    try:
        oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=10)
    except requests.RequestException as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500

    if oauth_response.status_code != 200:
        try:
            data = oauth_response.json()
        except ValueError:
            data = {"message": oauth_response.text}
        data["status"] = "error"
        return jsonify(data), oauth_response.status_code

    try:
        oauth_data = oauth_response.json()
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid JSON response"}), 500

    if "access_token" not in oauth_data or "open_id" not in oauth_data:
        return jsonify({"status": "error", "message": "OAuth response missing access_token or open_id"}), 500

    access_token = oauth_data["access_token"]
    open_id = oauth_data["open_id"]
    headers_major = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
    }
    try:
        encrypted_data = encrypt_message(build_game_data(access_token, open_id, 4))
        response = requests.post(MAJOR_LOGIN_URL, data=encrypted_data, headers=headers_major, verify=False, timeout=8)
        example_msg = output_pb2.Garena_420()
        example_msg.ParseFromString(response.content)
        token_value = getattr(example_msg, "token", None)
        if not token_value:
            return jsonify({"status": "error", "message": "No token returned"}), 400
        decoded_token = decode_jwt_payload(token_value)
        return jsonify({
            "access_token": access_token,
            "account_id": decoded_token.get("account_id"),
            "open_id": open_id,
            "platform": PLATFORM_MAP.get(decoded_token.get("external_type")),
            "platform_type": decoded_token.get("external_type"),
            "region": decoded_token.get("lock_region"),
            "status": "success",
            "token": token_value,
        }), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/eat", methods=["GET", "POST"])
def eat_endpoint():
    eat_input = get_request_param("eat_token")
    if not eat_input or eat_input.strip() == "":
        return jsonify({"status": "error", "message": "eat_token required"}), 400
    eat_token = extract_eat_token(eat_input)
    if not eat_token:
        return jsonify({"status": "error", "message": "invalid eat_token"}), 400
    access_token = get_access_token_from_eat(eat_token)
    if not access_token:
        return jsonify({"status": "error", "message": "failed to resolve access_token"}), 400
    result, status_code = internal_generate_jwt(access_token)
    return jsonify(result), status_code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1080, debug=False)

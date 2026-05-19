from flask import Flask, request, jsonify, render_template_string, redirect
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
HTTP_LOCAL = threading.local()
HTTP_TIMEOUT = 8


def http():
    if not hasattr(HTTP_LOCAL, "session"):
        HTTP_LOCAL.session = requests.Session()
    return HTTP_LOCAL.session


WEBS_HTML = r'''
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>JWT Toolkit</title>
<style>:root{color-scheme:dark;--bg:#080b10;--panel:#111821;--panel2:#0d131b;--line:#263340;--text:#edf3fa;--muted:#94a3b4;--accent:#38bdf8;--ok:#34d399;--bad:#fb7185}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif}.wrap{max-width:1240px;margin:0 auto;padding:24px 14px 32px}.top{display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:16px}.brand h1{margin:0;font-size:30px;line-height:1.05}.brand span,.dev,.status{color:var(--muted);font-size:13px}.dev{white-space:nowrap}.layout{display:grid;grid-template-columns:360px 1fr;gap:14px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}.head{display:flex;align-items:center;justify-content:space-between;padding:12px 13px;border-bottom:1px solid var(--line)}.tabs{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;padding:12px}.tab{height:38px;border:1px solid var(--line);background:#141d28;color:var(--text);border-radius:7px;font-weight:700;cursor:pointer}.tab.active{background:var(--accent);border-color:var(--accent);color:#041018}.form{padding:13px;display:none}.form.active{display:block}.field{margin-bottom:12px}label{display:block;color:var(--muted);font-size:12px;margin-bottom:6px}input,textarea{width:100%;border:1px solid var(--line);background:var(--panel2);color:var(--text);border-radius:7px;outline:0;padding:10px 11px;font:13px/1.45 Consolas,monospace}textarea{min-height:154px;resize:vertical}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.checks{display:flex;align-items:center;gap:8px;margin:4px 0 12px;color:var(--muted);font-size:13px}.checks input{width:16px;height:16px}.actions{display:flex;gap:8px;flex-wrap:wrap}.btn{border:1px solid var(--line);background:#172231;color:var(--text);border-radius:7px;padding:10px 12px;font-weight:700;cursor:pointer}.btn.primary{background:var(--accent);border-color:var(--accent);color:#06111f}.btn:disabled{opacity:.55;cursor:not-allowed}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}.metric{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}.metric b{display:block;font-size:22px}.metric span{color:var(--muted);font-size:12px}.result{min-height:560px}.json{margin:0;white-space:pre-wrap;word-break:break-word;padding:13px;font:12px/1.45 Consolas,monospace;color:#dbeafe}.status{padding:10px 13px;border-top:1px solid var(--line);min-height:38px}.pill{display:inline-flex;align-items:center;min-height:26px;padding:4px 8px;border-radius:999px;background:#162334;border:1px solid var(--line);font-size:12px}.ok{color:var(--ok)}.bad{color:var(--bad)}@media(max-width:900px){.layout{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.top{align-items:start;flex-direction:column}.dev{white-space:normal}}@media(max-width:520px){.tabs{grid-template-columns:repeat(2,1fr)}.row{grid-template-columns:1fr}.grid{grid-template-columns:1fr}.brand h1{font-size:25px}}</style></head>
<body><div class="wrap"><div class="top"><div class="brand"><h1>JWT Toolkit</h1><span>Token, EAT, guest and bulk tools</span></div><div class="dev">dev nur sailauov</div></div><div class="layout"><section class="panel"><div class="head"><b>Tools</b><span class="pill" id="modeName">Token</span></div><div class="tabs"><button class="tab active" data-tab="token">Token</button><button class="tab" data-tab="eat">EAT</button><button class="tab" data-tab="guest">Guest</button><button class="tab" data-tab="bulk">Bulk</button></div>
<div class="form active" id="form-token"><div class="field"><label>Access token</label><textarea id="tokenAccess" spellcheck="false"></textarea></div><div class="field"><label>Open ID optional</label><input id="tokenOpen" spellcheck="false"></div><label class="checks"><input id="tokenDebug" type="checkbox"> debug</label><div class="actions"><button class="btn primary" id="runToken">Run token</button><button class="btn" data-clear="token">Clear</button></div></div>
<div class="form" id="form-eat"><div class="field"><label>EAT token or URL</label><textarea id="eatInput" spellcheck="false"></textarea></div><label class="checks"><input id="eatDebug" type="checkbox"> debug</label><div class="actions"><button class="btn primary" id="runEat">Run EAT</button><button class="btn" data-clear="eat">Clear</button></div></div>
<div class="form" id="form-guest"><div class="row"><div class="field"><label>UID</label><input id="guestUid" spellcheck="false"></div><div class="field"><label>Password</label><input id="guestPassword" spellcheck="false"></div></div><div class="actions"><button class="btn primary" id="runGuest">Run guest</button><button class="btn" data-clear="guest">Clear</button></div></div>
<div class="form" id="form-bulk"><div class="field"><label>Accounts uid:password</label><textarea id="bulkAccounts" spellcheck="false" placeholder="4305390755:password&#10;4442030961:password"></textarea></div><div class="actions"><button class="btn primary" id="runBulk">Run bulk</button><button class="btn" data-clear="bulk">Clear</button></div></div>
<div class="status" id="status">Ready.</div></section><main><div class="grid"><div class="metric"><b id="mStatus">-</b><span>Status</span></div><div class="metric"><b id="mRegion">-</b><span>Region</span></div><div class="metric"><b id="mLevel">-</b><span>Level</span></div><div class="metric"><b id="mLatency">-</b><span>Latency</span></div></div><section class="panel" style="margin-bottom:14px"><div class="head"><b>Account</b><span class="pill" id="profileState">No data</span></div><div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;padding:13px"><div class="metric"><b id="pName">-</b><span>Name</span></div><div class="metric"><b id="pAccount">-</b><span>Account ID</span></div><div class="metric"><b id="pPlatform">-</b><span>Platform</span></div><div class="metric"><b id="pLikes">-</b><span>Likes</span></div><div class="metric" style="grid-column:1/-1"><b id="pOpen" style="font-size:14px;word-break:break-all">-</b><span>Open ID</span><div class="actions" style="margin-top:8px"><button class="btn" data-copy-field="open_id">Copy Open ID</button></div></div><div class="metric" style="grid-column:1/-1"><b id="pAccess" style="font-size:12px;word-break:break-all">-</b><span>Access Token</span><div class="actions" style="margin-top:8px"><button class="btn" data-copy-field="access_token">Copy Access</button></div></div><div class="metric" style="grid-column:1/-1"><b id="pToken" style="font-size:12px;word-break:break-all">-</b><span>JWT Token</span><div class="actions" style="margin-top:8px"><button class="btn" data-copy-field="token">Copy JWT</button></div></div></div></section><section class="panel result"><div class="head"><b>Response</b><div class="actions"><button class="btn" id="copyJson">Copy</button><button class="btn" id="downloadJson">Download</button></div></div><pre class="json" id="jsonOut">{}</pre></section></main></div></div>
<script>
const $=id=>document.getElementById(id);let last={};let active='token';
function setStatus(t,cls=''){const el=$('status');el.className='status '+cls;el.textContent=t}
function showJson(data,ms){last=data||{};$('jsonOut').textContent=JSON.stringify(last,null,2);$('mStatus').textContent=last.status||String(last.success??'-');$('mStatus').className=last.status==='success'||last.success?'ok':(last.status==='error'||last.error?'bad':'');$('mRegion').textContent=last.region||'-';$('mLevel').textContent=last.level??'-';$('mLatency').textContent=ms?`${ms} ms`:'-';$('profileState').textContent=last.status==='success'||last.token?'Loaded':'No data';$('pName').textContent=last.account_name||'-';$('pAccount').textContent=last.account_id??last.uid??'-';$('pPlatform').textContent=last.platform||last.platform_type||'-';$('pLikes').textContent=last.likes??'-';$('pOpen').textContent=last.open_id||'-';$('pAccess').textContent=last.access_token||'-';$('pToken').textContent=last.token||last.jwt||'-'}
async function call(path,opts={}){const t=performance.now();setBusy(true);setStatus('Running.');try{const res=await fetch(path,opts);let data;try{data=await res.json()}catch{data={status:'error',message:await res.text()}}const ms=Math.round(performance.now()-t);showJson(data,ms);setStatus(res.ok?'Done.':`HTTP ${res.status}.`,res.ok?'ok':'bad')}catch(e){showJson({status:'error',message:e.message});setStatus(e.message,'bad')}finally{setBusy(false)}}
function setBusy(v){document.querySelectorAll('button').forEach(b=>{if(!b.classList.contains('tab'))b.disabled=v})}
function q(v){return encodeURIComponent(v.trim())}
function tokenUrl(){let u='/token?access_token='+q($('tokenAccess').value);if($('tokenOpen').value.trim())u+='&open_id='+q($('tokenOpen').value);if($('tokenDebug').checked)u+='&debug=1';return u}
function eatUrl(){let u='/eat?eat_token='+q($('eatInput').value);if($('eatDebug').checked)u+='&debug=1';return u}
function guestUrl(){return '/guest?uid='+q($('guestUid').value)+'&password='+q($('guestPassword').value)}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{active=b.dataset.tab;document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll('.form').forEach(x=>x.classList.remove('active'));$('form-'+active).classList.add('active');$('modeName').textContent=b.textContent;setStatus('Ready.')});
$('runToken').onclick=()=>call(tokenUrl());$('runEat').onclick=()=>call(eatUrl());$('runGuest').onclick=()=>call(guestUrl());$('runBulk').onclick=()=>call('/bulk_guest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({accounts:$('bulkAccounts').value})});
document.querySelectorAll('[data-clear]').forEach(b=>b.onclick=()=>{document.querySelectorAll('#form-'+b.dataset.clear+' input,#form-'+b.dataset.clear+' textarea').forEach(x=>{if(x.type==='checkbox')x.checked=false;else x.value=''});showJson({});setStatus('Cleared.')});
$('copyJson').onclick=async()=>{await navigator.clipboard.writeText(JSON.stringify(last,null,2));setStatus('Copied.')};
$('downloadJson').onclick=()=>{const blob=new Blob([JSON.stringify(last,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='jwt-result.json';a.click();URL.revokeObjectURL(a.href)};
document.querySelectorAll('[data-copy-field]').forEach(b=>b.onclick=async()=>{const key=b.dataset.copyField;await navigator.clipboard.writeText(String(last[key]||''));setStatus('Copied '+key+'.')});
</script></body></html>
'''


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
        parsed_url = urlparse(user_input)
        query_params = parse_qs(parsed_url.query)
        return query_params.get("eat", [None])[0]
    return user_input


def get_access_token_from_eat(eat_token):
    api_url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
    headers = {"User-Agent": "Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 Chrome/114.0.0.0 Mobile"}
    try:
        response = http().get(api_url, headers=headers, allow_redirects=True, timeout=HTTP_TIMEOUT)
        final_params = parse_qs(urlparse(response.url).query)
        return final_params.get("access_token", [None])[0]
    except Exception:
        return None


def response_debug(response, body_limit=300):
    text = response.text or ""
    preview = text[:body_limit]
    return {"status_code": response.status_code, "url": response.url, "content_type": response.headers.get("content-type"), "server": response.headers.get("server"), "captcha_detected": "captcha" in preview.lower() or "captcha-delivery" in preview.lower(), "body_preview": preview}


def fetch_open_id_from_oauth_inspect(access_token, diagnostics):
    response = http().get("https://100067.connect.garena.com/oauth/token/inspect", params={"token": access_token}, headers={"User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)"}, verify=False, timeout=HTTP_TIMEOUT)
    step = {"step": "oauth_token_inspect", "response": response_debug(response)}
    try:
        data = response.json()
    except Exception:
        data = {}
    step["json"] = data
    diagnostics.append(step)
    return data.get("open_id") or data.get("openId")


def fetch_open_id(access_token, debug=False):
    diagnostics = []
    try:
        open_id = fetch_open_id_from_oauth_inspect(access_token, diagnostics)
        if open_id:
            return open_id, None, diagnostics
        uid_headers = {"authority": "prod-api.reward.ff.garena.com", "accept": "application/json, text/plain, */*", "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7", "access-token": access_token, "origin": "https://reward.ff.garena.com", "referer": "https://reward.ff.garena.com/", "sec-ch-ua": '"Not-A.Brand";v="99", "Chromium";v="124"', "sec-ch-ua-mobile": "?1", "sec-ch-ua-platform": '"Android"', "sec-fetch-dest": "empty", "sec-fetch-mode": "cors", "sec-fetch-site": "same-site", "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
        uid_res = http().get("https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/", headers=uid_headers, verify=False, timeout=HTTP_TIMEOUT)
        uid_step = {"step": "reward_inspect_token", "response": response_debug(uid_res)}
        try:
            uid_data = uid_res.json()
        except Exception:
            uid_data = {}
        uid_step["json"] = uid_data
        diagnostics.append(uid_step)
        uid = uid_data.get("uid")
        if not uid:
            return None, f"Failed to extract UID: inspect_http_{uid_res.status_code}", diagnostics
        payload = {"app_id": 100067, "login_id": str(uid)}
        shop_headers = {"Accept": "application/json, text/plain, */*", "Content-Type": "application/json", "Cookie": "source=mb; region=MA; language=ar", "Origin": "https://shop2game.com", "Referer": "https://shop2game.com/", "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"}
        topup_headers = {"Accept": "application/json, text/plain, */*", "Content-Type": "application/json", "Origin": "https://topup.pk", "Referer": "https://topup.pk/", "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"}
        errors = []
        for label, url, headers in [("shop2game", "https://shop2game.com/api/auth/player_id_login", shop_headers), ("topup", "https://topup.pk/api/auth/player_id_login", topup_headers)]:
            openid_res = http().post(url, headers=headers, json=payload, verify=False, timeout=HTTP_TIMEOUT)
            step = {"step": f"{label}_player_id_login", "response": response_debug(openid_res)}
            try:
                openid_data = openid_res.json()
            except Exception:
                openid_data = {}
            step["json"] = openid_data
            diagnostics.append(step)
            open_id = openid_data.get("open_id") or openid_data.get("openId")
            if open_id:
                return open_id, None, diagnostics
            detail = openid_data.get("error") or openid_data.get("message") or openid_res.text[:80]
            errors.append(f"{label}_http_{openid_res.status_code}:{detail}")
        return None, "Failed to extract open_id: " + " | ".join(errors), diagnostics
    except Exception as exc:
        return None, f"Exception occurred: {str(exc)}", diagnostics


def platform_order_from_diagnostics(diagnostics):
    preferred = []
    for item in diagnostics:
        data = item.get("json") if isinstance(item, dict) else None
        if not isinstance(data, dict):
            continue
        for key in ("platform", "login_platform", "main_active_platform"):
            value = data.get(key)
            if isinstance(value, int) and value not in preferred:
                preferred.append(value)
    return list(dict.fromkeys(preferred + DEFAULT_PLATFORMS))


def get_profile_url(region):
    if str(region).upper() in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    return "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"


def fetch_profile_stats(account_id, region, token_value):
    try:
        payload = encrypt_message(pb_int(1, int(account_id)) + pb_int(2, 1))
        headers = {"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)", "Authorization": f"Bearer {token_value}", "Content-Type": "application/x-www-form-urlencoded", "X-GA": "v1 1", "ReleaseVersion": "OB53"}
        response = http().post(get_profile_url(region), data=payload, headers=headers, verify=False, timeout=HTTP_TIMEOUT)
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
    result = {"access_token": access_token, "account_id": account_id, "account_name": account_name, "open_id": open_id, "platform": PLATFORM_MAP.get(external_type, f"Unknown ({external_type})"), "platform_type": external_type, "region": region, "status": "success", "token": token_value}
    if account_id:
        result.update(fetch_profile_stats(account_id, region, token_value))
    return result


def major_login(access_token, open_id, platform_type):
    headers = {"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)", "Connection": "Keep-Alive", "Accept-Encoding": "gzip", "Content-Type": "application/octet-stream", "Expect": "100-continue", "X-Unity-Version": "2018.4.11f1", "X-GA": "v1 1", "ReleaseVersion": "OB53"}
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
    response = http().post(MAJOR_LOGIN_URL, data=encrypt_message(game_data.SerializeToString()), headers=headers, verify=False, timeout=HTTP_TIMEOUT)
    if response.status_code != 200:
        return None
    msg = output_pb2.Garena_420()
    msg.ParseFromString(response.content)
    return getattr(msg, "token", None)


def generate_jwt_from_access(access_token, open_id=None, debug=False):
    diagnostics = []
    if not open_id:
        open_id, error, diagnostics = fetch_open_id(access_token, debug=debug)
        if error:
            result = {"status": "error", "message": error}
            if debug:
                result["diagnostics"] = diagnostics
            return result, 400
    for platform_type in platform_order_from_diagnostics(diagnostics):
        token = major_login(access_token, open_id, platform_type)
        if token:
            result = make_success_response(access_token, open_id, token)
            if debug:
                result["diagnostics"] = diagnostics
                result["platform_type_used"] = platform_type
            return result, 200
    result = {"status": "error", "message": "No valid platform found"}
    if debug:
        result["diagnostics"] = diagnostics
    return result, 400


def generate_guest_account(uid, password):
    try:
        payload = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3", "client_id": "100067"}
        headers = {"User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)", "Connection": "Keep-Alive", "Accept-Encoding": "gzip"}
        oauth = http().post("https://100067.connect.garena.com/oauth/guest/token/grant", data=payload, headers=headers, timeout=HTTP_TIMEOUT)
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
    return jsonify({"status": "success", "web": "/web", "webs": "/webs", "endpoints": {"/token": "GET or POST /token?access_token=ACCESS_TOKEN[&open_id=OPEN_ID][&debug=1]", "/eat": "GET or POST /eat?eat_token=EAT_TOKEN_OR_URL[&debug=1]", "/guest": "GET or POST /guest?uid=UID&password=PASSWORD", "/bulk_guest": "POST /bulk_guest with JSON {accounts: 'uid:password\\nuid:password'}"}, "platforms": PLATFORM_MAP})


@app.route("/", methods=["GET"])
def index():
    return docs_response()


@app.route("/api", methods=["GET"])
def api_docs():
    return docs_response()


@app.route("/web", methods=["GET"])
def web():
    return redirect("/webs")


@app.route("/webs", methods=["GET"])
def webs():
    return render_template_string(WEBS_HTML)


@app.route("/token", methods=["GET", "POST"])
def token_endpoint():
    access_token = get_request_param("access_token")
    open_id = get_request_param("open_id")
    debug = str(get_request_param("debug") or "").lower() in {"1", "true", "yes"}
    if not access_token or not str(access_token).strip():
        return jsonify({"status": "error", "message": "access_token required"}), 400
    result, status_code = generate_jwt_from_access(str(access_token).strip(), str(open_id).strip() if open_id else None, debug=debug)
    return jsonify(result), status_code


@app.route("/eat", methods=["GET", "POST"])
def eat_endpoint():
    eat_input = get_request_param("eat_token") or get_request_param("eat") or get_request_param("url")
    debug = str(get_request_param("debug") or "").lower() in {"1", "true", "yes"}
    if not eat_input or not str(eat_input).strip():
        return jsonify({"status": "error", "message": "eat_token required"}), 400
    eat_token = extract_eat_token(eat_input)
    if not eat_token:
        return jsonify({"status": "error", "message": "invalid eat_token"}), 400
    access_token = get_access_token_from_eat(eat_token)
    if not access_token:
        return jsonify({"status": "error", "message": "failed to resolve access_token"}), 400
    result, status_code = generate_jwt_from_access(access_token, debug=debug)
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

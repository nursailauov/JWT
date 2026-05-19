from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from concurrent.futures import ThreadPoolExecutor, as_completed
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
PLATFORM_MAP = {3: "Facebook", 4: "Guest", 5: "VK", 6: "Huawei", 8: "Google", 11: "X (Twitter)", 13: "AppleId"}
DEFAULT_PLATFORMS = [3, 4, 5, 6, 8, 11, 13]

WEB_HTML = r'''
<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>JWT Account Checker</title>
<style>:root{color-scheme:dark;--bg:#0b0f17;--panel:#121925;--panel2:#0f1520;--line:#253247;--text:#e8eef8;--muted:#8fa0b8;--ok:#43d17a;--bad:#ff6473;--warn:#f5c15b;--accent:#4ea1ff}*{box-sizing:border-box}body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text)}.wrap{max-width:1180px;margin:0 auto;padding:28px 16px 40px}h1{margin:0;font-size:clamp(26px,4vw,42px);letter-spacing:0}.sub{color:var(--muted);margin:6px 0 18px}.grid{display:grid;grid-template-columns:minmax(320px,420px) 1fr;gap:14px;align-items:start}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}.panel-head{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:13px 14px;border-bottom:1px solid var(--line);background:var(--panel2)}.panel-title{font-weight:700}textarea{width:100%;min-height:430px;resize:vertical;border:0;outline:0;padding:14px;background:#0a0f18;color:var(--text);font:13px/1.45 Consolas,monospace}.actions{display:flex;gap:10px;padding:12px;border-top:1px solid var(--line)}button{border:1px solid var(--line);background:#172235;color:var(--text);border-radius:7px;padding:10px 13px;cursor:pointer;font-weight:700}button.primary{background:var(--accent);border-color:var(--accent);color:#06111f}button:disabled{opacity:.55;cursor:not-allowed}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}.stat{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:13px}.stat b{display:block;font-size:22px;margin-bottom:3px}.stat span{color:var(--muted);font-size:13px}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:10px 11px;border-bottom:1px solid var(--line);vertical-align:middle}th{color:var(--muted);background:var(--panel2);position:sticky;top:0;z-index:1}.table-wrap{max-height:560px;overflow:auto}.badge{display:inline-flex;align-items:center;min-width:58px;justify-content:center;padding:4px 7px;border-radius:999px;background:#1b2840;color:var(--muted);font-weight:700}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.small{color:var(--muted);font-size:12px}.status{padding:10px 12px;color:var(--muted);border-top:1px solid var(--line);min-height:39px}@media(max-width:860px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}</style></head>
<body><div class="wrap"><h1>JWT Account Checker</h1><div class="sub">Проверка guest аккаунтов: уровень, лайки, регион и статус. Вставь строки uid:password.</div><div class="grid"><section class="panel"><div class="panel-head"><div class="panel-title">Аккаунты</div><div class="small" id="lineCount">0 строк</div></div><textarea id="accounts" spellcheck="false" placeholder="4305390755:password&#10;4442030961:password"></textarea><div class="actions"><button class="primary" id="checkBtn">Проверить</button><button id="clearBtn">Очистить</button></div><div class="status" id="status">Ожидает проверки.</div></section><main><div class="stats"><div class="stat"><b id="total">0</b><span>Всего</span></div><div class="stat"><b id="ok">0</b><span>Рабочие</span></div><div class="stat"><b id="lvl22">0</b><span>Уровень 22+</span></div><div class="stat"><b id="bad">0</b><span>Ошибки</span></div></div><section class="panel"><div class="panel-head"><div class="panel-title">Результаты</div><button id="copyBtn">Скопировать JSON</button></div><div class="table-wrap"><table><thead><tr><th>#</th><th>UID</th><th>Уровень</th><th>Лайки</th><th>Регион</th><th>Имя</th><th>Статус</th></tr></thead><tbody id="rows"><tr><td colspan="7" class="small">Результатов пока нет.</td></tr></tbody></table></div></section></main></div></div>
<script>
const $=id=>document.getElementById(id);let results=[];let running=false;
function parseLines(){return $('accounts').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean).map(line=>{const p=line.indexOf(':');return p<0?{raw:line,status:'error',message:'invalid_format'}:{uid:line.slice(0,p).trim(),password:line.slice(p+1).trim(),status:'pending'}})}
function updateCount(){$('lineCount').textContent=`${parseLines().length} строк`}
function setStatus(t){$('status').textContent=t}
function esc(v){return String(v??'-').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function draw(){const ok=results.filter(r=>r.status==='success');$('total').textContent=results.length;$('ok').textContent=ok.length;$('lvl22').textContent=ok.filter(r=>Number(r.level||0)>=22).length;$('bad').textContent=results.filter(r=>r.status==='error').length;if(!results.length){$('rows').innerHTML='<tr><td colspan="7" class="small">Результатов пока нет.</td></tr>';return}$('rows').innerHTML=results.map((r,i)=>{const level=r.level==null?'-':r.level;const cls=Number(level)>=22?'ok':(level==='-'?'':'warn');const st=r.status==='success'?'<span class="ok">success</span>':(r.status==='pending'?'<span class="warn">pending</span>':`<span class="bad">${esc(r.message||'error')}</span>`);return `<tr><td>${i+1}</td><td>${esc(r.uid||r.raw)}</td><td><span class="badge ${cls}">${esc(level)}</span></td><td>${esc(r.likes)}</td><td>${esc(r.region)}</td><td>${esc(r.account_name)}</td><td>${st}</td></tr>`}).join('')}
async function checkOne(item,index){if(!item.uid||!item.password){results[index]={...item,status:'error',message:'invalid_format'};draw();return}try{const res=await fetch('/guest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uid:item.uid,password:item.password})});const data=await res.json();results[index]={...data,uid:item.uid,status:data.status||'error'};}catch(e){results[index]={uid:item.uid,status:'error',message:e.message}}draw();}
async function check(){if(running)return;const items=parseLines();if(!items.length){setStatus('Вставь аккаунты в формате uid:password.');return}running=true;$('checkBtn').disabled=true;results=items.map(x=>({...x,status:x.status==='error'?'error':'pending'}));draw();let done=0;setStatus(`Проверка: 0/${items.length}`);let next=0;async function worker(){while(next<items.length){const i=next++;await checkOne(items[i],i);done++;setStatus(`Проверка: ${done}/${items.length}`)}}await Promise.all(Array.from({length:Math.min(4,items.length)},worker));setStatus(`Готово: ${results.filter(r=>r.status==='success').length}/${items.length} рабочих.`);running=false;$('checkBtn').disabled=false;}
$('accounts').addEventListener('input',updateCount);$('checkBtn').addEventListener('click',check);$('clearBtn').addEventListener('click',()=>{if(running)return;$('accounts').value='';results=[];updateCount();draw();setStatus('Ожидает проверки.')});$('copyBtn').addEventListener('click',async()=>{await navigator.clipboard.writeText(JSON.stringify(results,null,2));setStatus('JSON скопирован.')});updateCount();
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


def pb_varint(value):
    output = bytearray(); value = int(value)
    while True:
        byte = value & 0x7F; value >>= 7
        if value: output.append(byte | 0x80)
        else: output.append(byte); break
    return bytes(output)


def pb_key(field_number, wire_type): return pb_varint((field_number << 3) | wire_type)
def pb_int(field_number, value): return pb_key(field_number, 0) + pb_varint(value)


def read_varint(data, index):
    shift = 0; value = 0
    while index < len(data):
        byte = data[index]; index += 1; value |= (byte & 0x7F) << shift
        if not byte & 0x80: return value, index
        shift += 7
    return None, index


def parse_pb_fields(data):
    fields = {}; index = 0
    while index < len(data):
        key, index = read_varint(data, index)
        if key is None: break
        field_number = key >> 3; wire_type = key & 7
        if wire_type == 0: value, index = read_varint(data, index)
        elif wire_type == 1: value = data[index:index + 8]; index += 8
        elif wire_type == 2:
            length, index = read_varint(data, index)
            if length is None: break
            value = data[index:index + length]; index += length
        elif wire_type == 5: value = data[index:index + 4]; index += 4
        else: break
        fields.setdefault(field_number, []).append(value)
    return fields


def decode_ff_name(b64_str):
    try:
        if not b64_str: return ""
        key = b"1e5898ccb8dfdd921f9bdea848768b64a201"
        b64_str = b64_str.strip() + "=" * ((4 - len(b64_str) % 4) % 4)
        encrypted_bytes = base64.b64decode(b64_str)
        return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(encrypted_bytes)).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def get_profile_url(region):
    return "https://client.us.freefiremobile.com/GetPlayerPersonalShow" if str(region).upper() in {"BR", "US", "SAC", "NA"} else "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"


def fetch_profile_stats(account_id, region, token_value):
    try:
        payload = encrypt_message(pb_int(1, int(account_id)) + pb_int(2, 1))
        headers = {"User-Agent":"Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)","Authorization":f"Bearer {token_value}","Content-Type":"application/x-www-form-urlencoded","X-GA":"v1 1","ReleaseVersion":"OB53"}
        response = requests.post(get_profile_url(region), data=payload, headers=headers, verify=False, timeout=8)
        if response.status_code != 200: return {}
        account_info = parse_pb_fields(response.content).get(1, [None])[0]
        if not isinstance(account_info, (bytes, bytearray)): return {}
        info = parse_pb_fields(account_info)
        return {"level": info.get(6, [None])[0], "likes": info.get(21, [None])[0]}
    except Exception:
        return {}


def make_success_response(access_token, open_id, token_value):
    decoded = decode_jwt_payload(token_value)
    external_type = decoded.get("external_type"); raw_nickname = decoded.get("nickname", "")
    account_name = decode_ff_name(raw_nickname)
    if not account_name:
        import urllib.parse; account_name = urllib.parse.unquote(raw_nickname)
    account_id = decoded.get("account_id"); region = decoded.get("lock_region")
    result = {"access_token":access_token,"account_id":account_id,"account_name":account_name,"open_id":open_id,"platform":PLATFORM_MAP.get(external_type, f"Unknown ({external_type})"),"platform_type":external_type,"region":region,"status":"success","token":token_value}
    if account_id: result.update(fetch_profile_stats(account_id, region, token_value))
    return result


def major_login(access_token, open_id, platform_type):
    headers = {"User-Agent":"Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)","Connection":"Keep-Alive","Accept-Encoding":"gzip","Content-Type":"application/octet-stream","Expect":"100-continue","X-Unity-Version":"2018.4.11f1","X-GA":"v1 1","ReleaseVersion":"OB53"}
    game_data = my_pb2.GameData(); game_data.timestamp="2024-12-05 18:15:32"; game_data.game_name="free fire"; game_data.game_version=1; game_data.version_code="1.108.3"; game_data.os_info="Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"; game_data.device_type="Handheld"; game_data.network_provider="Verizon Wireless"; game_data.connection_type="WIFI"; game_data.screen_width=1280; game_data.screen_height=960; game_data.dpi="240"; game_data.cpu_info="ARMv7 VFPv3 NEON VMH | 2400 | 4"; game_data.total_ram=5951; game_data.gpu_name="Adreno (TM) 640"; game_data.gpu_version="OpenGL ES 3.0"; game_data.user_id="Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"; game_data.ip_address="172.190.111.97"; game_data.language="en"; game_data.open_id=open_id; game_data.access_token=access_token; game_data.platform_type=int(platform_type); game_data.field_99=str(platform_type); game_data.field_100=str(platform_type)
    response = requests.post(MAJOR_LOGIN_URL, data=encrypt_message(game_data.SerializeToString()), headers=headers, verify=False, timeout=8)
    if response.status_code != 200: return None
    msg = output_pb2.Garena_420(); msg.ParseFromString(response.content)
    return getattr(msg, "token", None)


def generate_guest_account(uid, password):
    try:
        payload = {"uid":uid,"password":password,"response_type":"token","client_type":"2","client_secret":"2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id":"100067"}
        headers = {"User-Agent":"GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)","Connection":"Keep-Alive","Accept-Encoding":"gzip"}
        oauth = requests.post("https://100067.connect.garena.com/oauth/guest/token/grant", data=payload, headers=headers, timeout=8)
        if oauth.status_code != 200: return {"uid":uid,"status":"error","message":f"oauth_http_{oauth.status_code}"}
        data = oauth.json(); access_token = data.get("access_token"); open_id = data.get("open_id")
        if not access_token or not open_id: return {"uid":uid,"status":"error","message":"missing_access_token_or_open_id"}
        token = major_login(access_token, open_id, 4)
        if not token: return {"uid":uid,"status":"error","message":"no_jwt_token"}
        result = make_success_response(access_token, open_id, token); result["uid"] = str(uid); return result
    except Exception as exc:
        return {"uid":uid,"status":"error","message":str(exc)}


def parse_accounts(raw):
    accounts = []
    for line in str(raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if ":" not in line: accounts.append({"raw":line,"status":"error","message":"invalid_format"}); continue
        uid, password = line.split(":", 1); uid = uid.strip(); password = password.strip()
        if not uid or not password: accounts.append({"raw":line,"status":"error","message":"invalid_format"}); continue
        accounts.append({"uid":uid,"password":password})
    return accounts


def get_request_param(param_name):
    data = request.get_json(silent=True) if request.is_json else None
    if isinstance(data, dict) and param_name in data: return data.get(param_name)
    if request.form and param_name in request.form: return request.form.get(param_name)
    return request.args.get(param_name)


def docs_response():
    return jsonify({"status":"success","web":"/web","endpoints":{"/guest":"GET or POST /guest?uid=UID&password=PASSWORD","/bulk_guest":"POST /bulk_guest with JSON {accounts: 'uid:password\\nuid:password'}"},"platforms":PLATFORM_MAP})


@app.route("/", methods=["GET"])
def index(): return docs_response()


@app.route("/api", methods=["GET"])
def api_docs(): return docs_response()


@app.route("/web", methods=["GET"])
def web(): return render_template_string(WEB_HTML)


@app.route("/bulk_guest", methods=["POST"])
def bulk_guest_endpoint():
    raw = get_request_param("accounts")
    parsed = parse_accounts(raw)
    if not parsed: return jsonify({"status":"error","message":"accounts list is empty","results":[]}), 400
    invalid = [item for item in parsed if item.get("status") == "error"]
    valid = [item for item in parsed if item.get("uid") and item.get("password")]
    results = list(invalid)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(generate_guest_account, item["uid"], item["password"]) for item in valid]
        for future in as_completed(futures): results.append(future.result())
    results.sort(key=lambda item: int(item.get("uid", "0")) if str(item.get("uid", "0")).isdigit() else 0)
    success = sum(1 for item in results if item.get("status") == "success")
    return jsonify({"total":len(results),"success":success,"failed":len(results)-success,"results":results})


@app.route("/guest", methods=["GET", "POST"])
def guest_endpoint():
    uid = get_request_param("uid"); password = get_request_param("password")
    if not uid or not password: return jsonify({"status":"error","message":"uid and password required"}), 400
    result = generate_guest_account(uid, password); return jsonify(result), 200 if result.get("status") == "success" else 400


if __name__ == "__main__": app.run(host="0.0.0.0", port=1080, debug=False)

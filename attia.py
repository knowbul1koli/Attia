import sqlite3
import base64
import json
import urllib.parse
import requests
import uuid
import random
import os
import concurrent.futures
from collections import defaultdict
from functools import wraps
from flask import Flask, request, render_template, redirect, url_for, Response, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import urllib3

# 屏蔽自签证书警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'attia_ultimate_secure_key_v10'
DB_FILE = 'attia.db'
KEY_FILE = 'attia.key'

if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'wb') as f: f.write(Fernet.generate_key())
with open(KEY_FILE, 'rb') as f: FERNET_KEY = f.read()
cipher = Fernet(FERNET_KEY)

GUEST_DATA = {}

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, password_plain TEXT, sub_token TEXT UNIQUE, is_admin BOOLEAN NOT NULL CHECK (is_admin IN (0, 1)))''')
    c.execute('''CREATE TABLE IF NOT EXISTS nodes 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, remark TEXT, link_encrypted TEXT, is_admin_provided BOOLEAN DEFAULT 0,
                 FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def is_first_run():
    db = get_db()
    count = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    db.close()
    return count == 0

@app.before_request
def check_setup():
    if is_first_run() and request.endpoint not in ['register', 'static']: return redirect(url_for('register'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session and 'guest_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'): return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_first_run(): return redirect(url_for('register'))
    if request.method == 'POST':
        username, password = request.form.get('username', '').strip(), request.form.get('password', '').strip()
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'], session['is_admin'] = user['id'], bool(user['is_admin'])
            session['username'], session['sub_token'] = user['username'], user['sub_token']
            return redirect(url_for('dashboard'))
        return render_template('auth.html', mode='login', error="Invalid credentials")
    return render_template('auth.html', mode='login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    first_run = is_first_run()
    if request.method == 'POST':
        username, password = request.form['username'].strip(), request.form['password'].strip()
        db = get_db()
        if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            return render_template('auth.html', mode='register', error="Username exists")
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        sub_token = str(uuid.uuid4())
        is_admin = 1 if first_run else 0
        db.execute('INSERT INTO users (username, password_hash, password_plain, sub_token, is_admin) VALUES (?, ?, ?, ?, ?)', 
                   (username, hashed_pw, password, sub_token, is_admin))
        db.commit()
        db.close()
        return redirect(url_for('login'))
    return render_template('auth.html', mode='register', is_first=first_run)

@app.route('/guest_login')
def guest_login():
    session.clear()
    guest_id = str(uuid.uuid4())
    session['guest_id'], session['username'], session['sub_token'] = guest_id, "Guest", guest_id
    GUEST_DATA[guest_id] = []
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    if 'guest_id' in session: GUEST_DATA.pop(session['guest_id'], None)
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    nodes = []
    if 'guest_id' in session:
        nodes = GUEST_DATA.get(session['guest_id'], [])
    else:
        db = get_db()
        raw_nodes = db.execute('SELECT id, remark, link_encrypted FROM nodes WHERE user_id = ? AND is_admin_provided = 0 ORDER BY id DESC', (session['user_id'],)).fetchall()
        for rn in raw_nodes:
            try: nodes.append({"id": rn['id'], "remark": rn['remark'], "link": cipher.decrypt(rn['link_encrypted'].encode()).decode()})
            except: pass
        db.close()
    return render_template('index.html', user=session, nodes=nodes)

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute('SELECT id, username, password_plain, sub_token FROM users WHERE is_admin = 0 ORDER BY id DESC').fetchall()
    db.close()
    return render_template('admin.html', user=session, users=users)

@app.route('/api/admin/user/<int:uid>/nodes', methods=['GET'])
@login_required
@admin_required
def get_user_admin_nodes(uid):
    db = get_db()
    raw_nodes = db.execute('SELECT id, remark, link_encrypted FROM nodes WHERE user_id = ? AND is_admin_provided = 1 ORDER BY id DESC', (uid,)).fetchall()
    db.close()
    nodes = []
    for rn in raw_nodes:
        try: nodes.append({"id": rn['id'], "remark": rn['remark'], "link": cipher.decrypt(rn['link_encrypted'].encode()).decode()})
        except: pass
    return jsonify({"nodes": nodes})

@app.route('/api/admin/user/<int:uid>/add_nodes', methods=['POST'])
@login_required
@admin_required
def admin_add_nodes(uid):
    data = request.json
    db = get_db()
    for link in data.get('links', []):
        remark = urllib.parse.unquote(link.split('#')[-1]) if '#' in link else "Admin Node"
        enc_link = cipher.encrypt(link.encode()).decode()
        db.execute('INSERT INTO nodes (user_id, remark, link_encrypted, is_admin_provided) VALUES (?, ?, ?, 1)', (uid, remark, enc_link))
    db.commit()
    db.close()
    return jsonify({"status": "ok"})

@app.route('/api/admin/user/<int:uid>/clear_nodes', methods=['DELETE'])
@login_required
@admin_required
def admin_clear_user_nodes(uid):
    db = get_db()
    db.execute('DELETE FROM nodes WHERE user_id = ? AND is_admin_provided = 1', (uid,))
    db.commit()
    db.close()
    return jsonify({"status": "ok"})

def fetch_panel(panel_info):
    raw_url, user, pwd = panel_info['url'].strip(), panel_info['user'].strip(), panel_info['pwd'].strip()
    
    if not raw_url.startswith('http'):
        urls_to_try = [f"http://{raw_url}", f"https://{raw_url}"]
    else:
        urls_to_try = [raw_url]

    s = requests.Session()
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Accept': 'application/json'
    })
    
    last_err = "ERR_UNKNOWN"
    for url in urls_to_try:
        url = url.rstrip('/')
        host_display = urllib.parse.urlparse(url).netloc
        try:
            login_res = s.post(f"{url}/login", data={'username': user, 'password': pwd}, timeout=8, verify=False)
            try: login_data = login_res.json()
            except ValueError:
                last_err = "ERR_JSON"
                continue
                
            if not login_data.get('success'): 
                return {"error": f"[{host_display}] ERR_AUTH"}

            inbounds_res = s.get(f"{url}/panel/api/inbounds", timeout=8, verify=False)
            if inbounds_res.status_code == 404:
                inbounds_res = s.get(f"{url}/xui/api/inbounds", timeout=8, verify=False)
                
            try: inbounds = inbounds_res.json().get('obj', [])
            except ValueError: return {"error": f"[{host_display}] ERR_JSON"}

            server_ip = urllib.parse.urlparse(url).hostname
            extracted_nodes = []

            for inbound in inbounds:
                if not inbound.get('enable'): continue
                proto, remark, port = inbound.get('protocol'), inbound.get('remark', 'Node'), inbound.get('port')
                try:
                    settings = json.loads(inbound.get('settings', '{}'))
                    stream_settings = json.loads(inbound.get('streamSettings', '{}'))
                except: continue
                
                if proto in ['vless', 'vmess', 'trojan'] and settings.get('clients'):
                    client = settings['clients'][0]
                    uuid_val = client.get('id') or client.get('password')
                    net = stream_settings.get('network', 'tcp')
                    
                    if proto == 'vless':
                        extracted_nodes.append((f"[3x] {remark}", f"vless://{uuid_val}@{server_ip}:{port}?type={net}#{urllib.parse.quote(remark)}"))
                    elif proto == 'vmess':
                        v_json = {"v": "2", "ps": f"[3x] {remark}", "add": server_ip, "port": str(port), "id": uuid_val, "aid": "0", "net": net, "type": "none"}
                        extracted_nodes.append((f"[3x] {remark}", "vmess://" + base64.b64encode(json.dumps(v_json).encode('utf-8')).decode('utf-8')))
                    elif proto == 'trojan':
                        extracted_nodes.append((f"[3x] {remark}", f"trojan://{uuid_val}@{server_ip}:{port}?type={net}#{urllib.parse.quote(remark)}"))
                        
            return {"success": True, "nodes": extracted_nodes}
            
        except requests.exceptions.ConnectTimeout: last_err = "ERR_TIMEOUT"
        except requests.exceptions.ConnectionError: last_err = "ERR_CONN"
        except Exception: last_err = "ERR_UNKNOWN"
            
    clean_host = raw_url.replace('http://', '').replace('https://', '')
    return {"error": f"[{clean_host}] {last_err}"}

@app.route('/api/sync_multiple', methods=['POST'])
@login_required
def sync_multiple():
    data = request.json
    target_uid = data.get('target_uid')
    is_admin_mode = bool(target_uid) and session.get('is_admin')
    actual_uid = target_uid if is_admin_mode else session.get('user_id')
    
    total_added, errors = 0, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(fetch_panel, data.get('panels', []))
        db = get_db() if 'guest_id' not in session or is_admin_mode else None
        for res in results:
            if res.get('success'):
                for remark, link in res['nodes']:
                    if 'guest_id' in session and not is_admin_mode:
                        GUEST_DATA[session['guest_id']].append({"id": str(uuid.uuid4())[:8], "remark": remark, "link": link})
                    else:
                        enc_link = cipher.encrypt(link.encode()).decode()
                        is_provided = 1 if is_admin_mode else 0
                        db.execute('INSERT INTO nodes (user_id, remark, link_encrypted, is_admin_provided) VALUES (?, ?, ?, ?)', (actual_uid, remark, enc_link, is_provided))
                    total_added += 1
            else: errors.append(res.get('error'))
        if db: db.commit(); db.close()
    return jsonify({"status": "ok", "added": total_added, "errors": errors})

@app.route('/add_batch', methods=['POST'])
@login_required
def add_batch():
    raw_links = request.form.get('links', '').strip().split('\n')
    db = get_db() if 'guest_id' not in session else None
    for link in raw_links:
        link = link.strip()
        if not link: continue
        remark = urllib.parse.unquote(link.split('#')[-1]) if '#' in link else "Custom Node"
        if 'guest_id' in session: GUEST_DATA[session['guest_id']].append({"id": str(uuid.uuid4())[:8], "remark": remark, "link": link})
        else:
            db.execute('INSERT INTO nodes (user_id, remark, link_encrypted, is_admin_provided) VALUES (?, ?, ?, 0)', (session['user_id'], remark, cipher.encrypt(link.encode()).decode()))
    if db: db.commit(); db.close()
    return redirect(url_for('dashboard'))

@app.route('/delete/<node_id>')
@login_required
def delete_node(node_id):
    if 'guest_id' in session: GUEST_DATA[session['guest_id']] = [n for n in GUEST_DATA[session['guest_id']] if n['id'] != node_id]
    else:
        db = get_db()
        db.execute('DELETE FROM nodes WHERE id = ?', (int(node_id),))
        db.commit(); db.close()
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/clear_my_nodes')
@login_required
def clear_my_nodes():
    if 'guest_id' in session: GUEST_DATA[session['guest_id']] = []
    else:
        db = get_db()
        db.execute('DELETE FROM nodes WHERE user_id = ? AND is_admin_provided = 0', (session['user_id'],))
        db.commit(); db.close()
    return redirect(url_for('dashboard'))

# ---------------- 智能国家识别辅助函数 ----------------
def get_country_bucket(remark):
    ru = remark.upper()
    if any(k in ru for k in ['港', 'HK', 'HONG']): return 'HK'
    if any(k in ru for k in ['台', 'TW', 'TAIWAN', '台北']): return 'TW'
    if any(k in ru for k in ['日', 'JP', 'JAPAN', '东京', '大阪']): return 'JP'
    if any(k in ru for k in ['新', 'SG', 'SINGAPORE', '狮城']): return 'SG'
    if any(k in ru for k in ['美', 'US', 'AMERICA', '洛杉矶']): return 'US'
    if any(k in ru for k in ['韩', 'KR', 'KOREA', '首尔']): return 'KR'
    if any(k in ru for k in ['英', 'UK', 'BRITAIN', '伦敦']): return 'UK'
    if any(k in ru for k in ['德', 'DE', 'GERMANY', '法兰克福']): return 'DE'
    return 'OTHER'

# ---------------- 终极订阅分发逻辑 ----------------
@app.route('/sub/<token>')
def generate_sub(token):
    sub_source = request.args.get('source', 'self')
    raw_nodes_data = []

    if token in GUEST_DATA:
        raw_nodes_data = GUEST_DATA[token]
    else:
        db = get_db()
        user = db.execute('SELECT id FROM users WHERE sub_token = ?', (token,)).fetchone()
        if not user: return Response("Invalid Token", status=403)
        is_provided = 1 if sub_source == 'admin' else 0
        raw_nodes = db.execute('SELECT remark, link_encrypted FROM nodes WHERE user_id = ? AND is_admin_provided = ?', (user['id'], is_provided)).fetchall()
        db.close()
        for rn in raw_nodes:
            try:
                raw_nodes_data.append({
                    'remark': rn['remark'], 
                    'link': cipher.decrypt(rn['link_encrypted'].encode()).decode()
                })
            except: pass

    links = []
    
    if sub_source == 'admin':
        # --- 管理员下发策略：强制随机，每国家最少2个，最多10个 ---
        buckets = defaultdict(list)
        for n in raw_nodes_data:
            buckets[get_country_bucket(n['remark'])].append(n['link'])
            
        selected = []
        for b in buckets: random.shuffle(buckets[b]) # 先在组内打乱

        # 优先提取各国家2个节点
        for b in list(buckets.keys()):
            selected.extend(buckets[b][:2])
            buckets[b] = buckets[b][2:] # 移除已选的

        # 如果超额截断，如果不足从剩余随机补充至10个
        if len(selected) > 10:
            random.shuffle(selected)
            selected = selected[:10]
        else:
            remaining_all = []
            for b in buckets.values(): remaining_all.extend(b)
            random.shuffle(remaining_all)
            selected.extend(remaining_all[:10 - len(selected)])
            
        random.shuffle(selected) # 最终再打乱一次
        links = selected

    else:
        # --- 个人订阅中心策略：可选随机，超20截断 ---
        links = [n['link'] for n in raw_nodes_data]
        if request.args.get('sort') == 'random':
            random.shuffle(links)
            if len(links) > 20: 
                links = links[:20]
            
    raw_links = "\n".join(links)
    encoded = base64.b64encode(raw_links.encode('utf-8')).decode('utf-8') if raw_links else ""
    return Response(encoded, headers={'Content-Type': 'text/plain; charset=utf-8', 'Profile-Update-Interval': '24'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005)
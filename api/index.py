import sqlite3, jwt, os, secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
SECRET_KEY = "acas-test-secret-key"

_db_conn = None

def get_db():
    global _db_conn
    if _db_conn is None:
        _db_conn = sqlite3.connect(":memory:", check_same_thread=False)
        _db_conn.row_factory = sqlite3.Row
        _seed(_db_conn)
    return _db_conn

def _seed(conn):
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,password TEXT,role TEXT DEFAULT 'user',phone TEXT,address TEXT,dob TEXT);
        CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,item TEXT,amount REAL,status TEXT,created_at TEXT);
        CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,title TEXT,content TEXT,created_at TEXT);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,subject TEXT,body TEXT,created_at TEXT);
        CREATE TABLE IF NOT EXISTS payment_methods(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,card_last4 TEXT,card_type TEXT,expiry TEXT);
        CREATE TABLE IF NOT EXISTS api_keys(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,key TEXT,created_at TEXT);
        CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,price REAL,description TEXT);
    """)
    c.executemany("INSERT OR IGNORE INTO users VALUES(?,?,?,?,?,?,?)", [
        (1,"alice@test.com","alice123","user","+91-9000000001","12 MG Road, Kozhikode","1995-03-14"),
        (2,"bob@test.com","bob123","user","+91-9000000002","45 Park Ave, Bangalore","1992-07-22"),
        (3,"carol@test.com","carol123","user","+91-9000000003","8 Beach Road, Kochi","1998-11-05"),
        (4,"admin@test.com","admin123","admin","+91-9000000004","1 Admin Block, Chennai","1988-01-01"),
    ])
    for uid, name in [(1,"Alice"),(2,"Bob"),(3,"Carol"),(4,"Admin")]:
        c.executemany("INSERT INTO orders(user_id,item,amount,status,created_at)VALUES(?,?,?,?,?)",[
            (uid, name+"'s MacBook Pro", 1299.99, "delivered", "2024-01-10"),
            (uid, name+"'s iPhone 15",   999.00,  "shipped",   "2024-02-15"),
            (uid, name+"'s AirPods",     249.00,  "pending",   "2024-03-01"),
        ])
        c.executemany("INSERT INTO documents(user_id,title,content,created_at)VALUES(?,?,?,?)",[
            (uid, name+" Passport",       "PASSPORT: "+name.upper()+" | NUM: P"+str(uid)+"001", "2024-01-01"),
            (uid, name+" Bank Statement", "Account: "+str(uid)+"0000000 | Balance: INR "+str(uid*50000), "2024-01-15"),
            (uid, name+" Medical Report", "Patient: "+name+" | Blood: O+ | Notes: CONFIDENTIAL", "2024-02-01"),
        ])
        c.executemany("INSERT INTO messages(user_id,subject,body,created_at)VALUES(?,?,?,?)",[
            (uid, "Welcome",        "Hello "+name+", welcome aboard!", "2024-01-01"),
            (uid, "Invoice Ready",  "Hi "+name+", invoice #INV-"+str(uid)+"001 ready.", "2024-01-20"),
            (uid, "Security Alert", "Dear "+name+", new login from 10.0.0."+str(uid), "2024-02-10"),
        ])
    c.executemany("INSERT INTO payment_methods(user_id,card_last4,card_type,expiry)VALUES(?,?,?,?)",[
        (1,"4242","Visa","12/26"),(2,"5555","Mastercard","08/25"),
        (3,"3782","Amex","03/27"),(4,"6011","Discover","11/25"),
    ])
    for uid, name in [(1,"alice"),(2,"bob"),(3,"carol"),(4,"admin")]:
        c.execute("INSERT INTO api_keys(user_id,key,created_at)VALUES(?,?,?)",
                  (uid, "sk_live_"+name+"_"+secrets.token_hex(16), "2024-01-01"))
    c.executemany("INSERT INTO products(name,price,description)VALUES(?,?,?)",[
        ("Bug Bounty Course",     199.00, "Learn ethical hacking"),
        ("ACAS Pro License",      499.00, "Advanced access control scanner"),
        ("Pentest Toolkit",       299.00, "Complete pentest bundle"),
        ("Web Security Handbook",  49.00, "Web security reference"),
        ("VPS Hosting 1mo",        15.00, "512MB RAM 10GB SSD"),
    ])
    conn.commit()

def make_token(uid, role):
    return jwt.encode(
        {"user_id": uid, "role": role, "exp": datetime.utcnow()+timedelta(hours=24)},
        SECRET_KEY, algorithm="HS256"
    )

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error":"unauthorized","message":"No token provided"}), 401
        try:
            p = jwt.decode(auth[7:], SECRET_KEY, algorithms=["HS256"])
            g.uid = p["user_id"]
            g.role = p["role"]
        except:
            return jsonify({"error":"unauthorized","message":"Invalid token"}), 401
        return f(*args, **kwargs)
    return wrapper

# AUTH
@app.route("/api/auth/login", methods=["POST"])
def login():
    d = request.get_json() or {}
    u = get_db().execute("SELECT * FROM users WHERE email=? AND password=?",
                         (d.get("email",""), d.get("password",""))).fetchone()
    if not u:
        return jsonify({"error":"invalid","message":"Wrong email or password"}), 401
    return jsonify({"token":make_token(u["id"],u["role"]),"user_id":u["id"],"email":u["email"],"role":u["role"]})

@app.route("/api/auth/register", methods=["POST"])
def register():
    d = request.get_json() or {}
    try:
        get_db().execute("INSERT INTO users(email,password,role,phone,address,dob)VALUES(?,?,'user','','','')",
                         (d.get("email",""), d.get("password","")))
        get_db().commit()
        u = get_db().execute("SELECT * FROM users WHERE email=?", (d.get("email",""),)).fetchone()
        return jsonify({"token":make_token(u["id"],"user"),"user_id":u["id"]}), 201
    except:
        return jsonify({"error":"conflict","message":"Email already exists"}), 409

# VULNERABLE
@app.route("/api/users/<int:uid>/profile", methods=["GET"])
@require_auth
def get_profile(uid):
    u = get_db().execute("SELECT id,email,phone,address,dob,role FROM users WHERE id=?", (uid,)).fetchone()
    return jsonify(dict(u)) if u else (jsonify({"error":"not_found"}), 404)

@app.route("/api/users/<int:uid>/profile", methods=["PUT"])
@require_auth
def update_profile(uid):
    d = request.get_json() or {}
    get_db().execute("UPDATE users SET phone=?,address=? WHERE id=?",
                     (d.get("phone",""), d.get("address",""), uid))
    get_db().commit()
    return jsonify({"success":True,"updated_user_id":uid})

@app.route("/api/users/<int:uid>/orders", methods=["GET"])
@require_auth
def get_user_orders(uid):
    rows = get_db().execute("SELECT * FROM orders WHERE user_id=?", (uid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/orders/<int:oid>", methods=["GET"])
@require_auth
def get_order(oid):
    r = get_db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    return jsonify(dict(r)) if r else (jsonify({"error":"not_found"}), 404)

@app.route("/api/documents/<int:did>", methods=["GET"])
@require_auth
def get_document(did):
    r = get_db().execute("SELECT * FROM documents WHERE id=?", (did,)).fetchone()
    return jsonify(dict(r)) if r else (jsonify({"error":"not_found"}), 404)

@app.route("/api/documents/<int:did>", methods=["DELETE"])
@require_auth
def delete_document(did):
    get_db().execute("DELETE FROM documents WHERE id=?", (did,))
    get_db().commit()
    return jsonify({"success":True,"deleted":did})

@app.route("/api/users/<int:uid>/payment-method", methods=["GET"])
@require_auth
def get_payment(uid):
    r = get_db().execute("SELECT * FROM payment_methods WHERE user_id=?", (uid,)).fetchone()
    return jsonify(dict(r)) if r else (jsonify({"error":"not_found"}), 404)

@app.route("/api/users/<int:uid>/apikey", methods=["GET"])
@require_auth
def get_apikey(uid):
    r = get_db().execute("SELECT * FROM api_keys WHERE user_id=?", (uid,)).fetchone()
    return jsonify(dict(r)) if r else (jsonify({"error":"not_found"}), 404)

@app.route("/api/export", methods=["GET"])
@require_auth
def export_data():
    uid = request.args.get("user_id", g.uid)
    db = get_db()
    user = db.execute("SELECT id,email,phone,address,dob FROM users WHERE id=?", (uid,)).fetchone()
    ords = db.execute("SELECT * FROM orders WHERE user_id=?", (uid,)).fetchall()
    docs = db.execute("SELECT * FROM documents WHERE user_id=?", (uid,)).fetchall()
    return jsonify({"user":dict(user) if user else None,
                    "orders":[dict(o) for o in ords],
                    "documents":[dict(d) for d in docs]})

@app.route("/api/reports/generate", methods=["POST"])
@require_auth
def generate_report():
    d = request.get_json() or {}
    uid = d.get("target_user_id", g.uid)
    db = get_db()
    u = db.execute("SELECT id,email,phone,address,dob FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        return jsonify({"error":"not_found"}), 404
    ords = db.execute("SELECT * FROM orders WHERE user_id=?", (uid,)).fetchall()
    return jsonify({"report_id":"RPT-"+str(uid),"generated_for":dict(u),"orders":[dict(o) for o in ords]})

# PROTECTED
@app.route("/api/users/<int:uid>/messages", methods=["GET"])
@require_auth
def get_messages(uid):
    if g.uid != uid and g.role != "admin":
        return jsonify({"error":"forbidden","message":"Access denied - not your resource"}), 403
    rows = get_db().execute("SELECT * FROM messages WHERE user_id=?", (uid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/users/me", methods=["GET"])
@require_auth
def get_me():
    u = get_db().execute("SELECT id,email,phone,address,dob,role FROM users WHERE id=?", (g.uid,)).fetchone()
    return jsonify(dict(u))

@app.route("/api/products", methods=["GET"])
def get_products():
    return jsonify([dict(r) for r in get_db().execute("SELECT * FROM products").fetchall()])

@app.route("/api/products/<int:pid>", methods=["GET"])
def get_product(pid):
    r = get_db().execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    return jsonify(dict(r)) if r else (jsonify({"error":"not_found"}), 404)

# WEB UI
PAGE = open(__file__).read().split("###HTML###")[1] if "###HTML###" in open(__file__).read() else ""

NAV = '''<div class="nav">
<span class="brand">&#9889; ACAS Target</span>
<a href="/">Login</a><a href="/dashboard">Dashboard</a><a href="/profile">Profile</a>
<a href="/orders">Orders</a><a href="/documents">Documents</a><a href="/endpoints">Endpoints</a>
<span class="nr" id="nv">Not logged in</span>
</div>'''

CSS = '''*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,sans-serif;background:#0f172a;color:#e2e8f0}
.nav{background:#1e293b;padding:14px 24px;display:flex;align-items:center;gap:20px;border-bottom:1px solid #334155;flex-wrap:wrap}
.nav a{color:#94a3b8;text-decoration:none;font-size:14px}.nav a:hover{color:#fff}
.brand{color:#f97316;font-weight:700;font-size:16px;margin-right:20px}
.nr{margin-left:auto;font-size:13px;color:#64748b}
.c{max-width:900px;margin:40px auto;padding:0 24px}
h1{font-size:22px;color:#f8fafc;margin-bottom:20px}
h2{font-size:13px;color:#64748b;margin:24px 0 10px;text-transform:uppercase;letter-spacing:1px}
.card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:18px;margin-bottom:12px}
.card p{font-size:14px;color:#94a3b8;margin:3px 0}.card strong{color:#e2e8f0}
.fi{margin-bottom:12px}label{display:block;font-size:13px;color:#94a3b8;margin-bottom:5px}
input{width:100%;padding:9px 12px;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#e2e8f0;font-size:14px}
.btn{padding:10px 20px;background:#f97316;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600}
.err{color:#f87171;font-size:13px;margin-top:8px}
pre{background:#0f172a;padding:10px;border-radius:6px;font-size:12px;overflow-x:auto;color:#4ade80;margin-top:6px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;padding:9px 12px;color:#64748b;font-size:12px;text-transform:uppercase;border-bottom:1px solid #334155}
td{padding:9px 12px;border-bottom:1px solid #1e293b;color:#cbd5e1;vertical-align:top}
.tv{background:#450a0a;color:#f87171;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:600}
.tp{background:#14532d;color:#4ade80;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:600}
.tpub{background:#1e3a5f;color:#60a5fa;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:600}'''

JS_BASE = '''var T=localStorage.getItem("t"),UID=localStorage.getItem("uid"),EM=localStorage.getItem("em");
if(EM)document.getElementById("nv").textContent=EM+" (id="+UID+")";
async function api(m,p,b){
  var o={method:m,headers:{"Content-Type":"application/json"}};
  if(T)o.headers["Authorization"]="Bearer "+T;
  if(b)o.body=JSON.stringify(b);
  return(await fetch(p,o)).json();
}'''

def render(body, js=""):
    return (
        "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>ACAS Target</title>"
        "<style>" + CSS + "</style></head><body>"
        + NAV + body
        + "<script>" + JS_BASE + js + "</script>"
        + "</body></html>"
    )

@app.route("/")
def index():
    body = (
        '<div class="c"><h1>Login</h1>'
        '<div class="card" style="max-width:420px">'
        '<div class="fi"><label>Email</label><input id="em" placeholder="alice@test.com"/></div>'
        '<div class="fi"><label>Password</label><input id="pw" type="password" placeholder="alice123"/></div>'
        '<button class="btn" onclick="doLogin()">Login</button>'
        '<p class="err" id="er"></p>'
        '<p style="margin-top:14px;font-size:12px;color:#475569">'
        'alice@test.com / alice123 &nbsp;|&nbsp; bob@test.com / bob123<br>'
        'carol@test.com / carol123 &nbsp;|&nbsp; admin@test.com / admin123'
        '</p></div></div>'
    )
    js = (
        'async function doLogin(){'
        'var r=await api("POST","/api/auth/login",'
        '{email:document.getElementById("em").value,password:document.getElementById("pw").value});'
        'if(r.token){localStorage.setItem("t",r.token);localStorage.setItem("uid",r.user_id);'
        'localStorage.setItem("em",r.email);window.location="/dashboard";}'
        'else document.getElementById("er").textContent=r.message||"Login failed";}'
    )
    return render(body, js)

@app.route("/dashboard")
def dashboard():
    body = (
        '<div class="c"><h1>Dashboard</h1>'
        '<div id="me" class="card"></div>'
        '<h2>Your Orders</h2><div id="ord"></div>'
        '<h2>Products (Public - FP Test)</h2><div id="prod"></div>'
        '</div>'
    )
    js = (
        '(async function(){'
        'if(!T){window.location="/";return;}'
        'var me=await api("GET","/api/users/me");'
        'document.getElementById("me").innerHTML="<p>Email: <strong>"+me.email+"</strong> ID: <strong>"+me.id+"</strong> Role: <strong>"+me.role+"</strong></p>";'
        'var ords=await api("GET","/api/users/"+UID+"/orders");'
        'var h="";for(var i=0;i<ords.length;i++){var o=ords[i];'
        'h+="<div class=\'card\'><p><strong>"+o.item+"</strong></p><p>$"+o.amount+" - "+o.status+"</p>"'
        '+"<p style=\'font-size:12px;color:#475569\'>Order ID: "+o.id+"</p></div>";}'
        'document.getElementById("ord").innerHTML=h;'
        'var prods=await api("GET","/api/products");'
        'var t="<table><tr><th>ID</th><th>Name</th><th>Price</th></tr>";'
        'for(var j=0;j<prods.length;j++)t+="<tr><td>"+prods[j].id+"</td><td>"+prods[j].name+"</td><td>$"+prods[j].price+"</td></tr>";'
        'document.getElementById("prod").innerHTML=t+"</table>";'
        '})();'
    )
    return render(body, js)

@app.route("/profile")
def profile():
    body = (
        '<div class="c"><h1>My Profile</h1>'
        '<div id="prf" class="card"></div>'
        '<h2>Payment Method</h2><div id="pay" class="card"></div>'
        '<h2>API Key (Sensitive)</h2><div id="key" class="card"></div>'
        '</div>'
    )
    js = (
        '(async function(){'
        'if(!T){window.location="/";return;}'
        'var p=await api("GET","/api/users/"+UID+"/profile");'
        'document.getElementById("prf").innerHTML="<p>Email: <strong>"+p.email+"</strong></p><p>Phone: <strong>"+p.phone+"</strong></p><p>Address: <strong>"+p.address+"</strong></p><p>DOB: <strong>"+p.dob+"</strong></p>";'
        'var pay=await api("GET","/api/users/"+UID+"/payment-method");'
        'document.getElementById("pay").innerHTML="<p>"+pay.card_type+" ending in <strong>"+pay.card_last4+"</strong> Expiry: "+pay.expiry+"</p>";'
        'var k=await api("GET","/api/users/"+UID+"/apikey");'
        'document.getElementById("key").innerHTML="<pre>"+k.key+"</pre>";'
        '})();'
    )
    return render(body, js)

@app.route("/orders")
def orders():
    body = '<div class="c"><h1>My Orders</h1><div id="ord"></div></div>'
    js = (
        '(async function(){'
        'if(!T){window.location="/";return;}'
        'var o=await api("GET","/api/users/"+UID+"/orders");'
        'var h="";for(var i=0;i<o.length;i++){'
        'h+="<div class=\'card\'><p><strong>"+o[i].item+"</strong></p><p>$"+o[i].amount+" - "+o[i].status+"</p>"'
        '+"<p style=\'font-size:12px;color:#475569\'>ID: "+o[i].id+"</p></div>";}'
        'document.getElementById("ord").innerHTML=h;'
        '})();'
    )
    return render(body, js)

@app.route("/documents")
def documents():
    body = '<div class="c"><h1>My Documents</h1><div id="docs"></div></div>'
    js = (
        '(async function(){'
        'if(!T){window.location="/";return;}'
        'var all=[];'
        'for(var i=1;i<=12;i++){var d=await api("GET","/api/documents/"+i);if(!d.error&&d.user_id==UID)all.push(d);}'
        'var h="";for(var j=0;j<all.length;j++){'
        'h+="<div class=\'card\'><p><strong>"+all[j].title+"</strong></p><pre>"+all[j].content+"</pre>"'
        '+"<p style=\'font-size:12px;color:#475569\'>Doc ID: "+all[j].id+"</p></div>";}'
        'document.getElementById("docs").innerHTML=h;'
        '})();'
    )
    return render(body, js)

@app.route("/endpoints")
def endpoint_map():
    body = (
        '<div class="c"><h1>Endpoint Map</h1>'
        '<p style="color:#64748b;font-size:13px;margin-bottom:20px">Browse as Alice (Actor A). Set Bob as Actor B in ACAS.</p>'
        '<table>'
        '<tr><th>Method</th><th>Endpoint</th><th>Type</th><th>Expected ACAS Result</th></tr>'
        '<tr><td>GET</td><td>/api/users/me</td><td><span class="tp">protected</span></td><td>Not flagged</td></tr>'
        '<tr><td>GET</td><td>/api/users/{id}/profile</td><td><span class="tv">IDOR</span></td><td>CONFIRMED ~85</td></tr>'
        '<tr><td>PUT</td><td>/api/users/{id}/profile</td><td><span class="tv">IDOR</span></td><td>CONFIRMED ~80</td></tr>'
        '<tr><td>GET</td><td>/api/users/{id}/orders</td><td><span class="tv">IDOR</span></td><td>CONFIRMED ~80</td></tr>'
        '<tr><td>GET</td><td>/api/orders/{id}</td><td><span class="tv">IDOR</span></td><td>CONFIRMED ~78</td></tr>'
        '<tr><td>GET</td><td>/api/documents/{id}</td><td><span class="tv">IDOR</span></td><td>CONFIRMED ~88</td></tr>'
        '<tr><td>DELETE</td><td>/api/documents/{id}</td><td><span class="tv">IDOR</span></td><td>CONFIRMED ~82</td></tr>'
        '<tr><td>GET</td><td>/api/users/{id}/payment-method</td><td><span class="tv">IDOR</span></td><td>CONFIRMED ~92 HIGH</td></tr>'
        '<tr><td>GET</td><td>/api/users/{id}/apikey</td><td><span class="tv">IDOR</span></td><td>CONFIRMED ~95 CRITICAL</td></tr>'
        '<tr><td>GET</td><td>/api/export?user_id={id}</td><td><span class="tv">IDOR</span></td><td>Review Queue</td></tr>'
        '<tr><td>POST</td><td>/api/reports/generate</td><td><span class="tv">IDOR</span></td><td>Review Queue</td></tr>'
        '<tr><td>GET</td><td>/api/users/{id}/messages</td><td><span class="tp">protected</span></td><td>NOT flagged 403</td></tr>'
        '<tr><td>GET</td><td>/api/products</td><td><span class="tpub">public</span></td><td>FALSE POSITIVE</td></tr>'
        '<tr><td>GET</td><td>/api/products/{id}</td><td><span class="tpub">public</span></td><td>FALSE POSITIVE</td></tr>'
        '</table></div>'
    )
    return render(body)
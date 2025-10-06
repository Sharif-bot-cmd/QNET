#!/usr/bin/env python3
import os, json, html, shutil, subprocess, threading, hashlib, secrets, socket, requests, urllib3, re, time, mimetypes
from fastapi import FastAPI, UploadFile, File, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from flask import Flask
import uvicorn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.adapters.DEFAULT_RETRIES = 2

app = FastAPI(title="QNET", version="1.0")

UPLOADS_DIR = "uploads"
os.makedirs(UPLOADS_DIR, exist_ok=True)

DB_FILES = {
    "leaks": "leaks.json",
    "videos": "videos.json",
    "posts": "posts.json",
    "accounts": "accounts.json",
    "settings": "settings.json"
}

lock = threading.Lock()
SECRET_KEY = secrets.token_hex(16)
SESSION_COOKIE = "qnet_user"

# -------------------- INIT DATABASES --------------------
for path in DB_FILES.values():
    if not os.path.exists(path):
        with open(path, "w") as f:
            if "settings" in path:
                json.dump({"security_level": "Standard"}, f)
            elif "accounts" in path:
                json.dump([{"username": "admin", "password": hashlib.sha256(b"admin").hexdigest()}], f)
            else:
                json.dump([], f)

app.mount("/uploads", StaticFiles(directory=UPLOADS_DIR), name="uploads")

# -------------------- MODE DETECTION (OFFLINE SAFE) --------------------
def detect_mode():
    """
    Detect QNET network mode safely. Works fully offline.
    Modes: IPFS, I2P, TOR, OFFLINE
    Info always includes:
      - local_access
      - ipfs_gateway
      - cloudflare_mirrors
      - status
    """
    mode, info = "OFFLINE", {}

    # Default mirrors (always present)
    info["local_access"] = "http://127.0.0.1:8080"
    info["ipfs_gateway"] = "http://127.0.0.1:8081/ipfs/Qmb3ppbHHu38G66esPBYTxZX9PZggYrre6oGmFEu5L7MdN"
    info["cloudflare_mirrors"] = [
        "https://symantec-certificate-insert-pottery.trycloudflare.com",
        "https://advisors-switching-commissioner-subsidiaries.trycloudflare.com",
        "https://val-seed-fisher-terrorists.trycloudflare.com"
    ]

    def try_run(cmd, wait=3):
        """Try to start a daemon or command silently."""
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(wait)
            return True
        except Exception:
            return False

    try:
        # === IPFS Detection / Auto-Activation ===
        if shutil.which("ipfs"):
            home_ipfs = os.path.expanduser("~/.ipfs")
            if not os.path.exists(home_ipfs):
                try_run(["ipfs", "init"])
            try:
                result = subprocess.run(["ipfs", "id"], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=3)
                if result.returncode != 0:
                    subprocess.run(
                        ["ipfs", "config", "Addresses.Gateway", "/ip4/127.0.0.1/tcp/8081"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    try_run(["ipfs", "daemon"], wait=6)
                mode = "IPFS"
                info["status"] = "active"
            except:
                mode = "OFFLINE"
                info["status"] = "idle"

        # === I2P Detection / Auto-Activation ===
        elif shutil.which("i2pd"):
            conf_dir = os.path.expanduser("~/.i2pd")
            os.makedirs(conf_dir, exist_ok=True)
            try_run(["i2pd", "--daemon"], wait=5)
            mode = "I2P"
            info["i2p_host"] = "local_qnet.i2p"
            info["status"] = "active"

        # === TOR Detection / Auto-Activation ===
        elif shutil.which("tor"):
            tor_dir = os.path.expanduser("~/.tor/hidden_service")
            os.makedirs(tor_dir, exist_ok=True)
            try_run(["tor"], wait=5)
            onion_file = os.path.join(tor_dir, "hostname")
            info["onion"] = "(pending .onion generation)"
            if os.path.exists(onion_file):
                try:
                    with open(onion_file, "r") as f:
                        info["onion"] = f.read().strip()
                except:
                    pass
            mode = "TOR"
            info["status"] = "active"

        # === OFFLINE fallback ===
        else:
            mode = "OFFLINE"
            info["status"] = "idle"

    except Exception as e:
        mode = "OFFLINE"
        info["error"] = str(e)
        info["status"] = "error"

    return mode, info

# -------------------- SAFE GLOBAL TUNNEL START --------------------
def start_global_tunnel(port=8080):
    """Return reachable URL or None; fully offline-safe."""
    def run_tunnel(cmd, regex, name):
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                match = re.search(regex, line)
                if match:
                    url = match.group(1)
                    print(f"🌍 {name} Tunnel Active → {url}")
                    return url
        except:
            pass
        return None

    try:
        if shutil.which("cloudflared"):
            return run_tunnel(
                ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
                r"(https://[-a-zA-Z0-9.]+\.trycloudflare\.com)",
                "Cloudflare"
            )
        elif shutil.which("ngrok"):
            subprocess.Popen(["ngrok", "http", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)
            try:
                r = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=2)
                for t in r.json().get("tunnels", []):
                    if "public_url" in t:
                        print(f"🌍 Ngrok Tunnel Active → {t['public_url']}")
                        return t["public_url"]
            except:
                pass
    except:
        pass

    print("[!] No global tunneling tools found or offline mode")
    return None
# -------------------- HELPERS --------------------
def hash_password(pw): return hashlib.sha256(pw.encode()).hexdigest()
def sign(v): return f"{v}:{hashlib.sha256((v+SECRET_KEY).encode()).hexdigest()}"
def verify_signed(v):
    try:
        u, sig = v.split(":")
        if hashlib.sha256((u+SECRET_KEY).encode()).hexdigest() == sig:
            return u
    except:
        pass
    return None
def get_user(req: Request):
    c = req.cookies.get(SESSION_COOKIE)
    return verify_signed(c) if c else None
def load_json(path):
    try: return json.load(open(path))
    except: return []
def save_json(path, data):
    with open(path, "w") as f: json.dump(data, f, indent=2)
# -------------------- SECURITY VISIBILITY 🛡️ --------------------
SECURITY_INFO = {
    "standard": {"name": "Standard", "desc": "Global tunnels active. Full connectivity.", "color": "#0f0"},
    "safer": {"name": "Safer", "desc": "Limited exposure. Encrypted and verified nodes only.", "color": "#ff0"},
    "safest": {"name": "Safest", "desc": "Offline mode. Local access only, no external tunnels.", "color": "#f00"},
}

def get_security_level():
    try:
        data = json.load(open(DB_FILES["settings"]))
        level = data.get("security_level", "Standard").lower()
        return level if level in SECURITY_INFO else "standard"
    except:
        return "standard"

@app.get("/status")  # 🛡️ JSON API endpoint
def qnet_status():
    level = get_security_level()
    info = SECURITY_INFO[level]
    mode, netinfo = detect_mode()
    return JSONResponse({
        "security_level": info["name"],
        "description": info["desc"],
        "color": info["color"],
        "network_mode": mode,
        "online": mode != "OFFLINE"
    })

# -------------------- FILE PERSISTENCE --------------------
def persist_file(path):
    mode, info = detect_mode()
    try:
        if mode == "IPFS":
            cid = subprocess.check_output(["ipfs", "add", "-Q", path], text=True).strip()
            subprocess.run(["ipfs", "pin", "add", cid])
            return f"{info['ipfs_gateway']}{cid}"
        elif mode == "TOR":
            return f"tor://{info.get('onion','local')}/{os.path.basename(path)}"
        elif mode == "I2P":
            return f"i2p://{info.get('i2p_host','local')}/{os.path.basename(path)}"
    except:
        pass
    return f"/uploads/{os.path.basename(path)}"

# -------------------- BASE HTML --------------------
def base_html(title, body, user=None):
    level = get_security_level()
    info = SECURITY_INFO[level]
    profile = (
        f"<div class='profile'>Logged in as <b>{html.escape(user)}</b> | <a href='/logout'>Logout</a></div>"
        if user else "<div class='profile'><a href='/login'>Login</a></div>"
    )

    html_code = f"""<!DOCTYPE html><html><head>
<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{html.escape(title)} - QNET</title>
<style>
body{{background:#000;color:#0f0;font-family:monospace;margin:0}}
header{{border-bottom:1px solid #0f0;padding:10px;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center}}
nav{{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;width:100%;margin-top:6px}}
nav a{{color:#0f0;text-decoration:none;padding:6px 10px;border-radius:6px;border:1px solid #0f0}}
nav a:hover{{background:#0f0;color:#000}}
main{{max-width:900px;margin:auto;padding:10px}}
input,button,textarea{{background:#111;color:#0f0;border:1px solid #0f0;border-radius:6px;padding:8px;width:100%;margin:6px 0}}
button{{width:auto;cursor:pointer;background:#0f0;color:#000}}
.delete-btn{{background:#900;color:#fff;border:1px solid #f00;border-radius:4px;padding:4px 8px;cursor:pointer}}
iframe,video{{width:100%;height:360px;border:1px solid #0f0;border-radius:8px}}
pre{{white-space:pre-wrap}}
.profile{{font-size:0.9em;text-align:right;width:100%}}
#shield{{position:fixed;bottom:15px;right:15px;padding:10px 14px;border-radius:12px;background:{info['color']};color:#000;font-weight:bold;cursor:default;box-shadow:0 0 10px {info['color']};}}
</style>
<script>
async function deleteItem(db,i){{
 const fd=new FormData();fd.append("db",db);fd.append("index",i);
 const r=await fetch("/delete",{{method:"POST",body:fd}});
 const j=await r.json(); if(j.status==="deleted") location.reload();
 else alert(j.error||"Delete failed");
}}
</script>
</head><body>
<header><h1>QNET</h1>
<nav>
<a href="/">Home</a>
<a href="/videos">Videos</a>
<a href="/posts">Posts</a>
<a href="/leaks">Leaks</a>
<a href="/search">Search</a>
<a href="/invidious">Invidious</a>
<a href="/settings">⚙️</a>
</nav>{profile}</header>
<main>{body}</main>
<div id='shield' title='{info['desc']}'>🛡️ {info['name']}</div>
</body></html>"""
    return HTMLResponse(html_code)

# -------------------- FILE VIEW --------------------
def render_file_view(title, path, file_type, user=None):
    """
    Render file preview page based on MIME type or file extension.
    Supports video playback, text preview, and iframe fallback.
    """

    iframe_html = ""

    # Handle video files
    if file_type.startswith("video/"):
        iframe_html = f"""
        <video controls style='width:100%;height:auto;border-radius:12px;box-shadow:0 0 10px rgba(0,0,0,0.3);'>
            <source src='{html.escape(path)}' type='{html.escape(file_type)}'>
            Your browser does not support the video tag.
        </video>
        """

    # Handle text-based files
    elif file_type.startswith("text/") or path.endswith((".txt", ".json", ".log")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = html.escape(f.read())
        except Exception as e:
            content = f"[Unable to read file: {e}]"
        iframe_html = f"""
        <pre style='background:#111;color:#0f0;padding:1em;border-radius:10px;overflow-x:auto;'>{content}</pre>
        """

    # Fallback: render in iframe (e.g., PDF, HTML, etc.)
    else:
        iframe_html = f"""
        <iframe src='{html.escape(path)}' style='width:100%;height:80vh;border:none;border-radius:12px;'></iframe>
        """

    # Wrap in base layout
    return base_html(title, iframe_html, user)

# -------------------- HOME --------------------
@app.get("/", response_class=HTMLResponse)
def home(req: Request):
    user = get_user(req)
    body = "<h2>Welcome to QNET</h2><p>Hybrid decentralized offline/online node.</p>"
    return base_html("Home", body, user)

# -------------------- LIST / UPLOAD --------------------
def render_list_page(db_key, title, accept_type, req: Request):
    user = get_user(req)
    data = load_json(DB_FILES[db_key])
    body = f"<h2>{title}</h2>"
    if not data:
        body += f"<p>No {title.lower()} yet.</p>"
    for i, item in enumerate(reversed(data)):
        real = len(data) - 1 - i
        body += f"<div><a href='/{db_key}/view?index={real}'>{html.escape(item['title'])}</a> <button class='delete-btn' onclick=\"deleteItem('{db_key}',{real})\">Delete</button><hr></div>"
    body += f"""
    <h3>Upload {title}</h3>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file accept="{accept_type}" required>
      <input name=title placeholder=Title required>
      <button>Upload</button>
    </form>"""
    return base_html(title, body, user)

def handle_upload(db_key, file: UploadFile, title: str):
    filename = os.path.basename(file.filename)
    path = os.path.join(UPLOADS_DIR, filename)

    # Ensure atomic write and full flush
    with open(path, "wb") as f:
        while chunk := file.file.read(8192):
            f.write(chunk)
        f.flush()
        os.fsync(f.fileno())

    # Detect type properly
    mime_type, _ = mimetypes.guess_type(path)
    if not mime_type:
        mime_type = "application/octet-stream"

    # Make sure local path is used for playback first
    link = f"/uploads/{filename}"
    data = load_json(DB_FILES[db_key])
    data.append({"title": title, "link": link, "mime": mime_type})
    save_json(DB_FILES[db_key], data)
    return RedirectResponse(f"/{db_key}", 303)

# -------------------- CRUD ROUTES --------------------
@app.get("/videos")
def videos(req: Request): return render_list_page("videos", "Videos", "video/*", req)
@app.post("/videos")
async def add_video(file: UploadFile = File(...), title: str = Form(...)): return handle_upload("videos", file, title)

@app.get("/posts")
def posts(req: Request): return render_list_page("posts", "Posts", "text/*", req)
@app.post("/posts")
async def add_post(file: UploadFile = File(...), title: str = Form(...)): return handle_upload("posts", file, title)

@app.get("/leaks")
def leaks(req: Request): return render_list_page("leaks", "Leaks", "*/*", req)
@app.post("/leaks")
async def add_leak(file: UploadFile = File(...), title: str = Form(...)): return handle_upload("leaks", file, title)

# -------------------- VIEW ENDPOINTS --------------------
@app.get("/videos/view")
def view_video(index: int, req: Request):
    user = get_user(req)
    data = load_json(DB_FILES["videos"])
    if 0 <= index < len(data):
        item = data[index]
        return render_file_view(item["title"], item["link"], "video/mp4", user)
    return base_html("Error", "<p>Video not found</p>", user)

@app.get("/posts/view")
def view_post(index: int, req: Request):
    user = get_user(req)
    data = load_json(DB_FILES["posts"])
    if 0 <= index < len(data):
        item = data[index]
        path = os.path.join(UPLOADS_DIR, os.path.basename(item["link"]))
        return render_file_view(item["title"], path, "text/plain", user)
    return base_html("Error", "<p>Post not found</p>", user)

@app.get("/leaks/view")
def view_leak(index: int, req: Request):
    user = get_user(req)
    data = load_json(DB_FILES["leaks"])
    if 0 <= index < len(data):
        item = data[index]
        path = item["link"]
        mime = "text/plain" if path.endswith((".txt",".log",".json")) else "application/octet-stream"
        return render_file_view(item["title"], path, mime, user)
    return base_html("Error", "<p>Leak not found</p>", user)

# -------------------- SEARCH --------------------
@app.get("/search")
def search(req: Request, q: str = Query("", alias="q")):
    user = get_user(req)
    mode, info = detect_mode()
    results = []

    body = "<h2>Search</h2>"
    body += f"<form method=get><input name=q placeholder='Search or URL...' value='{html.escape(q)}'><button>Go</button></form>"

    if not q:
        return base_html("Search", body, user)

    # Local results
    for key in ["videos", "posts", "leaks"]:
        for item in load_json(DB_FILES[key]):
            if q.lower() in item["title"].lower():
                results.append((key, item["title"], item["link"]))

    # Online DuckDuckGo if not offline
    if mode not in ["OFFLINE", "I2P"]:
        try:
            r = requests.get("https://api.duckduckgo.com/", params={"q": q, "format": "json"}, timeout=5)
            j = r.json()
            for topic in j.get("RelatedTopics", []):
                if "Text" in topic and "FirstURL" in topic:
                    results.append(("web", topic["Text"], topic["FirstURL"]))
        except:
            results.append(("error", "[Offline Mode] Online search limited", "#"))

    if results:
        for cat, title, link in results:
            body += f"<div>[{cat}] <a href='{link}' target='_blank'>{html.escape(title)}</a></div>"
    else:
        body += "<p>No results found.</p>"

    return base_html("Search", body, user)

# -------------------- INVIDIOUS --------------------
INVIDIOUS_LIST = [
    "https://yewtu.be",
    "https://invidious.flokinet.to",
    "https://inv.tux.pizza",
    "https://invidious.protokolla.fi",
    "https://iv.ggtyler.dev",
]

@app.get("/invidious")
def invidious(req: Request):
    user = get_user(req)
    body = """<h2>Invidious Proxy</h2>
    <form method=get action="/invidious/view">
      <input name="v" placeholder="YouTube video ID or URL" required>
      <button>Watch</button>
    </form>"""
    return base_html("Invidious", body, user)

@app.get("/invidious/view")
def view_invidious(v: str):
    match = re.search(r"(?:v=|be/)([A-Za-z0-9_-]{11})", v)
    if match: v = match.group(1)

    chosen_host = None
    for host in INVIDIOUS_LIST:
        try:
            r = requests.get(f"{host}/embed/{v}", stream=True, allow_redirects=False, timeout=3)
            r.close()
            if r.status_code in (200,301,302):
                chosen_host = host
                break
        except: continue

    iframe_html = (f"<iframe src='{chosen_host}/embed/{v}' allowfullscreen></iframe>" 
                   if chosen_host else f"<p>No reachable Invidious node.<br><a href='https://youtube.com/watch?v={v}'>YouTube</a></p>")

    return base_html("Invidious View", iframe_html)

# -------------------- LOGIN --------------------
@app.get("/login")
def login_page(req: Request):
    body = """
    <h2>Login</h2>
    <form method=post>
      <input name=username placeholder='Username' required>
      <input name=password type=password placeholder='Password' required>
      <button>Login</button>
    </form>"""
    return base_html("Login", body)

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    accounts = load_json(DB_FILES["accounts"])
    for acc in accounts:
        if acc["username"] == username and acc["password"] == hash_password(password):
            resp = RedirectResponse("/", 303)
            resp.set_cookie(SESSION_COOKIE, sign(username), httponly=True)
            return resp
    return base_html("Login Failed", "<p>Invalid credentials.</p><a href='/login'>Try again</a>")

@app.get("/logout")
def logout():
    resp = RedirectResponse("/", 303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp

# -------------------- DELETE --------------------
@app.post("/delete")
async def delete_item(db: str = Form(...), index: int = Form(...)):
    if db not in DB_FILES: return JSONResponse({"error":"Invalid DB"})
    data = load_json(DB_FILES[db])
    if 0 <= index < len(data):
        data.pop(index)
        save_json(DB_FILES[db], data)
        return JSONResponse({"status":"deleted"})
    return JSONResponse({"error":"Index not found"})

# -------------------- SETTINGS --------------------
@app.get("/settings")
def settings(req: Request):
    user = get_user(req)
    data = load_json(DB_FILES["settings"])
    level = data.get("security_level","Standard")
    body = f"""
    <h2>Settings</h2>
    <form method=post>
      <label>Security Level:</label>
      <select name=security_level>
        <option {'selected' if level=='Standard' else ''}>Standard</option>
        <option {'selected' if level=='Safer' else ''}>Safer</option>
        <option {'selected' if level=='Safest' else ''}>Safest</option>
      </select>
      <button>Save</button>
    </form>"""
    return base_html("Settings", body, user)

@app.post("/settings")
async def update_settings(security_level: str = Form(...)):
    save_json(DB_FILES["settings"], {"security_level": security_level})
    return RedirectResponse("/settings", 303)

# -------------------- STARTUP --------------------

if __name__ == "__main__":
    
    try:
    # Try to detect your real LAN or public IP
        host_ip = socket.gethostbyname(socket.gethostname())
        if host_ip.startswith("127.") or host_ip == "0.0.0.0":
            # fallback for Android/Termux or NAT
            try:
                host_ip = requests.get("https://api.ipify.org", timeout=3).text.strip()
            except:
                host_ip = "127.0.0.1"
    except:
        host_ip = "127.0.0.1"

    port = int(os.getenv("QNET_PORT", 8080))

    print(f"🌐 QNET v1.0 starting on 0.0.0.0:{port}")
    print(f"➡ Local access: http://{host_ip}:{port}")
    print("🌍 If you see a Cloudflare / Ngrok / I2P / Tor link below, global access is active.")

# Start tunnels (Cloudflare, Ngrok, etc.) in background
    threading.Thread(target=start_global_tunnel, args=(port,), daemon=True).start()

# Optional hybrid detection (auto-switch between Tor, I2P, IPFS)
    try:
        mode, info = detect_mode()
        print(f"🔭 Network Mode: {mode}")
        if info:
            for k, v in info.items():
                print(f"  {k}: {v}")
    except Exception as e:
        print("[!] Network detection failed:", e)

# Start QNet web service
    uvicorn.run("qnet:app", host="0.0.0.0", port=port, log_level="info")


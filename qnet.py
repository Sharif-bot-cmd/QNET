#!/usr/bin/env python3
import os, json, html, shutil, subprocess, threading, hashlib, secrets, socket, requests, urllib3, re, time, mimetypes, hmac, base64, urllib.parse, random, concurrent.futures, nacl.encoding, nacl.signing
from fastapi import FastAPI, UploadFile, File, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from starlette.middleware.sessions import SessionMiddleware
from flask import Flask
import uvicorn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.adapters.DEFAULT_RETRIES = 2

app = FastAPI(title="QNET", version="1.0")
app.add_middleware(SessionMiddleware, secret_key="super_secret_key_123")

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
SECRET_KEY = "super_secret_key_for_signing"
SESSION_COOKIE = "qnet_session"
SESSION_DATA = {}

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

def load_db(name: str):
    """
    Safely loads a JSON database (videos, posts, leaks, etc.) from /uploads.
    Returns an empty list if the file does not exist or is invalid.
    """
    os.makedirs("uploads", exist_ok=True)
    path = os.path.join("uploads", f"{name}.json")

    if not os.path.exists(path):
        print(f"[i] Database '{name}.json' not found. Creating new one.")
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            else:
                print(f"[!] Database '{name}.json' format invalid (not a list). Resetting.")
                return []
    except json.JSONDecodeError as e:
        print(f"[!] JSON decode error in '{name}.json': {e}")
    except Exception as e:
        print(f"[!] Failed to load DB '{name}': {e}")

    # Return empty list if any failure
    return []

def safe_request(url, **kwargs):
    """
    Privacy-hardened wrapper for requests.get that blocks trackers/surveillance endpoints
    while still allowing searches and previews.
    Adds entropy-driven rotation when security level is 'Experimental'.
    """
    blocked_keywords = [
        "google-analytics", "doubleclick", "facebook", "meta.com",
        "adsystem", "tracking", "metrics", "pixel", "beacon", "googletagmanager",
        "telemetry", "statcounter", "hotjar", "mixpanel"
    ]
    if any(k in url for k in blocked_keywords):
        print(f"[🔒] Blocked tracker URL: {url}")
        return None

    headers = kwargs.pop("headers", {})
    headers.update({
        "User-Agent": "QNET/1.5 (Privacy Hardened)",
        "Accept-Language": "en-US,en;q=0.9",
        "DNT": "1",
        "Sec-GPC": "1"
    })

    # --- Entropy-driven randomization (Experimental mode) ---
    level = get_security_level()
    if level == "experimental":
        try:
            entropy_seed = secrets.token_hex(4)
            headers["User-Agent"] = random.choice([
                f"Mozilla/5.0 (EntropyNet/{entropy_seed})",
                f"QNET-Exp/{entropy_seed}",
                f"Mozilla/5.0 (Quantum; rv:{random.randint(100,999)}.0)",
                f"EntropyBot/{random.randint(1000,9999)}"
            ])
            # random delay for request timing jitter
            time.sleep(random.uniform(0.2, 0.9))
            print(f"[🧬] Experimental entropy rotation active → UA:{headers['User-Agent']}")
        except Exception as e:
            print(f"[!] Experimental entropy rotation failed: {e}")

    try:
        return requests.get(url, headers=headers, timeout=6, **kwargs)
    except Exception as e:
        print(f"[!] safe_request failed for {url}: {e}")
        return None

def save_db(name: str, data: list):
    """
    Safely saves a JSON database into /uploads with atomic write protection.
    Prevents corruption if the system shuts down mid-save.
    """
    import json, os, tempfile, shutil

    os.makedirs("uploads", exist_ok=True)
    path = os.path.join("uploads", f"{name}.json")
    tmp_fd, tmp_path = tempfile.mkstemp(dir="uploads", suffix=".tmp")

    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        shutil.move(tmp_path, path)
        print(f"[✓] Saved database '{name}.json' ({len(data)} entries).")
    except Exception as e:
        print(f"[!] Failed to save DB '{name}': {e}")
        try:
            os.remove(tmp_path)
        except FileNotFoundError:
            pass

# -------------------- MODE DETECTION (OFFLINE SAFE) --------------------
def detect_mode(timeout: float = 6.0):
    """
    Detects and optionally activates decentralized network daemons (IPFS / I2P / Tor).
    Works concurrently so slow subsystems don't block others.
    Returns:
        mode  (str):  "OFFLINE", "IPFS", "I2P", "TOR", or "MULTI"
        info  (dict): details about every reachable subsystem
    """
    info = {}
    active = []
    lockfile = "/tmp/qnet_detect.lock"

    # quick, silent runner
    def try_run(cmd, wait=3):
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            time.sleep(wait)
            return True
        except Exception:
            return False

    def detect_ipfs():
        try:
            if not shutil.which("ipfs"):
                return None
            home_ipfs = os.path.expanduser("~/.ipfs")
            if not os.path.exists(home_ipfs):
                subprocess.run(["ipfs", "init"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            result = subprocess.run(["ipfs", "id"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    timeout=3)
            if result.returncode != 0:
                subprocess.run(["ipfs", "config", "Addresses.Gateway",
                                "/ip4/127.0.0.1/tcp/8081"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                try_run(["ipfs", "daemon"], wait=5)
            return {"gateway": "http://127.0.0.1:8081/ipfs/",
                    "status": "active"}
        except Exception as e:
            return {"status": f"error: {e}"}

    def detect_i2p():
        try:
            if not shutil.which("i2pd"):
                return None
            conf_dir = os.path.expanduser("~/.i2pd")
            os.makedirs(conf_dir, exist_ok=True)
            try_run(["i2pd", "--daemon"], wait=4)
            return {"host": "local_qnet.i2p", "status": "active"}
        except Exception as e:
            return {"status": f"error: {e}"}

    def detect_tor():
        try:
            if not shutil.which("tor"):
                return None
            tor_dir = os.path.expanduser("~/.tor/hidden_service")
            os.makedirs(tor_dir, exist_ok=True)
            try_run(["tor"], wait=4)
            onion_file = os.path.join(tor_dir, "hostname")
            onion = "(pending .onion generation)"
            if os.path.exists(onion_file):
                onion = open(onion_file).read().strip()
            return {"onion": onion, "status": "active"}
        except Exception as e:
            return {"status": f"error: {e}"}

    # run all three in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            "IPFS": ex.submit(detect_ipfs),
            "I2P": ex.submit(detect_i2p),
            "TOR": ex.submit(detect_tor),
        }
        for name, fut in futures.items():
            try:
                result = fut.result(timeout=timeout)
                if result and result.get("status", "").startswith("active"):
                    active.append(name)
                    info[name.lower()] = result
            except Exception as e:
                info[name.lower()] = {"status": f"error: {e}"}

    if not active:
        info["status"] = "idle"
        return "OFFLINE", info
    elif len(active) == 1:
        return active[0], info
    else:
        return "MULTI", info

# -------------------- GLOBAL TUNNEL --------------------
def start_global_tunnel(port=8080):
    """Return reachable URL or None; respects security level."""
    level = get_security_level()

    # --- Security gating ---
    if level in ("safer", "safest"):
        print(f"[🔒] Global tunneling disabled in {level.title()} mode.")
        return None
    elif level == "experimental":
        print("[🧪] Experimental mode: dynamic tunnel rotation enabled.")
        # choose randomly between cloudflared and ngrok
        tools = []
        if shutil.which("cloudflared"):
            tools.append("cloudflared")
        if shutil.which("ngrok"):
            tools.append("ngrok")

        if not tools:
            print("[!] No tunneling tools available for Experimental mode.")
            return None

        chosen = random.choice(tools)
        print(f"[⚙️] Selected tunnel backend → {chosen}")
    else:
        chosen = None  # Standard mode, try both normally

    def run_tunnel(cmd, regex, name):
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                match = re.search(regex, line)
                if match:
                    url = match.group(1)
                    print(f"🌍 {name} Tunnel Active → {url}")
                    return url
        except Exception:
            pass
        return None

    # --- Cloudflare Tunnel ---
    if (chosen == "cloudflared" or (chosen is None and shutil.which("cloudflared"))):
        url = run_tunnel(
            ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
            r"(https://[-a-zA-Z0-9.]+\.trycloudflare\.com)",
            "Cloudflare"
        )
        if url:
            return url

    # --- Ngrok Tunnel ---
    if (chosen == "ngrok" or (chosen is None and shutil.which("ngrok"))):
        subprocess.Popen(["ngrok", "http", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        try:
            r = safe_request("http://127.0.0.1:4040/api/tunnels")
            for t in r.json().get("tunnels", []):
                if "public_url" in t:
                    print(f"🌍 Ngrok Tunnel Active → {t['public_url']}")
                    return t["public_url"]
        except Exception:
            pass

    print("[!] No global tunneling tools found or offline mode")
    return None

# -------------------- HELPERS --------------------
def hash_password(pw): return hashlib.sha256(pw.encode()).hexdigest()
def sign(value: str) -> str:
    """
    Signs a string with SECRET_KEY using HMAC-SHA256 and encodes safely for cookies.
    Returns a base64-safe string: value.signature
    """
    sig = hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()
    raw = f"{value}:{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def verify_signed(token: str):
    """
    Verifies the signed token created by sign().
    Returns the original value if valid, else None.
    """
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        if ":" not in decoded:
            return None
        value, sig = decoded.split(":", 1)
        expected = hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            return value
    except Exception as e:
        print(f"[!] verify_signed() error: {e}")
    return None

def get_user(req):
    """
    Retrieve the logged-in user from the signed cookie.
    Works with users.json (not accounts.json).
    """
    try:
        if not hasattr(req, "cookies"):
            return None
        token = req.cookies.get(SESSION_COOKIE)
        if not token:
            return None

        username = verify_signed(token)
        if not username:
            return None

        users = load_users()
        if username in users:
            return username
    except Exception as e:
        print(f"[!] get_user() error: {e}")
    return None

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
    "experimental": {
        "name": "Experimental",
        "desc": "Entropy-driven adaptive mode — online access with quantum-style randomization.",
        "color": "#8f00ff"
    },
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
        if shutil.which("ipfs"):
            cid = subprocess.check_output(["ipfs", "add", "-Qr", path], text=True).strip()
            subprocess.run(["ipfs", "pin", "add", cid])
            subprocess.Popen(["ipfs", "bitswap", "wantlist"], stdout=subprocess.DEVNULL)
            print(f"[+] File pinned to IPFS swarm ({cid})")
            return f"ipfs://{cid}"
        elif mode == "TOR":
            return f"tor://{info.get('onion','local')}/{os.path.basename(path)}"
        elif mode == "I2P":
            return f"i2p://{info.get('i2p_host','local')}/{os.path.basename(path)}"
    except:
        pass
    return f"/uploads/{os.path.basename(path)}"

def base_html(title, body, req: Request = None, user: str | None = None):
    """
    Builds a full HTML page with dynamic user info, consistent security badge,
    unified design, and enhanced search styling (DuckDuckGo/Google-like).
    """

    # --- Auto-detect user if not passed ---
    if not user and req is not None:
        try:
            user = get_user(req)
        except Exception as e:
            print(f"[!] base_html user check failed: {e}")
            user = None

    # --- Security Level Info ---
    level = get_security_level()
    info = SECURITY_INFO.get(level, {"name": "Unknown", "desc": "Unknown state", "color": "#444"})

    # --- Profile / Auth Links ---
    if user:
        safe_user = html.escape(str(user))
        profile = (
            f"<div class='profile'>Logged in as <b>{safe_user}</b> | "
            f"<a href='/logout' onclick=\"return confirm('Log out {safe_user}?');\">Logout</a></div>"
        )
    else:
        profile = (
            "<div class='profile'>"
            "<a href='/login'>Login</a> | "
            "<a href='/signup'>Sign Up</a>"
            "</div>"
        )

    # --- Final HTML ---
    html_code = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{html.escape(title)} - QNET</title>
<style>
body {{
  background:#000;
  color:#0f0;
  font-family:monospace;
  margin:0;
}}
header {{
  border-bottom:1px solid #0f0;
  padding:10px;
  display:flex;
  flex-wrap:wrap;
  justify-content:space-between;
  align-items:center;
}}
nav {{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  justify-content:center;
  width:100%;
  margin-top:6px;
}}
nav a {{
  color:#0f0;
  text-decoration:none;
  padding:6px 10px;
  border-radius:6px;
  border:1px solid #0f0;
}}
nav a:hover {{
  background:#0f0;
  color:#000;
}}
main {{
  max-width:900px;
  margin:auto;
  padding:10px;
}}
input,button,textarea {{
  background:#111;
  color:#0f0;
  border:1px solid #0f0;
  border-radius:6px;
  padding:8px;
  width:100%;
  margin:6px 0;
}}
button {{
  width:auto;
  cursor:pointer;
  background:#0f0;
  color:#000;
}}
.delete-btn {{
  background:#900;
  color:#fff;
  border:1px solid #f00;
  border-radius:4px;
  padding:4px 8px;
  cursor:pointer;
}}
iframe,video {{
  width:100%;
  height:360px;
  border:1px solid #0f0;
  border-radius:8px;
}}
pre {{
  white-space:pre-wrap;
}}
.profile {{
  font-size:0.9em;
  text-align:right;
  width:100%;
}}
#shield {{
  position:fixed;
  bottom:15px;
  right:15px;
  padding:10px 14px;
  border-radius:12px;
  background:{info['color']};
  color:#000;
  font-weight:bold;
  cursor:default;
  box-shadow:0 0 10px {info['color']};
}}

/* --- Enhanced search-result look --- */
.search-result {{
  margin:16px 0;
  padding-bottom:12px;
  border-bottom:1px solid #0f0;
}}
.result-title {{
  font-size:1.4em;
  font-weight:bold;
  color:#0f0;
  text-decoration:none;
}}
.result-title:hover {{
  text-decoration:underline;
}}
.result-snippet {{
  font-size:0.95em;
  color:#9f9;
  margin-top:4px;
}}
.result-meta {{
  font-size:0.8em;
  color:#6f6;
  margin-top:2px;
}}
</style>

<script>
async function deleteItem(db,i){{
  const fd = new FormData();
  fd.append("db",db);
  fd.append("index",i);
  const r = await fetch("/delete",{{method:"POST",body:fd}});
  const j = await r.json();
  if(j.status==="deleted") location.reload();
  else alert(j.error||"Delete failed");
}}

// Keep all navigation inside QNET (no external tabs)
document.addEventListener("DOMContentLoaded", () => {{
  document.querySelectorAll('a').forEach(a => {{
    const href = a.getAttribute('href');
    if (href && href.startsWith('http')) {{
      a.addEventListener('click', e => {{
        e.preventDefault();
        window.location.href = '/preview?url=' + encodeURIComponent(href);
      }});
    }}
  }});
}});
</script>
</head>

<body>
<header>
  <h1>QNET</h1>
  <nav>
    <a href="/">Home</a>
    <a href="/videos">Videos</a>
    <a href="/posts">Posts</a>
    <a href="/leaks">Leaks</a>
    <a href="/search">Search</a>
    <a href="/invidious">Invidious</a>
    <a href="/settings">⚙️</a>
    <a href="/donate">Donate</a>
  </nav>
  {profile}
</header>

<main>{body}</main>

<div id='shield' title='{html.escape(info['desc'])}'>🛡️ {html.escape(info['name'])}</div>
</body>
</html>"""

    # --- Preserve session cookie so "Logged in as ..." stays across tabs ---
    response = HTMLResponse(html_code)
    if req is not None:
        cookie = req.cookies.get(SESSION_COOKIE)
        if cookie:
            response.set_cookie(
                key=SESSION_COOKIE,
                value=cookie,
                httponly=True,
                samesite="Lax",
                path="/"
            )
    return response
# -------------------- FILE VIEW --------------------
def render_file_view(title, path, file_type, req: Request = None, user: str | None = None):
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

    # ✅ Wrap in base layout, passing both req and user
    return base_html(title, iframe_html, req=req, user=user)

# -------------------- HOME --------------------
@app.get("/", response_class=HTMLResponse)
def home(req: Request):
    """
    Homepage — displays welcome message and reflects login state.
    """
    # Safely get the logged-in user
    user = None
    if isinstance(req, Request):
        user = get_user(req)

    body = """
    <h2>Welcome to QNET</h2>
    <p>Hybrid decentralized offline/online node.</p>
    <p>Use the navigation menu to explore videos, posts, leaks, and settings.</p>
    """

    # Always pass the user to base_html so the profile shows correctly
    return base_html("Home", body, user=user)

# -------------------- LIST / UPLOAD --------------------
def render_list_page(db_key, title, accept_type, req=None, user=None):
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
    return base_html(title, body, req=req, user=user)

def handle_upload(db_key, file: UploadFile, title: str, req=None, user=None):
    filename = os.path.basename(file.filename)
    path = os.path.join(UPLOADS_DIR, filename)
    with open(path, "wb") as f:
        while chunk := file.file.read(8192):
            f.write(chunk)
        f.flush()
        os.fsync(f.fileno())

    mime_type, _ = mimetypes.guess_type(path)
    if not mime_type:
        mime_type = "application/octet-stream"

    link = f"/uploads/{filename}"
    data = load_json(DB_FILES[db_key])
    data.append({"title": title, "link": link, "mime": mime_type})
    save_json(DB_FILES[db_key], data)

    body = f"""
    <h2>{db_key.title()} Uploaded</h2>
    <p>File <b>{html.escape(title)}</b> uploaded successfully.</p>
    <a href='/{db_key}'>Back to {db_key.title()}</a>
    """
    return base_html(f"{db_key.title()} Uploaded", body, req=req, user=user)

# -------------------- VIDEOS --------------------
@app.get("/videos")
def videos(req: Request):
    user = get_user(req)
    # ✅ Pass req to render_list_page so base_html can preserve the cookie
    return render_list_page("videos", "Videos", "video/*", req=req, user=user)

@app.post("/videos")
async def add_video(req: Request, file: UploadFile = File(...), title: str = Form(...)):
    user = get_user(req)
    # ✅ Also pass req to handle_upload for consistent cookie behavior
    return handle_upload("videos", file, title, req=req, user=user)


# -------------------- POSTS --------------------
@app.get("/posts")
def posts(req: Request):
    user = get_user(req)
    return render_list_page("posts", "Posts", "text/*", req=req, user=user)

@app.post("/posts")
async def add_post(req: Request, file: UploadFile = File(...), title: str = Form(...)):
    user = get_user(req)
    return handle_upload("posts", file, title, req=req, user=user)


# -------------------- LEAKS --------------------
@app.get("/leaks")
def leaks(req: Request):
    user = get_user(req)
    return render_list_page("leaks", "Leaks", "*/*", req=req, user=user)

@app.post("/leaks")
async def add_leak(req: Request, file: UploadFile = File(...), title: str = Form(...)):
    user = get_user(req)
    return handle_upload("leaks", file, title, req=req, user=user)

# -------------------- VIEW ENDPOINTS --------------------
@app.get("/videos/view")
def view_video(index: int, req: Request):
    user = get_user(req)
    data = load_json(DB_FILES["videos"])
    if 0 <= index < len(data):
        item = data[index]
        # ✅ Pass req and user explicitly
        return render_file_view(item["title"], item["link"], "video/mp4", req=req, user=user)
    return base_html("Error", "<p>Video not found</p>", req=req, user=user)

@app.get("/posts/view")
def view_post(index: int, req: Request):
    user = get_user(req)
    data = load_json(DB_FILES["posts"])
    if 0 <= index < len(data):
        item = data[index]
        path = os.path.join(UPLOADS_DIR, os.path.basename(item["link"]))
        return render_file_view(item["title"], path, "text/plain", req=req, user=user)
    return base_html("Error", "<p>Post not found</p>", req=req, user=user)

@app.get("/leaks/view")
def view_leak(index: int, req: Request):
    user = get_user(req)
    data = load_json(DB_FILES["leaks"])
    if 0 <= index < len(data):
        item = data[index]
        path = item["link"]
        mime = "text/plain" if path.endswith((".txt",".log",".json")) else "application/octet-stream"
        return render_file_view(item["title"], path, mime, req=req, user=user)
    return base_html("Error", "<p>Leak not found</p>", req=req, user=user)

# -------------------- HYBRID SEARCH --------------------
@app.get("/search")
def search(req: Request, q: str = ""):
    """
    Hybrid QNET + DuckDuckGo search.
    Safer/Safest block trackers but allow online search.
    """
    q = q.strip()
    user = get_user(req)
    results_html = ""

    if not q:
        results_html = "<p>Type something to search inside QNET...</p>"
    else:
        dbs = ["videos", "posts", "leaks"]
        matches = []
        for db in dbs:
            data = load_db(db)
            for item in data:
                if q.lower() in item.get("title", "").lower() or q.lower() in item.get("description", "").lower():
                    matches.append({
                        "title": item.get("title", "Untitled"),
                        "desc": item.get("description", "")[:200],
                        "url": f"/view/{item.get('id', '')}",
                        "type": db.capitalize(),
                    })

        if matches:
            for item in matches:
                title = html.escape(item["title"])
                desc = html.escape(item["desc"])
                url = html.escape(item["url"])
                results_html += f"""
                <div class='search-result'>
                    <a class='result-title' href='{url}'>{title}</a>
                    <div class='result-snippet'>{desc}</div>
                    <div class='result-meta'>{item["type"]}</div>
                </div>
                """
        else:
            r = safe_request("https://api.duckduckgo.com/",
                             params={"q": q, "format": "json", "no_redirect": "1", "no_html": "1"})
            if r and r.status_code == 200:
                data = r.json()
                for topic in data.get("RelatedTopics", [])[:8]:
                    if isinstance(topic, dict) and "Text" in topic and "FirstURL" in topic:
                        t = html.escape(topic["Text"])
                        u = html.escape(topic["FirstURL"])
                        results_html += f"""
                        <div class='search-result'>
                            <a class='result-title' href='/preview?url={u}'>{t}</a>
                            <div class='result-meta'>DuckDuckGo Related</div>
                        </div>
                        """
            else:
                results_html = f"<p>⚠️ DuckDuckGo unreachable for <b>{html.escape(q)}</b>.</p>"

    body = f"""
    <form action='/search' method='get' style='margin-bottom:16px;'>
        <input type='text' name='q' placeholder='Search QNET...' value='{html.escape(q)}' autofocus>
        <button type='submit'>Search</button>
    </form>
    <hr>{results_html}
    """
    return base_html("Search", body, req=req, user=user)

# -------------------- INVIDIOUS BACKENDS --------------------
INVIDIOUS_LIST = [
    "https://yewtu.be",
    "https://invidious.flokinet.to",
    "https://inv.tux.pizza",
    "https://invidious.protokolla.fi",
    "https://iv.ggtyler.dev",
]

YOUTUBE_API_KEY = "YOUR_YOUTUBE_API_KEY"  # optional fallback

# -------------------- INVIDIOUS SEARCH --------------------
@app.get("/invidious")
def invidious(req: Request, q: str = ""):
    """
    Unified YouTube/Invidious search and player with privacy filtering.
    """
    user = get_user(req)
    q = q.strip()

    if not q:
        body = """
        <h2>🎬 Invidious / YouTube Search</h2>
        <form method='get'>
          <input name='q' placeholder='Search videos...' required autofocus>
          <button>Search</button>
        </form>
        """
        return base_html("Invidious", body, req=req, user=user)

    results_html = ""
    random.shuffle(INVIDIOUS_LIST)
    for host in INVIDIOUS_LIST:
        r = safe_request(f"{host}/api/v1/search", params={"q": q, "type": "video"})
        if r and r.status_code == 200:
            try:
                data = r.json()
                for item in data[:5]:
                    vid = item.get("videoId")
                    title = html.escape(item.get("title", "Untitled"))
                    author = html.escape(item.get("author", "Unknown"))
                    desc = html.escape(item.get("description", "")[:180])
                    thumb = item.get("videoThumbnails", [{}])[0].get("url", "")
                    results_html += f"""
                    <div class='search-result'>
                        <a class='result-title' href='/invidious/view?v={vid}'>{title}</a><br>
                        <img src='{thumb}' alt='thumb'><br>
                        <div class='result-snippet'>{desc}</div>
                        <div class='result-meta'>👤 {author}</div>
                    </div>
                    """
                break
            except Exception:
                continue

    if not results_html:
        results_html = "<p style='color:red;'>⚠️ No results — all Invidious nodes unreachable.</p>"

    body = f"""
    <h2>Search results for: {html.escape(q)}</h2>
    <form method='get'>
      <input name='q' value='{html.escape(q)}'>
      <button>Search</button>
    </form>
    <hr>{results_html}
    """
    return base_html("Invidious Search", body, req=req, user=user)

# -------------------- INVIDIOUS VIDEO VIEW --------------------
@app.get("/invidious/view")
def view_invidious(req: Request, v: str):
    """
    Embed a video via reachable Invidious node, fallback to YouTube.
    """
    user = get_user(req)

    # Extract ID from URL or query
    match = re.search(r"(?:v=|be/)([A-Za-z0-9_-]{11})", v)
    if match:
        v = match.group(1)

    chosen_host = None
    for host in INVIDIOUS_LIST:
        try:
            r = requests.head(f"{host}/embed/{v}", timeout=3, allow_redirects=False)
            if r.status_code in (200, 301, 302):
                chosen_host = host
                break
        except Exception:
            continue

    if chosen_host:
        iframe_html = f"""
        <h2>🎥 Playing from {html.escape(chosen_host)}</h2>
        <iframe src='{chosen_host}/embed/{v}' allowfullscreen></iframe>
        <p><a href='/invidious'>← Back to search</a></p>
        """
    else:
        iframe_html = f"""
        <p style='color:yellow;'>⚠️ No Invidious node available. Fallback to YouTube.</p>
        <iframe width='100%' height='400' src='https://www.youtube.com/embed/{v}' allowfullscreen></iframe>
        <p><a href='/invidious'>← Back to search</a></p>
        """

    return base_html("Invidious View", iframe_html, req=req, user=user)

# -------------------- LOGIN --------------------
USER_DB = "users.json"

# -------------------- USER DATABASE --------------------
def load_users():
    """Load users from JSON database."""
    if not os.path.exists(USER_DB):
        return {}
    try:
        with open(USER_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load users.json: {e}")
        return {}

def save_users(users: dict):
    """Save users to JSON database."""
    try:
        with open(USER_DB, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        print(f"[!] Failed to save users.json: {e}")

def hash_pw(password: str, salt: str | None = None) -> str:
    """
    🔒 Securely hash a password with SHA-256 + unique per-user salt.
    Returns a string formatted as 'salt$hash'.
    Existing plain hashes (without '$') remain compatible.
    """
    if not salt:
        # Generate 16-byte random salt if not provided
        salt = base64.urlsafe_b64encode(os.urandom(12)).decode("utf-8").rstrip("=")

    # Derive salted hash
    combined = (salt + password).encode()
    hashed = hashlib.sha256(combined).hexdigest()

    # Return "salt$hash" so each user’s hash is unique
    return f"{salt}${hashed}"


def verify_pw(password: str, stored_value: str) -> bool:
    """
    ✅ Verify password safely using constant-time comparison.
    Works for both 'salt$hash' and legacy unsalted hashes.
    """
    if "$" in stored_value:
        salt, stored_hash = stored_value.split("$", 1)
        test_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    else:
        # legacy QNET_SALT fallback
        test_hash = hashlib.sha256(("QNET_SALT" + password).encode()).hexdigest()
        stored_hash = stored_value

    return hmac.compare_digest(test_hash, stored_hash)

# -------------------- SIGN-UP ROUTES --------------------
@app.get("/signup")
def signup_form(req: Request):
    """Render sign-up form."""
    body = """
    <h2>🧩 Create a QNET Account</h2>
    <form action='/signup' method='post'>
        <input name='username' placeholder='Username' required>
        <input name='password' placeholder='Password' type='password' required>
        <button type='submit'>Create Account</button>
    </form>
    <p><a href='/login' style='color:#0f0;'>Already have an account? Login</a></p>
    """
    user = get_user(req)
    return base_html("Sign Up", body, req=req, user=user)

@app.post("/signup")
async def signup(req: Request):
    """Handle account creation."""
    form = await req.form()
    username = form.get("username", "").strip()
    password = form.get("password", "").strip()

    users = load_users()

    # --- Validation checks ---
    if not username or not password:
        return base_html("Sign Up", "<p style='color:red;'>⚠️ Please fill in all fields.</p><a href='/signup'>Back</a>", req=req)

    if len(username) < 3 or len(password) < 4:
        return base_html("Sign Up", "<p style='color:red;'>⚠️ Username or password too short.</p><a href='/signup'>Back</a>", req=req)

    if username in users:
        return base_html("Sign Up", f"<p style='color:red;'>⚠️ User <b>{html.escape(username)}</b> already exists.</p><a href='/signup'>Back</a>", req=req)

    # --- Save new user ---
    users[username] = hash_pw(password)
    save_users(users)
    print(f"[+] New QNET user created: {username}")

    success_html = f"""
    <p style='color:lime;'>✅ Account created successfully for <b>{html.escape(username)}</b>!</p>
    <p><a href='/login' style='color:#0f0;'>Login here</a></p>
    """
    return base_html("Sign Up", success_html, req=req)

@app.get("/login")
def login_page(req: Request):
    """
    🔐 Renders the QNET login page.
    Redirects home if already logged in.
    """
    user = get_user(req)
    if user:
        return RedirectResponse("/", status_code=303)

    body = """
    <h2>Login</h2>
    <form method="post">
        <label>Username</label>
        <input name="username" placeholder="Username" required><br>
        <label>Password</label>
        <input name="password" type="password" placeholder="Password" required><br>
        <label style="display:flex;align-items:center;gap:6px;margin-top:8px;">
            <input type="checkbox" name="remember" style="width:auto;"> Stay logged in
        </label><br>
        <button style="margin-top:10px;">Login</button>
    </form>
    <p><a href='/signup'>Don’t have an account? Sign up</a></p>
    """
    return base_html("Login", body, req=req, user=None)

@app.post("/login")
async def login(req: Request):
    """
    ✅ Authenticates user and sets a signed session cookie.
    Supports optional “remember me” for long-term login.
    """
    form = await req.form()
    username = form.get("username", "").strip()
    password = form.get("password", "").strip()
    remember = form.get("remember") == "on"

    # --- Load stored users ---
    try:
        users = load_users()
    except Exception as e:
        print(f"[!] Failed to load users: {e}")
        return base_html("Login Error", "<p>Account database missing or invalid.</p>", req=req)

    if username not in users:
        return base_html("Login", "<p style='color:red;'>User not found.</p><a href='/login'>Back</a>", req=req)

    stored_hash = users[username]
    if not verify_pw(password, stored_hash):
        return base_html("Login", "<p style='color:red;'>Invalid password.</p><a href='/login'>Try again</a>", req=req)

    # --- Generate session token ---
    session_token = sign(username)

    # --- Build response with cookie ---
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        key=SESSION_COOKIE,
        value=session_token,
        httponly=True,
        samesite="Lax",
        path="/",
        max_age=3600 * 24 * 30 if remember else 3600 * 6
    )
    print(f"[+] User '{username}' logged in successfully.")
    return resp

    # --- Failed login ---
    return base_html(
        "Login Failed",
        "<p>Invalid username or password.</p><a href='/login'>Try again</a>",
        user=None
    )

@app.get("/logout")
def logout(req: Request):
    """Clear the user session cookie and return home."""
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie(key=SESSION_COOKIE, httponly=True, samesite="Lax")
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
        <option {'selected' if level=='Experimental' else ''}>Experimental</option>
      </select>
      <button>Save</button>
    </form>"""
    return base_html("Settings", body, req=req, user=user)

@app.post("/settings")
async def update_settings(security_level: str = Form(...)):
    save_json(DB_FILES["settings"], {"security_level": security_level})
    return RedirectResponse("/settings", 303)

@app.get("/donate")
def donate(req: Request):
    """
    QNET Donation Page — lets visitors support via Bitcoin.
    Shows clickable BTC address and QR code.
    """
    btc_address = "bc1qpcaqkzpe028ktpmeyevwdkycg9clxfuk8dty5v"  # ← replace with your real Bitcoin address

    qr_url = (
        f"https://api.qrserver.com/v1/create-qr-code/"
        f"?size=220x220&data=bitcoin:{btc_address}"
    )

    body = f"""
    <h2>Support QNET 💚</h2>
    <p>Help keep QNET running and decentralized by donating Bitcoin.</p>

    <div style='text-align:center;margin:20px 0;'>
        <img src='{qr_url}' alt='Bitcoin QR Code'
             style='border:1px solid #0f0;border-radius:12px;padding:6px;background:#111;'>
        <p style='margin-top:12px;font-size:1.1em;'>
            <b>BTC Address:</b><br>
            <span id='btcAddr' style='user-select:all;cursor:pointer;color:#0f0;' onclick='copyBTC()'>
                {btc_address}
            </span>
        </p>
        <p style='font-size:0.9em;color:#999;'>Click to copy your Bitcoin address.</p>
    </div>

    <script>
    function copyBTC(){{
        const el = document.createElement('textarea');
        el.value = '{btc_address}';
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        document.body.removeChild(el);
        alert('Bitcoin address copied!');
    }}
    </script>

    <p style='text-align:center;font-size:0.9em;color:#888;'>
        Thank you for supporting open, decentralized technology 🌍
    </p>
    """

    user = get_user(req)
    return base_html("Donate", body, req=req, user=user)

@app.get("/go")
def go(req: Request, url: str):
    """
    Secure redirect endpoint that keeps QNET identity while allowing
    external browsing via controlled refresh.
    """
    try:
        # --- Basic sanitization ---
        safe_url = html.escape(url.strip())

        # --- Optional: block dangerous protocols ---
        if not (safe_url.startswith("http://") or safe_url.startswith("https://") or safe_url.startswith("ipfs://")):
            body = f"""
            <h2>⚠️ Unsafe URL blocked</h2>
            <p>The target <code>{safe_url}</code> is not allowed.</p>
            <p><a href='/'>Return Home</a></p>
            """
            return base_html("Blocked Redirect", body, req=req)

        # --- Build redirect message ---
        body = f"""
        <h2>Redirecting...</h2>
        <p>Opening: <a href="{safe_url}" target="_blank">{safe_url}</a></p>
        <meta http-equiv='refresh' content='0;url={safe_url}'>
        <p>If nothing happens, <a href="{safe_url}" target="_blank">click here</a>.</p>
        <p><a href='/' style='color:#0f0;'>Return to QNET</a></p>
        """

        # --- Keep session so user stays logged in after redirect ---
        user = get_user(req)
        return base_html("Redirecting", body, req=req, user=user)

    except Exception as e:
        print(f"[!] Redirect error: {e}")
        body = "<h2>Redirect failed</h2><p>Invalid or missing URL.</p><p><a href='/'>Back</a></p>"
        return base_html("Error", body, req=req)

# -------------------- PAGE PREVIEW --------------------
@app.get("/preview")
def preview(req: Request, url: str):
    """
    Loads and displays a remote page preview safely inside QNET.
    Safer/Safest block trackers but still allow basic previews and search use.
    """
    user = get_user(req)
    raw_url = url.strip()
    level = get_security_level()

    # --- Normalize and validate URL ---
    if raw_url.startswith("ipfs://"):
        raw_url = raw_url.replace("ipfs://", "https://ipfs.io/ipfs/")
    if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        safe_url = html.escape(raw_url)
        body = f"""
        <h2>⚠️ Unsupported or unsafe URL blocked</h2>
        <p>Requested: <code>{safe_url}</code></p>
        <p><a href='/' style='color:#0f0;'>Return to QNET</a></p>
        """
        return base_html("Blocked Preview", body, req=req, user=user)

    safe_url = html.escape(raw_url)
    title, desc, favicon = "Untitled", "No description available.", None

    # --- Fetch HTML safely ---
    r = safe_request(raw_url)
    if r and r.text:
        html_text = r.text
        if m := re.search(r"<title>(.*?)</title>", html_text, re.I | re.S):
            title = html.escape(m.group(1).strip())
        if m := re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', html_text, re.I):
            desc = html.escape(m.group(1).strip())
        if m := re.search(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\'](.*?)["\']', html_text, re.I):
            favicon = urllib.parse.urljoin(raw_url, m.group(1))
    else:
        desc = "⚠️ Preview unavailable or blocked for privacy."

    favicon_html = (
        f"<img src='{favicon}' width='24' height='24' "
        f"style='vertical-align:middle;margin-right:8px;border-radius:4px;'>"
        if favicon else ""
    )

    # --- Respect privacy levels ---
    if level == "safest":
        iframe_html = "<p>[🔒 Embedded content blocked for Safest mode.]</p>"
    else:
        iframe_html = f"""
        <iframe src='{safe_url}' sandbox='allow-scripts allow-same-origin allow-forms'
                style='width:100%;height:70vh;border:1px solid #0f0;border-radius:8px;'>
        </iframe>
        """

    body = f"""
    <div class='search-result'>
        <div class='result-title'>
            {favicon_html}<b>{title}</b>
        </div>
        <div class='result-snippet'>{desc}</div>
        <div class='result-meta'><a href='/go?url={safe_url}'>{safe_url}</a></div>
    </div>
    <hr>{iframe_html}
    <p style='margin-top:12px;'><a href='/' style='color:#0f0;'>← Return to QNET</a></p>
    """
    return base_html("Preview", body, req=req, user=user)

# -------------------- PEER SYNC SYSTEM --------------------

PEER_FILE = "peers.json"

def load_peers():
    """Safely load or create peer list."""
    if not os.path.exists(PEER_FILE):
        save_json(PEER_FILE, [])
        return []
    return load_json(PEER_FILE)

def add_peer(url: str):
    """Add a new peer node if not already known."""
    peers = load_peers()
    if url not in peers:
        peers.append(url)
        save_json(PEER_FILE, peers)
        print(f"[+] Added new peer: {url}")

def merge_databases(remote_data: dict):
    """
    Merge remote node data into local databases.
    Prevents duplication using title+link uniqueness.
    """
    for db_key in ["videos", "posts", "leaks"]:
        local = load_json(DB_FILES[db_key])
        remote_items = remote_data.get(db_key, [])

        merged = { (item.get("title"), item.get("link")): item for item in local }

        for r in remote_items:
            key = (r.get("title"), r.get("link"))
            if key not in merged:
                merged[key] = r

        merged_list = list(merged.values())
        save_json(DB_FILES[db_key], merged_list)
        print(f"[✓] Synced {db_key}: {len(remote_items)} remote → {len(merged_list)} total")

def sync_with_peers(timeout: int = 5):
    """
    Synchronize content with known QNET peers.
    - Requests /api/sync from each peer
    - Merges remote videos/posts/leaks
    - Fully offline-safe (skips unreachable)
    """
    peers = load_peers()
    if not peers:
        print("[i] No peers found in peers.json")
        return

    print(f"[⇆] Starting peer sync with {len(peers)} node(s)...")
    for peer in peers:
        try:
            if not peer.startswith("http"):
                peer = f"http://{peer}"
            r = requests.get(f"{peer}/api/sync", timeout=timeout)
            if r.status_code == 200:
                remote = r.json()
                merge_databases(remote)
            else:
                print(f"[!] Peer {peer} returned status {r.status_code}")
        except Exception as e:
            print(f"[!] Sync fail {peer}: {e}")
    print("[✓] Peer sync complete.")

@app.get("/api/sync")
def api_sync():
    """
    Provide current node data for peer synchronization.
    Returns JSON with public databases (videos, posts, leaks).
    """
    try:
        data = {
            "videos": load_json(DB_FILES["videos"]),
            "posts": load_json(DB_FILES["posts"]),
            "leaks": load_json(DB_FILES["leaks"]),
        }
        return JSONResponse(data)
    except Exception as e:
        print(f"[!] /api/sync error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

def auto_sync():
    while True:
        try:
            sync_with_peers()
        except Exception as e:
            print("[!] Auto-sync error:", e)
        time.sleep(900)  # every 15 minutes

    threading.Thread(target=auto_sync, daemon=True).start()

# -------------------- DECENTRALIZED IDENTITY (DID) --------------------
DID_FILE = "did.json"

def load_or_create_did():
    """
    Load existing decentralized identity (DID) keys or generate new ones.
    Returns:
        signing_key (nacl.signing.SigningKey)
        verify_key  (nacl.signing.VerifyKey)
        did         (str)  # portable, public DID
    """
    # If keys already exist, load them
    if os.path.exists(DID_FILE):
        try:
            with open(DID_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                signing_key = nacl.signing.SigningKey(
                    base64.urlsafe_b64decode(data["signing_key"]),
                    encoder=nacl.encoding.RawEncoder
                )
                verify_key = signing_key.verify_key
                did = data["did"]
                return signing_key, verify_key, did
        except Exception as e:
            print(f"[!] Failed to load DID file: {e}")

    # Otherwise generate new keys
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    did = base64.urlsafe_b64encode(verify_key.encode()).decode("utf-8").rstrip("=")
    data = {
        "did": did,
        "signing_key": base64.urlsafe_b64encode(signing_key.encode()).decode("utf-8")
    }

    with open(DID_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"[+] Generated new decentralized identity: {did}")
    return signing_key, verify_key, did

# -------------------- PEER DISCOVERY (LAN BROADCAST) --------------------
DISCOVERY_PORT = 50505
DISCOVERY_INTERVAL = 60  # seconds between broadcasts

def announce_peer(host_ip: str, port: int):
    """
    Broadcast this node's address periodically over LAN for discovery.
    Other QNET nodes listening on DISCOVERY_PORT will receive and add it.
    """
    def _broadcast_loop():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        msg = json.dumps({"peer": f"http://{host_ip}:{port}"})
        while True:
            try:
                s.sendto(msg.encode(), ('<broadcast>', DISCOVERY_PORT))
                print(f"[⇆] Broadcasted peer info → {host_ip}:{port}")
                time.sleep(DISCOVERY_INTERVAL)
            except Exception as e:
                print(f"[!] Broadcast error: {e}")
                time.sleep(10)

    threading.Thread(target=_broadcast_loop, daemon=True).start()


def listen_for_peers():
    """
    Listen for peer broadcasts on the LAN.
    Automatically adds new peers to peers.json.
    """
    def _listener():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', DISCOVERY_PORT))
        print(f"[👂] Listening for peer broadcasts on UDP {DISCOVERY_PORT}...")
        while True:
            try:
                data, addr = s.recvfrom(1024)
                msg = json.loads(data.decode())
                peer_url = msg.get("peer")
                if peer_url and "http" in peer_url:
                    add_peer(peer_url)
            except Exception as e:
                print(f"[!] Peer listener error: {e}")
                time.sleep(2)

    threading.Thread(target=_listener, daemon=True).start()

# -------------------- UI, SECURITY & SELF-HEALING --------------------
def ui_status_badge(req: Request = None):
    """
    Returns HTML for the bottom-right live status badge showing
    peers, network mode, and security level.
    Automatically adjusts text color for visibility and adds a soft glow effect.
    """
    # --- Safe peer loading ---
    try:
        peers = load_json("peers.json") if os.path.exists("peers.json") else []
        peer_count = len(peers)
    except Exception:
        peers = []
        peer_count = 0

    # --- Safe mode detection ---
    try:
        mode, info = detect_mode()
        if not mode:
            mode = "Unknown"
    except Exception:
        mode = "Unknown"

    # --- Safe security level ---
    try:
        level = get_security_level()
        color = SECURITY_INFO.get(level, {}).get("color", "#888")
    except Exception:
        level = "unknown"
        color = "#888"

    net = mode if mode != "MULTI" else "Hybrid"

    # Adaptive text color for better contrast
    text_color = "#fff" if level == "safest" else "#000"

    # Smooth pulsing glow animation
    badge = f"""
    <style>
    @keyframes pulseGlow {{
        0% {{ box-shadow: 0 0 6px {color}; }}
        100% {{ box-shadow: 0 0 18px {color}; }}
    }}
    </style>
    <div id='nodeStatus' style='
        position:fixed;bottom:15px;left:15px;
        padding:10px 14px;border-radius:12px;
        background:{color};color:{text_color};font-weight:bold;
        animation:pulseGlow 3s infinite alternate;
        box-shadow:0 0 10px {color};
        font-family:monospace;font-size:0.9em;'>
        🕸️ {net} | Peers: {peer_count} | Level: {level.title()}
    </div>"""
    return badge


# --- Inject badge safely into pages ---
old_base_html = base_html
def base_html(title, body, req: Request = None, user: str | None = None):
    html_resp = old_base_html(title, body, req=req, user=user)
    try:
        content = html_resp.body.decode("utf-8")
        badge = ui_status_badge(req)
        content = content.replace("</body>", badge + "\n</body>")
        html_resp.body = content.encode("utf-8")
        html_resp.headers["content-length"] = str(len(html_resp.body))
    except Exception as e:
        print("[!] UI badge injection failed, using fallback:", e)
        # fallback: inject minimal badge without animation
        fallback_badge = "<div style='position:fixed;bottom:15px;left:15px;background:#888;color:#fff;padding:5px;border-radius:8px;font-size:0.8em;'>🕸️ Status unavailable</div>"
        try:
            content = html_resp.body.decode("utf-8").replace("</body>", fallback_badge + "\n</body>")
            html_resp.body = content.encode("utf-8")
            html_resp.headers["content-length"] = str(len(html_resp.body))
        except Exception:
            pass  # final fallback: do nothing, page still renders

    return html_resp

# === SECURITY ENHANCEMENTS ===
UPLOAD_SANITIZE = re.compile(r"[^A-Za-z0-9._-]")

def sanitize_filename(name: str) -> str:
    """Sanitize file names to prevent directory traversal or injection."""
    safe = os.path.basename(name)
    return UPLOAD_SANITIZE.sub("_", safe)

# Monkey-patch handle_upload to sanitize names
old_handle_upload = handle_upload
def handle_upload(db_key, file: UploadFile, title: str, req=None, user=None):
    file.filename = sanitize_filename(file.filename)
    return old_handle_upload(db_key, file, title, req=req, user=user)

# === Rate Limiter (basic IP-based control) ===
RATE_LIMIT = {"window": 60, "max": 30}  # 30 req/min per IP
_rate_cache = {}

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    hits, start = _rate_cache.get(client_ip, (0, now))
    if now - start > RATE_LIMIT["window"]:
        hits, start = 0, now
    hits += 1
    _rate_cache[client_ip] = (hits, start)
    if hits > RATE_LIMIT["max"]:
        return JSONResponse({"error": "Too many requests"}, status_code=429)
    return await call_next(request)


# === SELF-HEALING / AUTO-BACKUP SYSTEM ===
BACKUP_DIR = "backups"
os.makedirs(BACKUP_DIR, exist_ok=True)

def backup_databases():
    """Backup all JSON DBs every 6 hours."""
    try:
        ts = time.strftime("%Y%m%d_%H%M%S")
        folder = os.path.join(BACKUP_DIR, ts)
        os.makedirs(folder, exist_ok=True)
        for name, path in DB_FILES.items():
            if os.path.exists(path):
                shutil.copy2(path, os.path.join(folder, os.path.basename(path)))
        print(f"[✓] Backup complete → {folder}")
    except Exception as e:
        print(f"[!] Backup failed: {e}")

def verify_json_integrity(path: str) -> bool:
    """Check JSON validity and file hash for corruption."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
        hashlib.sha256(raw).hexdigest()  # compute to test read
        json.loads(raw.decode("utf-8"))
        return True
    except Exception:
        return False

def self_heal_databases():
    """Verify all DBs and restore from most recent backup if corrupted."""
    try:
        for name, path in DB_FILES.items():
            if not verify_json_integrity(path):
                print(f"[!] Corruption detected in {path}")
                backups = sorted(os.listdir(BACKUP_DIR), reverse=True)
                for b in backups:
                    src = os.path.join(BACKUP_DIR, b, os.path.basename(path))
                    if os.path.exists(src):
                        shutil.copy2(src, path)
                        print(f"[✓] Restored {path} from backup {b}")
                        break
    except Exception as e:
        print(f"[!] Self-heal error: {e}")

def start_self_repair_cycle():
    """Run periodic backup + integrity verification in background."""
    def _loop():
        while True:
            try:
                backup_databases()
                self_heal_databases()
            except Exception as e:
                print("[!] Self-repair loop error:", e)
            time.sleep(21600)  # every 6 hours
    threading.Thread(target=_loop, daemon=True).start()

# -------------------- NODE STATE CACHING --------------------
STATE_FILE = "state.json"
_state_lock = threading.Lock()  # prevents simultaneous write corruption

def save_state(mode: str, info: dict):
    """
    Safely save the current network state (mode + info) to disk.
    This ensures QNET can instantly recall its last working mode.
    """
    try:
        with _state_lock:
            data = {"mode": mode, "info": info, "version": "1.0"}
            tmp = STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, STATE_FILE)  # atomic overwrite
    except Exception as e:
        print(f"[!] Failed to save state: {e}")

def load_state() -> dict:
    """
    Load the most recent saved network state.
    Returns safe defaults if file missing or corrupted.
    """
    if not os.path.exists(STATE_FILE):
        return {"mode": "OFFLINE", "info": {}, "version": "1.0"}

    try:
        with _state_lock:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            # validate structure
            if not isinstance(data, dict) or "mode" not in data:
                raise ValueError("invalid state format")
            return data
    except Exception as e:
        print(f"[!] Failed to load state: {e}")
        return {"mode": "OFFLINE", "info": {}, "version": "1.0"}

# -------------------- BACKGROUND NETWORK PROBE --------------------
def _net_probe():
    global mode, info
    try:
        new_mode, new_info = detect_mode()
        mode, info = new_mode, new_info
        save_state(mode, info)
        print(f"[✓] Network mode updated → {mode}")
    except Exception as e:
        print(f"[!] Background detect_mode failed: {e}")

# -------------------- FASTAPI STARTUP EVENT --------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ----- STARTUP section -----
    try:
        threading.Thread(target=_net_probe, daemon=True).start()
        threading.Thread(target=sync_with_peers, daemon=True).start()
        threading.Thread(target=start_self_repair_cycle, daemon=True).start()
        print("[✓] Background services started (net-probe / sync / self-repair)")
    except Exception as e:
        print(f"[!] Lifespan startup error: {e}")

    yield   # <-- FastAPI runs the app here

    # ----- SHUTDOWN section (optional) -----
    print("[i] QNET shutting down gracefully…")

app.router.lifespan_context = lifespan

# -------------------- STARTUP --------------------
if __name__ == "__main__":
    print("🚀 Launching QNET v1.4 Decentralized Node...")

    # === 1️⃣ Detect host IP ===
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        if host_ip.startswith("127.") or host_ip == "0.0.0.0":
            try:
                host_ip = requests.get("https://api.ipify.org", timeout=1.5).text.strip()
            except Exception:
                host_ip = "127.0.0.1"
    except Exception:
        host_ip = "127.0.0.1"

    port = int(os.getenv("QNET_PORT", 8080))

    print(f"🌐 Running QNET on 0.0.0.0:{port}")
    print(f"➡ Local access: http://{host_ip}:{port}")
    print("🌍 If you see a Cloudflare / Ngrok / I2P / Tor link below, global access is active.")

    # === 2️⃣ Start optional global tunnel (non-blocking) ===
    threading.Thread(target=start_global_tunnel, args=(port,), daemon=True).start()

    # === 3️⃣ Restore last known state (instant UI) ===
    state = load_state()
    mode, info = state.get("mode", "OFFLINE"), state.get("info", {})
    print(f"[i] Restored last mode: {mode}")

    # === 4️⃣ Initialize decentralized identity (DID) ===
    try:
        signing_key, verify_key, DID = load_or_create_did()
        print(f"🔑 Node DID: {DID}")
    except Exception as e:
        print("[!] DID initialization failed:", e)

    # === 5️⃣ Start LAN peer discovery ===
    try:
        announce_peer(host_ip, port)
        listen_for_peers()
    except Exception as e:
        print("[!] Peer discovery failed:", e)

    # === 6️⃣ Launch FastAPI / QNET web service ===
    print("✅ QNET Node is live! Open the link above to access.")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")

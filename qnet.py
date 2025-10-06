#!/usr/bin/env python3
import os, json, html, shutil, subprocess, threading, hashlib, secrets, socket, requests, urllib3, re, time, mimetypes, hmac, base64
from fastapi import FastAPI, UploadFile, File, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
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
def detect_mode():
    mode, info = "OFFLINE", {}

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
            # Ensure repo exists
            home_ipfs = os.path.expanduser("~/.ipfs")
            if not os.path.exists(home_ipfs):
                subprocess.run(["ipfs", "init"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Check if daemon is running
            result = subprocess.run(["ipfs", "id"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            if result.returncode != 0:
                # Change gateway port to avoid QNET conflict
                subprocess.run(["ipfs", "config", "Addresses.Gateway", "/ip4/127.0.0.1/tcp/8081"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try_run(["ipfs", "daemon"], wait=6)

            mode = "IPFS"
            info["ipfs_gateway"] = "http://127.0.0.1:8081/ipfs/"
            info["status"] = "active"

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
            if os.path.exists(onion_file):
                info["onion"] = open(onion_file).read().strip()
            else:
                info["onion"] = "(pending .onion generation)"
            mode = "TOR"
            info["status"] = "active"

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
    Safely retrieves the logged-in user from a signed session cookie.
    Returns the username if valid, otherwise None.
    """
    try:
        if not hasattr(req, "cookies"):
            # Not a Request object
            return None

        c = req.cookies.get(SESSION_COOKIE)
        if not c:
            return None

        user = verify_signed(c)
        if not user:
            return None

        accounts = load_json(DB_FILES.get("accounts", "accounts.json"))
        if isinstance(accounts, list) and any(a.get("username") == user for a in accounts):
            return user

        return None
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

    # --- Profile Display ---
    if user:
        safe_user = html.escape(str(user))
        profile = (
            f"<div class='profile'>Logged in as <b>{safe_user}</b> | "
            f"<a href='/logout' onclick=\"return confirm('Log out {safe_user}?');\">Logout</a></div>"
        )
    else:
        profile = "<div class='profile'><a href='/login'>Login</a></div>"

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

// Open external links in a new tab but keep them inside QNET redirect
document.addEventListener("DOMContentLoaded", () => {{
  document.querySelectorAll('a[target="_blank"]').forEach(a => {{
    a.addEventListener("click", e => {{
      e.preventDefault();
      window.open(a.href, "_blank");
    }});
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
        return render_file_view(item["title"], item["link"], "video/mp4", user)
    return base_html("Error", "<p>Video not found</p>", req=req, user=user)

@app.get("/posts/view")
def view_post(index: int, req: Request):
    user = get_user(req)
    data = load_json(DB_FILES["posts"])
    if 0 <= index < len(data):
        item = data[index]
        path = os.path.join(UPLOADS_DIR, os.path.basename(item["link"]))
        return render_file_view(item["title"], path, "text/plain", user)
    return base_html("Error", "<p>Post not found</p>", req=req, user=user)

@app.get("/leaks/view")
def view_leak(index: int, req: Request):
    user = get_user(req)
    data = load_json(DB_FILES["leaks"])
    if 0 <= index < len(data):
        item = data[index]
        path = item["link"]
        mime = "text/plain" if path.endswith((".txt",".log",".json")) else "application/octet-stream"
        return render_file_view(item["title"], path, mime, user)
    return base_html("Error", "<p>Leak not found</p>", req=req, user=user)

# -------------------- SEARCH --------------------
@app.get("/search")
def search(req: Request, q: str = ""):
    """
    QNET local search engine — DuckDuckGo-style layout.
    Shows results from local uploads (videos, posts, leaks)
    and safely handles external links via /go.
    """
    q = q.strip().lower()
    results_html = ""

    if not q:
        results_html = "<p>Type something to search your local QNET files...</p>"
    else:
        dbs = ["videos", "posts", "leaks"]
        matches = []
        for db in dbs:
            data = load_db(db)
            for i, item in enumerate(data):
                if q in item.get("title", "").lower() or q in item.get("description", "").lower():
                    item_type = db.capitalize()
                    matches.append((item_type, item))

        if matches:
            for item_type, item in matches:
                title = html.escape(item.get("title", "Untitled"))
                desc = html.escape(item.get("description", "")[:180])
                link = f"/view/{item.get('id', '')}" if "id" in item else "#"
                date = html.escape(item.get("date", "Unknown"))
                results_html += f"""
                <div class='search-result'>
                    <a class='result-title' href='{link}'>{title}</a>
                    <div class='result-snippet'>{desc}</div>
                    <div class='result-meta'>{item_type} | {date}</div>
                </div>
                """
        else:
            # Instead of using DuckDuckGo externally, route to /go within QNET
            safe_q = html.escape(q)
            ddg_url = f"https://duckduckgo.com/?q={safe_q}"
            results_html = f"""
            <p>No local results found for <b>{safe_q}</b>.</p>
            <p>You can still search externally (opens in new tab):</p>
            <div class='search-result'>
              <a class='result-title' href='/go?url={ddg_url}' target='_blank'>Search the Web for "{safe_q}"</a>
              <div class='result-meta'>via DuckDuckGo (in QNET sandbox)</div>
            </div>
            """

    body = f"""
    <form action='/search' method='get'>
        <input type='text' name='q' placeholder='Search QNET...' value='{html.escape(q)}' autofocus>
        <button type='submit'>Search</button>
    </form>
    <hr>
    {results_html}
    """

    user = get_user(req)
    return base_html("Search", body, req=req, user=user)

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
    return base_html("Invidious", body, req=req, user=user)

@app.get("/invidious/view")
def view_invidious(req: Request, v: str):
    user = get_user(req)
    match = re.search(r"(?:v=|be/)([A-Za-z0-9_-]{11})", v)
    if match:
        v = match.group(1)

    chosen_host = None
    for host in INVIDIOUS_LIST:
        try:
            r = requests.get(f"{host}/embed/{v}", stream=True, allow_redirects=False, timeout=3)
            r.close()
            if r.status_code in (200,301,302):
                chosen_host = host
                break
        except:
            continue

    iframe_html = (f"<iframe src='{chosen_host}/embed/{v}' allowfullscreen></iframe>"
                   if chosen_host else f"<p>No reachable Invidious node.<br><a href='https://youtube.com/watch?v={v}'>YouTube</a></p>")

    return base_html("Invidious View", iframe_html, req=req, user=user)

# -------------------- LOGIN --------------------
@app.get("/login")
def login_page(req: Request):
    """
    Renders the login page.
    If already logged in, redirect to home.
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
    """
    return base_html("Login", body, user=None)   # explicitly pass None


@app.post("/login")
def login(
    req: Request,
    username: str = Form(...),
    password: str = Form(...),
    remember: bool = Form(False)
):
    """
    Authenticates user and sets a signed session cookie.
    Supports optional 'remember me' for longer session.
    """
    try:
        accounts = load_json(DB_FILES.get("accounts", "accounts.json"))
    except Exception as e:
        print(f"[!] Error loading accounts: {e}")
        return base_html("Login Error", "<p>Account database not found.</p>")

    # --- Credential check ---
    for acc in accounts:
        if acc.get("username") == username and acc.get("password") == hash_password(password):
            cookie_val = sign(username)
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie(
                key=SESSION_COOKIE,
                value=cookie_val,
                httponly=True,
                samesite="Lax",
                path="/",                     # 🔥 ensure cookie is visible to ALL routes
                max_age=3600 * 24 * 30 if remember else 3600 * 6  # 30 days or 6 hours
            )
            print(f"[+] User '{username}' logged in.")
            return resp

    # --- Failed login ---
    return base_html(
        "Login Failed",
        "<p>Invalid username or password.</p><a href='/login'>Try again</a>",
        user=None
    )

@app.get("/logout")
def logout(req: Request):
    """
    Logs out the current user by deleting their session cookie.
    Automatically redirects to the home page with a confirmation message.
    """
    user = get_user(req)

    # Create redirect response
    resp = RedirectResponse("/", status_code=303)

    # Explicitly clear the session cookie
    resp.delete_cookie(
        key=SESSION_COOKIE,
        httponly=True,
        samesite="Lax"
    )

    # Optional: clear any signed or session-related state
    if user:
        print(f"[-] User '{user}' logged out.")

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

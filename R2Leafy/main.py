import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Gateway")

app = FastAPI(title="CORE", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", "default-secret-key"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / "panel_state.json"
INDEX_HTML_FILE = BASE_DIR / "index.html"
BACKUP_DIR = BASE_DIR / "backups"

connections: dict = {}
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {
    "total_bytes": 0,
    "total_down": 0,
    "total_up": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

CUSTOM_DOMAIN: str = ""
CUSTOM_DOMAIN_LOCK = asyncio.Lock()

SESSION_COOKIE = "app_session"
SESSION_TTL = 60 * 60 * 24 * 7


def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()


AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

# ---- Panel persistent state (clients + subscription lab + advanced settings) ----
PANEL_STATE: dict = {
    "clients": {},
    "subClientSubscriptions": {},
    "settings": {
        "advanced": {
            "domainStrategy": "UseIP",
            "deepSniff": True,
            "sniffHttp": True,
            "sniffTls": True,
            "sniffQuic": True,
            "sniffFakedns": False,
            "bypassIr": False,
            "bypassRu": False,
            "bypassCn": False,
            "bypassLan": False,
            "dnsPrimary": "1.1.1.1",
            "dnsFallback": "8.8.8.8",
            "dnsCache": True,
            "mux": False,
            "muxConcurrency": 8,
            "logLevel": "warning",
            "accessLog": False,
        }
    },
}


def load_state():
    global PANEL_STATE
    try:
        if STATE_FILE.exists():
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                clients = data.get("clients", {})
                if isinstance(clients, dict):
                    PANEL_STATE["clients"] = clients
                if "subClientSubscriptions" in data and isinstance(data.get("subClientSubscriptions"), dict):
                    PANEL_STATE["subClientSubscriptions"] = data["subClientSubscriptions"]
                if isinstance(data.get("settings"), dict):
                    st = data["settings"]
                    if isinstance(st.get("advanced"), dict):
                        adv = dict(PANEL_STATE["settings"]["advanced"])
                        adv.update(st["advanced"])
                        PANEL_STATE["settings"]["advanced"] = adv
    except Exception as e:
        logger.warning("Failed to load panel state: %s", e)


def save_state():
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(PANEL_STATE, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        logger.warning("Failed to save panel state: %s", e)


async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token


async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True


async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)


async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token


async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass


@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    load_state()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"CORE started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())


@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()


def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")


def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def generate_vless_link(uuid: str, remark: str = "CORE", address: str = None) -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"


def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)


def compute_expiry(expiry_days) -> str:
    try:
        days = float(expiry_days or 0)
    except (TypeError, ValueError):
        days = 0
    if days <= 0:
        return ""
    return (datetime.now() + timedelta(days=days)).isoformat()


def is_expired(link) -> bool:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return False
    try:
        return datetime.now() >= datetime.fromisoformat(exp)
    except (TypeError, ValueError):
        return False


def expiry_epoch(link) -> int:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return 0
    try:
        return int(datetime.fromisoformat(exp).timestamp())
    except (TypeError, ValueError):
        return 0


async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            LINKS[CUSTOM_DOMAIN or get_domain()] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "max_connections": 0, "created_at": datetime.now().isoformat(), "active": True, "expiry": ""}


def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"


def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))


def remove_ip_from_link(uid: str, ip: str):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]:
            link_ip_map.pop(uid, None)


async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)


# ============================================================================
# HTML serving
# ============================================================================

def render_index(request: Request) -> str:
    html = INDEX_HTML_FILE.read_text(encoding="utf-8") if INDEX_HTML_FILE.exists() else "<h1>index.html missing</h1>"
    token = request.cookies.get(SESSION_COOKIE)
    logged_in = "false"
    if token:
        exp = SESSIONS.get(token)
        if exp is not None:
            if exp < time.time():
                SESSIONS.pop(token, None)
            else:
                logged_in = "true"
    return html.replace("{{PASS_SETUP}}", "true").replace("{{LOGGED_IN}}", logged_in)


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return HTMLResponse(content=render_index(request))


@app.get("/login")
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/")
    return HTMLResponse(content=render_index(request))


@app.get("/dashboard")
async def dashboard_page(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=render_index(request))


@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}


# ============================================================================
# Auth API
# ============================================================================

@app.post("/api/setup")
async def api_setup(request: Request):
    body = await request.json()
    password = str(body.get("pass") or body.get("password") or "")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(password)
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp


@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("pass") or body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp


@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/api/me")
async def api_me(request: Request):
    return {"authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))}


@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    return {"ok": True}


# ============================================================================
# State API (clients / subscription lab / advanced settings / telemetry)
# ============================================================================

def _link_to_client(uid: str, link: dict) -> dict:
    used_gb = round(link.get("used_bytes", 0) / (1024 ** 3), 4)
    limit_gb = round(link.get("limit_bytes", 0) / (1024 ** 3), 4)
    return {
        "id": uid,
        "name": link.get("label", uid),
        "utls": link.get("utls", "chrome"),
        "usage": used_gb,
        "limit": limit_gb,
        "expiry": link.get("expiry", ""),
        "status": 1 if link.get("active", True) else 0,
    }


def _import_client_state():
    """Merge PANEL_STATE['clients'] into LINKS so the relay/subscription work,
    without overwriting live usage counters."""
    for uid, c in PANEL_STATE["clients"].items():
        if not isinstance(c, dict):
            continue
        limit_bytes = int(float(c.get("limit", 0) or 0) * (1024 ** 3))
        existing = LINKS.get(uid) or {}
        LINKS[uid] = {
            "label": str(c.get("name") or uid),
            "utls": str(c.get("utls") or "chrome"),
            "limit_bytes": limit_bytes,
            "used_bytes": int(existing.get("used_bytes", 0)),
            "max_connections": int(c.get("max_connections", 0)),
            "created_at": existing.get("created_at", datetime.now().isoformat()),
            "active": bool(c.get("status", 1)),
            "expiry": str(c.get("expiry") or ""),
        }


def _snapshot_clients() -> list:
    return [_link_to_client(uid, link) for uid, link in LINKS.items()]


@app.get("/api/state")
async def get_state(_=Depends(require_auth)):
    _import_client_state()
    vm = psutil.virtual_memory()
    try:
        load_avg = list(psutil.getloadavg())
    except Exception:
        load_avg = [0.0, 0.0, 0.0]
    state = {
        "clients": _snapshot_clients(),
        "subClientSubscriptions": PANEL_STATE.get("subClientSubscriptions") or {},
        "settings": PANEL_STATE.get("settings") or {"advanced": {}},
    }
    logs = "\n".join(f"[{l.get('time')}] {l.get('error')}" for l in list(error_logs)[-25:])
    return {
        "ok": True,
        "state": state,
        "portDomain": get_domain(),
        "webDomain": get_domain(),
        "tcpCc": "bbr",
        "connections": len(connections),
        "totalRxGb": round(stats["total_down"] / (1024 ** 3), 4),
        "totalTxGb": round(stats["total_up"] / (1024 ** 3), 4),
        "speedDownMbps": round(_current_speed()[0], 2),
        "speedUpMbps": round(_current_speed()[1], 2),
        "loadAvg": load_avg,
        "ramMb": round(vm.used / (1024 ** 2), 1),
        "ramTotalMb": round(vm.total / (1024 ** 2), 1),
        "logs": logs,
    }


@app.put("/api/state")
async def put_state(request: Request, _=Depends(require_auth)):
    global PANEL_STATE
    body = await request.json()
    st = body.get("state") or {}
    # Persist advanced settings + subscription lab exactly as the frontend sent them.
    new_state = dict(PANEL_STATE)
    if isinstance(st.get("settings"), dict):
        adv = dict(PANEL_STATE.get("settings", {}).get("advanced", {}))
        incoming_adv = st["settings"].get("advanced")
        if isinstance(incoming_adv, dict):
            adv.update(incoming_adv)
        new_state["settings"] = {"advanced": adv}
    if "subClientSubscriptions" in st:
        new_state["subClientSubscriptions"] = st["subClientSubscriptions"] or {}
    PANEL_STATE = new_state

    # Reconcile clients into both PANEL_STATE and LINKS (preserving used_bytes).
    clients = st.get("clients")
    if isinstance(clients, list):
        reconciled = {}
        for c in clients:
            if not isinstance(c, dict):
                continue
            uid = str(c.get("id"))
            if not uid:
                continue
            reconciled[uid] = c
        PANEL_STATE["clients"] = reconciled
        # Remove clients that no longer exist, keeping used_bytes for existing ones.
        async with LINKS_LOCK:
            remove_uids = [u for u in list(LINKS.keys()) if u not in reconciled]
            for u in remove_uids:
                LINKS.pop(u, None)
        _import_client_state()
    save_state()
    return {"ok": True}


# ---- Logs action ----
@app.post("/api/action")
async def api_action(request: Request, _=Depends(require_auth)):
    body = await request.json()
    action = body.get("action")
    if action == "clear_logs":
        error_logs.clear()
        return {"ok": True}
    return {"ok": True}


# ============================================================================
# Backup / Import
# ============================================================================

@app.get("/api/backup")
async def export_backup(_=Depends(require_auth)):
    data = dict(PANEL_STATE)
    data["exported_at"] = datetime.now().isoformat()
    data["links"] = {u: dict(v) for u, v in LINKS.items()}
    content = json.dumps(data, ensure_ascii=False, indent=2)
    headers = {"Content-Disposition": 'attachment; filename="backup.json"'}
    return Response(content=content, headers=headers, media_type="application/json")


@app.post("/api/backup")
async def backup_panel(_=Depends(require_auth)):
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    fname = f"backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    path = BACKUP_DIR / fname
    data = dict(PANEL_STATE)
    data["exported_at"] = datetime.now().isoformat()
    data["links"] = {u: dict(v) for u, v in LINKS.items()}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "file": fname}


@app.post("/api/import")
async def import_backup(request: Request, _=Depends(require_auth)):
    global PANEL_STATE
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Invalid backup file")
    new_state = dict(PANEL_STATE)
    if isinstance(body.get("clients"), dict):
        new_state["clients"] = body["clients"]
    if isinstance(body.get("subClientSubscriptions"), dict):
        new_state["subClientSubscriptions"] = body["subClientSubscriptions"]
    if isinstance(body.get("settings"), dict):
        new_state["settings"] = body["settings"]
    PANEL_STATE = new_state
    if isinstance(body.get("links"), dict):
        async with LINKS_LOCK:
            for uid, v in body["links"].items():
                if isinstance(v, dict):
                    LINKS[str(uid)] = {
                        "label": str(v.get("label") or uid)[:60],
                        "utls": str(v.get("utls") or "chrome"),
                        "limit_bytes": int(float(v.get("limit_bytes") or 0)),
                        "used_bytes": int(float(v.get("used_bytes") or 0)),
                        "max_connections": int(v.get("max_connections") or 0),
                        "created_at": v.get("created_at") or datetime.now().isoformat(),
                        "active": bool(v.get("active", True)),
                        "expiry": v.get("expiry") or "",
                    }
    _import_client_state()
    save_state()
    return {"ok": True, "imported": len(PANEL_STATE.get("clients", {}))}


# ============================================================================
# Relay provisioning (Cloudflare Worker)
# ============================================================================

@app.post("/api/relay")
async def api_relay(request: Request, _=Depends(require_auth)):
    body = await request.json()
    token = str(body.get("token") or "").strip()
    origin = str(body.get("origin") or "").strip().replace("https://", "").replace("http://", "").rstrip("/")
    if not token:
        raise HTTPException(status_code=400, detail="Missing Cloudflare token")
    if not origin:
        raise HTTPException(status_code=400, detail="Missing origin")
    try:
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=30.0) as client:
            acct_resp = await client.get("https://api.cloudflare.com/client/v4/accounts", headers=headers)
            acct_data = acct_resp.json()
            if not acct_data.get("success"):
                raise HTTPException(status_code=400, detail="Invalid Cloudflare token")
            accounts = acct_data.get("result") or []
            if not accounts:
                raise HTTPException(status_code=400, detail="No Cloudflare account on this token")
            account_id = accounts[0]["id"]

            sub_resp = await client.get(f"https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/subdomain", headers=headers)
            sub_data = sub_resp.json()
            subdomain = (sub_data.get("result") or {}).get("subdomain")
            if not subdomain:
                raise HTTPException(status_code=400, detail="Worker subdomain not available on this account")

            name = f"r2leafy-relay-{secrets.token_hex(4)}"
            script = _relay_worker_js(origin)
            worker_url = f"https://{name}.{subdomain}.workers.dev"

            # Deploy script
            deploy = await client.put(
                f"https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts/{name}",
                headers={"Authorization": f"Bearer {token}"},
                content=script,
                params={"subdomain": subdomain},
            )
            if deploy.status_code not in (200, 201):
                raise HTTPException(status_code=502, detail="Failed to deploy worker")
            return {"ok": True, "relay": {"relay_url": worker_url, "name": name}}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Relay provisioning failed: {exc}")


def _relay_worker_js(origin: str) -> str:
    return f"""
addEventListener('fetch', event => {{
  event.respondWith(handle(event.request))
}})

async function handle(request) {{
  const url = new URL(request.url)
  const origin = '{origin}'
  const isWs = request.headers.get('upgrade')?.toLowerCase() === 'websocket'
  const scheme = isWs ? 'wss' : 'https'
  const target = new URL(scheme + '://' + origin + url.pathname + url.search)
  const newRequest = new Request(target, {{
    method: request.method,
    headers: request.headers,
    body: (request.method === 'GET' || request.method === 'HEAD') ? undefined : request.body,
    duplex: 'half'
  }})
  return fetch(newRequest)
}}
"""


# ============================================================================
# Subscription + VLESS relay engine (preserved from original backend)
# ============================================================================

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
    if is_expired(link):
        raise HTTPException(status_code=403, detail="link expired")
    sub_links = []
    server_link = generate_vless_link(uid, remark=f"CORE-{link['label']}-Server")
    sub_links.append(server_link)
    for i, addr in enumerate(CUSTOM_ADDRESSES):
        remark = f"CORE-{link['label']}-IP{i+1}"
        vless_link = generate_vless_link(uid, remark=remark, address=addr)
        sub_links.append(vless_link)
    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode()).decode()
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire={expiry_epoch(link)}"
    }
    return Response(content=encoded, headers=headers)


@app.get("/api/links/{uid}/sub")
async def get_subscription(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    vless_link = generate_vless_link(uid, remark=f"CORE-{link['label']}")
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    used_mb = round(used / (1024 * 1024), 2)
    limit_mb = round(limit / (1024 * 1024), 2) if limit > 0 else 0
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    remaining_mb = round((limit - used) / (1024 * 1024), 2) if limit > 0 else 0
    sub_content = f"""# Subscription
# Label: {link['label']}
# Used: {used_mb} MB / {limit_mb if limit > 0 else 'Unlimited'} MB
# Remaining: {remaining_mb if limit > 0 else 'Unlimited'} MB
# Usage: {pct}%
# Status: {'Active' if link['active'] else 'Disabled'}
# Expiry: {link.get('expiry', '')[:10] if link.get('expiry') else 'Unlimited'}
{vless_link}"""
    encoded = base64.b64encode(sub_content.encode()).decode()
    return {
        "subscription_url": f"{get_domain()}/api/links/{uid}/sub",
        "config": vless_link,
        "label": link["label"],
        "used_bytes": used,
        "limit_bytes": limit,
        "used_mb": used_mb,
        "limit_mb": limit_mb,
        "remaining_mb": remaining_mb,
        "usage_percent": pct,
        "active": link["active"],
        "sub_base64": encoded,
        "sub_text": sub_content,
    }


RELAY_BUF = 64 * 1024


async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]


async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if is_expired(link): return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]


async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n


async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1; stats["total_up"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass


async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_down"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass


@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link_data = LINKS.get(uuid)
            if link_data is None or not link_data["active"]:
                await websocket.close(code=1008, reason="link not found or disabled"); return
            if is_expired(link_data):
                await websocket.close(code=1008, reason="link expired"); return
            max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = client_ip in link_ip_map.get(uuid, set())
            if not already_connected:
                current = count_connections_for_link(uuid)
                if current >= max_conn:
                    await websocket.close(code=1008, reason="connection limit reached"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)
        size = len(first_chunk)
        stats["total_bytes"] += size; stats["total_requests"] += 1; stats["total_up"] += size
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size; stats["total_up"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload); await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid = info.get("uuid")
                ip = info.get("ip")
                if uid and ip:
                    has_other = any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values())
                    if not has_other:
                        remove_ip_from_link(uid, ip)


# ---- speed estimation (bytes/sec -> Mbps based on delta since last poll) ----
_SPEED_STATE = {"t": time.time(), "down": 0, "up": 0}


def _current_speed():
    now = time.time()
    dt = now - _SPEED_STATE["t"]
    if dt <= 0:
        dt = 1
    prev_down = int(stats["total_down"])
    prev_up = int(stats["total_up"])
    down_mbps = ((prev_down - _SPEED_STATE["down"]) * 8) / (dt * 1_000_000)
    up_mbps = ((prev_up - _SPEED_STATE["up"]) * 8) / (dt * 1_000_000)
    _SPEED_STATE.update({"t": now, "down": prev_down, "up": prev_up})
    return max(0.0, down_mbps), max(0.0, up_mbps)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])

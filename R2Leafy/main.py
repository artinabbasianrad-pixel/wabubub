import asyncio
import base64
import collections
import hashlib
import json
import logging
import os
import re
import secrets
import socket
import struct
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime, timedelta
from urllib.parse import quote, unquote

import httpx
import psutil
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("R2Leafy")

# ---------------------------------------------------------------------------
# Configuration & Environment
# ---------------------------------------------------------------------------
def get_listen_port() -> int:
    raw = os.environ.get("PORT", "8000")
    try:
        return int(raw)
    except (ValueError, TypeError):
        return 8000

_secret_key = os.environ.get("SECRET_KEY", "").strip()
if not _secret_key:
    # Railway may start the service before generated variables are attached.
    # Use a process-local strong key so health checks can come up; set SECRET_KEY
    # in Railway for stable sessions across restarts.
    _secret_key = secrets.token_urlsafe(48)
    logging.getLogger("R2Leafy").warning(
        "SECRET_KEY is not set; using a temporary process key. Configure SECRET_KEY in Railway for persistent sessions."
    )

CONFIG = {
    "port": get_listen_port(),
    "secret": _secret_key,
}

SESSION_COOKIE = "r2leafy_session"
SESSION_TTL = 60 * 60 * 24 * 7  # 7 days
STATE_FILE = os.environ.get("R2LEAFY_STATE_FILE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel_state.json")
INDEX_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

# Password setup is intentionally completed in the browser on first start.
# ADMIN_PASSWORD is not used as an automatic setup bypass; this matches G2Leafy's
# first-run flow and keeps the persisted panel state authoritative.
AUTH = {
    "password_hash": "",
    "pass_setup": False
}

SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

STATE_LOCK = asyncio.Lock()

# Real-time connection tracking
connections: dict = {}
connection_sockets: dict = {}
link_ip_map: dict = collections.defaultdict(set)

stats = {
    "total_bytes": 0,
    "rx_bytes": 0,
    "tx_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}

hourly_traffic: dict = collections.defaultdict(int)

_speed_tracker = {
    "last_time": time.time(),
    "last_rx": 0,
    "last_tx": 0,
    "down_mbps": 0.0,
    "up_mbps": 0.0,
}

CLIENTS: list = []
SUB_CLIENT_SUBSCRIPTIONS: dict = {}
SETTINGS: dict = {
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
}

CUSTOM_DOMAIN: str = ""
CUSTOM_ADDRESSES: list = []

http_client: httpx.AsyncClient | None = None
core_running: bool = True
RELAY_CONFIGS: dict[str, list[str]] = {}
INDEX_HTML_CACHE: str | None = None

# Embedded R2Leafy panel frontend
EMBEDDED_INDEX_HTML = '<!DOCTYPE html>\n<html lang="en">\n<head>\n    <meta charset="UTF-8">\n    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n    <title>R2Leafy</title>\n    <meta name="theme-color" content="#8b5cf6">\n    <link rel="icon" href="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 512 512\'><path fill=\'%238b5cf6\' d=\'M165.9 397.4c0 2-2.3 3.6-5.2 3.6-3.3.3-5.6-1.3-5.6-3.6 0-2 2.3-3.6 5.2-3.6 3-.3 5.6 1.3 5.6 3.6zm-31.1-4.5c-.7 2 1.3 4.3 4.3 4.9 2.6 1 5.6 0 6.2-2s-1.3-4.3-4.3-5.2c-2.6-.7-5.5.3-6.2 2.3zm44.2-1.7c-2.9.7-4.9 2.6-4.6 4.9.3 2 2.9 3.3 5.9 2.6 2.9-.7 4.9-2.6 4.6-4.6-.3-1.9-3-3.2-5.9-2.9zM244.8 8C106.1 8 0 113.3 0 252c0 110.9 69.8 205.8 169.5 239.2 12.8 2.3 17.3-5.6 17.3-12.1 0-6.2-.3-40.4-.3-61.4 0 0-70 15-84.7-29.8 0 0-11.4-29.1-27.8-36.6 0 0-22.9-15.7 1.6-15.4 0 0 24.9 2 38.6 25.8 21.9 38.6 58.6 27.5 72.9 20.9 2.3-16 8.8-27.1 16-33.7-55.9-6.2-112.3-14.3-112.3-110.5 0-27.5 7.6-41.3 23.6-58.9-2.6-6.5-11.1-33.3 2.6-67.9 20.9-6.5 69 27 69 27 20-5.6 41.5-8.5 62.8-8.5s42.8 2.9 62.8 8.5c0 0 48.1-33.6 69-27 13.7 34.7 5.2 61.4 2.6 67.9 16 17.7 25.8 31.5 25.8 58.9 0 96.5-58.9 104.2-114.8 110.5 9.2 7.9 17 22.9 17 46.4 0 33.7-.3 75.4-.3 83.6 0 6.5 4.6 14.4 17.3 12.1C428.2 457.8 496 362.9 496 252 496 113.3 383.5 8 244.8 8zM97.2 352.9c-1.3 1-1 3.3.7 5.2 1.6 1.6 3.9 2.3 5.2 1 1.3-1 1-3.3-.7-5.2-1.6-1.6-3.9-2.3-5.2-1zm-10.8-8.1c-.7 1.3.3 2.9 2.3 3.9 1.6 1 3.6.7 4.3-.7.7-1.3-.3-2.9-2.3-3.9-2-.6-3.6-.3-4.3.7zm32.4 35.6c-1.6 1.3-1 4.3 1.3 6.2 2.3 2.3 5.2 2.6 6.5 1 1.3-1.3.7-4.3-1.3-6.2-2.2-2.3-5.2-2.6-6.5-1zm-11.4-14.7c-1.6 1-1.6 3.6 0 5.9 1.6 2.3 4.3 3.3 5.6 2.3 1.6-1.3 1.6-3.9 0-6.2-1.4-2.3-4-3.3-5.6-2z\'/></svg>" />\n    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">\n    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">\n    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>\n    <style>\n        :root {\n            --bg-base: #09090b; --bg-panel: #121214; --bg-hover: #1f1f22; --bg-active: #27272a;\n            --border: rgba(255, 255, 255, 0.08); --border-hover: rgba(255, 255, 255, 0.15);\n            --text-main: #fafafa; --text-muted: #a1a1aa;\n            --accent: #8b5cf6; --accent-hover: #7c3aed; --accent-bg: rgba(139, 92, 246, 0.15);\n            --danger: #ef4444; --danger-bg: rgba(239, 68, 68, 0.12);\n            --warning: #f59e0b; --warning-bg: rgba(245, 158, 11, 0.12);\n            --info: #3b82f6; --info-bg: rgba(59, 130, 246, 0.12);\n            --purple: #8b5cf6; --purple-bg: rgba(139, 92, 246, 0.12);\n            --radius-lg: 16px; --radius-md: 12px; --radius-sm: 8px;\n            --transition: all 0.2s cubic-bezier(0.2, 0.8, 0.2, 1);\n        }\n        * { margin: 0; padding: 0; box-sizing: border-box; outline: none; -webkit-tap-highlight-color: transparent; user-select: none; -webkit-user-select: none; }\n        ::selection { background: rgba(139, 92, 246, 0.35); color: #fff; }\n        input, textarea, select, .mono, pre, code, #log-output, td, .form-label, th, p { user-select: text !important; -webkit-user-select: text !important; }\n        .btn, .nav-item, .custom-checkbox, .switch { user-select: none !important; -webkit-user-select: none !important; }\n\n        body { background-color: var(--bg-base); color: var(--text-main); font-family: \'Plus Jakarta Sans\', sans-serif; font-size: 14px; display: flex; height: 100vh; min-height: 100vh; width: 100vw; overflow: hidden; -webkit-font-smoothing: antialiased; }\n\n        h1, h2, h3, h4, h5 { font-weight: 700; letter-spacing: -0.01em; color: var(--text-main); }\n        .mono { font-family: \'JetBrains Mono\', monospace; }\n\n        .text-accent { color: var(--accent) !important; }\n        .text-info { color: var(--info) !important; }\n        .text-warning { color: var(--warning) !important; }\n        .text-danger { color: var(--danger) !important; }\n        .text-purple { color: var(--purple) !important; }\n\n        ::-webkit-scrollbar { width: 4px; height: 4px; }\n        ::-webkit-scrollbar-track { background: transparent; }\n        ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.15); border-radius: 10px; }\n        ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.25); }\n\n        #loader { position: fixed; inset: 0; background: var(--bg-base); z-index: 99999; display: flex; justify-content: center; align-items: center; transition: opacity 0.4s ease, visibility 0.4s; }\n        .spinner-ring { width: 40px; height: 40px; border: 3px solid var(--border-hover); border-top: 3px solid var(--accent); border-radius: 50%; animation: spin 0.85s linear infinite; }\n        @keyframes spin { 100% { transform: rotate(360deg); } }\n\n        .sidebar { width: 260px; background-color: var(--bg-panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; z-index: 100; transition: var(--transition); flex-shrink: 0; }\n        .logo-box { height: 60px; display: flex; align-items: center; gap: 12px; padding: 0 24px; font-size: 1.15rem; font-weight: 800; color: #fff; flex-shrink: 0; border-bottom: 1px solid var(--border); background: var(--bg-base); }\n        .logo-box svg { width: 22px; height: 22px; fill: var(--accent); }\n        .nav-menu { flex: 1; overflow-y: auto; padding: 16px 12px; display: flex; flex-direction: column; gap: 6px; }\n        .nav-label { font-size: 0.65rem; text-transform: uppercase; color: var(--text-muted); font-weight: 800; letter-spacing: 0.08em; margin: 16px 0 8px 12px; }\n        .nav-item { padding: 12px 14px; border-radius: var(--radius-sm); cursor: pointer; display: flex; align-items: center; gap: 12px; color: var(--text-muted); font-weight: 600; transition: var(--transition); font-size: 0.85rem; }\n        .nav-item i { font-size: 1.05rem; width: 20px; text-align: center; pointer-events: none; transition: var(--transition); }\n        .nav-item:hover { background-color: var(--bg-hover); color: var(--text-main); }\n        .nav-item.active { background-color: var(--accent-bg); color: var(--accent); }\n        .nav-item.active i { color: var(--accent); }\n        .sidebar-footer { padding: 14px; text-align: center; font-size: 0.75rem; color: var(--text-muted); font-weight: 600; flex-shrink: 0; border-top: 1px solid var(--border); }\n        .sidebar-footer a:hover { color: var(--text-main) !important; }\n\n        .app-wrapper { flex: 1; display: flex; flex-direction: column; min-width: 0; background: var(--bg-base); height: 100vh; overflow: hidden; }\n        .topbar { height: 60px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: 0 24px; background-color: var(--bg-base); z-index: 50; flex-shrink: 0; }\n        .topbar.hidden { display: none; }\n        .mini-stats { display: flex; gap: 24px; font-weight: 600; font-size: 0.85rem; font-family: \'JetBrains Mono\', monospace; }\n        .mini-stat-item { display: flex; align-items: center; gap: 8px; }\n        .content-area { flex: 1; padding: 24px; display: flex; flex-direction: column; overflow: hidden; gap: 16px; }\n\n        .tab-view { display: none; flex-direction: column; flex: 1; min-height: 0; gap: 16px; animation: slideFadeUp 0.3s cubic-bezier(0.2, 0.8, 0.2, 1) forwards; overflow-y: auto; overflow-x: hidden; padding-right: 4px; padding-bottom: 20px; }\n        .tab-view.active { display: flex; }\n        @keyframes slideFadeUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }\n\n        .header-section { flex-shrink: 0; display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; flex-wrap: wrap; margin-bottom: 8px; }\n        .header-section h2 { font-size: 1.4rem; }\n        .header-section p { color: var(--text-muted); font-weight: 500; font-size: 0.85rem; margin-top: 6px; }\n\n        .btn, .btn-icon, .chart-filter-btn { cursor: pointer; }\n        .btn { background: var(--bg-hover); color: var(--text-main); border: 1px solid var(--border); padding: 8px 16px; border-radius: var(--radius-sm); font-size: 0.8rem; font-weight: 600; transition: var(--transition); display: inline-flex; align-items: center; justify-content: center; gap: 8px; font-family: inherit; box-shadow: 0 1px 2px rgba(0,0,0,0.2); height: 38px; }\n        .btn:hover:not(:disabled) { background: var(--bg-active); border-color: var(--border-hover); transform: translateY(-1px); }\n        .btn:active:not(:disabled) { transform: translateY(1px); }\n        .btn:disabled { opacity: 0.5; cursor: not-allowed; }\n        .btn-primary { background: var(--accent); color: #000; border: none; box-shadow: 0 4px 12px rgba(139, 92, 246, 0.2); }\n        .btn-primary:hover:not(:disabled) { background: var(--accent-hover); color: #fff; box-shadow: 0 4px 12px rgba(139, 92, 246, 0.4); }\n        .btn-danger { background: var(--danger-bg); color: var(--danger); border: none; }\n        .btn-danger:hover:not(:disabled) { background: var(--danger); color: #fff; }\n        .btn-icon { padding: 6px; width: 38px; height: 38px; border-radius: var(--radius-sm); border: 1px solid transparent; display: inline-flex; align-items: center; justify-content: center; background: var(--bg-hover); color: var(--text-muted); transition: var(--transition); box-shadow: none; }\n        .btn-icon:hover { background: var(--bg-active); color: var(--text-main); transform: translateY(0); }\n        .btn-icon.btn-danger { background: transparent; color: var(--danger); }\n        .btn-icon.btn-danger:hover { background: var(--danger-bg); }\n\n        .panel { background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius-md); display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.2); }\n        .panel-full { flex: 1; min-height: 0; }\n        .panel-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-shrink: 0; background: rgba(255,255,255,0.02); min-height: 64px; }\n        .panel-title { font-size: 0.95rem; font-weight: 700; display: flex; align-items: center; gap: 10px; }\n        .panel-body { padding: 20px; flex: 1; min-height: 0; display: flex; flex-direction: column; overflow-y: auto; }\n        .panel-body-unpadded { padding: 0; flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden; }\n\n        .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; flex-shrink: 0; }\n        .grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; flex-shrink: 0; }\n        .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; flex-shrink: 0; }\n        .grid-settings { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; flex-shrink: 0; align-items: stretch; }\n        .grid-settings .panel { min-width: 0; }\n        .grid-1-2 { display: grid; grid-template-columns: 1fr 2fr; gap: 16px; flex-shrink: 0; }\n\n        .metric-card { background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 20px; display: flex; flex-direction: column; gap: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.2); position: relative; overflow: hidden; }\n        .metric-title { font-size: 0.75rem; color: var(--text-muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; display: flex; justify-content: space-between; align-items: center; z-index: 2; }\n        .metric-val { font-size: 2rem; font-weight: 800; color: var(--text-main); display: flex; align-items: baseline; gap: 8px; letter-spacing: -0.02em; z-index: 2; }\n        .metric-sub { font-size: 0.85rem; color: var(--text-muted); font-weight: 600; }\n\n        .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }\n        .form-group { display: flex; flex-direction: column; gap: 8px; margin-bottom: 4px; }\n        .form-label { color: var(--text-muted); font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px; }\n        .form-control { width: 100%; padding: 8px 12px; background: var(--bg-hover); border: 1px solid var(--border); color: var(--text-main); border-radius: var(--radius-sm); font-size: 0.85rem; transition: var(--transition); font-family: inherit; font-weight: 500; height: 38px; }\n        textarea.form-control { height: auto; }\n        .form-control:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-bg); background: var(--bg-active); }\n        input.form-control:read-only, input.form-control:disabled, textarea.form-control:read-only, textarea.form-control:disabled { background: var(--bg-base); color: var(--text-muted); cursor: not-allowed; opacity: 1; border-color: transparent; }\n        select.form-control { -webkit-appearance: none; appearance: none; cursor: pointer; background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%23a1a1aa\' stroke-width=\'2\' stroke-linecap=\'round\' stroke-linejoin=\'round\'%3e%3cpolyline points=\'6 9 12 15 18 9\'%3e%3c/polyline%3e%3c/svg%3e"); background-repeat: no-repeat; background-position: right 14px center; background-size: 14px; padding-right: 36px; }\n        select.form-control:not(:disabled) { color: var(--text-main) !important; background-color: var(--bg-hover) !important; }\n        select.form-control option { background-color: #1f1f22; color: #fafafa; }\n\n        .input-group { display: flex; gap: 8px; }\n        .switch { position: relative; display: inline-block; width: 38px; height: 20px; flex-shrink: 0; cursor: pointer; }\n        .switch input { opacity: 0; width: 0; height: 0; }\n        .slider { position: absolute; inset: 0; background-color: var(--bg-hover); border: 1px solid var(--border); transition: 0.3s ease; border-radius: 20px; }\n        .slider:before { position: absolute; content: ""; height: 14px; width: 14px; left: 2px; bottom: 2px; background-color: var(--text-muted); border-radius: 50%; transition: 0.3s ease; }\n        input:checked + .slider { background-color: var(--accent); border-color: var(--accent); }\n        input:checked + .slider:before { transform: translateX(18px); background-color: #fff; }\n\n        .table-wrap { flex: 1; overflow-y: auto; overflow-x: auto; background: var(--bg-panel); min-height: 0; }\n        table { width: 100%; border-collapse: collapse; text-align: left; white-space: nowrap; font-size: 0.85rem; }\n        th { position: sticky; top: 0; background: var(--bg-hover); color: var(--text-muted); font-weight: 700; font-size: 0.7rem; padding: 12px 20px; text-transform: uppercase; letter-spacing: 0.05em; z-index: 10; border-bottom: 1px solid var(--border); box-shadow: 0 1px 0 var(--border); }\n        td { padding: 14px 20px; border-bottom: 1px solid var(--border); font-weight: 500; vertical-align: middle; }\n        tr:last-child td { border-bottom: none; }\n        tr:hover td { background: rgba(255, 255, 255, 0.03); }\n\n        .tag { padding: 4px 10px; border-radius: 6px; font-size: 0.65rem; font-weight: 700; text-transform: uppercase; display: inline-flex; align-items: center; letter-spacing: 0.05em; }\n        .tag-green { background: var(--accent-bg); color: var(--accent); }\n        .tag-red { background: var(--danger-bg); color: var(--danger); }\n        .tag-blue { background: var(--info-bg); color: var(--info); }\n        .tag-purple { background: var(--purple-bg); color: var(--purple); }\n        .tag-warn { background: var(--warning-bg); color: var(--warning); }\n\n        .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(5px); display: none; justify-content: center; align-items: center; z-index: 1000; opacity: 0; transition: opacity 0.25s; padding: 20px; }\n        .modal-overlay.show { display: flex; opacity: 1; }\n        .modal { background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius-md); width: 100%; max-width: 600px; transform: scale(0.95) translateY(15px); transition: transform 0.25s cubic-bezier(0.2, 0.8, 0.2, 1); display: flex; flex-direction: column; max-height: 100%; box-shadow: 0 24px 48px rgba(0,0,0,0.6); }\n        .modal-overlay.show .modal { transform: scale(1) translateY(0); }\n        .modal-header { padding: 18px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-shrink: 0; background: rgba(255,255,255,0.02); border-radius: var(--radius-md) var(--radius-md) 0 0; }\n        .modal-tabs { display: flex; border-bottom: 1px solid var(--border); background: var(--bg-panel); padding: 0 12px; flex-shrink: 0; }\n        .modal-tab-btn { background: transparent; border: none; color: var(--text-muted); padding: 14px 20px; font-weight: 700; font-size: 0.8rem; cursor: pointer; border-bottom: 2px solid transparent; transition: var(--transition); text-transform: uppercase; letter-spacing: 0.05em; }\n        .modal-tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }\n        .modal-body { padding: 24px; overflow-y: auto; flex: 1; gap: 16px; display: flex; flex-direction: column; }\n        .modal-tab-content { display: none; flex-direction: column; gap: 16px; }\n        .modal-tab-content.active { display: flex; animation: slideFadeUp 0.2s ease forwards; }\n        .modal-footer { padding: 18px 24px; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 12px; flex-shrink: 0; background: rgba(255,255,255,0.01); border-radius: 0 0 var(--radius-md) var(--radius-md); }\n\n        .chart-wrapper { position: relative; width: 100%; height: 100%; min-height: 0; min-width: 0; flex: 1; display: flex; align-items: center; justify-content: center; }\n        .terminal { background: #050505; color: #a1a1aa; padding: 20px; font-size: 0.8rem; line-height: 1.6; flex: 1; overflow-y: auto; border-radius: 0 0 var(--radius-md) var(--radius-md); user-select: text; white-space: pre-wrap; font-family: \'JetBrains Mono\', monospace; }\n\n        .toast-box { position: fixed; bottom: 24px; right: 24px; display: flex; flex-direction: column; gap: 12px; z-index: 9999; pointer-events: none; }\n        .toast { background: var(--bg-panel); border: 1px solid var(--border); padding: 14px 20px; border-radius: var(--radius-md); display: flex; align-items: center; gap: 12px; box-shadow: 0 12px 24px rgba(0,0,0,0.4); font-weight: 600; font-size: 0.85rem; pointer-events: auto; border-left: 4px solid var(--accent); animation: slideFadeUp 0.25s cubic-bezier(0.2, 0.8, 0.2, 1) forwards; color: var(--text-main); }\n\n        .qr-wrapper { background: #fff; padding: 20px; border-radius: var(--radius-sm); display: inline-block; border: 4px solid var(--bg-hover); margin: 0 auto; }\n\n        .settings-row { display: flex; justify-content: space-between; align-items: center; padding: 16px 0; border-bottom: 1px solid var(--border); gap: 16px; }\n        .settings-row:last-child { border-bottom: none; padding-bottom: 0; }\n        .settings-row:first-child { padding-top: 0; }\n        .settings-info h4 { font-size: 0.85rem; margin-bottom: 4px; color: var(--text-main); }\n        .settings-info p { font-size: 0.75rem; color: var(--text-muted); line-height: 1.4; }\n\n        .checkbox-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; width: 100%; }\n        .custom-checkbox { display: flex; align-items: center; gap: 10px; font-size: 0.8rem; font-weight: 600; color: var(--text-muted); cursor: pointer; transition: var(--transition); }\n        .custom-checkbox:hover { color: var(--text-main); }\n        .custom-checkbox input { accent-color: var(--accent); width: 16px; height: 16px; cursor: pointer; }\n\n        .mobile-toggle { display: none; background: none; border: none; color: var(--text-main); font-size: 1.2rem; cursor: pointer; padding: 4px; }\n\n        .sublab-layout { display: grid; grid-template-columns: 1fr 340px; gap: 20px; flex: 1; min-height: 500px; flex-shrink: 0; }\n        .sublab-editor { display: flex; flex-direction: column; gap: 16px; min-height: 0; overflow-y: auto; padding-right: 4px; }\n        .sublab-preview { display: flex; flex-direction: column; gap: 16px; min-height: 0; }\n\n        .phone-mockup-wrapper { display: flex; justify-content: center; overflow: hidden; flex: 1; min-height: 0; padding: 10px; }\n        .phone-mockup { background: #0a0a0c; border: 2px solid rgba(255,255,255,0.08); border-radius: 40px; display: flex; flex-direction: column; align-items: center; box-shadow: 0 24px 60px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.04); width: 100%; max-width: 300px; height: 100%; position: relative; overflow: hidden; }\n        .phone-notch { width: 130px; height: 26px; background: #0a0a0c; border-radius: 0 0 16px 16px; position: absolute; top: 0; left: 50%; transform: translateX(-50%); z-index: 10; }\n        .phone-screen { flex: 1; width: 100%; background: #111113; border-radius: 38px; display: flex; flex-direction: column; padding-top: 36px; min-height: 0; overflow: hidden; border: 8px solid #0a0a0c; }\n        .phone-config-list { flex: 1; overflow-y: auto; padding: 10px 12px; display: flex; flex-direction: column; gap: 8px; }\n\n        .phone-config-list::-webkit-scrollbar { width: 2px; }\n        .phone-config-list::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.1); border-radius: 4px; }\n        .phone-config-list:hover::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.3); }\n\n        .phone-item { position: relative; background: #1c1c1f; border-radius: 12px; padding: 12px 14px; display: flex; align-items: center; gap: 12px; cursor: default; border: 1px solid rgba(255,255,255,0.04); transition: var(--transition); }\n        .phone-item:hover { background: #222225; border-color: rgba(255,255,255,0.1); }\n        .phone-item.info-item { background: linear-gradient(135deg, rgba(139,92,246,0.08), rgba(59,130,246,0.04)); border-color: rgba(139,92,246,0.2); }\n        .phone-item-icon { width: 36px; height: 36px; border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; font-size: 0.85rem; background: rgba(0,0,0,0.2); }\n        .phone-item-body { flex: 1; min-width: 0; }\n        .phone-item-name { font-size: 0.75rem; font-weight: 700; color: #e4e4e7; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n        .phone-item-sub { font-size: 0.65rem; color: #71717a; margin-top: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n        .phone-item-action { margin-left: auto; opacity: 0; transition: var(--transition); }\n        .phone-item:hover .phone-item-action { opacity: 1; }\n\n        .sub-entry { background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 14px 16px; display: flex; align-items: flex-start; gap: 12px; cursor: grab; transition: var(--transition); }\n        .sub-entry:hover { border-color: var(--border-hover); box-shadow: 0 4px 12px rgba(0,0,0,0.2); }\n        .sub-entry-drag { color: var(--text-muted); font-size: 1rem; flex-shrink: 0; cursor: grab; padding-top: 6px; }\n        .sub-entry-body { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 8px; }\n        .sub-entry-type { font-size: 0.65rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em; }\n\n        .ph-chip { font-size: 0.68rem; font-family: \'JetBrains Mono\', monospace; color: var(--info); background: var(--info-bg); padding: 6px 8px; border-radius: 6px; cursor: pointer; border: 1px solid transparent; transition: var(--transition); user-select: none; text-align: center; font-weight: 600; }\n        .ph-chip:hover { border-color: var(--info); background: rgba(59,130,246,0.2); transform: translateY(-1px); }\n\n        .collapsible-header { cursor: pointer; }\n        .collapsible-header:hover { background: rgba(255,255,255,0.03); }\n        .collapsible-body { transition: max-height 0.25s ease, opacity 0.2s ease, padding 0.2s ease; overflow: hidden; }\n        .collapsible-body.collapsed { max-height: 0 !important; padding-top: 0 !important; padding-bottom: 0 !important; opacity: 0; }\n        .collapse-icon.collapsed { transform: rotate(180deg); }\n\n        @media (max-width: 1280px) { .content-area { padding: 16px; } }\n        @media (max-width: 1400px) { .grid-settings { grid-template-columns: repeat(3, 1fr); } }\n        @media (max-width: 1100px) { .grid-settings { grid-template-columns: repeat(2, 1fr); } }\n        @media (max-width: 1024px) {\n            .grid-4, .grid-3 { grid-template-columns: repeat(2, 1fr); }\n            .grid-settings { grid-template-columns: repeat(2, 1fr); }\n            .grid-1-2 { grid-template-columns: 1fr; }\n            .sidebar { position: fixed; left: -260px; top: 0; bottom: 0; box-shadow: 10px 0 30px rgba(0,0,0,0.6); }\n            .sidebar.open { left: 0; }\n            .mobile-toggle { display: block; }\n            .topbar { display: flex !important; }\n            .mini-stats { display: none !important; }\n            .content-area { padding: 16px; }\n        }\n        @media (max-width: 600px) {\n            .grid-4, .grid-3, .grid-2, .grid-settings, .form-grid { grid-template-columns: 1fr; }\n            .header-section { flex-direction: column; align-items: flex-start; }\n            .checkbox-grid { grid-template-columns: 1fr; }\n            .modal-tabs { overflow-x: auto; white-space: nowrap; }\n            .content-area { padding: 12px; }\n            .panel-header { padding: 14px 16px; }\n            .panel-body { padding: 16px; }\n            .table-wrap { overflow-x: auto; }\n            .sublab-layout { grid-template-columns: 1fr; }\n            .metric-val { font-size: 1.5rem; }\n            .phone-mockup-wrapper { min-height: 500px; flex: none; }\n        }\n    </style>\n</head>\n<body>\n    <div id="loader"><div class="spinner-ring"></div></div>\n\n    <div id="auth-overlay" class="modal-overlay" style="display:none; opacity:1; z-index:100000; background: var(--bg-base); flex-direction:column; justify-content:center; align-items:center;">\n        <div class="logo-box" style="margin-bottom:24px; border:none; background:transparent; padding:0;">\n            <svg viewBox="0 0 496 512" fill="var(--accent)"><path d="M165.9 397.4c0 2-2.3 3.6-5.2 3.6-3.3.3-5.6-1.3-5.6-3.6 0-2 2.3-3.6 5.2-3.6 3-.3 5.6 1.3 5.6 3.6zm-31.1-4.5c-.7 2 1.3 4.3 4.3 4.9 2.6 1 5.6 0 6.2-2s-1.3-4.3-4.3-5.2c-2.6-.7-5.5.3-6.2 2.3zm44.2-1.7c-2.9.7-4.9 2.6-4.6 4.9.3 2 2.9 3.3 5.9 2.6 2.9-.7 4.9-2.6 4.6-4.6-.3-1.9-3-3.2-5.9-2.9zM244.8 8C106.1 8 0 113.3 0 252c0 110.9 69.8 205.8 169.5 239.2 12.8 2.3 17.3-5.6 17.3-12.1 0-6.2-.3-40.4-.3-61.4 0 0-70 15-84.7-29.8 0 0-11.4-29.1-27.8-36.6 0 0-22.9-15.7 1.6-15.4 0 0 24.9 2 38.6 25.8 21.9 38.6 58.6 27.5 72.9 20.9 2.3-16 8.8-27.1 16-33.7-55.9-6.2-112.3-14.3-112.3-110.5 0-27.5 7.6-41.3 23.6-58.9-2.6-6.5-11.1-33.3 2.6-67.9 20.9-6.5 69 27 69 27 20-5.6 41.5-8.5 62.8-8.5s42.8 2.9 62.8 8.5c0 0 48.1-33.6 69-27 13.7 34.7 5.2 61.4 2.6 67.9 16 17.7 25.8 31.5 25.8 58.9 0 96.5-58.9 104.2-114.8 110.5 9.2 7.9 17 22.9 17 46.4 0 33.7-.3 75.4-.3 83.6 0 6.5 4.6 14.4 17.3 12.1C428.2 457.8 496 362.9 496 252 496 113.3 383.5 8 244.8 8zM97.2 352.9c-1.3 1-1 3.3.7 5.2 1.6 1.6 3.9 2.3 5.2 1 1.3-1 1-3.3-.7-5.2-1.6-1.6-3.9-2.3-5.2-1zm-10.8-8.1c-.7 1.3.3 2.9 2.3 3.9 1.6 1 3.6.7 4.3-.7.7-1.3-.3-2.9-2.3-3.9-2-.6-3.6-.3-4.3.7zm32.4 35.6c-1.6 1.3-1 4.3 1.3 6.2 2.3 2.3 5.2 2.6 6.5 1 1.3-1.3.7-4.3-1.3-6.2-2.2-2.3-5.2-2.6-6.5-1zm-11.4-14.7c-1.6 1-1.6 3.6 0 5.9 1.6 2.3 4.3 3.3 5.6 2.3 1.6-1.3 1.6-3.9 0-6.2-1.4-2.3-4-3.3-5.6-2z"/></svg>\n            <span style="font-size:1.8rem; font-weight:800; color:#fff;">R2Leafy<span style="color:var(--text-muted); font-weight:500;">Panel</span></span>\n        </div>\n        <div class="modal show" style="max-width: 420px; width: 100%; margin:0 20px; position:relative; transform:none; box-shadow:0 24px 60px rgba(0,0,0,0.8);">\n            <div class="modal-header" style="justify-content:center; padding:20px;"><div class="panel-title" id="auth-title" style="font-size:1.1rem;"><i class="fa-solid fa-lock text-accent"></i> Authentication Required</div></div>\n            <div class="modal-body" id="auth-body" style="padding:24px;"></div>\n        </div>\n    </div>\n\n    <aside class="sidebar" id="sidebar">\n        <div class="logo-box">\n            <svg viewBox="0 0 496 512" fill="var(--accent)"><path d="M165.9 397.4c0 2-2.3 3.6-5.2 3.6-3.3.3-5.6-1.3-5.6-3.6 0-2 2.3-3.6 5.2-3.6 3-.3 5.6 1.3 5.6 3.6zm-31.1-4.5c-.7 2 1.3 4.3 4.3 4.9 2.6 1 5.6 0 6.2-2s-1.3-4.3-4.3-5.2c-2.6-.7-5.5.3-6.2 2.3zm44.2-1.7c-2.9.7-4.9 2.6-4.6 4.9.3 2 2.9 3.3 5.9 2.6 2.9-.7 4.9-2.6 4.6-4.6-.3-1.9-3-3.2-5.9-2.9zM244.8 8C106.1 8 0 113.3 0 252c0 110.9 69.8 205.8 169.5 239.2 12.8 2.3 17.3-5.6 17.3-12.1 0-6.2-.3-40.4-.3-61.4 0 0-70 15-84.7-29.8 0 0-11.4-29.1-27.8-36.6 0 0-22.9-15.7 1.6-15.4 0 0 24.9 2 38.6 25.8 21.9 38.6 58.6 27.5 72.9 20.9 2.3-16 8.8-27.1 16-33.7-55.9-6.2-112.3-14.3-112.3-110.5 0-27.5 7.6-41.3 23.6-58.9-2.6-6.5-11.1-33.3 2.6-67.9 20.9-6.5 69 27 69 27 20-5.6 41.5-8.5 62.8-8.5s42.8 2.9 62.8 8.5c0 0 48.1-33.6 69-27 13.7 34.7 5.2 61.4 2.6 67.9 16 17.7 25.8 31.5 25.8 58.9 0 96.5-58.9 104.2-114.8 110.5 9.2 7.9 17 22.9 17 46.4 0 33.7-.3 75.4-.3 83.6 0 6.5 4.6 14.4 17.3 12.1C428.2 457.8 496 362.9 496 252 496 113.3 383.5 8 244.8 8zM97.2 352.9c-1.3 1-1 3.3.7 5.2 1.6 1.6 3.9 2.3 5.2 1 1.3-1 1-3.3-.7-5.2-1.6-1.6-3.9-2.3-5.2-1zm-10.8-8.1c-.7 1.3.3 2.9 2.3 3.9 1.6 1 3.6.7 4.3-.7.7-1.3-.3-2.9-2.3-3.9-2-.6-3.6-.3-4.3.7zm32.4 35.6c-1.6 1.3-1 4.3 1.3 6.2 2.3 2.3 5.2 2.6 6.5 1 1.3-1.3.7-4.3-1.3-6.2-2.2-2.3-5.2-2.6-6.5-1zm-11.4-14.7c-1.6 1-1.6 3.6 0 5.9 1.6 2.3 4.3 3.3 5.6 2.3 1.6-1.3 1.6-3.9 0-6.2-1.4-2.3-4-3.3-5.6-2z"/></svg>\n            R2Leafy<span style="color:var(--text-muted); font-weight:500;">Panel</span>\n        </div>\n        <div class="nav-menu">\n            <div class="nav-label">Core Analytics</div>\n            <div class="nav-item active" onclick="switchTab(\'dashboard\')"><i class="fa-solid fa-chart-pie"></i> Dashboard</div>\n            <div class="nav-label">Traffic Routing</div>\n            <div class="nav-item" onclick="switchTab(\'clients\')"><i class="fa-solid fa-users"></i> Client Profiles</div>\n            <div class="nav-item" onclick="switchTab(\'sublab\')"><i class="fa-solid fa-flask"></i> Subscription Lab</div>\n            <div class="nav-label">System</div>\n        </div>\n        <div class="sidebar-footer">\n            <div style="margin-bottom: 8px;">\n                Built with <i class="fa-solid fa-mug-hot text-accent"></i> by <a href="https://github.com/Code-Leafy" target="_blank" style="color:var(--text-main); text-decoration:none; font-weight:700;">Code-Leafy</a>\n            </div>\n            <div>\n                <a href="https://github.com/Code-Leafy/R2Leafy" target="_blank" style="color:var(--text-muted); text-decoration:none; transition: var(--transition); font-weight:700;"><i class="fa-brands fa-github"></i> R2Leafy</a>\n            </div>\n        </div>\n    </aside>\n\n    <main class="app-wrapper">\n        <header class="topbar hidden" id="main-topbar">\n            <button class="mobile-toggle" onclick="document.getElementById(\'sidebar\').classList.toggle(\'open\')"><i class="fa-solid fa-bars"></i></button>\n            <div class="mini-stats" id="mini-stats">\n                <div class="mini-stat-item" style="color:var(--accent)"><i class="fa-solid fa-arrow-down-long"></i> <span id="m-rx-mini">0.00</span> GB</div>\n                <div class="mini-stat-item" style="color:var(--info)"><i class="fa-solid fa-arrow-up-long"></i> <span id="m-tx-mini">0.00</span> GB</div>\n                <div class="mini-stat-item" style="color:var(--purple)"><i class="fa-solid fa-gauge-high"></i> <span id="m-speed-mini">0 / 0</span> Mbps</div>\n            </div>\n            <div id="topbar-xray-status" style="display:flex; align-items:center; gap:8px; font-size:0.78rem; font-weight:700; font-family:\'JetBrains Mono\',monospace;">\n                <span id="topbar-xray-dot" style="width:8px; height:8px; border-radius:50%; background:var(--accent); box-shadow:0 0 6px var(--accent); display:inline-block; flex-shrink:0; transition:background 0.3s, box-shadow 0.3s;"></span>\n                <span id="topbar-xray-label" style="color:var(--accent); transition:color 0.3s;">Xray ON</span>\n            </div>\n        </header>\n\n        <button class="mobile-toggle" style="position:absolute; top:16px; left:20px; z-index:40;" id="mobile-dash-btn" onclick="document.getElementById(\'sidebar\').classList.toggle(\'open\')"><i class="fa-solid fa-bars"></i></button>\n\n        <div class="content-area">\n\n            <div id="tab-dashboard" class="tab-view active">\n                <div class="header-section"><div><h2>System Dashboard</h2><p>Real-time telemetry and core engine controls.</p></div></div>\n                <div class="grid-4">\n                    <div class="metric-card"><div class="metric-title">Download <i class="fa-solid fa-arrow-down-long" style="color:var(--accent)"></i></div><div class="metric-val mono" id="m-rx">0.00 <span class="metric-sub">GB</span></div></div>\n                    <div class="metric-card"><div class="metric-title">Upload <i class="fa-solid fa-arrow-up-long" style="color:var(--info)"></i></div><div class="metric-val mono" id="m-tx">0.00 <span class="metric-sub">GB</span></div></div>\n                    <div class="metric-card"><div class="metric-title">Speed (DL/UL) <i class="fa-solid fa-gauge-high" style="color:var(--purple)"></i></div><div class="metric-val mono" id="m-speed">0 <span class="metric-sub">/ 0 Mbps</span></div></div>\n                    <div class="metric-card"><div class="metric-title">Core Uptime <i class="fa-solid fa-clock" style="color:var(--warning)"></i></div><div class="metric-val mono" id="m-uptime">0h 00m</div></div>\n                </div>\n\n                <div class="grid-2" style="flex: 1; min-height: 320px; flex-shrink: 0;">\n                    <div style="display:flex; flex-direction:column; gap:16px; flex: 1;">\n                        <div class="panel" style="flex: 1;">\n                            <div class="panel-header"><div class="panel-title"><i class="fa-solid fa-heart-pulse text-accent"></i> Health Overview</div></div>\n                            <div class="panel-body" style="gap: 16px; justify-content: center;">\n                                <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border); padding-bottom:12px;"><span style="color:var(--text-muted); font-weight:600; font-size:0.85rem;">Engine Status</span><span class="tag tag-red" id="dash-status-tag">Offline</span></div>\n                                <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border); padding-bottom:12px;"><span style="color:var(--text-muted); font-weight:600; font-size:0.85rem;">System Load Avg</span><span class="mono" id="dash-load-avg">0.00</span></div>\n                                <div style="display:flex; justify-content:space-between; align-items:center;"><span style="color:var(--text-muted); font-weight:600; font-size:0.85rem;">Memory Allocation</span><span class="mono" id="dash-mem-alloc">0 / 0 MB</span></div>\n                            </div>\n                        </div>\n                        <div class="panel">\n                            <div class="panel-header"><div class="panel-title"><i class="fa-solid fa-power-off text-info"></i> Power Control</div></div>\n                            <div class="panel-body" style="gap: 16px; justify-content: center;">\n                                <p style="color:var(--text-muted); font-size:0.8rem; line-height:1.5;">Restarting or stopping the core will immediately sever all active client connections.</p>\n                                <div style="display:flex; gap:12px;">\n                                    <button class="btn" style="flex:1; background:var(--accent-bg); color:var(--accent); border:none;" onclick="window.setXrayStatus(\'start\')"><i class="fa-solid fa-play"></i> Start</button>\n                                    <button class="btn" style="flex:1; background:var(--danger-bg); color:var(--danger); border:none;" onclick="window.setXrayStatus(\'stop\')"><i class="fa-solid fa-stop"></i> Stop</button>\n                                    <button class="btn btn-primary" style="flex:1;" onclick="window.setXrayStatus(\'restart\')"><i class="fa-solid fa-rotate-right"></i> Restart</button>\n                                </div>\n                            </div>\n                        </div>\n                    </div>\n                    <div class="panel" style="flex: 1;">\n                        <div class="panel-header"><div class="panel-title"><i class="fa-solid fa-wave-square text-accent"></i> Global Traffic Flow</div></div>\n                        <div class="panel-body-unpadded chart-wrapper" style="padding: 16px;"><canvas id="chart-traffic"></canvas></div>\n                    </div>\n                </div>\n            </div>\n\n            <div id="tab-clients" class="tab-view">\n                <div class="header-section">\n                    <div><h2>Client Profiles</h2><p>Manage, provision, and monitor individual access credentials.</p></div>\n                    <div style="display:flex; gap:12px;">\n\n                        <button class="btn btn-primary" onclick="window.openAddClientModal()"><i class="fa-solid fa-user-plus"></i> Create Client</button>\n                    </div>\n                </div>\n                <div class="grid-1-2" style="height: 240px; flex-shrink:0;">\n                    <div class="panel"><div class="panel-header"><div class="panel-title"><i class="fa-solid fa-chart-pie text-accent"></i> Usage Share</div></div><div class="panel-body chart-wrapper" style="padding: 16px;"><canvas id="client-pie-chart"></canvas></div></div>\n                    <div class="panel">\n                        <div class="panel-header" style="position:relative;"><div class="panel-title"><i class="fa-solid fa-users-rays text-info"></i> Live Data Flow</div></div>\n                        <div class="panel-body-unpadded chart-wrapper" style="padding: 16px 16px 16px 8px;"><canvas id="client-flow-chart"></canvas></div>\n                    </div>\n                </div>\n                <div class="panel panel-full">\n                    <div class="table-wrap"><table id="tbl-clients"><thead><tr><th>Remarks / SubID</th><th>uTLS</th><th>Data Usage</th><th>Expiry Date</th><th>Status</th><th style="text-align:right;">Actions</th></tr></thead><tbody></tbody></table></div>\n                </div>\n            </div>\n\n            <div id="tab-sublab" class="tab-view">\n                <div class="header-section" style="flex-shrink:0;">\n                    <div style="flex:1;"><h2>Subscription Lab</h2><p>Build, customize, and preview subscription configs for any client.</p></div>\n                </div>\n\n                <div class="sublab-layout">\n                    <div class="sublab-editor">\n                        <div class="panel" style="flex-shrink:0;">\n                            <div class="panel-header collapsible-header" onclick="togglePanel(this)"><div class="panel-title"><i class="fa-solid fa-user-gear text-accent"></i> Target Client</div><i class="fa-solid fa-chevron-up collapse-icon" style="color:var(--text-muted); font-size:0.8rem; transition:transform 0.2s;"></i></div>\n                            <div class="collapsible-body panel-body" style="padding: 16px; gap: 16px; overflow:hidden;">\n                                <select class="form-control" id="sub-client" onchange="window.onSubClientChange()" style="width: 100%;"><option value="">— Select Client —</option></select>\n                                <button class="btn btn-primary" onclick="window.saveSubscriptionForClient()" style="width: 100%;"><i class="fa-solid fa-floppy-disk"></i> Save Configuration</button>\n                            </div>\n                        </div>\n\n                        <div class="panel" style="flex:1; min-height:0;">\n                            <div class="panel-header">\n                                <div class="panel-title"><i class="fa-solid fa-list text-info"></i> Config Entries <span id="sub-entry-count" class="tag tag-blue" style="margin-left:8px;">0</span></div>\n                                <div style="display:flex; gap:8px;">\n\n                                    <input type="hidden" id="transport-sel" value="ws">\n                                    <button class="btn" style="padding:4px 10px; height: 30px; font-size:0.75rem;" onclick="window.addSubEntry(\'proxy\')"><i class="fa-solid fa-plus"></i> Proxy</button>\n                                    <button class="btn" style="padding:4px 10px; height: 30px; font-size:0.75rem; background:var(--info-bg); color:var(--info); border:none;" onclick="window.addSubEntry(\'info\')"><i class="fa-solid fa-circle-info"></i> Info</button>\n                                </div>\n                            </div>\n                            <div class="panel-body-unpadded" style="overflow-y:auto; padding:16px;">\n                                <div id="sub-entries-list" style="display:flex; flex-direction:column; gap:12px; min-height:60px;">\n                                    <div id="sub-empty-hint" style="color:var(--text-muted); font-size:0.85rem; text-align:center; padding:30px 0;">Select a client and click <strong>+ Proxy</strong> or <strong>Info</strong>.</div>\n                                </div>\n                            </div>\n                        </div>\n                    </div>\n\n                    <div class="sublab-preview">\n                        <div class="panel" style="flex-shrink:0;">\n                            <div class="panel-header collapsible-header" onclick="togglePanel(this)"><div class="panel-title"><i class="fa-solid fa-code text-accent"></i> Placeholders</div><i class="fa-solid fa-chevron-up collapse-icon" style="color:var(--text-muted); font-size:0.8rem; transition:transform 0.25s;"></i></div>\n                            <div class="collapsible-body panel-body" style="padding:16px; gap:8px; overflow:hidden;">\n                                <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">\n                                    <div class="ph-chip" onclick="window.copyPlaceholder(\'%client-name%\')">%client-name%</div>\n                                    <div class="ph-chip" onclick="window.copyPlaceholder(\'%data-used%\')">%data-used%</div>\n                                    <div class="ph-chip" onclick="window.copyPlaceholder(\'%data-remain%\')">%data-remain%</div>\n                                    <div class="ph-chip" onclick="window.copyPlaceholder(\'%data-total%\')">%data-total%</div>\n                                    <div class="ph-chip" onclick="window.copyPlaceholder(\'%expiry-date%\')">%expiry-date%</div>\n                                </div>\n                                <p style="font-size:0.7rem; color:var(--text-muted); margin-top:8px; text-align:center;">Click to copy placeholder to clipboard.</p>\n                            </div>\n                        </div>\n\n                        <div class="panel" style="flex:1; min-height:0;">\n                            <div class="panel-header"><div class="panel-title"><i class="fa-solid fa-mobile-screen text-purple"></i> Live Preview</div></div>\n                            <div class="panel-body-unpadded phone-mockup-wrapper">\n                                <div class="phone-mockup">\n                                    <div class="phone-notch"></div>\n                                    <div class="phone-screen">\n                                        <div class="phone-config-list" id="phone-config-list" ondragover="event.preventDefault()">\n                                            <div style="color:#52525b; font-size:0.75rem; text-align:center; padding:30px 0;">No configs yet</div>\n                                        </div>\n                                    </div>\n                                </div>\n                            </div>\n                        </div>\n                    </div>\n                </div>\n            </div>\n\n        </div>\n    </main>\n\n    <div class="modal-overlay" id="modal-confirm">\n        <div class="modal" style="max-width: 420px;">\n            <div class="modal-header"><div class="panel-title text-warning"><i class="fa-solid fa-triangle-exclamation"></i> Action Required</div></div>\n            <div class="modal-body" id="confirm-msg" style="font-size: 0.95rem; line-height: 1.6; font-weight: 500; text-align: center;"></div>\n            <div class="modal-footer" style="justify-content: center; gap: 16px;">\n                <button class="btn" onclick="closeConfirm(false)" style="min-width: 100px;">Cancel</button>\n                <button class="btn btn-danger" onclick="closeConfirm(true)" style="min-width: 100px;">Proceed</button>\n            </div>\n        </div>\n    </div>\n\n    <div class="modal-overlay" id="modal-client">\n        <div class="modal" style="max-width: 580px;">\n            <div class="modal-header"><div class="panel-title">Client Profile</div><button class="btn-icon" style="background:none; border:none; color:var(--text-muted);" onclick="closeModal(\'modal-client\')"><i class="fa-solid fa-times fa-lg"></i></button></div>\n            <div class="modal-body">\n                <input type="hidden" id="c-edit-id" value="">\n\n                <div class="form-grid">\n                    <div class="form-group"><label class="form-label">Remarks</label><input type="text" class="form-control" id="c-name" placeholder="Enter Remark ..."></div>\n                    <div class="form-group"><label class="form-label">UUID</label><div class="input-group"><input type="text" class="form-control mono" id="c-uuid"><button class="btn btn-icon" id="btn-gen-uuid" onclick="document.getElementById(\'c-uuid\').value = genUUID()" style="height: auto;"><i class="fa-solid fa-rotate-right"></i></button></div></div>\n                    <div class="form-group"><label class="form-label">Expiry Date</label><input type="datetime-local" class="form-control" id="c-expiry"></div>\n                    <div class="form-group"><label class="form-label">Limit (GB) [0 = Unlim]</label><input type="number" class="form-control" id="c-limit" value="0"></div>\n                    <div class="form-group" style="grid-column: 1/-1;"><label class="form-label">uTLS Fingerprint</label><select class="form-control" id="c-utls"><option value="chrome">Chrome</option><option value="firefox">Firefox</option><option value="safari">Safari</option><option value="random">Random</option></select></div>\n                </div>\n                <div class="settings-row" style="margin-top:20px; padding:16px 0 0 0; border-top:1px solid var(--border); border-bottom:none;">\n                    <div class="settings-info"><h4>Client Active</h4><p>Enable or disable this client.</p></div>\n                    <label class="switch"><input type="checkbox" id="c-active" checked><span class="slider"></span></label>\n                </div>\n            </div>\n            <div class="modal-footer"><button class="btn" onclick="closeModal(\'modal-client\')">Cancel</button><button class="btn btn-primary" id="btn-save-client" onclick="window.saveClient()"><i class="fa-solid fa-check"></i> Save Client</button></div>\n        </div>\n    </div>\n\n\n\n    <div class="modal-overlay" id="modal-qr">\n        <div class="modal" style="max-width: 420px; text-align:center;">\n            <div class="modal-header"><div class="panel-title">QR Connect</div><button class="btn-icon" style="background:none; border:none; color:var(--text-muted);" onclick="closeModal(\'modal-qr\')"><i class="fa-solid fa-times fa-lg"></i></button></div>\n            <div class="modal-body" style="display:flex; flex-direction:column; align-items:center;">\n                <div class="qr-wrapper" id="qrcode"></div>\n                <textarea class="form-control mono" id="qr-text" rows="4" style="margin-top:20px; resize:none; font-size:0.75rem; width:100%;" readonly></textarea>\n            </div>\n            <div class="modal-footer" style="justify-content:center;">\n                <button class="btn btn-primary" onclick="copyToClipboard(document.getElementById(\'qr-text\').value); showToast(\'Copied to clipboard!\', \'success\');" style="width:100%;"><i class="fa-solid fa-copy"></i> Copy Link</button>\n            </div>\n        </div>\n    </div>\n\n    <div class="toast-box" id="toaster"></div>\n\n    <script>\n        const passSetup = {{PASS_SETUP}};\n        const loggedIn = {{LOGGED_IN}};\n\n        if (!passSetup) {\n            document.getElementById(\'auth-overlay\').style.display = \'flex\';\n            document.getElementById(\'auth-title\').innerHTML = \'<i class="fa-solid fa-key text-accent"></i> Setup Password\';\n            document.getElementById(\'auth-body\').innerHTML = `\n                <p style="color:var(--text-muted); font-size:0.85rem; text-align:center; margin-bottom:20px;">Welcome to R2Leafy. Please create a secure password to continue.</p>\n                <div class="form-group"><label class="form-label">New Password</label><input type="password" class="form-control" id="new-pass-input" placeholder="Enter password..."></div>\n                <div class="form-group" style="margin-top:8px;"><label class="form-label">Confirm Password</label><input type="password" class="form-control" id="confirm-pass-input" placeholder="Confirm password..." onkeydown="if(event.key===\'Enter\') window.setupPassword()"></div>\n                <button class="btn btn-primary" style="width:100%; margin-top:20px;" onclick="window.setupPassword()"><i class="fa-solid fa-arrow-right"></i> Save & Continue</button>\n                <div style="text-align:center; margin-top:20px; font-size:0.8rem; color:var(--text-muted);">\n                    <a href="https://github.com/Code-Leafy/R2Leafy" target="_blank" style="color:var(--text-main); text-decoration:none;"><i class="fa-brands fa-github"></i> R2Leafy Project</a>\n                </div>\n            `;\n        } else if (!loggedIn) {\n            document.getElementById(\'auth-overlay\').style.display = \'flex\';\n            document.getElementById(\'auth-title\').innerHTML = \'<i class="fa-solid fa-lock text-accent"></i> Authentication Required\';\n            document.getElementById(\'auth-body\').innerHTML = `\n                <div class="form-group"><label class="form-label">Password</label><input type="password" class="form-control" id="pass-input" placeholder="Enter password..." onkeydown="if(event.key===\'Enter\') window.doLogin()"></div>\n                <button class="btn btn-primary" style="width:100%; margin-top:20px;" onclick="window.doLogin()"><i class="fa-solid fa-arrow-right-to-bracket"></i> Login</button>\n                <div style="text-align:center; margin-top:20px; font-size:0.8rem; color:var(--text-muted);">\n                    <a href="https://github.com/Code-Leafy/R2Leafy" target="_blank" style="color:var(--text-main); text-decoration:none;"><i class="fa-brands fa-github"></i> R2Leafy Project</a>\n                </div>\n            `;\n        } else {\n            document.getElementById(\'auth-overlay\').style.display = \'none\';\n        }\n\n        window.setupPassword = function() {\n            const p1 = document.getElementById(\'new-pass-input\')?.value;\n            const p2 = document.getElementById(\'confirm-pass-input\')?.value;\n            if(!p1) return showToast(\'Password cannot be empty\', \'error\');\n            if(p1.length < 4) return showToast(\'Password must be at least 4 characters\', \'error\');\n            if(p1 !== p2) return showToast(\'Passwords do not match\', \'error\');\n            fetch(\'/api/setup\', { method:\'POST\', headers:{\'Content-Type\':\'application/json\'}, body:JSON.stringify({pass: p1}) })\n                .then(r=>r.json()).then(d=>{\n                if(d.ok) {\n                    const overlay = document.getElementById(\'auth-overlay\');\n                    if(overlay) overlay.style.display = \'none\';\n                    showToast(\'Password setup successful!\', \'success\');\n                    ensureCharts();\n                    if(window.initBackendSync) window.initBackendSync();\n                    setTimeout(() => location.reload(), 400);\n                } else {\n                    showToast(\'Setup failed: \' + (d.detail || \'check inputs\'), \'error\');\n                }\n            }).catch(()=>showToast(\'Network error\', \'error\'));\n        };\n\n        window.doLogin = function() {\n            const p = document.getElementById(\'pass-input\')?.value;\n            if(!p) return showToast(\'Enter a password\', \'error\');\n            fetch(\'/api/login\', { method:\'POST\', headers:{\'Content-Type\':\'application/json\'}, body:JSON.stringify({pass: p}) })\n                .then(r=>r.json()).then(d=>{\n                if(d.ok) {\n                    const overlay = document.getElementById(\'auth-overlay\');\n                    if(overlay) overlay.style.display = \'none\';\n                    showToast(\'Login successful!\', \'success\');\n                    ensureCharts();\n                    if(window.initBackendSync) window.initBackendSync();\n                    setTimeout(() => location.reload(), 400);\n                } else {\n                    showToast(\'Incorrect password\', \'error\');\n                }\n            }).catch(()=>showToast(\'Network error\', \'error\'));\n        };\n\n        Chart.defaults.color = \'#a1a1aa\'; Chart.defaults.font.family = "\'Plus Jakarta Sans\', sans-serif"; Chart.defaults.font.size = 12;\n\n        let trafficChart, clientPieChart, clientFlowChart;\n        window.clients = [];\n        window._clientGuard = { until: 0, added: {}, deleted: {} };\n        window.subEntries = []; window.subClientSubscriptions = {};\n        window.lastTelemetry = {}; window.PORT_DOMAIN = \'\'; window.WEB_DOMAIN = \'\';\n\n        const backendSync = { connected: false, syncing: false, debounceHandle: null };\n\n        let confirmCallback = null;\n        window.customConfirm = function(msg, cb) {\n            document.getElementById(\'confirm-msg\').innerText = msg;\n            confirmCallback = cb;\n            openModal(\'modal-confirm\');\n        };\n        window.closeConfirm = function(res) {\n            closeModal(\'modal-confirm\');\n            if(confirmCallback) confirmCallback(res);\n        };\n\n        function showAuthRequired() {\n            const overlay = document.getElementById(\'auth-overlay\');\n            if (overlay) {\n                overlay.style.display = \'flex\';\n                const title = document.getElementById(\'auth-title\');\n                if (title) title.innerHTML = \'<i class="fa-solid fa-lock text-accent"></i> Authentication Required\';\n            }\n        }\n\n        function switchTab(tabId) {\n            document.querySelectorAll(\'.nav-item\').forEach(e => e.classList.remove(\'active\'));\n            const trigger = (typeof event !== \'undefined\' && event?.currentTarget) ? event.currentTarget : document.querySelector(`.nav-item[onclick*="switchTab(\'${tabId}\')"]`);\n            if(trigger) trigger.classList.add(\'active\');\n            document.querySelectorAll(\'.tab-view\').forEach(e => e.classList.remove(\'active\'));\n            const target = document.getElementById(\'tab-\' + tabId);\n            if(target) target.classList.add(\'active\');\n\n            const topbar = document.getElementById(\'main-topbar\');\n            const mobileBtn = document.getElementById(\'mobile-dash-btn\');\n            if (tabId === \'dashboard\') {\n                topbar.classList.add(\'hidden\');\n                mobileBtn.style.display = window.innerWidth <= 1024 ? \'block\' : \'none\';\n            } else {\n                topbar.classList.remove(\'hidden\');\n                mobileBtn.style.display = \'none\';\n            }\n            if(window.innerWidth <= 1024) document.getElementById(\'sidebar\').classList.remove(\'open\');\n\n            ensureCharts();\n        }\n\n        function openModal(id) { const el = document.getElementById(id); if(el) el.classList.add(\'show\'); }\n        function closeModal(id) { const el = document.getElementById(id); if(el) el.classList.remove(\'show\'); }\n\n        function showToast(msg, type=\'info\') {\n            const toaster = document.getElementById(\'toaster\');\n            if(!toaster) return;\n            const el = document.createElement(\'div\'); el.className = \'toast\';\n            el.innerHTML = `<i class="fa-solid ${type===\'success\'?\'fa-check-circle text-accent\':(type===\'error\'?\'fa-circle-xmark text-danger\':\'fa-info-circle text-info\')}"></i> <span>${msg}</span>`;\n            toaster.appendChild(el);\n            setTimeout(() => { el.style.opacity=\'0\'; el.style.transform=\'translateY(10px)\'; setTimeout(() => el.remove(), 250); }, 2500);\n        }\n\n        function genUUID() {\n            if (window.crypto && typeof window.crypto.randomUUID === \'function\') return window.crypto.randomUUID();\n            const b = window.crypto.getRandomValues(new Uint8Array(16));\n            b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;\n            const h = [...b].map(x => x.toString(16).padStart(2, \'0\'));\n            return h.slice(0,4).join(\'\') + \'-\' + h.slice(4,6).join(\'\') + \'-\' + h.slice(6,8).join(\'\') + \'-\' + h.slice(8,10).join(\'\') + \'-\' + h.slice(10,16).join(\'\');\n        }\n\n        function copyToClipboard(text) {\n            if (navigator.clipboard && window.isSecureContext) { return navigator.clipboard.writeText(text).catch(() => _clipboardFallback(text)); }\n            _clipboardFallback(text); return Promise.resolve();\n        }\n        function _clipboardFallback(text) {\n            const ta = document.createElement(\'textarea\'); ta.value = text;\n            ta.style.cssText = \'position:fixed;top:-9999px;left:-9999px;opacity:0;\';\n            document.body.appendChild(ta); ta.focus(); ta.select();\n            try { document.execCommand(\'copy\'); } catch (_) {}\n            document.body.removeChild(ta);\n        }\n        window.copyPlaceholder = function(text) { copyToClipboard(text); showToast(\'Copied: \' + text, \'success\'); };\n\n        function togglePanel(header) {\n            const body = header.nextElementSibling; const icon = header.querySelector(\'.collapse-icon\');\n            if(body) body.classList.toggle(\'collapsed\'); if(icon) icon.classList.toggle(\'collapsed\');\n        }\n\n        function ensureCharts() {\n            const trafficCanvas = document.getElementById(\'chart-traffic\');\n            if(trafficCanvas && !trafficChart) {\n                trafficChart = new Chart(trafficCanvas.getContext(\'2d\'), {\n                    type: \'line\', data: { labels: Array(60).fill(\'\'), datasets: [\n                        { label: \'Speed DL (Mbps)\', data: Array(60).fill(0), borderColor: \'#8b5cf6\', backgroundColor: \'rgba(139, 92, 246, 0.15)\', borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4 },\n                        { label: \'Speed UL (Mbps)\', data: Array(60).fill(0), borderColor: \'#3b82f6\', backgroundColor: \'rgba(59, 130, 246, 0.08)\', borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4 }\n                    ]}, options: { responsive: true, maintainAspectRatio: false, animation: false, scales: { x: { display: false }, y: { beginAtZero: true } } }\n                });\n            }\n            const pieCanvas = document.getElementById(\'client-pie-chart\');\n            if(pieCanvas && !clientPieChart) {\n                clientPieChart = new Chart(pieCanvas.getContext(\'2d\'), {\n                    type: \'doughnut\', data: { labels: [], datasets: [{ data: [], backgroundColor: [\'#8b5cf6\', \'#a855f7\', \'#6366f1\', \'#3b82f6\', \'#f59e0b\', \'#ec4899\'], borderWidth: 0 }] },\n                    options: { responsive: true, maintainAspectRatio: false, cutout: \'75%\', plugins: { legend: { position: \'right\', labels: { color: \'#a1a1aa\', usePointStyle: true, boxWidth: 6 } } } }\n                });\n            }\n            const flowCanvas = document.getElementById(\'client-flow-chart\');\n            if(flowCanvas && !clientFlowChart) {\n                clientFlowChart = new Chart(flowCanvas.getContext(\'2d\'), {\n                    type: \'line\', data: { labels: Array(30).fill(\'\'), datasets: [\n                        { label: \'DL (Mbps)\', data: Array(30).fill(0), borderColor: \'#8b5cf6\', backgroundColor: \'rgba(139, 92, 246, 0.1)\', borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4 },\n                        { label: \'UL (Mbps)\', data: Array(30).fill(0), borderColor: \'#f59e0b\', backgroundColor: \'rgba(245, 158, 11, 0.1)\', borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4 }\n                    ]}, options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, display: false }, x: { display: false } } }\n                });\n            }\n        }\n\n        async function generateRelay(){\n            console.log(\'[relay] generateRelay() called\');\n            const token=document.getElementById(\'relay-token\').value.trim();\n            const origin=document.getElementById(\'relay-origin\').value.trim();\n            const out=document.getElementById(\'relay-result\');\n            if(!token||!origin){out.textContent=\'Enter both the origin and token.\';return;}\n            console.log(\'[relay] POST /api/relay\', { origin: origin, tokenLength: token.length });\n            out.textContent=\'Provisioning Worker…\';\n            try {\n                const r=await fetch(\'/api/relay\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({token,origin})});\n                console.log(\'[relay] response status:\', r.status);\n                let data;\n                try { data = await r.json(); } catch(e){ data = {}; console.warn(\'[relay] response was not JSON\', e); }\n                console.log(\'[relay] response body:\', data);\n                document.getElementById(\'relay-token\').value=\'\';\n                if(!r.ok||!data.ok) throw new Error(data.error||data.detail||(\'Provisioning failed (HTTP \'+r.status+\')\'));\n                console.log(\'[relay] SUCCESS:\', data.relay);\n                out.innerHTML=\'Relay ready: <a href="\'+data.relay.relay_url+\'" target="_blank">\'+data.relay.relay_url+\'</a>\';\n            } catch(e){\n                console.error(\'[relay] ERROR:\', e);\n                out.textContent=e.message;\n            }\n        }\n        let _settingsHydrated = false;\n        window.applyPanelState = function(state, dataPayload, forceSettings) {\n            if(!state) return;\n            if(dataPayload && dataPayload.portDomain) window.PORT_DOMAIN = dataPayload.portDomain;\n            if(Array.isArray(state.clients)) {\n                const g = window._clientGuard;\n                if (g && Date.now() < g.until) {\n                    let merged = state.clients.filter(c => !g.deleted[c.id]);\n                    for (const aid in g.added) {\n                        if (!merged.some(c => c.id === aid)) {\n                            const lc = clients.find(c => c.id === aid);\n                            if (lc) merged.push(lc);\n                        } else { delete g.added[aid]; }\n                    }\n                    clients = merged;\n                } else {\n                    clients = state.clients;\n                    if (g) { g.added = {}; g.deleted = {}; }\n                }\n            }\n            if(state.subClientSubscriptions) subClientSubscriptions = state.subClientSubscriptions;\n\n            if(state.settings && (!_settingsHydrated || forceSettings)) {\n                let adv = state.settings.advanced || {};\n                const domStrat = document.getElementById(\'adv-domain-strategy\'); if(domStrat) domStrat.value = adv.domainStrategy || \'UseIP\';\n                const deepSniff = document.getElementById(\'adv-deep-sniff\'); if(deepSniff) deepSniff.checked = adv.deepSniff !== false;\n                const sniffHttp = document.getElementById(\'adv-sniff-http\'); if(sniffHttp) sniffHttp.checked = adv.sniffHttp !== false;\n                const sniffTls = document.getElementById(\'adv-sniff-tls\'); if(sniffTls) sniffTls.checked = adv.sniffTls !== false;\n                const sniffQuic = document.getElementById(\'adv-sniff-quic\'); if(sniffQuic) sniffQuic.checked = adv.sniffQuic !== false;\n                const sniffFake = document.getElementById(\'adv-sniff-fakedns\'); if(sniffFake) sniffFake.checked = adv.sniffFakedns || false;\n                const byIr = document.getElementById(\'adv-bypass-ir\'); if(byIr) byIr.checked = adv.bypassIr || false;\n                const byRu = document.getElementById(\'adv-bypass-ru\'); if(byRu) byRu.checked = adv.bypassRu || false;\n                const byCn = document.getElementById(\'adv-bypass-cn\'); if(byCn) byCn.checked = adv.bypassCn || false;\n                const byLan = document.getElementById(\'adv-bypass-lan\'); if(byLan) byLan.checked = adv.bypassLan || false;\n                const dnsP = document.getElementById(\'adv-dns-primary\'); if(dnsP) dnsP.value = adv.dnsPrimary || \'1.1.1.1\';\n                const dnsF = document.getElementById(\'adv-dns-fallback\'); if(dnsF) dnsF.value = adv.dnsFallback || \'8.8.8.8\';\n                const dnsC = document.getElementById(\'adv-dns-cache\'); if(dnsC) dnsC.checked = adv.dnsCache !== false;\n                const muxEn = document.getElementById(\'adv-mux-en\'); if(muxEn) muxEn.checked = adv.mux || false;\n                const muxC = document.getElementById(\'adv-mux-concurrency\'); if(muxC) muxC.value = adv.muxConcurrency || 8;\n                const logL = document.getElementById(\'adv-log-level\'); if(logL) logL.value = adv.logLevel || \'warning\';\n                const accL = document.getElementById(\'adv-access-log\'); if(accL) accL.checked = adv.accessLog || false;\n                _settingsHydrated = true;\n                if(typeof refreshConfigPreview === \'function\') refreshConfigPreview();\n            }\n\n            renderClients();\n            populateSubClientSelect();\n        };\n\n        window.updateTelemetryFromBackend = function(t) {\n            window.lastTelemetry = t;\n            if(t.webDomain) window.WEB_DOMAIN = t.webDomain;\n\n            const _cc = String(t.tcpCc || \'bbr\');\n            const _ccEl = document.getElementById(\'adv-tcpcc\'); if(_ccEl){ _ccEl.innerText = _cc.toUpperCase(); _ccEl.className = \'tag tag-purple\'; }\n            const _connEl = document.getElementById(\'adv-conns\'); if(_connEl) _connEl.innerText = String(t.connections||0);\n\n            const xrayUp = t.xrayRunning !== false;\n            const statusTag = document.getElementById(\'dash-status-tag\');\n            if(statusTag) { statusTag.className = xrayUp ? \'tag tag-purple\' : \'tag tag-red\'; statusTag.innerText = xrayUp ? \'Online\' : \'Offline\'; }\n\n            const dot = document.getElementById(\'topbar-xray-dot\');\n            if(dot) { dot.style.background = xrayUp ? \'var(--accent)\' : \'var(--danger)\'; dot.style.boxShadow = xrayUp ? \'0 0 8px var(--accent)\' : \'none\'; }\n\n            const lbl = document.getElementById(\'topbar-xray-label\');\n            if(lbl) { lbl.style.color = xrayUp ? \'var(--accent)\' : \'var(--danger)\'; lbl.innerText = xrayUp ? \'Xray ON\' : \'Xray OFF\'; }\n\n            const mRx = document.getElementById(\'m-rx\'); if(mRx) mRx.innerHTML = `${Number(t.totalRxGb||0).toFixed(2)} <span class="metric-sub">GB</span>`;\n            const mTx = document.getElementById(\'m-tx\'); if(mTx) mTx.innerHTML = `${Number(t.totalTxGb||0).toFixed(2)} <span class="metric-sub">GB</span>`;\n            const mRxMini = document.getElementById(\'m-rx-mini\'); if(mRxMini) mRxMini.innerText = Number(t.totalRxGb||0).toFixed(2);\n            const mTxMini = document.getElementById(\'m-tx-mini\'); if(mTxMini) mTxMini.innerText = Number(t.totalTxGb||0).toFixed(2);\n            const mSpeed = document.getElementById(\'m-speed\'); if(mSpeed) mSpeed.innerHTML = `${Number(t.speedDownMbps||0).toFixed(1)} <span class="metric-sub">/ ${Number(t.speedUpMbps||0).toFixed(1)} Mbps</span>`;\n            const mSpeedMini = document.getElementById(\'m-speed-mini\'); if(mSpeedMini) mSpeedMini.innerText = `${Number(t.speedDownMbps||0).toFixed(1)} / ${Number(t.speedUpMbps||0).toFixed(1)}`;\n\n            const mUptime = document.getElementById(\'m-uptime\');\n            if(mUptime) {\n                let s = t.xrayUptimeSec || 0;\n                mUptime.innerText = xrayUp ? `${Math.floor(s/3600)}h ${Math.floor((s%3600)/60).toString().padStart(2,\'0\')}m` : \'Stopped\';\n            }\n\n            const loadAvgEl = document.getElementById(\'dash-load-avg\');\n            if(loadAvgEl) loadAvgEl.innerText = (Array.isArray(t.loadAvg)?t.loadAvg:[0.12,0.08,0.05]).map(x=>Number(x||0).toFixed(2)).join(\' / \');\n            const memAllocEl = document.getElementById(\'dash-mem-alloc\');\n            if(memAllocEl) memAllocEl.innerText = `${Number(t.ramMb||45).toFixed(0)} / ${Number(t.ramTotalMb||512).toFixed(0)} MB`;\n\n            // Update charts\n            if(trafficChart) {\n                trafficChart.data.datasets[0].data.push(t.speedDownMbps || 0);\n                trafficChart.data.datasets[1].data.push(t.speedUpMbps || 0);\n                if(trafficChart.data.datasets[0].data.length > 60) {\n                    trafficChart.data.datasets[0].data.shift();\n                    trafficChart.data.datasets[1].data.shift();\n                }\n                trafficChart.update(\'none\');\n            }\n            if(clientPieChart) {\n                clientPieChart.data.labels = clients.map(c => c.name);\n                clientPieChart.data.datasets[0].data = clients.map(c => c.usage || 0);\n                clientPieChart.update();\n            }\n            if(clientFlowChart) {\n                clientFlowChart.data.datasets[0].data.push(t.speedDownMbps || 0);\n                clientFlowChart.data.datasets[1].data.push(t.speedUpMbps || 0);\n                if(clientFlowChart.data.datasets[0].data.length > 30) {\n                    clientFlowChart.data.datasets[0].data.shift();\n                    clientFlowChart.data.datasets[1].data.shift();\n                }\n                clientFlowChart.update(\'none\');\n            }\n\n            renderClients();\n        };\n\n        window.serializePanelState = function() {\n            return {\n                clients, subClientSubscriptions,\n                settings: {\n                    advanced: {\n                        domainStrategy: document.getElementById(\'adv-domain-strategy\')?.value || \'UseIP\',\n                        deepSniff: document.getElementById(\'adv-deep-sniff\')?.checked !== false,\n                        sniffHttp: document.getElementById(\'adv-sniff-http\')?.checked !== false,\n                        sniffTls: document.getElementById(\'adv-sniff-tls\')?.checked !== false,\n                        sniffQuic: document.getElementById(\'adv-sniff-quic\')?.checked !== false,\n                        sniffFakedns: document.getElementById(\'adv-sniff-fakedns\')?.checked || false,\n                        bypassIr: document.getElementById(\'adv-bypass-ir\')?.checked || false,\n                        bypassRu: document.getElementById(\'adv-bypass-ru\')?.checked || false,\n                        bypassCn: document.getElementById(\'adv-bypass-cn\')?.checked || false,\n                        bypassLan: document.getElementById(\'adv-bypass-lan\')?.checked || false,\n                        dnsPrimary: document.getElementById(\'adv-dns-primary\')?.value || \'1.1.1.1\',\n                        dnsFallback: document.getElementById(\'adv-dns-fallback\')?.value || \'8.8.8.8\',\n                        dnsCache: document.getElementById(\'adv-dns-cache\')?.checked !== false,\n                        mux: document.getElementById(\'adv-mux-en\')?.checked || false,\n                        muxConcurrency: parseInt(document.getElementById(\'adv-mux-concurrency\')?.value) || 8,\n                        logLevel: document.getElementById(\'adv-log-level\')?.value || \'warning\',\n                        accessLog: document.getElementById(\'adv-access-log\')?.checked || false\n                    }\n                }\n            };\n        };\n\n        window.schedulePanelSync = function(reason=\'change\') {\n            if(backendSync.debounceHandle) clearTimeout(backendSync.debounceHandle);\n            backendSync.debounceHandle = setTimeout(() => pushPanelState(reason), 300);\n        };\n\n        window.pushPanelState = async function(reason=\'sync\') {\n            if(backendSync.syncing) { backendSync._queued = true; return; }\n            backendSync.syncing = true;\n            try {\n                const res = await fetch(\'/api/state\', {\n                    method: \'PUT\', headers: { \'Content-Type\': \'application/json\' },\n                    body: JSON.stringify({ state: serializePanelState(), reason })\n                });\n                if(res.status === 401) { showAuthRequired(); return; }\n                const data = await res.json();\n                if(!data.ok) throw new Error(data.error || \'state sync failed\');\n\n                try {\n                    const r2 = await fetch(\'/api/state\');\n                    if(r2.ok) {\n                        const d2 = await r2.json();\n                        if(d2.ok) {\n                            if(d2.state) applyPanelState(d2.state, d2, true);\n                            if(typeof updateTelemetryFromBackend === \'function\') updateTelemetryFromBackend(d2);\n                            _setConn(true);\n                        }\n                    }\n                } catch(_) {}\n            } catch (err) {\n                console.error(\'[push-state]\', err);\n                _setConn(false);\n            }\n            finally { backendSync.syncing = false; }\n            if(backendSync._queued) { backendSync._queued = false; setTimeout(() => pushPanelState(\'sync\'), 50); }\n        };\n\n        function renderClients() {\n            const tb = document.querySelector(\'#tbl-clients tbody\');\n            if(!tb) return;\n            const scrollPos = tb.parentElement.scrollTop;\n            tb.innerHTML = \'\';\n            clients.forEach(c => {\n                tb.innerHTML += `<tr>\n                    <td><div style="font-weight:700;">${c.name}</div><div class="mono" style="font-size:0.65rem; color:var(--text-muted);">${c.id.split(\'-\')[0]}...</div></td>\n                    <td><span class="tag tag-purple">${c.utls||\'chrome\'}</span></td>\n                    <td><strong>${(c.usage||0).toFixed(2)}</strong> <span style="font-size:0.75rem; color:var(--text-muted);">/ ${c.limit===0?\'∞\':c.limit+\' GB\'}</span></td>\n                    <td><span class="mono" style="color:var(--text-muted);">${c.expiry?new Date(c.expiry).toLocaleString():\'Never\'}</span></td>\n                    <td><span class="tag ${c.status?\'tag-purple\':\'tag-red\'}">${c.status?\'Active\':\'Disabled\'}</span></td>\n                    <td style="text-align:right;">\n                        <button class="btn btn-icon" onclick="window.showQR(\'${c.id}\')"><i class="fa-solid fa-qrcode"></i></button>\n                        <button class="btn btn-icon" onclick="window.copyClientSubscriptionLink(\'${c.id}\')"><i class="fa-solid fa-link"></i></button>\n                        <button class="btn btn-icon" onclick="window.openEditClient(\'${c.id}\')"><i class="fa-solid fa-pen"></i></button>\n                        <button class="btn btn-icon btn-danger" onclick="window.deleteClient(\'${c.id}\')"><i class="fa-solid fa-trash"></i></button>\n                    </td>\n                </tr>`;\n            });\n            tb.parentElement.scrollTop = scrollPos;\n            populateSubClientSelect();\n            if(typeof clientPieChart !== \'undefined\' && clientPieChart) {\n                try {\n                    clientPieChart.data.labels = clients.map(c => c.name);\n                    clientPieChart.data.datasets[0].data = clients.map(c => c.usage || 0);\n                    clientPieChart.update();\n                } catch(e) {}\n            }\n        }\n\n        window.openAddClientModal = function() {\n            document.getElementById(\'c-edit-id\').value=\'\'; document.getElementById(\'c-name\').value=\'\'; document.getElementById(\'c-uuid\').value=genUUID();\n            document.getElementById(\'c-limit\').value=0; document.getElementById(\'c-expiry\').value=\'\'; document.getElementById(\'c-active\').checked=true;\n            openModal(\'modal-client\');\n        }\n        window.openEditClient = function(id) {\n            const c = clients.find(x => x.id === id); if(!c) return;\n            document.getElementById(\'c-edit-id\').value = c.id; document.getElementById(\'c-name\').value = c.name;\n            document.getElementById(\'c-uuid\').value = c.id; document.getElementById(\'c-utls\').value = c.utls || \'chrome\';\n            document.getElementById(\'c-limit\').value = c.limit || 0; document.getElementById(\'c-expiry\').value = c.expiry || \'\';\n            document.getElementById(\'c-active\').checked = !!c.status;\n            openModal(\'modal-client\');\n        }\n        window.saveClient = function() {\n            const id = document.getElementById(\'c-edit-id\').value, name = document.getElementById(\'c-name\').value;\n            if(!name) return showToast(\'Name required\', \'error\');\n            const data = {\n                name, limit: parseFloat(document.getElementById(\'c-limit\').value)||0,\n                expiry: document.getElementById(\'c-expiry\').value ? new Date(document.getElementById(\'c-expiry\').value).toISOString() : \'\',\n                status: document.getElementById(\'c-active\').checked ? 1 : 0,\n                utls: document.getElementById(\'c-utls\').value\n            };\n            const finalId = id || document.getElementById(\'c-uuid\').value;\n            if(id) { const c = clients.find(x => x.id === id); if(c) Object.assign(c, data); }\n            else { clients.push({ id: finalId, usage: 0, ...data }); }\n            window._clientGuard.until = Date.now() + 12000; window._clientGuard.added[finalId] = true;\n            renderClients(); pushPanelState(\'saveClient\'); closeModal(\'modal-client\'); showToast(\'Client Saved\', \'success\');\n        }\n        window.deleteClient = function(id) {\n            window.customConfirm("Are you sure you want to delete this client?", (res) => {\n                if(res) {\n                    window._clientGuard.until = Date.now() + 12000; window._clientGuard.deleted[id] = true;\n                    clients = clients.filter(c => c.id !== id); renderClients(); pushPanelState(\'deleteClient\'); showToast(\'Client Removed\', \'success\');\n                }\n            });\n        }\n\n        async function getSubscriptionLink(clientId) {\n            const domain = window.WEB_DOMAIN || window.PORT_DOMAIN || window.location.host;\n            return `https://${domain}/sub/${clientId}`;\n        }\n\n        window.copyClientSubscriptionLink = async function(clientId) {\n            const link = await getSubscriptionLink(clientId);\n            copyToClipboard(link); showToast(\'Subscription link copied!\', \'success\');\n        }\n\n        window.showQR = async function(id) {\n            const link = await getSubscriptionLink(id);\n            document.getElementById(\'qr-text\').value = link; document.getElementById(\'qrcode\').innerHTML = \'\';\n            new QRCode(document.getElementById("qrcode"), { text: link, width: 240, height: 240, correctLevel : QRCode.CorrectLevel.M });\n            openModal(\'modal-qr\');\n        }\n\n        window.resolvePlaceholders = function(text, client) {\n            if(!text) return "";\n            let t = text;\n            t = t.replace(/%client-name%/g, client ? client.name : "");\n            t = t.replace(/%data-used%/g, client ? (client.usage || 0).toFixed(2) : "0.00");\n            t = t.replace(/%data-total%/g, (client && client.limit) ? client.limit.toFixed(2) : "∞");\n            t = t.replace(/%data-remain%/g, (client && client.limit) ? Math.max(0, client.limit - (client.usage || 0)).toFixed(2) : "∞");\n            t = t.replace(/%expiry-date%/g, client && client.expiry ? new Date(client.expiry).toLocaleDateString() : "Never");\n            return t;\n        };\n\n        function populateSubClientSelect() {\n            const sel = document.getElementById(\'sub-client\'); if(!sel) return;\n            const prev = sel.value;\n            sel.innerHTML = \'<option value="">— Select Client —</option>\';\n            clients.forEach(c => sel.innerHTML += `<option value="${c.id}">${c.name}</option>`);\n            if(prev && clients.some(c => c.id === prev)) {\n                sel.value = prev;\n            } else if(clients.length > 0) {\n                sel.value = clients[0].id;\n            }\n            window.onSubClientChange();\n        }\n        window.onSubClientChange = function() {\n            const clientId = document.getElementById(\'sub-client\').value;\n            if(clientId && subClientSubscriptions[clientId]) {\n                subEntries = JSON.parse(JSON.stringify(subClientSubscriptions[clientId]));\n            } else {\n                subEntries = [];\n            }\n            window.renderSubEntries(); window.renderSubPreview();\n        };\n\n        window.addSubEntry = function(type) {\n            const cId = document.getElementById(\'sub-client\').value;\n            if(!cId) return showToast(\'Select a client first\', \'error\');\n            let nName = \'\';\n            let transport = \'ws\';\n            if(type === \'proxy\') {\n                transport = document.getElementById(\'transport-sel\').value;\n                let pCnt = subEntries.filter(e => e.type === \'proxy\').length;\n                nName = `Code-Leafy🍃 ${pCnt + 1}`;\n            } else {\n                nName = \'Code-Leafy🍃 %data-used%GB / %data-total%GB\';\n            }\n            subEntries.push({\n                id: genUUID(), type: type, transport: transport,\n                name: nName,\n                ipAddress: window.PORT_DOMAIN || \'\'\n            });\n            window.renderSubEntries(); window.renderSubPreview();\n        };\n\n        window.removeSubEntry = function(id) {\n            subEntries = subEntries.filter(e => e.id !== id);\n            window.renderSubEntries(); window.renderSubPreview();\n        };\n\n        window.updateSubEntry = function(id, field, value) {\n            const entry = subEntries.find(e => e.id === id);\n            if(entry) entry[field] = value;\n            window.renderSubPreview();\n        };\n\n        let dragSrcIndex = null;\n        window.dragSubEntry = function(e, index) { dragSrcIndex = index; };\n        window.dropSubEntry = function(e, index) {\n            e.preventDefault();\n            if(dragSrcIndex === null || dragSrcIndex === index) return;\n            const item = subEntries.splice(dragSrcIndex, 1)[0];\n            subEntries.splice(index, 0, item);\n            window.renderSubEntries(); window.renderSubPreview();\n        };\n\n        window.renderSubEntries = function() {\n            const list = document.getElementById(\'sub-entries-list\');\n            const count = document.getElementById(\'sub-entry-count\');\n            if(!list) return;\n            if(subEntries.length === 0) {\n                list.innerHTML = \'<div id="sub-empty-hint" style="color:var(--text-muted); font-size:0.85rem; text-align:center; padding:30px 0;">Select a client and click <strong>+ Proxy</strong> or <strong>Info</strong>.</div>\';\n                if(count) count.innerText = \'0\';\n                return;\n            }\n            if(count) count.innerText = subEntries.length;\n            let html = \'\';\n            subEntries.forEach((entry, i) => {\n                html += `<div class="sub-entry" draggable="true" ondragstart="window.dragSubEntry(event, ${i})" ondragover="event.preventDefault()" ondrop="window.dropSubEntry(event, ${i})">\n                    <div class="sub-entry-drag"><i class="fa-solid fa-grip-vertical"></i></div>\n                    <div class="sub-entry-body">\n                        <div style="display:flex; justify-content:space-between; align-items:center;">\n                            <span class="sub-entry-type" style="color:${entry.type===\'proxy\'?\'var(--accent)\':\'var(--info)\'}">${entry.type.toUpperCase()}</span>\n                            <i class="fa-solid fa-times" style="cursor:pointer; color:var(--danger); padding:4px;" onclick="window.removeSubEntry(\'${entry.id}\')"></i>\n                        </div>\n                        <input type="text" class="form-control" style="padding:8px 12px; font-size:0.8rem;" value="${entry.name}" oninput="window.updateSubEntry(\'${entry.id}\', \'name\', this.value)">\n                        ${entry.type === \'proxy\'\n                            ? `<div style="display:flex; gap:10px; margin-top:4px;">\n                                   <input type="text" class="form-control" style="flex:1; padding:8px 12px; font-size:0.8rem;" placeholder="IP (Leave blank for default)" value="${entry.ipAddress || \'\'}" oninput="window.updateSubEntry(\'${entry.id}\', \'ipAddress\', this.value)">\n                                   <span class="tag tag-purple" style="align-self:center;">WEBSOCKET</span>\n                               </div>`\n                            : ``}\n                    </div>\n                </div>`;\n            });\n            list.innerHTML = html;\n        };\n\n        window.renderSubPreview = function() {\n            const list = document.getElementById(\'phone-config-list\');\n            if(!list) return;\n            const cId = document.getElementById(\'sub-client\').value;\n            const client = clients.find(c => c.id === cId);\n\n            if(subEntries.length === 0) {\n                list.innerHTML = \'<div style="color:#52525b; font-size:0.75rem; text-align:center; padding:30px 0;">No configs yet</div>\';\n                return;\n            }\n            let html = \'\';\n            subEntries.forEach(entry => {\n                const icon = entry.type === \'proxy\' ? \'<i class="fa-solid fa-shield-halved" style="color:var(--accent)"></i>\' : \'<i class="fa-solid fa-circle-info" style="color:var(--info)"></i>\';\n                const sub = entry.type === \'proxy\' ? (entry.ipAddress || \'Auto IP\') + ` • WEBSOCKET` : \'Info\';\n                const title = window.resolvePlaceholders(entry.name, client);\n                html += `<div class="phone-item ${entry.type===\'info\'?\'info-item\':\'\'}">\n                    <div class="phone-item-icon">${icon}</div>\n                    <div class="phone-item-body">\n                        <div class="phone-item-name">${title}</div>\n                        <div class="phone-item-sub">${sub}</div>\n                    </div>\n                    <div class="phone-item-action">\n                        <button class="btn btn-icon" style="width:28px; height:28px; padding:0;" onclick="window.copySingleEntry(\'${entry.id}\')"><i class="fa-solid fa-copy" style="font-size:0.7rem;"></i></button>\n                    </div>\n                </div>`;\n            });\n            list.innerHTML = html;\n        };\n\n        window.copySingleEntry = function(entryId) {\n            const entry = subEntries.find(e => e.id === entryId);\n            if(!entry) return;\n            const cId = document.getElementById(\'sub-client\').value;\n            const client = clients.find(c => c.id === cId);\n\n            let link = \'\';\n            if(entry.type === \'proxy\') {\n                // The Python gateway only speaks VLESS-over-WebSocket on /ws/<uuid>,\n                // so every copied config must be type=ws with the client uuid in the\n                // path (xhttp is not implemented server-side and never worked).\n                let host = String(window.WEB_DOMAIN || window.PORT_DOMAIN || window.location.host).trim().replace(/^https?:\\/\\//, \'\');\n                if(host.charAt(0) === \'[\') {\n                    const e = host.indexOf(\']\');\n                    if(e !== -1) host = host.slice(0, e + 1);\n                } else {\n                    host = host.split(\':\')[0];\n                }\n                host = host.replace(/\\.$/, \'\') || \'localhost\';\n                let ip = entry.ipAddress ? String(entry.ipAddress).trim() : host;\n                if(ip.charAt(0) === \'[\') {\n                    const e = ip.indexOf(\']\');\n                    if(e !== -1) ip = ip.slice(0, e + 1);\n                } else {\n                    ip = ip.split(\':\')[0];\n                }\n                ip = ip.replace(/\\.$/, \'\') || host;\n                let name = encodeURIComponent(window.resolvePlaceholders(entry.name, client));\n                link = `vless://${client.id}@${ip}:443?encryption=none&security=tls&type=ws&host=${host}&path=%2Fws%2F${client.id}&sni=${host}&fp=chrome&alpn=http/1.1#${name}`;\n            } else {\n                let text = encodeURIComponent(window.resolvePlaceholders(entry.name, client));\n                link = `trojan://${genUUID()}@127.0.0.1:80?security=none#${text}`;\n            }\n            copyToClipboard(link);\n            showToast(\'Config copied!\', \'success\');\n        };\n\n        window.saveSubscriptionForClient = async function() {\n            const clientId = document.getElementById(\'sub-client\').value;\n            if(!clientId) return showToast(\'Select a client first\', \'error\');\n            subClientSubscriptions[clientId] = JSON.parse(JSON.stringify(subEntries));\n            window.renderSubPreview();\n            showToast(\'Saving subscription configuration...\', \'info\');\n            try {\n                const res = await fetch(\'/api/state\', {\n                    method: \'PUT\',\n                    headers: { \'Content-Type\': \'application/json\' },\n                    body: JSON.stringify({\n                        state: {\n                            clients: window.clients,\n                            subClientSubscriptions: window.subClientSubscriptions,\n                            settings: window.serializePanelState().settings\n                        },\n                        reason: \'saveSub\'\n                    })\n                });\n                if(res.ok) {\n                    showToast(\'Subscription Configuration Saved & Synced!\', \'success\');\n                } else {\n                    showToast(\'Server error saving subscription\', \'error\');\n                }\n            } catch(e) {\n                showToast(\'Network error saving subscription\', \'error\');\n            }\n        };\n\n        window.onload = () => {\n            setTimeout(() => {\n                const loader = document.getElementById(\'loader\');\n                if(loader) {\n                    loader.style.opacity = \'0\';\n                    setTimeout(() => { loader.style.visibility = \'hidden\'; }, 300);\n                }\n                ensureCharts();\n                if(loggedIn && passSetup) {\n                    if(window.initBackendSync) window.initBackendSync();\n                }\n            }, 200);\n        };\n    </script>\n    <script>\nfunction _setConn(ok) { backendSync.connected = ok; }\n\nwindow.initBackendSync = async function() {\n    let lastLogLine = "";\n    let failCount = 0;\n\n    async function syncLoop() {\n        const authOverlay = document.getElementById(\'auth-overlay\');\n        const isOverlayVisible = authOverlay && (authOverlay.style.display === \'flex\' || authOverlay.style.display === \'block\');\n        if(!isOverlayVisible && !backendSync.syncing) {\n            try {\n                const res = await fetch(\'/api/state\');\n                if(res.status === 401) { showAuthRequired(); return; }\n                if(!res.ok) throw new Error(\'HTTP \' + res.status);\n                const data = await res.json();\n                if(!data.ok) throw new Error(\'bad payload\');\n                _setConn(true);\n                failCount = 0;\n                if(typeof applyPanelState === \'function\' && data.state) applyPanelState(data.state, data);\n                if(typeof updateTelemetryFromBackend === \'function\') updateTelemetryFromBackend(data);\n                if(false) {\n                    let lines = data.logs.split(\'\\n\').filter(x => x.trim());\n                    if(lines.length > 0 && lines[lines.length-1] !== lastLogLine) {\n                        lastLogLine = lines[lines.length-1];\n                        lines.slice(-10).forEach(l => { if(!window.logEntries.some(e => e.msg === l)) logCore(l); });\n                    }\n                }\n            } catch(e) {\n                failCount++;\n                if(failCount === 1) { _setConn(false); }\n            }\n        }\n        setTimeout(syncLoop, failCount > 2 ? 5000 : 2000);\n    }\n    syncLoop();\n};\n\nwindow.setXrayStatus = async function(action) {\n    if(action !== \'clear_logs\') showToast(\'Executing \' + action + \'...\', \'info\');\n    try {\n        let res = await fetch(\'/api/action\', { method: \'POST\', body: JSON.stringify({action}), headers: {\'Content-Type\': \'application/json\'} });\n        if(res.status === 401) return showAuthRequired();\n        if(res.ok && action !== \'clear_logs\') showToast(\'Command completed: \' + action, \'success\');\n        else if(!res.ok) showToast(\'Command failed\', \'error\');\n    } catch(e) { showToast(\'Network error\', \'error\'); }\n};\n\nwindow.exportPanelDraft = function() {\n    let dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(serializePanelState()));\n    let dlAnchorElem = document.createElement(\'a\');\n    dlAnchorElem.setAttribute("href", dataStr);\n    dlAnchorElem.setAttribute("download", "panel_draft.json");\n    dlAnchorElem.click();\n};\n\nwindow.importPanelDraftFromFile = function(event) {\n    const file = event.target.files[0];\n    if(!file) return;\n    const reader = new FileReader();\n    reader.onload = e => {\n        try {\n            const data = JSON.parse(e.target.result);\n            applyPanelState(data, null, true);\n            pushPanelState(\'import\');\n            showToast(\'Draft imported successfully\', \'success\');\n        } catch(err) {\n            showToast(\'Failed to parse draft\', \'error\');\n        }\n    };\n    reader.readAsText(file);\n};\n    </script>\n<script>(function(){function c(){var b=a.contentDocument||(a.contentWindow&&a.contentWindow.document);if(b){var d=b.createElement(\'script\');d.innerHTML="window.__CF$cv$params={r:\'a27e28433dfedf30\',t:\'MTc4NjE4ODI5Mw==\'};var a=document.createElement(\'script\');a.src=\'/cdn-cgi/challenge-platform/scripts/jsd/main.js\';document.getElementsByTagName(\'head\')[0].appendChild(a);";b.getElementsByTagName(\'head\')[0].appendChild(d)}}if(document.body){var a=document.createElement(\'iframe\');a.height=1;a.width=1;a.style.position=\'absolute\';a.style.top=0;a.style.left=0;a.style.border=\'none\';a.style.visibility=\'hidden\';document.body.appendChild(a);if(\'loading\'!==document.readyState)c();else if(window.addEventListener)document.addEventListener(\'DOMContentLoaded\',c);else{var e=document.onreadystatechange||function(){};document.onreadystatechange=function(b){e(b);\'loading\'!==document.readyState&&(document.onreadystatechange=e,c())}}}})();</script></body>\n</html>\n'

# ---------------------------------------------------------------------------
# Logging & Helper Functions
# ---------------------------------------------------------------------------
def add_log(msg: str):
    # Panel console logging removed.
    return None

def get_domain() -> str:
    global CUSTOM_DOMAIN
    if CUSTOM_DOMAIN:
        return CUSTOM_DOMAIN
    render_url = os.environ.get("RENDER_EXTERNAL_URL", "")
    railway_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")
    domain = render_url or railway_domain or "localhost"
    return domain.replace("https://", "").replace("http://", "").rstrip("/")

def get_config_host() -> str:
    """Host used inside generated VLESS configs (never includes a port).

    The proxy always listens on 443, so embedding a port here would produce
    malformed addresses like `host:8014:443` and break every generated config.
    """
    domain = get_domain()
    if not domain:
        return "localhost"
    # Strip an explicit port if one sneaks in (e.g. CUSTOM_DOMAIN set to `host:443`).
    host = domain
    if host.startswith("["):  # IPv6 literal
        end = host.find("]")
        if end != -1:
            return host[: end + 1]
    elif ":" in host:
        host = host.rsplit(":", 1)[0]
    return host.rstrip(".") or "localhost"

def uptime_seconds() -> int:
    return int(time.time() - stats["start_time"])

def uptime_str() -> str:
    secs = uptime_seconds()
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h}h {m:02d}m {s:02d}s"

def generate_uuid() -> str:
    return secrets.token_hex(4) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)

def generate_vless_link(uuid: str, remark: str = "R2Leafy", address: str = None) -> str:
    host = get_config_host()
    addr = (address or host).strip()
    if not addr:
        addr = host
    # The proxy always listens on 443; never let a port leak in from a custom
    # address or host (would produce `host:8443:443` and break the config).
    if addr.startswith("["):
        end = addr.find("]")
        if end != -1:
            addr = addr[: end + 1]
    elif ":" in addr:
        addr = addr.rsplit(":", 1)[0]
    addr = addr.rstrip(".") or host
    path = f"/ws/{uuid}"
    # High ALPN negotiation: h2, http/1.1 for maximum performance
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": host,
        "path": path,
        "sni": host,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def resolve_name_placeholders(text: str, client: dict) -> str:
    if not text:
        return "R2Leafy Node"
    t = text
    used_gb = round(client.get("used_bytes", 0) / (1024.0 * 1024.0 * 1024.0), 2)
    limit_gb = client.get("limit", 0)
    limit_str = f"{limit_gb:.2f}GB" if limit_gb > 0 else "Unlimited"
    remain_str = f"{max(0, limit_gb - used_gb):.2f}GB" if limit_gb > 0 else "Unlimited"
    exp_str = client.get("expiry", "")[:10] if client.get("expiry") else "Never"

    t = t.replace("%client-name%", client.get("name", "Client"))
    t = t.replace("%data-used%", f"{used_gb:.2f}")
    t = t.replace("%data-total%", limit_str)
    t = t.replace("%data-remain%", remain_str)
    t = t.replace("%expiry-date%", exp_str)
    return t

def build_client_sub_links(client: dict, endpoint: str | None = None) -> list:
    cid = str(client.get("id", "")).strip()
    cname = str(client.get("name", "")).strip()
    domain = endpoint or get_domain()

    custom_entries = SUB_CLIENT_SUBSCRIPTIONS.get(cid) or SUB_CLIENT_SUBSCRIPTIONS.get(cname) or []

    sub_links = []
    if custom_entries and isinstance(custom_entries, list) and len(custom_entries) > 0:
        for entry in custom_entries:
            etype = entry.get("type", "proxy")
            raw_name = entry.get("name", "R2Leafy Node")
            resolved_name = resolve_name_placeholders(raw_name, client)

            if etype == "proxy":
                ip = (entry.get("ipAddress") or "").strip() or domain
                # Route through the shared generator so the address is sanitised
                # (ports stripped) exactly like the direct/server links.
                link = generate_vless_link(cid, remark=resolved_name, address=ip)
                sub_links.append(link)
            elif etype == "info":
                info_link = f"trojan://{generate_uuid()}@127.0.0.1:80?security=none#{quote(resolved_name)}"
                sub_links.append(info_link)

    if not sub_links:
        sub_links.append(generate_vless_link(cid, remark=f"R2Leafy🍃 {client['name']}-Direct", address=domain))
        for i, addr in enumerate(CUSTOM_ADDRESSES):
            if addr:
                sub_links.append(generate_vless_link(cid, remark=f"R2Leafy🍃 {client['name']}-Node{i+1}", address=addr))

    return sub_links

def build_relay_sub_links(client: dict, relay_url: str) -> list:
    """Build a relay-only subscription without mutating the direct subscription."""
    relay = urlsplit(str(relay_url).strip())
    if relay.scheme != "https" or not relay.hostname:
        raise ValueError("Relay URL must be a valid HTTPS URL")
    return build_client_sub_links(client, relay.hostname)

# ---------------------------------------------------------------------------
# State Persistence (Save & Load)
# ---------------------------------------------------------------------------
def save_state_to_disk():
    try:
        data = {
            "clients": CLIENTS,
            "subClientSubscriptions": SUB_CLIENT_SUBSCRIPTIONS,
            "settings": SETTINGS,
            "custom_domain": CUSTOM_DOMAIN,
            "custom_addresses": CUSTOM_ADDRESSES,
            "auth": {
                "password_hash": AUTH["password_hash"],
                "pass_setup": AUTH["pass_setup"]
            }
        }
        with open(STATE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not persist state to disk: {e}")

def load_state_from_disk():
    global CLIENTS, SUB_CLIENT_SUBSCRIPTIONS, SETTINGS, CUSTOM_DOMAIN, CUSTOM_ADDRESSES, AUTH
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
            if "clients" in data and isinstance(data["clients"], list):
                CLIENTS = data["clients"]
            if "subClientSubscriptions" in data and isinstance(data["subClientSubscriptions"], dict):
                SUB_CLIENT_SUBSCRIPTIONS = data["subClientSubscriptions"]
            if "settings" in data and isinstance(data["settings"], dict):
                SETTINGS.update(data["settings"])
            if "custom_domain" in data:
                CUSTOM_DOMAIN = str(data["custom_domain"])
            if "custom_addresses" in data and isinstance(data["custom_addresses"], list):
                CUSTOM_ADDRESSES = data["custom_addresses"]
            if "auth" in data and isinstance(data["auth"], dict):
                if data["auth"].get("password_hash"):
                    AUTH["password_hash"] = data["auth"]["password_hash"]
                if "pass_setup" in data["auth"]:
                    AUTH["pass_setup"] = bool(data["auth"]["pass_setup"])
            logger.info("Loaded persisted state from disk")
        except Exception as e:
            logger.warning(f"Failed to load state from disk: {e}")

def ensure_default_client():
    global CLIENTS, SUB_CLIENT_SUBSCRIPTIONS
    if not CLIENTS:
        default_id = generate_uuid()
        default_client = {
            "id": default_id,
            "name": "Default",
            "limit": 0.0,
            "usage": 0.0,
            "limit_bytes": 0,
            "used_bytes": 0,
            "max_connections": 0,
            "expiry": "",
            "status": 1,
            "active": True,
            "utls": "chrome",
            "created_at": datetime.now().isoformat()
        }
        CLIENTS.append(default_client)

        # Pre-configured Subscription Lab layout: Info banner at top, then ultra-fast WebSocket node
        SUB_CLIENT_SUBSCRIPTIONS[default_id] = [
            {
                "id": "info-" + secrets.token_hex(4),
                "type": "info",
                "name": "📢 Welcome to R2Leafy | %data-used%GB / %data-total%",
                "ipAddress": ""
            },
            {
                "id": "ws-" + secrets.token_hex(4),
                "type": "proxy",
                "transport": "ws",
                "name": "⚡ %client-name%-WebSocket",
                "ipAddress": ""
            }
        ]
        save_state_to_disk()

load_state_from_disk()
ensure_default_client()

# ---------------------------------------------------------------------------
# Sessions & Auth Helpers
# ---------------------------------------------------------------------------
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
        raise HTTPException(status_code=401, detail="Unauthorized")
    return token

# ---------------------------------------------------------------------------
# Speed & Telemetry Background Tasks
# ---------------------------------------------------------------------------
async def speed_monitor_loop():
    while True:
        await asyncio.sleep(1.0)
        now = time.time()
        dt = max(0.1, now - _speed_tracker["last_time"])
        cur_rx = stats["rx_bytes"]
        cur_tx = stats["tx_bytes"]
        d_rx = cur_rx - _speed_tracker["last_rx"]
        d_tx = cur_tx - _speed_tracker["last_tx"]

        _speed_tracker["down_mbps"] = round((d_rx * 8.0) / (dt * 1024 * 1024), 2)
        _speed_tracker["up_mbps"] = round((d_tx * 8.0) / (dt * 1024 * 1024), 2)

        _speed_tracker["last_time"] = now
        _speed_tracker["last_rx"] = cur_rx
        _speed_tracker["last_tx"] = cur_tx

# ---------------------------------------------------------------------------
# Modern FastAPI Lifespan Context Manager
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    load_state_from_disk()
    ensure_default_client()
    max_connections = int(os.environ.get("R2LEAFY_MAX_CONNECTIONS", "2000"))
    keepalive_connections = int(os.environ.get("R2LEAFY_KEEPALIVE_CONNECTIONS", "500"))
    limits = httpx.Limits(max_connections=max_connections, max_keepalive_connections=keepalive_connections, keepalive_expiry=30.0)
    timeout = httpx.Timeout(float(os.environ.get("R2LEAFY_TIMEOUT", "30")), connect=float(os.environ.get("R2LEAFY_CONNECT_TIMEOUT", "10")))
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True, http2=False)
    asyncio.create_task(speed_monitor_loop())
    add_log(f"R2Leafy gateway listening on port {get_listen_port()}")
    yield
    if http_client:
        await http_client.aclose()
    save_state_to_disk()
    add_log("R2Leafy gateway stopped")

app = FastAPI(title="R2Leafy", docs_url=None, redoc_url=None, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Frontend Template Serving Endpoints
# ---------------------------------------------------------------------------
def get_raw_index_html() -> str:
    global INDEX_HTML_CACHE
    if INDEX_HTML_CACHE:
        return INDEX_HTML_CACHE
    INDEX_HTML_CACHE = EMBEDDED_INDEX_HTML
    return INDEX_HTML_CACHE
    candidates = [
        INDEX_HTML_PATH,
        os.path.join(os.getcwd(), "index.html"),
        "index.html",
        "/app/index.html",
        "/home/user/index.html"
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    INDEX_HTML_CACHE = f.read()
                    return INDEX_HTML_CACHE
            except Exception:
                pass
    return "<!DOCTYPE html><html><body><h1>R2Leafy</h1><p>Running on Render</p></body></html>"

def serve_index_html(request: Request) -> HTMLResponse:
    token = request.cookies.get(SESSION_COOKIE)
    is_auth = False
    if token:
        exp = SESSIONS.get(token)
        if exp and exp >= time.time():
            is_auth = True

    content = get_raw_index_html()

    pass_setup_js = "true" if AUTH["pass_setup"] else "false"
    logged_in_js = "true" if is_auth else "false"

    content = content.replace("{{PASS_SETUP}}", pass_setup_js)
    content = content.replace("{{LOGGED_IN}}", logged_in_js)

    headers = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }
    return HTMLResponse(content=content, headers=headers)

@app.get("/")
@app.head("/")
async def root_view(request: Request):
    return serve_index_html(request)

@app.get("/login")
async def login_view(request: Request):
    return serve_index_html(request)

@app.get("/dashboard")
async def dashboard_view(request: Request):
    return serve_index_html(request)

@app.get("/index.html")
async def index_view(request: Request):
    return serve_index_html(request)

@app.get("/health")
@app.head("/health")
async def health_check():
    return {
        "status": "ok",
        "service": "R2Leafy",
        "connections": len(connections),
        "uptime": uptime_str(),
        "uptime_sec": uptime_seconds(),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2)
    }

# ---------------------------------------------------------------------------
# Auth API Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/setup")
async def api_setup(request: Request):
    body = await request.json()
    pwd = str(body.get("pass") or body.get("password") or "")
    if len(pwd) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    # Serialize first-run setup so concurrent requests cannot overwrite the password.
    async with STATE_LOCK:
        if AUTH["pass_setup"]:
            raise HTTPException(status_code=409, detail="Password setup is already complete")
        AUTH["password_hash"] = hash_password(pwd)
        AUTH["pass_setup"] = True
        save_state_to_disk()

    token = await create_session()
    add_log("Admin password configured on first startup")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    pwd = str(body.get("pass") or body.get("password") or "")
    if hash_password(pwd) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    add_log("Admin logged in successfully")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    add_log("Admin logged out")
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    is_auth = await is_valid_session(token)
    return {"authenticated": is_auth, "pass_setup": AUTH["pass_setup"]}

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
    AUTH["pass_setup"] = True
    save_state_to_disk()
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    add_log("Admin password changed")
    return {"ok": True}

# ---------------------------------------------------------------------------
# State & Telemetry Synchronization API
# ---------------------------------------------------------------------------
@app.get("/api/state")
async def get_panel_state(_=Depends(require_auth)):
    global CLIENTS, SUB_CLIENT_SUBSCRIPTIONS, SETTINGS

    try:
        load_avg = list(os.getloadavg())
    except (AttributeError, OSError):
        load_avg = [0.12, 0.08, 0.05]

    proc_mem_mb = psutil.Process().memory_info().rss / (1024.0 * 1024.0)
    ram_used_mb = round(max(38.0, min(500.0, proc_mem_mb)), 1)
    ram_total_mb = 512.0

    total_rx_gb = round(stats["rx_bytes"] / (1024.0 * 1024.0 * 1024.0), 3)
    total_tx_gb = round(stats["tx_bytes"] / (1024.0 * 1024.0 * 1024.0), 3)

    domain = get_domain()
    logs_text = chr(10).join(console_logs)

    return {
        "ok": True,
        "state": {
            "clients": CLIENTS,
            "subClientSubscriptions": SUB_CLIENT_SUBSCRIPTIONS,
            "settings": SETTINGS
        },
        "clients": CLIENTS,
        "portDomain": domain,
        "webDomain": domain,
        "xrayRunning": core_running,
        "xrayUp": core_running,
        "xrayUptimeSec": uptime_seconds(),
        "connections": len(connections),
        "totalRxGb": total_rx_gb,
        "totalTxGb": total_tx_gb,
        "speedDownMbps": _speed_tracker["down_mbps"],
        "speedUpMbps": _speed_tracker["up_mbps"],
        "loadAvg": load_avg,
        "ramMb": ram_used_mb,
        "ramTotalMb": ram_total_mb,
        "tcpCc": "bbr",
        "certSha256": "",
    }

@app.put("/api/state")
@app.post("/api/state")
async def update_panel_state(request: Request, _=Depends(require_auth)):
    global CLIENTS, SUB_CLIENT_SUBSCRIPTIONS, SETTINGS
    body = await request.json()
    new_state = body.get("state") if isinstance(body.get("state"), dict) else body
    reason = body.get("reason", "sync")

    async with STATE_LOCK:
        if "clients" in new_state and isinstance(new_state["clients"], list):
            existing_map = {c["id"]: c for c in CLIENTS}
            updated_clients = []
            for c in new_state["clients"]:
                cid = c.get("id") or generate_uuid()
                old = existing_map.get(cid, {})
                c_data = {
                    "id": cid,
                    "name": str(c.get("name") or "Client")[:60],
                    "limit": float(c.get("limit") or 0.0),
                    "usage": float(c.get("usage") if c.get("usage") is not None else old.get("usage", 0.0)),
                    "limit_bytes": int(float(c.get("limit") or 0.0) * 1024 * 1024 * 1024),
                    "used_bytes": int(old.get("used_bytes", 0)),
                    "max_connections": int(c.get("max_connections") or 0),
                    "expiry": str(c.get("expiry") or ""),
                    "status": int(c.get("status") if "status" in c else 1),
                    "active": bool(c.get("status", 1)),
                    "utls": str(c.get("utls") or "chrome"),
                    "created_at": str(c.get("created_at") or old.get("created_at") or datetime.now().isoformat())
                }
                updated_clients.append(c_data)
            CLIENTS = updated_clients

        if "subClientSubscriptions" in new_state and isinstance(new_state["subClientSubscriptions"], dict):
            SUB_CLIENT_SUBSCRIPTIONS.update(new_state["subClientSubscriptions"])

        if "settings" in new_state and isinstance(new_state["settings"], dict):
            SETTINGS.update(new_state["settings"])

    save_state_to_disk()
    return {"ok": True, "state": {"clients": CLIENTS, "subClientSubscriptions": SUB_CLIENT_SUBSCRIPTIONS, "settings": SETTINGS}}

@app.post("/api/action")
async def handle_core_action(request: Request, _=Depends(require_auth)):
    global core_running
    body = await request.json()
    action = str(body.get("action") or "").lower()

    if action == "restart":
        core_running = True
        add_log("Core engine restarted")
        return {"ok": True, "action": "restart"}
    elif action == "stop":
        core_running = False
        add_log("Core engine stopped")
        return {"ok": True, "action": "stop"}
    elif action == "start":
        core_running = True
        add_log("Core engine started")
        return {"ok": True, "action": "start"}
    elif action == "clear_logs":
        console_logs.clear()
        error_logs.clear()
        add_log("Console logs cleared")
        return {"ok": True, "action": "clear_logs"}
    else:
        return {"ok": True, "action": action}

# ---------------------------------------------------------------------------
# Client Profiles, Inbounds & Links Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    res = []
    for c in CLIENTS:
        res.append({
            "uuid": c["id"],
            "label": c["name"],
            "limit_bytes": c.get("limit_bytes", 0),
            "used_bytes": c.get("used_bytes", 0),
            "max_connections": c.get("max_connections", 0),
            "active": bool(c.get("status", 1)),
            "expiry": c.get("expiry", ""),
            "created_at": c.get("created_at", ""),
            "vless_link": generate_vless_link(c["id"], remark=f"R2Leafy-{c['name']}")
        })
    return {"links": res}

@app.post("/api/links")
async def create_link_api(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    limit_val = float(body.get("limit_value") or 0.0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = int(limit_val * 1024 * 1024 * 1024) if limit_unit == "GB" else int(limit_val * 1024 * 1024)
    cid = generate_uuid()

    c_data = {
        "id": cid,
        "name": label,
        "limit": limit_val,
        "usage": 0.0,
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "max_connections": int(body.get("max_connections") or 0),
        "expiry": str(body.get("expiry") or body.get("expiry_date") or ""),
        "status": 1,
        "active": True,
        "utls": "chrome",
        "created_at": datetime.now().isoformat()
    }
    CLIENTS.append(c_data)
    save_state_to_disk()
    add_log(f"Created client inbound '{label}' ({cid})")
    return {"ok": True, "uuid": cid, "link": generate_vless_link(cid, remark=f"R2Leafy-{label}")}

@app.patch("/api/links/{uid}")
async def patch_link_api(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    client = next((c for c in CLIENTS if c["id"] == uid), None)
    if not client:
        raise HTTPException(status_code=404, detail="Link not found")

    if "active" in body:
        client["status"] = 1 if body["active"] else 0
        client["active"] = bool(body["active"])
    if "label" in body:
        client["name"] = str(body["label"])[:60]
    if "limit_value" in body:
        lv = float(body["limit_value"] or 0)
        client["limit"] = lv
        client["limit_bytes"] = int(lv * 1024 * 1024 * 1024)
    if "reset_usage" in body and body["reset_usage"]:
        client["usage"] = 0.0
        client["used_bytes"] = 0
    save_state_to_disk()
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link_api(uid: str, _=Depends(require_auth)):
    global CLIENTS
    CLIENTS = [c for c in CLIENTS if c["id"] != uid]
    SUB_CLIENT_SUBSCRIPTIONS.pop(uid, None)
    save_state_to_disk()
    add_log(f"Deleted client {uid}")
    return {"ok": True}

# ---------------------------------------------------------------------------
# Subscription Generation Endpoints & Web HTML Page
# ---------------------------------------------------------------------------
def _b64url_decode(s: str) -> str:
    try:
        padded = s + "=" * ((4 - len(s) % 4) % 4)
        return base64.urlsafe_b64decode(padded.encode()).decode(errors="ignore")
    except Exception:
        return s

@app.get("/api/sub/link/{client_id}")
async def get_subscription_link_url(client_id: str):
    domain = get_domain()
    url = f"https://{domain}/sub/{client_id}"
    return {"ok": True, "link": url}

@app.get("/api/links/{uid}/sub")
async def get_single_link_subscription(uid: str, request: Request, _=Depends(require_auth)):
    client = next((c for c in CLIENTS if c["id"] == uid or c["name"] == uid), None)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    vless_link = generate_vless_link(client["id"], remark=f"R2Leafy-{client['name']}")
    return {
        "ok": True,
        "subscription_url": f"https://{get_domain()}/sub/{client['id']}",
        "config": vless_link,
        "label": client["name"],
        "used_bytes": client.get("used_bytes", 0),
        "limit_bytes": client.get("limit_bytes", 0),
    }

@app.get("/sub/{encoded_id}")
async def public_subscription_endpoint(encoded_id: str, request: Request):
    clean_id = str(encoded_id).strip()
    raw_id = _b64url_decode(clean_id).strip()

    # Match client
    client = None
    for c in CLIENTS:
        c_id = str(c.get("id", "")).strip()
        c_name = str(c.get("name", "")).strip()
        if c_id == clean_id or c_id == raw_id or c_name == clean_id or c_name == raw_id:
            client = c
            break

    if not client:
        raise HTTPException(status_code=404, detail="Subscription client not found")
    if not client.get("status", 1):
        raise HTTPException(status_code=403, detail="Subscription disabled")

    # Generate custom nodes from Subscription Lab
    relay_data = RELAY_CONFIGS.get(client["id"])
    sub_links = build_client_sub_links(client)
    sub_content = chr(10).join(sub_links)
    encoded_payload = base64.b64encode(sub_content.encode()).decode()

    # If accessed from browser (HTML), render subscription landing page
    accept_header = request.headers.get("accept", "").lower()
    user_agent = request.headers.get("user-agent", "").lower()
    is_browser = ("text/html" in accept_header or "mozilla" in user_agent) and "raw" not in request.query_params

    if is_browser:
        data_obj = {
            "client": {
                "id": client["id"],
                "name": client["name"],
                "usage": round(client.get("used_bytes", 0) / (1024.0 * 1024.0 * 1024.0), 3),
                "limit": client.get("limit", 0),
                "expiry": client.get("expiry", ""),
                "status": client.get("status", 1)
            },
            "links": sub_links,
            "relay_links": relay_data.get("links", []) if relay_data else [],
            "relay_subscription": relay_data.get("subscription", "") if relay_data else ""
        }
        b64_json = base64.b64encode(json.dumps(data_obj).encode()).decode()
        html_page = SUB_HTML_TEMPLATE.replace("{{SUB_DATA_B64}}", b64_json)
        return HTMLResponse(content=html_page)

    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f'attachment; filename="R2Leafy_{client["name"]}.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={client.get('used_bytes', 0)}; download=0; total={client.get('limit_bytes', 0)}; expire=0"
    }
    return Response(content=encoded_payload, headers=headers)

# ---------------------------------------------------------------------------
# Custom Domains, Clean IPs & Advanced Config Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/domain")
async def get_domain_api(_=Depends(require_auth)):
    return {"domain": CUSTOM_DOMAIN}

@app.post("/api/domain")
async def set_domain_api(request: Request, _=Depends(require_auth)):
    global CUSTOM_DOMAIN
    body = await request.json()
    domain = (body.get("domain") or "").strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
    CUSTOM_DOMAIN = domain
    save_state_to_disk()
    domain_label = CUSTOM_DOMAIN if CUSTOM_DOMAIN else "(default)"
    add_log(f"Custom domain set to: {domain_label}")
    return {"ok": True, "domain": CUSTOM_DOMAIN}

@app.get("/api/addresses")
async def list_addresses_api(_=Depends(require_auth)):
    return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
async def add_address_api(request: Request, _=Depends(require_auth)):
    global CUSTOM_ADDRESSES
    body = await request.json()
    addr = (body.get("address") or "").strip()
    if not addr:
        raise HTTPException(status_code=400, detail="Address is required")
    if addr not in CUSTOM_ADDRESSES:
        CUSTOM_ADDRESSES.append(addr)
        save_state_to_disk()
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses/{index}")
async def delete_address_api(index: int, _=Depends(require_auth)):
    global CUSTOM_ADDRESSES
    if 0 <= index < len(CUSTOM_ADDRESSES):
        CUSTOM_ADDRESSES.pop(index)
        save_state_to_disk()
        return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}
    raise HTTPException(status_code=404, detail="Address not found")

@app.post("/api/relay")
async def provision_cloudflare_relay(request: Request, _=Depends(require_auth)):
    body = await request.json()
    try:
        relay = provision_relay(body.get("token"), body.get("origin"), "v2leafy-r2")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)[:200])
    relay_configs = {}
    for client in CLIENTS:
        links = build_relay_sub_links(client, relay["relay_url"])
        payload = base64.b64encode("\n".join(links).encode()).decode()
        relay_configs[client["id"]] = {"links": links, "subscription": payload}
    RELAY_CONFIGS.update(relay_configs)
    return {"ok": True, "relay": relay, "relay_configs": relay_configs}

@app.post("/api/backup")
async def create_backup_api(_=Depends(require_auth)):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"r2leafy_backup_{stamp}.json"
    save_state_to_disk()
    return {
        "ok": True,
        "file": backup_filename,
        "state": {
            "clients": CLIENTS,
            "subClientSubscriptions": SUB_CLIENT_SUBSCRIPTIONS,
            "settings": SETTINGS,
            "custom_domain": CUSTOM_DOMAIN,
            "custom_addresses": CUSTOM_ADDRESSES
        }
    }

@app.get("/stats")
async def get_stats_api(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime_str(),
        "clients_count": len(CLIENTS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": psutil.virtual_memory().percent,
    }

# ---------------------------------------------------------------------------
# VLESS Proxy Header Parser & Core Engine
# ---------------------------------------------------------------------------
RELAY_BUF = int(os.environ.get("R2LEAFY_RELAY_BUFFER", str(256 * 1024)))

def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("Packet chunk too small for VLESS protocol")
    pos = 0
    pos += 1
    pos += 16
    addon_len = first_chunk[pos]
    pos += 1 + addon_len
    command = first_chunk[pos]
    pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big")
    pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]
        pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"Unknown VLESS address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

def check_client_quota(client_id: str, extra_bytes: int) -> bool:
    client = next((c for c in CLIENTS if c["id"] == client_id), None)
    if not client or not client.get("status", 1):
        return False
    limit_b = client.get("limit_bytes", 0)
    if limit_b > 0 and (client.get("used_bytes", 0) + extra_bytes) > limit_b:
        return False
    return True

def record_traffic(client_id: str, size: int, is_rx: bool):
    stats["total_bytes"] += size
    if is_rx:
        stats["rx_bytes"] += size
    else:
        stats["tx_bytes"] += size

    hour_key = datetime.now().strftime("%H:00")
    hourly_traffic[hour_key] += size

    client = next((c for c in CLIENTS if c["id"] == client_id), None)
    if client:
        client["used_bytes"] = client.get("used_bytes", 0) + size
        client["usage"] = round(client["used_bytes"] / (1024.0 * 1024.0 * 1024.0), 3)

# ---------------------------------------------------------------------------
# Ultra-Fast WebSocket VLESS Tunnel Engine
# ---------------------------------------------------------------------------
async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, client_id: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            size = len(data)
            if not check_client_quota(client_id, size):
                await websocket.close(code=1008, reason="Quota exceeded")
                break
            record_traffic(client_id, size, is_rx=True)
            if conn_id in connections:
                connections[conn_id]["bytes"] += size
            writer.write(data)
            await writer.drain()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, client_id: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            size = len(data)
            if not check_client_quota(client_id, size):
                await websocket.close(code=1008, reason="Quota exceeded")
                break
            record_traffic(client_id, size, is_rx=False)
            if conn_id in connections:
                connections[conn_id]["bytes"] += size
            prefix = bytes([0, 0]) if first else b""
            await websocket.send_bytes(prefix + data)
            first = False
    except Exception:
        pass

@app.websocket("/ws/{uuid}")
@app.websocket("/ws")
async def websocket_vless_tunnel(websocket: WebSocket, uuid: str = None):
    if not core_running:
        await websocket.close(code=1008, reason="Core engine stopped")
        return

    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = websocket.client.host if websocket.client else "unknown"

    try:
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        command, address, port, initial_payload = parse_vless_header(first_chunk)

        target_uuid = uuid
        if not target_uuid and len(first_chunk) >= 17:
            raw_u = first_chunk[1:17].hex()
            target_uuid = f"{raw_u[:8]}-{raw_u[8:12]}-{raw_u[12:16]}-{raw_u[16:20]}-{raw_u[20:]}"

        # Strict identity check: an unknown or absent client id must never be
        # mapped to another client. This closes the open-relay hole where a bare
        # /ws or an arbitrary UUID got free transit billed to client #0.
        if not target_uuid:
            await websocket.close(code=1008, reason="Missing client identifier")
            return

        client = next((c for c in CLIENTS if c["id"] == target_uuid), None)
        if not client or not client.get("status", 1):
            await websocket.close(code=1008, reason="Invalid or disabled client")
            return

        cid = client["id"]
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {
            "uuid": cid,
            "ip": client_ip,
            "connected_at": datetime.now().isoformat(),
            "bytes": len(first_chunk)
        }
        connection_sockets[conn_id] = websocket
        link_ip_map[cid].add(client_ip)
        record_traffic(cid, len(first_chunk), is_rx=True)

        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)

        # Apply TCP_NODELAY for lowest latency
        try:
            sock = writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        if initial_payload:
            p_size = len(initial_payload)
            record_traffic(cid, p_size, is_rx=True)
            writer.write(initial_payload)
            await writer.drain()

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, cid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, cid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid_to_clean = info.get("uuid")
                ip_to_clean = info.get("ip")
                if uid_to_clean and ip_to_clean:
                    has_other = any(c.get("uuid") == uid_to_clean and c.get("ip") == ip_to_clean for c in connections.values())
                    if not has_other and uid_to_clean in link_ip_map:
                        link_ip_map[uid_to_clean].discard(ip_to_clean)


"""Cloudflare Worker relay provisioning for R2Leafy.

The API token is used only for the request and is never persisted or returned.
"""
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request

CF_API = "https://api.cloudflare.com/client/v4"
WORKER_SCRIPT = r'''const TARGET = __TARGET__;
addEventListener("fetch", (event) => {
  event.respondWith(handle(event.request));
});
async function handle(request) {
  const target = new URL(TARGET); const incoming = new URL(request.url);
  incoming.protocol=target.protocol; incoming.hostname=target.hostname; incoming.port=target.port;
  const isWs=(request.headers.get("Upgrade")||"").toLowerCase()==="websocket";
  if ((request.method==="GET"||request.method==="HEAD")&&incoming.pathname==="/health") return new Response("ok",{headers:{"Cache-Control":"no-store"}});
  if (isWs) { const ac=new AbortController(); const timer=setTimeout(()=>ac.abort(),10000); let upstream;
    try { upstream=await fetch(incoming.toString(),{method:"GET",headers:request.headers,signal:ac.signal}); } catch (_) { return new Response("relay upstream unavailable",{status:502}); } finally { clearTimeout(timer); }
    if (!upstream.webSocket) return new Response("upstream did not upgrade",{status:502}); const pair=new WebSocketPair(), client=pair[0], edge=pair[1], server=upstream.webSocket; server.accept(); edge.accept();
    server.addEventListener("message",e=>{try{edge.send(e.data)}catch(_){}}); edge.addEventListener("message",e=>{try{server.send(e.data)}catch(_){}});
    const close=(ws,e)=>{try{ws.close([1000,1001,1002,1003,1007,1008,1009,1011].includes(e?.code)?e.code:1000)}catch(_){}};
    server.addEventListener("close",e=>close(edge,e)); edge.addEventListener("close",e=>close(server,e)); server.addEventListener("error",()=>{try{edge.close(1011)}catch(_){}}); edge.addEventListener("error",()=>{try{server.close(1011)}catch(_){}});
    return new Response(null,{status:101,webSocket:client}); }
  const headers=new Headers(request.headers); headers.set("Host",target.hostname); headers.delete("Cookie"); const init={method:request.method,headers,redirect:"manual"};
  if(request.method!=="GET"&&request.method!=="HEAD"){init.body=request.body;init.duplex="half";} const response=await fetch(incoming.toString(),init), out=new Headers(response.headers); out.delete("set-cookie"); out.delete("cf-cache-status"); out.set("Cache-Control","no-store"); return new Response(response.body,{status:response.status,statusText:response.statusText,headers:out});
}'''

def validate_origin(value):
    value=str(value or "").strip(); parsed=urllib.parse.urlparse(value if "://" in value else "https://"+value)
    if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment: raise ValueError("Origin must be a clean HTTPS URL")
    host=parsed.hostname.lower().rstrip(".")
    if host in {"localhost","localhost.localdomain"}: raise ValueError("Private origins are not allowed")
    try:
        ip=ipaddress.ip_address(host)
        if not ip.is_global: raise ValueError("Private origins are not allowed")
    except ValueError as exc:
        if str(exc)=="Private origins are not allowed": raise
        if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",host): raise ValueError("Origin hostname is invalid")
    return "https://"+host+(f":{parsed.port}" if parsed.port else "")+(parsed.path.rstrip("/") if parsed.path not in ("","/") else "")

def _json_request(url, token, method="GET", payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=body, method=method, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="ignore").strip()[:300]
        raise ValueError(f"Cloudflare API {exc.code}: {detail or exc.reason}")
    except urllib.error.URLError as exc:
        raise ValueError(f"Cloudflare API unreachable: {exc.reason}")


def _upload_worker(url, token, script):
    """Deploy the Cloudflare relay Worker via a plain PUT.

    The relay script uses the classic service-worker format (addEventListener), so
    a single `application/javascript` body is the documented, reliable upload."
    """
    req = urllib.request.Request(url, data=script.encode(), method="PUT", headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/javascript",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read().decode()
            if response.status not in (200, 201):
                raise ValueError(f"Cloudflare rejected Worker deployment ({response.status})")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="ignore").strip()[:300]
        raise ValueError(f"Cloudflare Worker upload failed ({exc.code}): {detail or exc.reason}")
    except urllib.error.URLError as exc:
        raise ValueError(f"Cloudflare Worker upload unreachable: {exc.reason}")


def provision_relay(token, origin, name_prefix="v2leafy-r2"):
    logger.info("[relay] starting Cloudflare worker provisioning")
    token = str(token or "").strip()
    if len(token) < 20 or len(token) > 300 or any(c.isspace() for c in token): raise ValueError("Cloudflare token is invalid")
    origin = validate_origin(origin)
    logger.info("[relay] verifying token with Cloudflare")
    verify = _json_request(CF_API + "/user/tokens/verify", token)
    if not verify.get("success"): raise ValueError("Cloudflare token verification failed")
    accounts = _json_request(CF_API + "/accounts?per_page=1", token).get("result", [])
    if not accounts: raise ValueError("No Cloudflare account is available for this token")
    account = accounts[0]["id"]
    name = re.sub(r"[^a-z0-9-]", "-", name_prefix.lower())[:40].strip("-") or "v2leafy-relay"
    script = WORKER_SCRIPT.replace("__TARGET__", json.dumps(origin))
    logger.info(f"[relay] deploying worker '{name}' on account {account[:8]}...")
    _upload_worker(f"{CF_API}/accounts/{account}/workers/scripts/{name}", token, script)
    logger.info(f"[relay] worker deployed: https://{name}.{account[:8]}.workers.dev")
    return {"worker_name": name, "relay_url": f"https://{name}.{account[:8]}.workers.dev", "origin": urllib.parse.urlparse(origin).hostname}

# ---------------------------------------------------------------------------
# Direct entry point for Render and compatible Python hosts
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    port = get_listen_port()
    uvicorn.run(app, host="0.0.0.0", port=port, access_log=False)

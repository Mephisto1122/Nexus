#!/usr/bin/env python3
"""
Nexus Gate — Smart Setup

Run:
    python setup.py

A secure, UI-first onboarding flow for Nexus Gate.
- Detects supported AI agent platforms
- Installs the local verification client
- Configures all detected local tool integrations safely
- Starts the admin dashboard locally
- Delegates dashboard initialization to the dashboard server itself

This installer intentionally keeps the first-run dashboard local-only.
External/admin deployment should use the dedicated dashboard deployment flow.
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, List, Optional, Tuple

# ──────────────────────────────────────────────────────────────
# Paths and constants
# ──────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent
NEXUS_DIR = Path.home() / ".nexus"
CLIENT_INSTALL_DIR = NEXUS_DIR / "client"
ADMIN_INSTALL_DIR = NEXUS_DIR / "admin"
SERVER_DATA_DIR = Path.home() / ".nexus-server"
SETUP_PORT = 9090
DASHBOARD_PORT = 7070
SETUP_TOKEN = secrets.token_urlsafe(24)

INSTALL_STATE: Dict[str, Any] = {
    "dashboard_proc": None,
    "install_result": None,
}

# Windows ANSI
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────
class SetupError(RuntimeError):
    pass


def _json_dump(path: Path, data: Dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _copy_required(src: Path, dst: Path, mode: int = 0o600) -> None:
    if not src.exists():
        raise SetupError(f"Required file not found: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        if os.path.realpath(str(src)) == os.path.realpath(str(dst)):
            return
    except OSError:
        pass

    tmp = dst.with_suffix(dst.suffix + ".tmp")
    shutil.copy2(str(src), str(tmp))
    try:
        os.chmod(str(tmp), mode)
    except OSError:
        pass
    tmp.replace(dst)


def _copy_optional(src: Path, dst: Path, mode: int = 0o600) -> bool:
    if not src.exists():
        return False
    _copy_required(src, dst, mode=mode)
    return True


def _safe_run(cmd: List[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _https_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request_json(method: str, url: str, data: Optional[Dict[str, Any]] = None, timeout: int = 5) -> Dict[str, Any]:
    body = None
    headers = {"Accept": "application/json"}
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    ctx = _https_context() if url.startswith("https://") else None
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


# ──────────────────────────────────────────────────────────────
# Detection
# ──────────────────────────────────────────────────────────────
def detect_agents() -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []

    claude_home = Path.home() / ".claude"
    claude_project = Path.cwd() / ".claude"
    if claude_home.exists():
        found.append({
            "id": "claude",
            "name": "Claude Code",
            "location": str(claude_home),
            "target": str(claude_home / "settings.json"),
            "recommended": True,
        })
    elif claude_project.exists():
        found.append({
            "id": "claude",
            "name": "Claude Code",
            "location": str(claude_project),
            "target": str(claude_project / "settings.json"),
            "recommended": True,
        })
    elif shutil.which("claude"):
        found.append({
            "id": "claude",
            "name": "Claude Code",
            "location": "Detected in PATH",
            "target": str(claude_home / "settings.json"),
            "recommended": True,
        })

    codex_home = Path.home() / ".codex"
    if codex_home.exists() or shutil.which("codex"):
        found.append({
            "id": "codex",
            "name": "Codex CLI",
            "location": str(codex_home) if codex_home.exists() else "Detected in PATH",
            "target": str(codex_home / "hooks.json"),
            "recommended": True,
        })

    gemini_home = Path.home() / ".gemini"
    if gemini_home.exists() or shutil.which("gemini"):
        found.append({
            "id": "gemini",
            "name": "Gemini CLI",
            "location": str(gemini_home) if gemini_home.exists() else "Detected in PATH",
            "target": str(gemini_home / "settings.json"),
            "recommended": True,
        })

    if not found:
        found.append({
            "id": "manual",
            "name": "Manual integration",
            "location": "No supported agent auto-detected",
            "target": "You can copy the hook command after install",
            "recommended": True,
        })

    return found


def detect_system() -> Dict[str, Any]:
    return {
        "os": platform.system(),
        "hostname": socket.gethostname(),
        "python": sys.version.split()[0],
        "home": str(Path.home()),
        "nexus_dir": str(NEXUS_DIR),
        "client_dir": str(CLIENT_INSTALL_DIR),
        "admin_dir": str(ADMIN_INSTALL_DIR),
        "already_installed": (CLIENT_INSTALL_DIR / "nexus_hook.py").exists(),
        "dashboard_configured": (SERVER_DATA_DIR / "nexus.db").exists(),
    }


# ──────────────────────────────────────────────────────────────
# Client install and agent integration
# ──────────────────────────────────────────────────────────────
def _mode_config(mode: str, platform_ids: List[str]) -> Dict[str, Any]:
    modes = {
        "strict": {"green": "note", "orange": "block", "red": "block", "audit": "all"},
        "balanced": {"green": "note", "orange": "pass_note", "red": "block", "audit": "all"},
        "monitor": {"green": "silent", "orange": "pass_note", "red": "block_log", "audit": "all"},
    }
    cfg = dict(modes.get(mode, modes["strict"]))
    cfg["platforms"] = list(platform_ids)
    cfg["platform"] = platform_ids[0] if platform_ids else "manual"
    cfg["installed_at"] = int(time.time())
    return cfg


def _write_cli_shortcuts() -> Tuple[str, str, List[str]]:
    """Returns (direct_cmd, wrapper_cmd, created_files).
    Claude Code handles quoted paths. Gemini/Codex need a .cmd wrapper.
    """
    py = sys.executable
    hook_path = CLIENT_INSTALL_DIR / "nexus_hook.py"
    created: List[str] = []
    direct_cmd = f'"{py}" "{hook_path}"'

    if sys.platform == "win32":
        bat = NEXUS_DIR / "nexus.bat"
        bat.write_text(f'@echo off\r\n"{py}" "{hook_path}" %*\r\n', encoding="utf-8")
        created.append(str(bat))
        hook_bat = CLIENT_INSTALL_DIR / "nexus_hook.cmd"
        hook_bat.write_text(f'@echo off\r\n"{py}" "{hook_path}"\r\n', encoding="utf-8")
        wrapper_cmd = str(hook_bat)
        created.append(wrapper_cmd)
    else:
        sh = NEXUS_DIR / "nexus"
        sh.write_text(f'#!/bin/sh\nexec "{py}" "{hook_path}" "$@"\n', encoding="utf-8")
        try:
            os.chmod(sh, 0o755)
        except OSError:
            pass
        created.append(str(sh))
        wrapper_cmd = direct_cmd
    return direct_cmd, wrapper_cmd, created


def _install_claude(hook_cmd: str) -> str:
    claude_home = Path.home() / ".claude"
    claude_project = Path.cwd() / ".claude"
    settings_dir = claude_home if claude_home.exists() or not claude_project.exists() else claude_project
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_file = settings_dir / "settings.json"

    hook_entry = {
        "hooks": {
            "PreToolUse": [
                {"hooks": [{"type": "command", "command": hook_cmd}]}
            ]
        }
    }

    try:
        existing = json.loads(settings_file.read_text(encoding="utf-8")) if settings_file.exists() else {}
    except Exception:
        existing = {}
    existing.setdefault("hooks", {})["PreToolUse"] = hook_entry["hooks"]["PreToolUse"]
    settings_file.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return f"Updated Claude Code hook at {settings_file}"


def _install_codex(hook_cmd: str) -> str:
    """Configure Codex CLI via native hooks.json (PreToolUse event).
    Also enables the codex_hooks feature flag in config.toml.
    """
    codex_dir = Path.home() / ".codex"
    codex_hooks = codex_dir / "hooks.json"
    codex_config = codex_dir / "config.toml"

    # 1. Write hooks.json
    hook_entry = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": ".*",
                    "hooks": [
                        {"type": "command", "command": hook_cmd, "timeout": 10}
                    ]
                }
            ]
        }
    }
    try:
        codex_dir.mkdir(parents=True, exist_ok=True)
        if codex_hooks.exists():
            existing = json.loads(codex_hooks.read_text(encoding="utf-8"))
            existing.setdefault("hooks", {})["PreToolUse"] = hook_entry["hooks"]["PreToolUse"]
            codex_hooks.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        else:
            codex_hooks.write_text(json.dumps(hook_entry, indent=2), encoding="utf-8")
    except Exception:
        return f"Could not write {codex_hooks}. Codex hooks require manual setup."

    # 2. Enable codex_hooks feature flag in config.toml
    try:
        if codex_config.exists():
            content = codex_config.read_text(encoding="utf-8")
        else:
            content = ""
        if "[features]" in content:
            import re as _re
            if "codex_hooks" in content:
                content = _re.sub(
                    r'^codex_hooks\s*=.*$', 'codex_hooks = true',
                    content, flags=_re.MULTILINE)
            else:
                content = content.replace("[features]", "[features]\ncodex_hooks = true")
        else:
            content = content.rstrip() + "\n\n[features]\ncodex_hooks = true\n"
        codex_config.write_text(content, encoding="utf-8")
    except Exception:
        pass

    note = f"Configured Codex CLI at {codex_dir}"
    if sys.platform == "win32":
        note += " (Codex hooks are experimental on Windows)"
    return note


def _install_gemini(hook_cmd: str) -> str:
    """Configure Gemini CLI via settings.json (BeforeTool event)."""
    gemini_settings = Path.home() / ".gemini" / "settings.json"
    hook_entry = {
        "hooks": {
            "BeforeTool": [
                {
                    "matcher": ".*",
                    "hooks": [
                        {"type": "command", "command": hook_cmd, "timeout": 30000}
                    ]
                }
            ]
        }
    }
    try:
        gemini_settings.parent.mkdir(parents=True, exist_ok=True)
        if gemini_settings.exists():
            existing = json.loads(gemini_settings.read_text(encoding="utf-8"))
            existing.setdefault("hooks", {})["BeforeTool"] = hook_entry["hooks"]["BeforeTool"]
            gemini_settings.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        else:
            gemini_settings.write_text(json.dumps(hook_entry, indent=2), encoding="utf-8")
        return f"Configured Gemini CLI hooks at {gemini_settings}"
    except Exception as e:
        return f"Could not configure Gemini CLI: {e}"


def install_client(agent_platforms: List[str], mode: str) -> Dict[str, Any]:
    steps: List[str] = []
    NEXUS_DIR.mkdir(parents=True, exist_ok=True)
    CLIENT_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    ADMIN_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(NEXUS_DIR, 0o700)
        os.chmod(CLIENT_INSTALL_DIR, 0o700)
        os.chmod(ADMIN_INSTALL_DIR, 0o700)
    except OSError:
        pass
    steps.append("Created secure Nexus directories")

    client_src = ROOT_DIR / "client"
    admin_src = ROOT_DIR / "dashboard"

    required_client = [
        "nexus_hook.py",
        "nexus_structural.py",
        "nexus_reporter.py",
        "nexus_learn.py",
        "nexus_trace_compress.py",
    ]
    required_admin = [
        "nexus_server.py",
        "nexus_dashboard.html",
    ]

    for name in required_client:
        _copy_required(client_src / name, CLIENT_INSTALL_DIR / name)
    steps.append("Installed verification client and supporting tools")

    for name in required_admin:
        _copy_required(admin_src / name, ADMIN_INSTALL_DIR / name)
    steps.append("Installed dashboard server and interface")

    config_path = NEXUS_DIR / "config.json"
    normalized_platforms = []
    for p in (agent_platforms or []):
        if p and p not in normalized_platforms:
            normalized_platforms.append(p)
    if not normalized_platforms:
        normalized_platforms = ["manual"]

    _json_dump(config_path, _mode_config(mode, normalized_platforms))
    steps.append(f"Applied {mode} protection mode")

    direct_cmd, wrapper_cmd, shortcuts = _write_cli_shortcuts()
    steps.append("Created local Nexus launcher")

    integration_notes: List[str] = []
    if "claude" in normalized_platforms:
        integration_notes.append(_install_claude(direct_cmd))
    if "codex" in normalized_platforms:
        integration_notes.append(_install_codex(wrapper_cmd))
    if "gemini" in normalized_platforms:
        integration_notes.append(_install_gemini(wrapper_cmd))
    if not integration_notes:
        integration_notes.append(f"Manual integration ready. Hook command: {direct_cmd}")
    steps.extend(integration_notes)

    compress = CLIENT_INSTALL_DIR / "nexus_trace_compress.py"
    try:
        r = _safe_run([sys.executable, str(compress)], timeout=30)
        if r.returncode == 0:
            steps.append("Verified internal trace tables")
        else:
            steps.append("Trace verification skipped; continuing with install")
    except Exception:
        steps.append("Trace verification skipped; continuing with install")

    return {
        "steps": steps,
        "hook_command": direct_cmd,
        "shortcuts": shortcuts,
    }


# ──────────────────────────────────────────────────────────────
# Dashboard bootstrap
# ──────────────────────────────────────────────────────────────
def _dashboard_url(scheme: str = "https") -> str:
    return f"{scheme}://localhost:{DASHBOARD_PORT}"


def _health_url(scheme: str = "https") -> str:
    return f"{scheme}://127.0.0.1:{DASHBOARD_PORT}/health"


def probe_existing_dashboard() -> Optional[Dict[str, Any]]:
    for scheme in ("https", "http"):
        try:
            data = _request_json("GET", _health_url(scheme), timeout=2)
            if data.get("status") == "ok":
                return {"scheme": scheme, "url": _dashboard_url(scheme)}
        except Exception:
            continue
    return None


def start_dashboard() -> Tuple[Optional[subprocess.Popen], str, Optional[str]]:
    existing = probe_existing_dashboard()
    if existing:
        return None, existing["url"], None

    server_py = ADMIN_INSTALL_DIR / "nexus_server.py"
    if not server_py.exists():
        return None, "", f"Dashboard server not found at {server_py}"

    env = os.environ.copy()
    env["NEXUS_DATA_DIR"] = str(SERVER_DATA_DIR)
    env.setdefault("PYTHONUNBUFFERED", "1")

    # Try TLS first. If it fails (no openssl on Windows), fall back to
    # plaintext on localhost. This is safe: data never leaves the machine.
    for attempt_tls in (True, False):
        cmd = [sys.executable, str(server_py), "--no-browser", "--bind", "127.0.0.1"]
        if attempt_tls:
            cmd.append("--tls")
        scheme = "https" if attempt_tls else "http"

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=sys.stderr,
            env=env,
        )

        url = _dashboard_url(scheme)
        for _ in range(20):
            time.sleep(0.5)
            if proc.poll() is not None:
                break  # process died, try next attempt
            try:
                data = _request_json("GET", _health_url(scheme), timeout=2)
                if data.get("status") == "ok":
                    if not attempt_tls:
                        return proc, url, "Running on localhost without TLS (openssl not available). Safe for local use."
                    return proc, url, None
            except Exception:
                pass

        if proc.poll() is not None:
            if attempt_tls:
                # TLS failed (likely no openssl), try plaintext localhost
                continue
            return None, "", f"Dashboard server exited with code {proc.returncode}"

        if proc.poll() is None:
            return proc, url, "Dashboard server started, but health check did not become ready in time"

    return None, "", "Dashboard server could not start"


def initialize_dashboard(password: str, dashboard_url: str) -> Dict[str, Any]:
    status = _request_json("GET", f"{dashboard_url}/api/status")
    if not status.get("needs_setup"):
        return {
            "initialized": False,
            "reused": True,
            "message": "Existing dashboard configuration detected; current admin password was kept.",
            "enrollment_key": None,
        }

    result = _request_json("POST", f"{dashboard_url}/api/setup", {"password": password})
    return {
        "initialized": True,
        "reused": False,
        "message": "Dashboard initialized securely on this machine.",
        "enrollment_key": result.get("enrollment_key"),
    }


# ──────────────────────────────────────────────────────────────
# Main install orchestration
# ──────────────────────────────────────────────────────────────
def perform_install(agent_platforms: List[str], mode: str, password: str) -> Dict[str, Any]:
    if len(password) < 12:
        raise SetupError("Password must be at least 12 characters")

    result = install_client(agent_platforms, mode)
    proc, dashboard_url, start_error = start_dashboard()
    INSTALL_STATE["dashboard_proc"] = proc

    if start_error and not dashboard_url:
        raise SetupError(start_error)

    dashboard_info = initialize_dashboard(password, dashboard_url)

    steps = list(result["steps"])
    steps.append("Started local dashboard in local-only mode")
    if dashboard_info["initialized"]:
        steps.append("Initialized dashboard credentials using the server setup flow")
    else:
        steps.append("Connected to existing local dashboard configuration")

    return {
        "ok": True,
        "steps": steps,
        "dashboard_url": dashboard_url,
        "dashboard_initialized": dashboard_info["initialized"],
        "dashboard_reused": dashboard_info["reused"],
        "dashboard_message": dashboard_info["message"],
        "dashboard_warning": start_error,
        "enrollment_key": dashboard_info.get("enrollment_key"),
        "hook_command": result["hook_command"],
        "shortcuts": result["shortcuts"],
        "security_note": "The dashboard is started on localhost only. Use the dedicated admin deployment flow to expose it to other machines.",
    }


# ──────────────────────────────────────────────────────────────
# Setup web server
# ──────────────────────────────────────────────────────────────
class SetupHandler(BaseHTTPRequestHandler):
    server_version = "NexusSetup/2.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _require_setup_token(self) -> bool:
        token = self.headers.get("X-Setup-Token", "")
        if not secrets.compare_digest(token, SETUP_TOKEN):
            self._json(403, {"error": "Invalid setup token"})
            return False
        return True

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path == "/":
            self._serve_html()
        elif path == "/api/detect":
            self._json(200, {
                "system": detect_system(),
                "agents": detect_agents(),
                "recommended_platforms": [a["id"] for a in detect_agents() if a["id"] != "manual"] or ["manual"],
            })
        else:
            self._json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        if not self._require_setup_token():
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._json(400, {"error": "Invalid JSON"})
            return

        if path == "/api/install":
            self._handle_install(payload)
            return
        self._json(404, {"error": "Not found"})

    def _handle_install(self, body: Dict[str, Any]) -> None:
        platforms = body.get("platforms")
        if isinstance(platforms, str):
            platforms = [platforms]
        if not isinstance(platforms, list):
            legacy = body.get("platform", "manual")
            platforms = [legacy] if legacy else ["manual"]
        mode = body.get("mode", "strict")
        password = body.get("password", "")
        try:
            result = perform_install(platforms, mode, password)
            INSTALL_STATE["install_result"] = result
            self._json(200, result)
            def _shutdown() -> None:
                time.sleep(1.0)
                self.server.shutdown()
            threading.Thread(target=_shutdown, daemon=True).start()
        except SetupError as e:
            self._json(400, {"error": str(e)})
        except Exception as e:
            self._json(500, {"error": str(e)})

    def _json(self, code: int, obj: Dict[str, Any]) -> None:
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _serve_html(self) -> None:
        html = SETUP_HTML.replace("__SETUP_TOKEN__", SETUP_TOKEN).replace("__SETUP_PORT__", str(SETUP_PORT))
        raw = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)


class ThreadedSetup(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ──────────────────────────────────────────────────────────────
# UI
SETUP_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nexus Gate</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a0c;--surface:rgba(255,255,255,.06);--ink:#f0f0f0;--muted:rgba(255,255,255,.5);--faint:rgba(255,255,255,.12);
  --accent:#e0e0e0;--good:#34d399;--good-soft:rgba(52,211,153,.12);
  --warn:#FBBF24;--danger:#F87171;
  --font:'Outfit',system-ui,sans-serif;--mono:ui-monospace,'SF Mono',monospace;
  --ease:cubic-bezier(.22,1,.36,1);--ease-out:cubic-bezier(0,0,.2,1);
}
html,body{height:100%}
body{font-family:var(--font);background:#0a0a0c;color:var(--ink);
  display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px;
  -webkit-font-smoothing:antialiased;overflow:hidden}

/* ── Aura background ── */
.aura{position:fixed;inset:0;z-index:0;pointer-events:none;
  background:radial-gradient(ellipse 80% 60% at 20% 30%,rgba(147,112,219,.15),transparent),
             radial-gradient(ellipse 60% 70% at 80% 70%,rgba(52,211,153,.1),transparent),
             radial-gradient(ellipse 50% 50% at 50% 50%,rgba(99,102,241,.08),transparent);
  animation:auraShift 20s ease infinite alternate}
@keyframes auraShift{0%{opacity:.8}50%{opacity:1}100%{opacity:.7}}


.shell{width:100%;max-width:460px;position:relative;min-height:480px;display:flex;flex-direction:column;justify-content:center;z-index:1}

/* ── Step transition ── */
.view{animation:viewIn .7s var(--ease) both}
@keyframes viewIn{from{opacity:0;transform:translateY(30px) scale(.98)}to{opacity:1;transform:none}}

/* ── Welcome cycling words ── */
.cycle-wrap{height:280px;display:flex;flex-direction:column;align-items:center;justify-content:center;position:relative;margin-bottom:24px}
.cycle-word{position:absolute;font-size:clamp(52px,12vw,72px);font-weight:800;letter-spacing:-.04em;
  opacity:0;transform:translateY(20px);transition:all .8s var(--ease);text-align:center;line-height:1}
.cycle-word.active{opacity:1;transform:translateY(0)}
.cycle-word.exit{opacity:0;transform:translateY(-20px)}
.cycle-sub{position:absolute;bottom:0;font-size:14px;color:rgba(255,255,255,.6);opacity:0;transform:translateY(8px);
  transition:all .6s var(--ease);text-align:center;max-width:280px;line-height:1.6}
.cycle-sub.show{opacity:1;transform:none}

.cycle-desc{font-size:15px;color:rgba(255,255,255,.55);text-align:center;margin-bottom:40px;line-height:1.7;
  opacity:0;animation:fadeSlide .6s var(--ease) 4.8s both}

/* ── Detected pills ── */
.pills{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-bottom:40px;
  opacity:0;animation:fadeSlide .6s var(--ease) 5.2s both}
.pill{display:inline-flex;align-items:center;gap:6px;padding:7px 16px;border-radius:999px;
  font-size:12px;font-weight:600;border:1.5px solid rgba(52,211,153,.3);color:#34d399;background:rgba(52,211,153,.1)}
.pill.none{color:var(--muted);border-color:var(--faint);background:transparent}
.pill svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round}

@keyframes fadeSlide{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}

/* ── Buttons ── */
.actions{display:flex;justify-content:center;opacity:0;animation:fadeSlide .5s var(--ease) 5.5s both}
.actions.instant{animation:none;opacity:1}
.btn{font-family:var(--font);font-size:15px;font-weight:600;border:none;cursor:pointer;
  border-radius:14px;padding:16px 40px;transition:all .25s var(--ease)}
.btn-primary{background:rgba(255,255,255,.12);color:#fff;border:1px solid rgba(255,255,255,.15);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}
.btn-primary:hover{background:rgba(255,255,255,.2);transform:translateY(-1px);box-shadow:0 8px 32px rgba(147,112,219,.2)}
.btn-primary:disabled{opacity:.35;cursor:default;transform:none;box-shadow:none}
.btn-back{background:none;color:rgba(255,255,255,.5);padding:16px 20px}
.btn-back:hover{color:var(--ink)}

/* ── Mode select ── */
.mode-title{font-size:32px;font-weight:700;letter-spacing:-.03em;text-align:center;margin-bottom:8px;
  animation:fadeSlide .6s var(--ease) both}
.mode-sub{font-size:14px;color:rgba(255,255,255,.55);text-align:center;margin-bottom:36px;
  animation:fadeSlide .5s var(--ease) .15s both}
.modes{display:flex;flex-direction:column;gap:10px;margin-bottom:36px}
.mode{display:flex;align-items:center;gap:16px;padding:20px 22px;border-radius:16px;
  background:var(--surface);border:2px solid transparent;cursor:pointer;width:100%;text-align:left;
  transition:all .25s var(--ease);animation:fadeSlide .5s var(--ease) both;
  backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
.mode:nth-child(1){animation-delay:.2s}
.mode:nth-child(2){animation-delay:.35s}
.mode:nth-child(3){animation-delay:.5s}
.mode:hover{border-color:rgba(255,255,255,.2)}
.mode.on{border-color:rgba(147,112,219,.5);background:rgba(147,112,219,.1)}
.radio{width:18px;height:18px;border-radius:50%;border:2px solid var(--faint);
  flex-shrink:0;transition:all .2s;position:relative}
.mode.on .radio{border-color:rgba(147,112,219,.8);background:rgba(147,112,219,.8);box-shadow:inset 0 0 0 3px rgba(10,10,12,.8)}
.mode-name{font-weight:600;font-size:14px;color:var(--ink)}
.mode-desc{font-size:12px;color:rgba(255,255,255,.6);margin-top:2px}

/* ── Password ── */
.pw-title{font-size:32px;font-weight:700;letter-spacing:-.03em;text-align:center;margin-bottom:8px;
  animation:fadeSlide .6s var(--ease) both}
.pw-sub{font-size:14px;color:rgba(255,255,255,.55);text-align:center;margin-bottom:36px;
  animation:fadeSlide .5s var(--ease) .1s both}
.field{margin-bottom:20px;animation:fadeSlide .5s var(--ease) .2s both}
.field label{display:block;font-size:12px;font-weight:600;color:rgba(255,255,255,.6);margin-bottom:8px;letter-spacing:.02em}
.field input{width:100%;padding:16px 18px;border-radius:14px;font-size:16px;
  border:1.5px solid var(--faint);background:rgba(255,255,255,.05);font-family:var(--font);
  color:var(--ink);transition:border-color .2s;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
.field input:focus{outline:none;border-color:rgba(147,112,219,.5)}
.field input::placeholder{color:rgba(255,255,255,.3)}
.pw-wrap{position:relative}
.pw-wrap input{padding-right:50px}
.pw-eye{position:absolute;right:12px;top:50%;transform:translateY(-50%);
  width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;
  color:rgba(255,255,255,.3);cursor:pointer;border:none;background:none;font-size:16px;
  transition:color .2s}
.pw-eye:hover{color:rgba(255,255,255,.6)}
.field-match{font-size:11px;margin-top:6px;font-weight:500;text-align:left;transition:color .2s}
.strength{height:3px;border-radius:2px;background:var(--faint);margin-top:10px;overflow:hidden}
.strength-fill{height:100%;border-radius:2px;transition:all .35s var(--ease)}
.hint{font-size:11px;color:rgba(255,255,255,.45);margin-top:8px;text-align:center}
.error{font-size:13px;color:var(--danger);margin-top:10px;text-align:center;font-weight:500}

/* ── Installing ── */
.inst-title{font-size:32px;font-weight:700;letter-spacing:-.03em;text-align:center;margin-bottom:8px;
  animation:fadeSlide .6s var(--ease) both}
.inst-sub{font-size:14px;color:rgba(255,255,255,.55);text-align:center;margin-bottom:44px;
  animation:fadeSlide .5s var(--ease) .1s both}
.steps-list{display:flex;flex-direction:column;gap:18px;max-width:320px;margin:0 auto}
.step-row{display:flex;align-items:center;gap:14px;font-size:14px;color:rgba(255,255,255,.6);font-weight:500;
  opacity:0;animation:fadeSlide .5s var(--ease) both}
.step-dot{width:24px;height:24px;border-radius:50%;border:2px solid var(--faint);
  flex-shrink:0;display:flex;align-items:center;justify-content:center}
@keyframes pulse-dot{0%,100%{opacity:.3}50%{opacity:1}}
.step-dot.active{border-color:rgba(147,112,219,.8);animation:pulse-dot 1.2s ease infinite}
.step-dot.done{border-color:var(--good);background:var(--good-soft)}
.step-dot.done svg{opacity:1}
.step-dot svg{width:14px;height:14px;fill:none;stroke:var(--good);stroke-width:2.5;
  stroke-linecap:round;stroke-linejoin:round;opacity:0;transition:opacity .3s}
.step-row.done{color:var(--ink)}

/* ── Done ── */
@keyframes scaleCheck{from{transform:scale(0);opacity:0}to{transform:scale(1);opacity:1}}
@keyframes drawCheck{from{stroke-dashoffset:24}to{stroke-dashoffset:0}}
.done-icon{width:72px;height:72px;border-radius:50%;background:rgba(52,211,153,.12);margin:0 auto 28px;
  display:flex;align-items:center;justify-content:center;animation:scaleCheck .5s var(--ease) both;
  border:1px solid rgba(52,211,153,.2)}
.done-icon svg{width:36px;height:36px;fill:none;stroke:var(--good);stroke-width:2.5;
  stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:24;animation:drawCheck .45s var(--ease) .35s both}
.done-title{font-size:32px;font-weight:700;letter-spacing:-.03em;text-align:center;margin-bottom:6px;
  animation:fadeSlide .5s var(--ease) .4s both}
.done-sub{font-size:14px;color:rgba(255,255,255,.55);text-align:center;margin-bottom:28px;
  animation:fadeSlide .5s var(--ease) .55s both}
.done-steps{max-width:360px;margin:0 auto 24px}
.done-row{display:flex;align-items:center;gap:10px;padding:5px 0;font-size:13px;color:rgba(255,255,255,.7);
  animation:fadeSlide .35s var(--ease) both}
.done-row svg{width:15px;height:15px;fill:none;stroke:var(--good);stroke-width:2.5;
  stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.result-box{padding:16px;border-radius:12px;background:rgba(255,255,255,.06);margin:16px auto;max-width:360px;text-align:left;
  animation:fadeSlide .4s var(--ease) both;border:1px solid var(--faint)}
.result-label{font-size:11px;font-weight:600;color:rgba(255,255,255,.5);letter-spacing:.03em;margin-bottom:4px}
.result-value{font-family:var(--mono);font-size:12px;word-break:break-all;color:var(--ink)}
.result-warn{font-size:13px;color:var(--warn);margin:16px auto;padding:14px 16px;max-width:360px;
  border-radius:12px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.2);
  line-height:1.6;text-align:left;animation:fadeSlide .4s var(--ease) both}

.footer{position:fixed;bottom:20px;left:0;right:0;text-align:center;font-size:11px;color:rgba(255,255,255,.2);font-weight:500;z-index:1}
</style>
</head>
<body>
<div class="aura"></div>
<div class="shell" id="root"></div>
<div class="footer">nexus gate</div>
<script>
const SETUP_TOKEN="__SETUP_TOKEN__";
const S={step:0,agents:[],system:{},platforms:[],mode:'strict',password:'',_confirm:'',error:'',result:null,working:false};

function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function $(id){return document.getElementById(id)}

async function api(path,opts={}){
  const h=Object.assign({'Accept':'application/json','X-Setup-Token':SETUP_TOKEN},opts.headers||{});
  return fetch(path,Object.assign({},opts,{headers:h}));
}

async function detect(){
  try{const r=await fetch('/api/detect',{headers:{'Accept':'application/json'}});
  const d=await r.json();S.agents=d.agents||[];S.system=d.system||{};
  S.platforms=d.recommended_platforms||(S.agents||[]).map(a=>a.id).filter(id=>id!=='manual');
  if(!S.platforms.length)S.platforms=['manual'];}catch(e){}
  render();
}

function render(){
  const root=$('root');root.innerHTML='';
  const v=document.createElement('div');v.className='view';v.style.animationDelay='0s';
  [welcome,modes,password,installing,done][S.step]?.(v);
  root.appendChild(v);
}

/* ═══ Step 0: Welcome ═══ */
function welcome(v){
  // Cycling words container
  const wrap=document.createElement('div');wrap.className='cycle-wrap';

  const words=[
    {text:'Intercept.',sub:'Every command caught before it runs.'},
    {text:'Analyze.',sub:'Data flow traced through pipes, flags, redirects.'},
    {text:'Decide.',sub:'Allow, warn, or block. Under 1ms.'},
    {text:'Nexus Gate.',sub:''},
  ];

  words.forEach((w,i)=>{
    const el=document.createElement('div');el.className='cycle-word';el.textContent=w.text;el.dataset.i=i;
    wrap.appendChild(el);
    if(w.sub){
      const sub=document.createElement('div');sub.className='cycle-sub';sub.textContent=w.sub;sub.dataset.i=i;
      wrap.appendChild(sub);
    }
  });
  v.appendChild(wrap);

  // Description (appears after cycle)
  const desc=document.createElement('div');desc.className='cycle-desc';
  desc.textContent='Structural command verification for AI agents.';
  v.appendChild(desc);

  // Detected platforms
  const pills=document.createElement('div');pills.className='pills';
  const agents=(S.agents||[]).filter(a=>a.id!=='manual');
  if(agents.length){
    agents.forEach(a=>{
      const p=document.createElement('div');p.className='pill';
      p.innerHTML='<svg viewBox="0 0 24 24"><path d="M5 12.5l4.2 4.2L19 7"/></svg>'+esc(a.name);
      pills.appendChild(p);
    });
  }else{
    const p=document.createElement('div');p.className='pill none';p.textContent='Manual setup';
    pills.appendChild(p);
  }
  v.appendChild(pills);

  // CTA
  const actions=document.createElement('div');actions.className='actions';
  const btn=document.createElement('button');btn.className='btn btn-primary';btn.textContent='Begin';
  btn.onclick=()=>{S.step=1;render()};
  actions.appendChild(btn);
  v.appendChild(actions);

  // Start animation cycle
  let idx=0;
  const allWords=wrap.querySelectorAll('.cycle-word');
  const allSubs=wrap.querySelectorAll('.cycle-sub');

  function showWord(i){
    allWords.forEach(el=>{
      const j=parseInt(el.dataset.i);
      el.classList.remove('active','exit');
      if(j===i)el.classList.add('active');
      else if(j===i-1||(i===0&&j===words.length-1))el.classList.add('exit');
    });
    allSubs.forEach(el=>{
      const j=parseInt(el.dataset.i);
      el.classList.toggle('show',j===i);
    });
  }

  showWord(0);
  const interval=setInterval(()=>{
    idx++;
    if(idx>=words.length){clearInterval(interval);return}
    showWord(idx);
  },1400);
}

/* ═══ Step 1: Mode ═══ */
function modes(v){
  v.innerHTML='<div class="mode-title">How strict?</div><div class="mode-sub">Changeable anytime from the dashboard.</div>';

  const list=document.createElement('div');list.className='modes';
  [['strict','Strict','Blocks risky and dangerous commands.'],
   ['balanced','Balanced','Blocks dangerous. Warns on risky.'],
   ['monitor','Monitor','Logs everything. Blocks nothing.']
  ].forEach(([id,name,desc])=>{
    const card=document.createElement('button');card.className='mode'+(S.mode===id?' on':'');
    card.innerHTML='<div class="radio"></div><div><div class="mode-name">'+name+'</div><div class="mode-desc">'+desc+'</div></div>';
    card.onclick=()=>{S.mode=id;render()};
    list.appendChild(card);
  });
  v.appendChild(list);

  const row=document.createElement('div');row.className='actions instant';
  const back=document.createElement('button');back.className='btn btn-back';back.textContent='Back';
  back.onclick=()=>{S.step=0;render()};
  const next=document.createElement('button');next.className='btn btn-primary';next.textContent='Continue';
  next.onclick=()=>{S.step=2;render()};
  row.appendChild(back);row.appendChild(next);
  v.appendChild(row);
}

/* ═══ Step 2: Password ═══ */
function password(v){
  v.innerHTML='<div class="pw-title">Dashboard password.</div><div class="pw-sub">Protects your monitoring dashboard.</div>';

  // Password field with eye toggle
  const field=document.createElement('div');field.className='field';
  field.innerHTML='<label>Password</label>';
  const wrap=document.createElement('div');wrap.className='pw-wrap';
  const inp=document.createElement('input');inp.type='password';inp.placeholder='At least 12 characters';
  inp.value=S.password||'';
  inp.oninput=e=>{S.password=e.target.value;S.error='';updateBar();checkMatch()};
  inp.onkeydown=e=>{if(e.key==='Enter')$('pw2')?.focus()};
  wrap.appendChild(inp);
  const eye=document.createElement('button');eye.className='pw-eye';eye.type='button';
  eye.innerHTML='<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  eye.onclick=()=>{
    const show=inp.type==='password';
    inp.type=show?'text':'password';
    const c=$('pw2');if(c)c.type=inp.type;
    eye.style.color=show?'rgba(255,255,255,.6)':'rgba(255,255,255,.3)';
  };
  wrap.appendChild(eye);
  field.appendChild(wrap);
  const bar=document.createElement('div');bar.className='strength';
  bar.innerHTML='<div class="strength-fill" id="bar"></div>';
  field.appendChild(bar);
  v.appendChild(field);

  // Confirm field
  const field2=document.createElement('div');field2.className='field';
  field2.style.animationDelay='.3s';
  field2.innerHTML='<label>Confirm password</label>';
  const wrap2=document.createElement('div');wrap2.className='pw-wrap';
  const inp2=document.createElement('input');inp2.id='pw2';inp2.type='password';
  inp2.placeholder='Type it again';
  inp2.value=S._confirm||'';
  inp2.oninput=e=>{S._confirm=e.target.value;S.error='';checkMatch()};
  inp2.onkeydown=e=>{if(e.key==='Enter')doInstall()};
  wrap2.appendChild(inp2);
  field2.appendChild(wrap2);
  const matchMsg=document.createElement('div');matchMsg.className='field-match';matchMsg.id='match-msg';
  field2.appendChild(matchMsg);
  v.appendChild(field2);

  if(S.error){const err=document.createElement('div');err.className='error';err.textContent=S.error;v.appendChild(err)}

  const row=document.createElement('div');row.className='actions instant';row.style.marginTop='24px';
  const back=document.createElement('button');back.className='btn btn-back';back.textContent='Back';
  back.onclick=()=>{S.step=1;S.error='';render()};
  const btn=document.createElement('button');btn.className='btn btn-primary';
  btn.textContent=S.working?'Installing...':'Install';btn.disabled=S.working;
  btn.onclick=doInstall;
  row.appendChild(back);row.appendChild(btn);
  v.appendChild(row);

  setTimeout(()=>{inp.focus();updateBar();checkMatch()},80);

  function updateBar(){
    const f=$('bar');if(!f)return;
    const l=(S.password||'').length;
    const pct=Math.min(l/20*100,100);
    const c=l<8?'var(--danger)':l<12?'var(--warn)':l<16?'#3B82F6':'var(--good)';
    f.style.width=pct+'%';f.style.background=c;
  }
  function checkMatch(){
    const m=$('match-msg');if(!m)return;
    const p=S.password||'',c=S._confirm||'';
    if(!c){m.textContent='';return}
    if(p===c){m.textContent='Passwords match.';m.style.color='var(--good)'}
    else{m.textContent='Passwords do not match.';m.style.color='var(--danger)'}
  }
}

async function doInstall(){
  if(S.working)return;
  if((S.password||'').length<12){S.error='At least 12 characters.';render();return}
  if(S.password!==(S._confirm||'')){S.error='Passwords do not match.';render();return}
  S.error='';S.working=true;S.step=3;render();
  try{
    const r=await api('/api/install',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({platforms:S.platforms||['manual'],mode:S.mode,password:S.password})});
    const d=await r.json();
    if(!r.ok||!d.ok)throw new Error(d.error||'Install failed');
    S.result=d;S.working=false;S.step=4;
  }catch(e){S.working=false;S.step=2;S.error=e.message||'Install failed'}
  render();
}

/* ═══ Step 3: Installing ═══ */
function installing(v){
  v.innerHTML='<div class="inst-title">Installing.</div><div class="inst-sub">This takes a few seconds.</div>';

  const list=document.createElement('div');list.className='steps-list';
  ['Verification engine','Agent hooks','Dashboard','Security'].forEach((label,i)=>{
    const row=document.createElement('div');row.className='step-row';row.style.animationDelay=(i*.2+.2)+'s';
    const dot=document.createElement('div');dot.className='step-dot active';
    dot.innerHTML='<svg viewBox="0 0 24 24"><path d="M5 12.5l4.2 4.2L19 7"/></svg>';
    const txt=document.createElement('div');txt.textContent=label;
    row.appendChild(dot);row.appendChild(txt);
    list.appendChild(row);

    // Simulate completion
    setTimeout(()=>{dot.classList.remove('active');dot.classList.add('done');row.classList.add('done')},1200+i*600);
  });
  v.appendChild(list);
}

/* ═══ Step 4: Done ═══ */
function done(v){
  const res=S.result||{};

  v.innerHTML='<div class="done-icon"><svg viewBox="0 0 24 24"><path d="M5 12.5l4.2 4.2L19 7"/></svg></div>';
  v.innerHTML+='<div class="done-title">Protected.</div>';
  v.innerHTML+='<div class="done-sub">Dashboard is ready.</div>';

  // Completed steps
  if(res.steps&&res.steps.length){
    const list=document.createElement('div');list.className='done-steps';
    res.steps.forEach((s,i)=>{
      const row=document.createElement('div');row.className='done-row';row.style.animationDelay=(.6+i*.06)+'s';
      row.innerHTML='<svg viewBox="0 0 24 24"><path d="M5 12.5l4.2 4.2L19 7"/></svg><span>'+esc(s)+'</span>';
      list.appendChild(row);
    });
    v.appendChild(list);
  }

  if(res.enrollment_key){
    const box=document.createElement('div');box.className='result-box';
    box.style.animationDelay='.8s';
    box.innerHTML='<div class="result-label">ENROLLMENT KEY</div><div class="result-value">'+esc(res.enrollment_key)+'</div>';
    v.appendChild(box);
  }

  if(res.dashboard_warning){
    const w=document.createElement('div');w.className='result-warn';w.style.animationDelay='.9s';
    w.textContent=res.dashboard_warning;
    v.appendChild(w);
  }

  const row=document.createElement('div');row.className='actions instant';row.style.marginTop='28px';
  const btn=document.createElement('button');btn.className='btn btn-primary';btn.textContent='Open dashboard';
  btn.onclick=()=>{window.location.href=res.dashboard_url||'https://localhost:7070'};
  row.appendChild(btn);
  v.appendChild(row);
}

detect();render();
</script>
</body>
</html>
'''
# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────
def main() -> None:
    try:
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except (AttributeError, OSError):
        pass

    G = "\033[92m"
    B = "\033[1m"
    D = "\033[2m"
    X = "\033[0m"

    print(
        f"""
  {G}>{X} {B}nexus gate{X} -- setup

    Opening the setup assistant in your browser...
    {D}http://127.0.0.1:{SETUP_PORT}{X}
"""
    )

    server = ThreadedSetup(("127.0.0.1", SETUP_PORT), SetupHandler)

    def _open_browser() -> None:
        time.sleep(0.7)
        try:
            webbrowser.open(f"http://127.0.0.1:{SETUP_PORT}")
        except Exception:
            pass

    threading.Thread(target=_open_browser, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

    proc = INSTALL_STATE.get("dashboard_proc")
    if proc and proc.poll() is None:
        try:
            proc.wait()
        except KeyboardInterrupt:
            print(f"\n  {D}Stopping dashboard...{X}")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            print(f"  {D}Stopped.{X}\n")
    else:
        print(f"  {D}Setup complete.{X}\n")


if __name__ == "__main__":
    main()

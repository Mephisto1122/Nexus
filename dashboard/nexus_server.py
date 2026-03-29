#!/usr/bin/env python3
"""
Nexus Gate — Central Server (Production)

Fleet dashboard + API for distributed Nexus Gate agents.
SQLite storage, agent auth tokens, admin sessions, TLS support, threading.
Zero external dependencies. Python 3.8+ stdlib only.

First run:
    python nexus_server.py --setup

Start:
    python nexus_server.py
    python nexus_server.py --port 8080
    python nexus_server.py --tls              # auto-generate self-signed cert

Agent enrollment:
    Agents need the enrollment key shown during --setup or on first run.
    python nexus_reporter.py --server https://host:7070 --enroll-key <KEY>
"""

import json, os, sys, time, threading, argparse, hashlib, hmac, secrets
import sqlite3, ssl
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from socketserver import ThreadingMixIn
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════

DATA_DIR = Path.home() / ".nexus-server"
DB_PATH = DATA_DIR / "nexus.db"
CERT_PATH = DATA_DIR / "cert.pem"
KEY_PATH = DATA_DIR / "key.pem"
SECRET_FILE = DATA_DIR / "server.secret"

SESSION_TTL = 86400        # 24 hours
HEARTBEAT_TIMEOUT = 120    # agent goes offline after this
MAX_EVENTS = 50000         # max events in DB
RATE_LIMIT_WINDOW = 60     # seconds
RATE_LIMIT_MAX = 200       # requests per window per IP

_START_TIME = time.time()

# Env overrides for Docker
if os.environ.get("NEXUS_DATA_DIR"):
    DATA_DIR = Path(os.environ["NEXUS_DATA_DIR"])
    DB_PATH = DATA_DIR / "nexus.db"
    CERT_PATH = DATA_DIR / "cert.pem"
    KEY_PATH = DATA_DIR / "key.pem"
    SECRET_FILE = DATA_DIR / "server.secret"

# ═══════════════════════════════════════════════════════════════
# Crypto helpers
# ═══════════════════════════════════════════════════════════════

def _hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}${h.hex()}"

def _verify_password(password, stored):
    if "$" not in stored:
        return False
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(_hash_password(password, salt), stored)

def _generate_token():
    return secrets.token_urlsafe(32)

def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()

def _server_secret():
    """Persistent secret for HMAC operations."""
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text().strip()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_hex(32)
    SECRET_FILE.write_text(secret)
    try:
        os.chmod(str(SECRET_FILE), 0o600)
    except OSError:
        pass
    return secret

SERVER_SECRET = None  # set in main()

# ═══════════════════════════════════════════════════════════════
# Database
# ═══════════════════════════════════════════════════════════════

# SQLite WAL mode handles concurrent reads/writes

def _get_db():
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def _init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = _get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            team TEXT DEFAULT '',
            os TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            version TEXT DEFAULT '',
            status TEXT DEFAULT 'online',
            token_hash TEXT NOT NULL,
            approved INTEGER DEFAULT 1,
            first_seen REAL NOT NULL,
            last_heartbeat REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL DEFAULT '',
            agent TEXT NOT NULL,
            source TEXT DEFAULT '',
            tool TEXT DEFAULT '',
            command TEXT DEFAULT '',
            command_raw TEXT DEFAULT '',
            operation TEXT DEFAULT '',
            risk TEXT DEFAULT '',
            tier TEXT DEFAULT '',
            flow TEXT DEFAULT '',
            proof TEXT DEFAULT '',
            timestamp REAL,
            received_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_tier ON events(tier);
        CREATE INDEX IF NOT EXISTS idx_events_time ON events(received_at DESC);
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            scope TEXT DEFAULT 'global',
            created_at REAL NOT NULL,
            UNIQUE(type, value, scope)
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            created_at REAL NOT NULL,
            ip TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT DEFAULT '',
            agent TEXT DEFAULT '',
            severity TEXT DEFAULT 'info',
            title TEXT NOT NULL,
            detail TEXT DEFAULT '',
            event_id INTEGER DEFAULT NULL,
            acknowledged INTEGER DEFAULT 0,
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_events_op ON events(operation);
        CREATE INDEX IF NOT EXISTS idx_events_risk ON events(risk);
    """)
    # ── Migrations for existing databases ──
    # Add agent_id to events if missing (pre-v2 databases)
    try:
        cols = [row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()]
        if "agent_id" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''")
            conn.execute("UPDATE events SET agent_id = agent WHERE agent_id = ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id)")
    except Exception:
        pass
    # Add agent_id to alerts if missing
    try:
        cols = [row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()]
        if "agent_id" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN agent_id TEXT DEFAULT ''")
            conn.execute("UPDATE alerts SET agent_id = agent WHERE agent_id = ''")
    except Exception:
        pass
    # Add source, tool, command_raw columns to events if missing
    try:
        cols = [row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()]
        if "source" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN source TEXT DEFAULT ''")
        if "tool" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN tool TEXT DEFAULT ''")
        if "command_raw" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN command_raw TEXT DEFAULT ''")
    except Exception:
        pass
    # Add scope to rules unique constraint migration
    # (SQLite can't ALTER constraints, but new tables get it right via CREATE IF NOT EXISTS)
    conn.commit()
    conn.close()
    try:
        os.chmod(str(DB_PATH), 0o600)
    except OSError:
        pass

def _db_get_config(key, default=None):
    conn = _get_db()
    row = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default

def _db_set_config(key, value):
    conn = _get_db()
    conn.execute("INSERT OR REPLACE INTO config(key, value) VALUES(?, ?)", (key, value))
    conn.commit()
    conn.close()

# ═══════════════════════════════════════════════════════════════
# SSE
# ═══════════════════════════════════════════════════════════════

SSE_CLIENTS = []
SSE_LOCK = threading.Lock()

def _sse_broadcast(event_type):
    msg = f"event: {event_type}\ndata: {{}}\n\n".encode()
    dead = []
    with SSE_LOCK:
        for wfile in SSE_CLIENTS:
            try:
                wfile.write(msg)
                wfile.flush()
            except Exception:
                dead.append(wfile)
        for d in dead:
            try:
                SSE_CLIENTS.remove(d)
            except ValueError:
                pass

# ═══════════════════════════════════════════════════════════════
# Rate limiter
# ═══════════════════════════════════════════════════════════════

_rate_buckets = {}
_rate_lock = threading.Lock()
_rate_last_clean = 0

def _check_rate(ip):
    global _rate_last_clean
    now = time.time()
    with _rate_lock:
        # Cleanup stale IPs every 30 seconds, not every call
        if now - _rate_last_clean > 30:
            cutoff = now - RATE_LIMIT_WINDOW
            stale = [k for k, v in _rate_buckets.items() if not v or v[-1] < cutoff]
            for k in stale:
                del _rate_buckets[k]
            _rate_last_clean = now
        hits = _rate_buckets.get(ip, [])
        # Count only recent hits
        cutoff = now - RATE_LIMIT_WINDOW
        hits = [t for t in hits if t > cutoff]
        if len(hits) >= RATE_LIMIT_MAX:
            _rate_buckets[ip] = hits
            return False
        hits.append(now)
        _rate_buckets[ip] = hits
        return True

# ═══════════════════════════════════════════════════════════════
# Threaded server
# ═══════════════════════════════════════════════════════════════

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

# ═══════════════════════════════════════════════════════════════
# API Handler
# ═══════════════════════════════════════════════════════════════

class APIHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        ts = datetime.now().strftime("%H:%M:%S")
        sys.stderr.write(f"  {ts}  {args[0]}\n")

    def handle(self):
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            pass

    # ── Response helpers ──

    def _is_tls(self):
        return getattr(self.server, 'use_tls', False)

    def _session_cookie(self, token):
        """Build Set-Cookie header value. Adds Secure flag when TLS is active."""
        parts = f"nexus_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}"
        if self._is_tls():
            parts += "; Secure"
        return parts

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self._cors_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass

    def _cors_headers(self):
        # SECURITY: Only allow same-origin requests for the admin dashboard.
        # Agent API uses Bearer tokens (not cookies), so CORS is irrelevant for agents.
        # For admin endpoints, the dashboard is served from the same origin.
        origin = self.headers.get("Origin", "")
        if origin:
            # Only reflect origin if it matches our own host
            host = self.headers.get("Host", "")
            # Parse origin to compare: "http://localhost:7070" -> "localhost:7070"
            try:
                from urllib.parse import urlparse
                parsed = urlparse(origin)
                origin_host = parsed.netloc  # "localhost:7070"
            except Exception:
                origin_host = ""
            if origin_host == host:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            # If origin doesn't match, no CORS headers = browser blocks the request
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        if length > 10_485_760:  # 10MB cap
            raise ValueError("Request body too large")
        raw = self.rfile.read(length)
        return json.loads(raw)

    # ── Auth helpers ──

    def _get_agent_token(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return None

    def _verify_agent(self):
        token = self._get_agent_token()
        if not token:
            return None
        token_hash = _hash_token(token)
        conn = _get_db()
        row = conn.execute("SELECT * FROM agents WHERE token_hash=? AND approved=1",
                           (token_hash,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def _get_session(self):
        cookie_str = self.headers.get("Cookie", "")
        if not cookie_str:
            return None
        cookies = SimpleCookie()
        try:
            cookies.load(cookie_str)
        except Exception:
            return None
        morsel = cookies.get("nexus_session")
        if not morsel:
            return None
        token = morsel.value
        token_hash = _hash_token(token)
        conn = _get_db()
        row = conn.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
        conn.close()
        if not row:
            return None
        if time.time() - row["created_at"] > SESSION_TTL:
            conn = _get_db()
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
            conn.commit()
            conn.close()
            return None
        return token

    def _require_admin(self):
        if self._get_session():
            return True
        self._json(401, {"error": "Authentication required"})
        return False

    def _require_agent(self):
        agent = self._verify_agent()
        if agent:
            return agent
        self._json(401, {"error": "Invalid or missing agent token"})
        return None

    # ── Rate limit ──

    def _check_rate_limit(self):
        ip = self.client_address[0]
        if not _check_rate(ip):
            self._json(429, {"error": "Rate limit exceeded"})
            return False
        return True

    # ── Routes ──

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    def do_GET(self):
        if not self._check_rate_limit():
            return
        path = self.path.split("?")[0]

        # Public: login page, dashboard (session checked in JS)
        if path == "/":
            self._serve_dashboard()
            return

        # Public: health check (for Docker, load balancers)
        if path == "/health":
            self._json(200, {"status": "ok", "uptime": int(time.time() - _START_TIME)})
            return

        # Public: server status (tells dashboard what screen to show)
        if path == "/api/status":
            has_admin = _db_get_config("admin_password") is not None
            has_session = self._get_session() is not None
            self._json(200, {
                "needs_setup": not has_admin,
                "authenticated": has_session,
            })
            return

        # SSE: requires admin session
        if path == "/api/stream":
            if not self._get_session():
                self._json(401, {"error": "Auth required"})
                return
            self._handle_sse()
            return

        # Admin API: requires session
        if path.startswith("/api/"):
            if not self._require_admin():
                return

            conn = _get_db()
            try:
                if path == "/api/all":
                    self._handle_get_all(conn)
                elif path == "/api/agents":
                    self._handle_get_agents(conn)
                elif path == "/api/events":
                    self._handle_get_events(conn)
                elif path == "/api/stats":
                    self._handle_get_stats(conn)
                elif path == "/api/rules":
                    self._handle_get_rules(conn)
                elif path == "/api/enrollment-key":
                    key = _db_get_config("enrollment_key")
                    self._json(200, {"key": key})
                elif path == "/api/settings":
                    ek = _db_get_config("enrollment_key") or ""
                    import socket as _s
                    self._json(200, {
                        "enrollment_key": ek,
                        "hostname": _s.gethostname(),
                        "port": self.server.server_address[1],
                        "tls": hasattr(self.server.socket, 'getpeercert'),
                        "agents_total": conn.execute("SELECT COUNT(*) as c FROM agents").fetchone()["c"],
                        "events_total": conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"],
                    })
                elif path == "/api/agent-config":
                    raw = _db_get_config("agent_config", '{}')
                    try:
                        cfg = json.loads(raw)
                    except json.JSONDecodeError:
                        cfg = {}
                    # Ensure defaults
                    cfg.setdefault("green", "note")
                    cfg.setdefault("orange", "block")
                    cfg.setdefault("red", "block")
                    cfg.setdefault("audit", "all")
                    cfg.setdefault("custom_sensitive_paths", [])
                    self._json(200, cfg)
                elif path == "/api/alerts":
                    self._handle_get_alerts(conn)
                elif path == "/api/agent-stats":
                    self._handle_get_agent_stats(conn)
                elif path == "/api/insights":
                    self._handle_get_insights(conn)
                else:
                    self._json(404, {"error": "Not found"})
            finally:
                conn.close()
            return

        self._json(404, {"error": "Not found"})

    def do_POST(self):
        if not self._check_rate_limit():
            return
        path = self.path.split("?")[0]

        try:
            body = self._read_body()
        except (json.JSONDecodeError, ValueError):
            self._json(400, {"error": "Invalid JSON"})
            return

        # Public: login, enroll, first-run setup
        if path == "/api/login":
            self._handle_login(body)
            return

        if path == "/api/enroll":
            self._handle_enroll(body)
            return

        if path == "/api/setup":
            self._handle_setup(body)
            return

        # Agent API: requires agent token
        if path == "/api/heartbeat":
            agent = self._require_agent()
            if not agent:
                return
            self._handle_heartbeat(agent, body)
            return

        if path == "/api/events" and self._get_agent_token():
            agent = self._require_agent()
            if not agent:
                return
            self._handle_post_events(agent, body)
            return

        # Admin API: requires session
        if not self._require_admin():
            return

        if path == "/api/rules":
            self._handle_post_rules(body)
        elif path == "/api/events":
            self._handle_post_events(None, body)
        elif path == "/api/logout":
            self._handle_logout()
        elif path == "/api/settings/password":
            self._handle_change_password(body)
        elif path == "/api/settings/rotate-key":
            self._handle_rotate_key(body)
        elif path == "/api/agent-config":
            self._handle_post_agent_config(body)
        elif path == "/api/alerts/ack":
            self._handle_post_alert_ack(body)
        else:
            self._json(404, {"error": "Not found"})

    def do_DELETE(self):
        if not self._check_rate_limit():
            return
        if not self._require_admin():
            return
        path = self.path.split("?")[0]

        conn = _get_db()
        try:
            if path.startswith("/api/agents/"):
                agent_id = path.split("/api/agents/", 1)[1]
                conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))
                conn.commit()
                self._json(200, {"ok": True})
                threading.Thread(target=_sse_broadcast, args=("agents",), daemon=True).start()
            else:
                self._json(404, {"error": "Not found"})
        finally:
            conn.close()

    # ── GET handlers ──

    def _handle_get_all(self, conn):
        agents = [dict(r) for r in conn.execute(
            "SELECT id, name, team, os, ip, version, status, approved, first_seen, last_heartbeat FROM agents ORDER BY status='online' DESC, name"
        ).fetchall()]
        self._expire_agents(conn, agents)

        events = [dict(r) for r in conn.execute(
            "SELECT * FROM events ORDER BY received_at DESC LIMIT 500"
        ).fetchall()]

        alerts = [dict(r) for r in conn.execute(
            "SELECT * FROM alerts WHERE acknowledged=0 ORDER BY created_at DESC LIMIT 50"
        ).fetchall()]

        stats = self._build_stats(conn)
        rules = self._build_rules(conn)

        self._json(200, {
            "agents": agents,
            "events": events,
            "alerts": alerts,
            "stats": stats,
            "rules": rules,
        })

    def _handle_get_agents(self, conn):
        agents = [dict(r) for r in conn.execute(
            "SELECT id, name, team, os, ip, version, status, approved, first_seen, last_heartbeat FROM agents ORDER BY status='online' DESC, name"
        ).fetchall()]
        self._expire_agents(conn, agents)
        self._json(200, agents)

    def _handle_get_events(self, conn):
        events = [dict(r) for r in conn.execute(
            "SELECT * FROM events ORDER BY received_at DESC LIMIT 500"
        ).fetchall()]
        self._json(200, events)

    def _handle_get_stats(self, conn):
        self._json(200, self._build_stats(conn))

    def _handle_get_rules(self, conn):
        self._json(200, self._build_rules(conn))

    def _build_stats(self, conn):
        total = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]
        allowed = conn.execute("SELECT COUNT(*) as c FROM events WHERE tier='allow'").fetchone()["c"]
        warned = conn.execute("SELECT COUNT(*) as c FROM events WHERE tier='warn'").fetchone()["c"]
        blocked = conn.execute("SELECT COUNT(*) as c FROM events WHERE tier='block'").fetchone()["c"]
        online = conn.execute("SELECT COUNT(*) as c FROM agents WHERE status='online'").fetchone()["c"]
        total_agents = conn.execute("SELECT COUNT(*) as c FROM agents").fetchone()["c"]
        unack_alerts = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE acknowledged=0").fetchone()["c"]
        return {
            "total": total, "allowed": allowed, "warned": warned, "blocked": blocked,
            "agents_online": online, "agents_total": total_agents,
            "unacknowledged_alerts": unack_alerts,
        }

    def _build_rules(self, conn, scope_filter=None):
        """Build rules dict. If scope_filter is set, return only global + matching scope."""
        rules = {"trusted_hosts": [], "allowed_patterns": [], "blocked_patterns": []}
        if scope_filter:
            rows = conn.execute(
                "SELECT type, value, scope FROM rules WHERE scope='global' OR scope=? ORDER BY id",
                (scope_filter,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT type, value, scope FROM rules ORDER BY id").fetchall()
        for row in rows:
            key = row["type"]
            if key in rules:
                rules[key].append({"value": row["value"], "scope": row["scope"]})
        return rules

    def _expire_agents(self, conn, agents):
        now = time.time()
        for a in agents:
            if a["status"] == "online" and now - a.get("last_heartbeat", 0) > HEARTBEAT_TIMEOUT:
                a["status"] = "offline"
                conn.execute("UPDATE agents SET status='offline' WHERE id=?", (a["id"],))
        conn.commit()

    # ── Alerts ──

    def _handle_get_alerts(self, conn):
        qs = self.path.split("?", 1)[1] if "?" in self.path else ""
        params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
        limit = min(int(params.get("limit", "100")), 500)
        show_ack = params.get("acknowledged", "0") == "1"
        if show_ack:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE acknowledged=0 ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        self._json(200, [dict(r) for r in rows])

    def _handle_post_alert_ack(self, body):
        alert_id = body.get("id")
        ack_all = body.get("all", False)
        conn = _get_db()
        if ack_all:
            conn.execute("UPDATE alerts SET acknowledged=1 WHERE acknowledged=0")
        elif alert_id:
            conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
        conn.commit()
        conn.close()
        self._json(200, {"ok": True})

    @staticmethod
    def _generate_alerts(conn, events, agent_id, agent_name):
        """Auto-generate alerts from incoming events. Uses immutable agent_id for identity."""
        now = time.time()
        for ev in events:
            tier = ev.get("tier", "")
            risk = ev.get("risk", "")
            cmd = ev.get("command", "")[:120]
            op = ev.get("operation", "")
            proof = ev.get("proof", "")[:200]

            # Critical block = immediate alert
            if tier == "block" and risk == "critical":
                title = f"Critical block on {agent_name}"
                detail = f"Command: {cmd}\nOperation: {op}\nProof: {proof}"
                conn.execute(
                    "INSERT INTO alerts(agent_id, agent, severity, title, detail, created_at) VALUES(?,?,?,?,?,?)",
                    (agent_id, agent_name, "critical", title, detail, now))

            # Exfiltration attempt
            elif tier == "block" and "exfil" in proof.lower():
                title = f"Exfiltration attempt on {agent_name}"
                detail = f"Command: {cmd}\nProof: {proof}"
                conn.execute(
                    "INSERT INTO alerts(agent_id, agent, severity, title, detail, created_at) VALUES(?,?,?,?,?,?)",
                    (agent_id, agent_name, "critical", title, detail, now))

            # Self-protection trigger
            elif "SELF-PROTECTION" in proof:
                title = f"Self-protection triggered on {agent_name}"
                detail = f"Command: {cmd}\nProof: {proof}"
                conn.execute(
                    "INSERT INTO alerts(agent_id, agent, severity, title, detail, created_at) VALUES(?,?,?,?,?,?)",
                    (agent_id, agent_name, "critical", title, detail, now))

            # High-risk warn
            elif tier == "warn" and risk == "high":
                title = f"High-risk command on {agent_name}"
                detail = f"Command: {cmd}\nOperation: {op}"
                conn.execute(
                    "INSERT INTO alerts(agent_id, agent, severity, title, detail, created_at) VALUES(?,?,?,?,?,?)",
                    (agent_id, agent_name, "warning", title, detail, now))

        # Burst detection: >10 blocks in last 5 minutes from same agent (by immutable ID)
        five_min_ago = now - 300
        burst = conn.execute(
            "SELECT COUNT(*) as c FROM events WHERE agent_id=? AND tier='block' AND received_at>?",
            (agent_id, five_min_ago)).fetchone()["c"]
        if burst > 10:
            existing = conn.execute(
                "SELECT id FROM alerts WHERE agent_id=? AND title LIKE '%burst%' AND created_at>? AND acknowledged=0",
                (agent_id, five_min_ago)).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO alerts(agent_id, agent, severity, title, detail, created_at) VALUES(?,?,?,?,?,?)",
                    (agent_id, agent_name, "critical", f"Block burst on {agent_name}",
                     f"{burst} commands blocked in the last 5 minutes -- possible attack or misconfiguration.", now))

        # Trim old alerts (keep 2000)
        alert_count = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]
        if alert_count > 2000:
            conn.execute("DELETE FROM alerts WHERE id IN (SELECT id FROM alerts ORDER BY created_at ASC LIMIT ?)",
                         (alert_count - 2000,))

    # ── Per-Agent Stats & Insights ──

    def _handle_get_agent_stats(self, conn):
        """Top commands, operations, risk breakdown per agent."""
        qs = self.path.split("?", 1)[1] if "?" in self.path else ""
        params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
        agent_filter = params.get("agent", "")
        hours = min(int(params.get("hours", "24")), 720)
        cutoff = time.time() - hours * 3600

        where = "WHERE received_at > ?"
        args = [cutoff]
        if agent_filter:
            where += " AND agent_id = ?"
            args.append(agent_filter)

        # Top operations per agent (group by immutable ID, display name for UI)
        top_ops = [dict(r) for r in conn.execute(
            f"SELECT agent_id, agent, operation, COUNT(*) as count FROM events {where} "
            "GROUP BY agent_id, operation ORDER BY count DESC LIMIT 50", args).fetchall()]

        # Top commands per agent (sanitized)
        top_cmds = [dict(r) for r in conn.execute(
            f"SELECT agent_id, agent, command, tier, COUNT(*) as count FROM events {where} "
            "GROUP BY agent_id, command ORDER BY count DESC LIMIT 50", args).fetchall()]

        # Risk breakdown per agent
        risk_by_agent = [dict(r) for r in conn.execute(
            f"SELECT agent_id, agent, risk, COUNT(*) as count FROM events {where} "
            "GROUP BY agent_id, risk ORDER BY agent_id, count DESC", args).fetchall()]

        # Tier breakdown per agent
        tier_by_agent = [dict(r) for r in conn.execute(
            f"SELECT agent_id, agent, tier, COUNT(*) as count FROM events {where} "
            "GROUP BY agent_id, tier ORDER BY agent_id, count DESC", args).fetchall()]

        # Activity timeline (hourly buckets)
        timeline = [dict(r) for r in conn.execute(
            f"SELECT CAST((received_at / 3600) AS INTEGER) * 3600 as bucket, "
            f"tier, COUNT(*) as count FROM events {where} "
            "GROUP BY bucket, tier ORDER BY bucket", args).fetchall()]

        self._json(200, {
            "top_operations": top_ops,
            "top_commands": top_cmds,
            "risk_by_agent": risk_by_agent,
            "tier_by_agent": tier_by_agent,
            "timeline": timeline,
            "period_hours": hours,
        })

    def _handle_get_insights(self, conn):
        """Auto-generated security insights."""
        now = time.time()
        insights = []

        # 1. Most blocked agent (by immutable ID)
        row = conn.execute(
            "SELECT agent_id, agent, COUNT(*) as c FROM events WHERE tier='block' AND received_at>? "
            "GROUP BY agent_id ORDER BY c DESC LIMIT 1", (now - 86400,)).fetchone()
        if row and row["c"] > 5:
            insights.append({
                "type": "hotspot", "severity": "high",
                "title": f"Agent '{row['agent']}' has {row['c']} blocks in 24h",
                "detail": f"Agent ID: {row['agent_id']}. Review its recent activity.",
            })

        # 2. Unknown binary attempts
        row = conn.execute(
            "SELECT COUNT(*) as c FROM events WHERE tier='block' AND proof LIKE '%Unknown binary%' AND received_at>?",
            (now - 86400,)).fetchone()
        if row and row["c"] > 0:
            insights.append({
                "type": "unknown_binaries", "severity": "medium",
                "title": f"{row['c']} unknown binary attempts in 24h",
                "detail": "Unknown binaries are blocked by default. Use 'nexus allow' on agents that need specific tools.",
            })

        # 3. Exfiltration attempts
        row = conn.execute(
            "SELECT COUNT(*) as c FROM events WHERE tier='block' AND risk='critical' AND received_at>?",
            (now - 86400,)).fetchone()
        if row and row["c"] > 0:
            insights.append({
                "type": "exfiltration", "severity": "critical",
                "title": f"{row['c']} critical blocks in 24h",
                "detail": "Critical blocks indicate potential data exfiltration or dangerous operations.",
            })

        # 4. Agent offline
        offline = conn.execute(
            "SELECT COUNT(*) as c FROM agents WHERE status='offline'").fetchone()["c"]
        total_a = conn.execute(
            "SELECT COUNT(*) as c FROM agents").fetchone()["c"]
        if offline > 0 and total_a > 0:
            insights.append({
                "type": "offline", "severity": "info",
                "title": f"{offline} of {total_a} agents offline",
                "detail": "Offline agents are not reporting. Check connectivity or if the reporter is running.",
            })

        # 5. Top operation pattern
        row = conn.execute(
            "SELECT operation, COUNT(*) as c FROM events WHERE received_at>? "
            "GROUP BY operation ORDER BY c DESC LIMIT 1", (now - 86400,)).fetchone()
        if row:
            insights.append({
                "type": "pattern", "severity": "info",
                "title": f"Most common operation: {row['operation']} ({row['c']}x)",
                "detail": "This is the most frequent operation across all agents in the last 24 hours.",
            })

        # 6. Block rate trend
        blocks_24h = conn.execute(
            "SELECT COUNT(*) as c FROM events WHERE tier='block' AND received_at>?",
            (now - 86400,)).fetchone()["c"]
        blocks_prev = conn.execute(
            "SELECT COUNT(*) as c FROM events WHERE tier='block' AND received_at>? AND received_at<=?",
            (now - 172800, now - 86400)).fetchone()["c"]
        if blocks_prev > 0 and blocks_24h > blocks_prev * 1.5:
            insights.append({
                "type": "trend", "severity": "warning",
                "title": f"Block rate up {int((blocks_24h / blocks_prev - 1) * 100)}% vs yesterday",
                "detail": f"Today: {blocks_24h} blocks. Yesterday: {blocks_prev}.",
            })
        elif blocks_24h == 0 and total_a > 0:
            insights.append({
                "type": "trend", "severity": "info",
                "title": "Zero blocks in 24h",
                "detail": "All clear — no security events triggered.",
            })

        self._json(200, insights)

    # ── POST handlers ──

    def _handle_login(self, body):
        password = body.get("password", "")
        stored = _db_get_config("admin_password")
        if not stored:
            self._json(500, {"error": "Server not configured. Run with --setup"})
            return
        if not _verify_password(password, stored):
            time.sleep(1)  # brute-force delay
            self._json(403, {"error": "Invalid password"})
            return

        token = _generate_token()
        token_hash = _hash_token(token)
        conn = _get_db()
        conn.execute("INSERT INTO sessions(token_hash, created_at, ip) VALUES(?, ?, ?)",
                     (token_hash, time.time(), self.client_address[0]))
        # Cleanup old sessions
        conn.execute("DELETE FROM sessions WHERE created_at < ?", (time.time() - SESSION_TTL,))
        conn.commit()
        conn.close()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", self._session_cookie(token))
        self._cors_headers()
        self.end_headers()
        try:
            self.wfile.write(json.dumps({"ok": True}).encode())
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass

    def _handle_logout(self):
        session = self._get_session()
        if session:
            conn = _get_db()
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (_hash_token(session),))
            conn.commit()
            conn.close()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "nexus_session=; Path=/; Max-Age=0")
        self._cors_headers()
        self.end_headers()
        try:
            self.wfile.write(json.dumps({"ok": True}).encode())
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass

    def _handle_setup(self, body):
        """Browser-based first-run setup. Only works when no admin password is set."""
        if _db_get_config("admin_password"):
            self._json(403, {"error": "Server already configured"})
            return
        password = body.get("password", "")
        if len(password) < 12:
            self._json(400, {"error": "Password must be at least 12 characters"})
            return
        # Set admin password
        _db_set_config("admin_password", _hash_password(password))
        # Generate enrollment key if not set
        if not _db_get_config("enrollment_key"):
            _db_set_config("enrollment_key", secrets.token_urlsafe(24))
        # Generate local reporter token and auto-enroll local agent
        if not _db_get_config("local_reporter_token"):
            lt = _generate_token()
            _db_set_config("local_reporter_token", lt)
            import socket as _s
            aid = f"nxg-local-{secrets.token_hex(4)}"
            th = _hash_token(lt)
            conn = _get_db()
            conn.execute(
                "INSERT OR REPLACE INTO agents(id,name,team,os,ip,version,status,token_hash,approved,first_seen,last_heartbeat) "
                "VALUES(?,?,'',?,'127.0.0.1','2.0','online',?,1,?,?)",
                (aid, _s.gethostname(), sys.platform, th, time.time(), time.time()))
            conn.commit()
            conn.close()
        # Auto-login: create session
        token = _generate_token()
        token_hash = _hash_token(token)
        conn = _get_db()
        conn.execute("INSERT INTO sessions(token_hash, created_at, ip) VALUES(?, ?, ?)",
                     (token_hash, time.time(), self.client_address[0]))
        conn.commit()
        conn.close()
        enrollment_key = _db_get_config("enrollment_key")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", self._session_cookie(token))
        self._cors_headers()
        self.end_headers()
        try:
            self.wfile.write(json.dumps({
                "ok": True,
                "enrollment_key": enrollment_key,
            }).encode())
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass

    def _handle_change_password(self, body):
        """Change admin password. Requires current password. Invalidates all sessions."""
        current = body.get("current_password", "")
        new_pw = body.get("new_password", "")
        stored = _db_get_config("admin_password")
        if not stored or not _verify_password(current, stored):
            time.sleep(0.5)
            self._json(403, {"error": "Current password is incorrect"})
            return
        if len(new_pw) < 12:
            self._json(400, {"error": "New password must be at least 12 characters"})
            return
        conn = _get_db()
        _db_set_config("admin_password", _hash_password(new_pw))
        # Invalidate ALL existing sessions (stolen cookies become useless)
        conn.execute("DELETE FROM sessions")
        # Issue a new session for the current admin so they stay logged in
        new_token = _generate_token()
        new_hash = _hash_token(new_token)
        conn.execute("INSERT INTO sessions(token_hash, created_at, ip) VALUES(?, ?, ?)",
                     (new_hash, time.time(), self.client_address[0]))
        conn.commit()
        conn.close()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", self._session_cookie(new_token))
        self._cors_headers()
        self.end_headers()
        try:
            self.wfile.write(json.dumps({"ok": True}).encode())
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass

    def _handle_rotate_key(self, body):
        """Generate a new enrollment key. Old key stops working immediately."""
        new_key = secrets.token_urlsafe(24)
        _db_set_config("enrollment_key", new_key)
        self._json(200, {"ok": True, "enrollment_key": new_key})

    def _handle_post_agent_config(self, body):
        """Save agent-side security configuration. Pushed to agents on heartbeat."""
        allowed_keys = {"green", "orange", "red", "audit", "custom_sensitive_paths"}
        allowed_green = {"silent", "note"}
        allowed_orange = {"pass_silent", "pass_note", "block"}
        allowed_red = {"block", "block_log"}
        allowed_audit = {"all", "warn_block", "block", "off"}

        cfg = {}
        raw = _db_get_config("agent_config", '{}')
        try:
            cfg = json.loads(raw)
        except json.JSONDecodeError:
            pass

        if "green" in body and body["green"] in allowed_green:
            cfg["green"] = body["green"]
        if "orange" in body and body["orange"] in allowed_orange:
            cfg["orange"] = body["orange"]
        if "red" in body and body["red"] in allowed_red:
            cfg["red"] = body["red"]
        if "audit" in body and body["audit"] in allowed_audit:
            cfg["audit"] = body["audit"]
        if "custom_sensitive_paths" in body and isinstance(body["custom_sensitive_paths"], list):
            # Validate: must be strings, no empty, max 200 entries
            paths = [str(p).strip() for p in body["custom_sensitive_paths"] if str(p).strip()][:200]
            cfg["custom_sensitive_paths"] = paths

        _db_set_config("agent_config", json.dumps(cfg))
        self._json(200, {"ok": True})
        threading.Thread(target=_sse_broadcast, args=("config",), daemon=True).start()

    def _handle_enroll(self, body):
        enroll_key = body.get("enrollment_key", "")
        stored_key = _db_get_config("enrollment_key")
        if not stored_key or not hmac.compare_digest(enroll_key, stored_key):
            time.sleep(1)
            self._json(403, {"error": "Invalid enrollment key"})
            return

        # Server generates the authoritative agent identity.
        # Client sends metadata only (name, os, team, ip).
        # Re-enrollment requires proof of old token.
        old_token = body.get("old_token", "")
        name = body.get("name", "")
        if not name or len(name) > 128:
            self._json(400, {"error": "Agent name is required (max 128 chars)"})
            return

        conn = _get_db()

        # Check if this is a re-enrollment attempt (old_token provided)
        if old_token:
            old_hash = _hash_token(old_token)
            existing = conn.execute(
                "SELECT id, name FROM agents WHERE token_hash=?", (old_hash,)).fetchone()
            if not existing:
                conn.close()
                time.sleep(0.5)
                self._json(403, {"error": "Invalid old token for re-enrollment"})
                return
            # Valid re-enrollment: rotate token, keep same agent_id
            agent_id = existing["id"]
            new_token = _generate_token()
            new_hash = _hash_token(new_token)
            conn.execute(
                "UPDATE agents SET token_hash=?, status='online', last_heartbeat=?, "
                "name=COALESCE(NULLIF(?,''),(name)), os=COALESCE(NULLIF(?,''),(os)), "
                "ip=COALESCE(NULLIF(?,''),(ip)), version=COALESCE(NULLIF(?,''),(version)) WHERE id=?",
                (new_hash, time.time(), name, body.get("os", ""),
                 body.get("ip", ""), body.get("version", ""), agent_id))
            conn.commit()
            conn.close()
            self._json(200, {"ok": True, "agent_id": agent_id, "token": new_token})
            threading.Thread(target=_sse_broadcast, args=("agents",), daemon=True).start()
            return

        # New enrollment: server generates UUID
        agent_id = f"nxg-{secrets.token_hex(8)}"
        new_token = _generate_token()
        new_hash = _hash_token(new_token)
        conn.execute(
            "INSERT INTO agents(id, name, team, os, ip, version, status, token_hash, approved, first_seen, last_heartbeat) "
            "VALUES(?, ?, ?, ?, ?, ?, 'online', ?, 1, ?, ?)",
            (agent_id, name, body.get("team", ""),
             body.get("os", ""), body.get("ip", ""), body.get("version", ""),
             new_hash, time.time(), time.time()))
        conn.commit()
        conn.close()

        self._json(200, {"ok": True, "agent_id": agent_id, "token": new_token})
        threading.Thread(target=_sse_broadcast, args=("agents",), daemon=True).start()

    def _handle_heartbeat(self, agent, body):
        conn = _get_db()
        # SECURITY: name is NOT updatable via heartbeat to prevent display-name spoofing.
        # Name is set once at enrollment. Only metadata (team, os, ip, version) can change.
        conn.execute(
            "UPDATE agents SET status='online', last_heartbeat=?, "
            "team=COALESCE(NULLIF(?,''),(team)), os=COALESCE(NULLIF(?,''),(os)), "
            "ip=COALESCE(NULLIF(?,''),(ip)), version=COALESCE(NULLIF(?,''),(version)) WHERE id=?",
            (time.time(), body.get("team", ""),
             body.get("os", ""), body.get("ip", ""), body.get("version", ""), agent["id"]))
        conn.commit()
        # Return only global rules + rules scoped to this agent
        rules = self._build_rules(conn, scope_filter=agent["id"])
        conn.close()
        # Include agent config for push-down
        raw_cfg = _db_get_config("agent_config", '{}')
        try:
            agent_cfg = json.loads(raw_cfg)
        except json.JSONDecodeError:
            agent_cfg = {}
        self._json(200, {"ok": True, "rules": rules, "config": agent_cfg})
        threading.Thread(target=_sse_broadcast, args=("agents",), daemon=True).start()

    def _handle_post_events(self, agent, body):
        events = body if isinstance(body, list) else [body]
        conn = _get_db()
        now = time.time()
        # SECURITY: Stamp identity from authenticated agent record.
        # agent_id is immutable (server-generated UUID), agent_name is display only.
        if agent:
            agent_id = agent["id"]
            agent_name = agent["name"]
        else:
            agent_id = "admin"
            agent_name = "admin"
        for ev in events:
            conn.execute(
                "INSERT INTO events(agent_id, agent, source, tool, command, command_raw, operation, risk, tier, flow, proof, timestamp, received_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (agent_id, agent_name,
                 ev.get("source", ""), ev.get("tool", ""),
                 ev.get("command", ev.get("cmd", "")),
                 ev.get("command_raw", ev.get("command", ev.get("cmd", ""))),
                 ev.get("operation", ev.get("op", "")), ev.get("risk", ""),
                 ev.get("tier", ""), ev.get("flow", ""), ev.get("proof", ""),
                 ev.get("timestamp", now), now))
        # Generate alerts from events
        try:
            self._generate_alerts(conn, events, agent_id, agent_name)
        except Exception:
            pass  # alerts are best-effort
        # Trim old events
        count = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]
        if count > MAX_EVENTS:
            conn.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY received_at ASC LIMIT ?)",
                         (count - MAX_EVENTS,))
        conn.commit()
        conn.close()
        self._json(200, {"ok": True, "accepted": len(events)})
        threading.Thread(target=_sse_broadcast, args=("events",), daemon=True).start()

    def _handle_post_rules(self, body):
        scope = body.get("scope", "global")
        conn = _get_db()
        for rule_type in ("trusted_hosts", "allowed_patterns", "blocked_patterns"):
            if rule_type not in body:
                continue
            # Only delete rules of this type AND this scope -- don't clobber other scopes
            conn.execute("DELETE FROM rules WHERE type=? AND scope=?", (rule_type, scope))
            for item in body[rule_type]:
                value = item if isinstance(item, str) else (item.get("value") or item.get("host") or item.get("pattern") or "")
                if value:
                    conn.execute("INSERT OR IGNORE INTO rules(type, value, scope, created_at) VALUES(?, ?, ?, ?)",
                                 (rule_type, value, scope, time.time()))
        conn.commit()
        conn.close()
        self._json(200, {"ok": True})
        threading.Thread(target=_sse_broadcast, args=("rules",), daemon=True).start()

    # ── SSE ──

    def _handle_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._cors_headers()
        self.end_headers()
        with SSE_LOCK:
            SSE_CLIENTS.append(self.wfile)
        try:
            self.wfile.write(b"event: connected\ndata: {}\n\n")
            self.wfile.flush()
            while True:
                time.sleep(25)
                self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except Exception:
            pass
        finally:
            with SSE_LOCK:
                try:
                    SSE_CLIENTS.remove(self.wfile)
                except ValueError:
                    pass

    # ── Dashboard ──

    def _serve_dashboard(self):
        html = DASHBOARD_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(html))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.end_headers()
        try:
            self.wfile.write(html)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass


# ═══════════════════════════════════════════════════════════════
# Dashboard HTML
# ═══════════════════════════════════════════════════════════════

DASHBOARD_HTML = "Dashboard not loaded"

def _load_dashboard():
    global DASHBOARD_HTML
    dash_path = Path(__file__).parent / "nexus_dashboard.html"
    if dash_path.exists():
        DASHBOARD_HTML = dash_path.read_text(encoding="utf-8")
        return
    DASHBOARD_HTML = "<html><body><h1>Dashboard not found</h1><p>Place nexus_dashboard.html next to nexus_server.py</p></body></html>"


# ═══════════════════════════════════════════════════════════════
# Built-in local reporter
# ═══════════════════════════════════════════════════════════════

def _builtin_reporter(port, agent_token):
    """Watch local audit.jsonl and feed events to our own API."""
    import socket as _sock
    import urllib.request

    audit = Path.home() / ".nexus" / "audit.jsonl"
    agent_name = _sock.gethostname()
    base = f"http://127.0.0.1:{port}"
    offset = 0
    last_beat = 0

    def _post(path, data):
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            base + path, data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {agent_token}",
            },
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def _heartbeat():
        stats = {}
        mem = Path.home() / ".nexus" / "memory.json"
        if mem.exists():
            try:
                stats = json.loads(mem.read_text()).get("stats", {})
            except Exception:
                pass
        return _post("/api/heartbeat", {
            "name": agent_name, "os": sys.platform,
            "ip": _get_local_ip(), "version": "2.0", "stats": stats,
        })

    def _get_local_ip():
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _apply_rules(rules):
        if not rules:
            return
        mem_path = Path.home() / ".nexus" / "memory.json"
        try:
            mem = json.loads(mem_path.read_text()) if mem_path.exists() else {}
        except Exception:
            mem = {}
        prev_server = mem.get("_server_managed", {})
        new_server = {}
        changed = False
        for key in ("trusted_hosts", "allowed_patterns", "blocked_patterns"):
            if key not in rules:
                continue
            server_items = [
                (v if isinstance(v, str) else (v.get("value") or v.get("host") or v.get("pattern") or ""))
                for v in rules[key]
            ]
            server_items = [v for v in server_items if v]
            new_server[key] = server_items
            local = mem.get(key, [])
            # Remove revoked server rules
            old_items = set(prev_server.get(key, []))
            new_items = set(server_items)
            revoked = old_items - new_items
            if revoked:
                local = [v for v in local if v not in revoked]
                changed = True
            # Add new server rules
            for v in server_items:
                if v not in local:
                    local.append(v)
                    changed = True
            mem[key] = local
        mem["_server_managed"] = new_server
        if changed or new_server != prev_server:
            mem_path.write_text(json.dumps(mem, indent=2))

    time.sleep(2)

    while True:
        try:
            now = time.time()
            if now - last_beat >= 30:
                resp = _heartbeat()
                if resp and resp.get("rules"):
                    _apply_rules(resp["rules"])
                last_beat = now

            if audit.exists():
                fsize = audit.stat().st_size
                if fsize < offset:
                    offset = 0
                if fsize > offset:
                    events = []
                    with open(audit) as f:
                        f.seek(offset)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                ev = json.loads(line)
                                ev["agent"] = agent_name
                                ev.setdefault("timestamp", time.time())
                                events.append(ev)
                            except json.JSONDecodeError:
                                continue
                        offset = f.tell()
                    if events:
                        _post("/api/events", events)

            time.sleep(2)
        except Exception:
            time.sleep(10)


# ═══════════════════════════════════════════════════════════════
# TLS
# ═══════════════════════════════════════════════════════════════

def _generate_self_signed_cert():
    """Generate a self-signed cert using openssl CLI (available on most systems)."""
    import subprocess
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if CERT_PATH.exists() and KEY_PATH.exists():
        return True
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(KEY_PATH), "-out", str(CERT_PATH),
            "-days", "365", "-nodes",
            "-subj", "/CN=nexus-gate-server"
        ], capture_output=True, check=True, timeout=30)
        os.chmod(str(KEY_PATH), 0o600)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False


# ═══════════════════════════════════════════════════════════════
# Setup
# ═══════════════════════════════════════════════════════════════

def run_setup():
    """Interactive first-run setup."""
    G = "\033[92m"
    B = "\033[1m"
    D = "\033[2m"
    Y = "\033[93m"
    R = "\033[0m"

    print(f"""
{G}>{R} {B}nexus gate{R} -- server setup
""")

    _init_db()

    # Admin password
    existing_pw = _db_get_config("admin_password")
    if existing_pw:
        print(f"  {D}Admin password already set.{R}")
        change = input("  Change it? (y/N): ").strip().lower()
        if change != "y":
            print()
        else:
            existing_pw = None

    if not existing_pw:
        while True:
            pw = input("  Set admin password: ").strip()
            if len(pw) < 12:
                print(f"  {Y}At least 12 characters.{R}")
                continue
            pw2 = input("  Confirm: ").strip()
            if pw != pw2:
                print(f"  {Y}Passwords don't match.{R}")
                continue
            _db_set_config("admin_password", _hash_password(pw))
            print(f"  {G}OK{R} Admin password set.\n")
            break

    # Enrollment key
    existing_key = _db_get_config("enrollment_key")
    if not existing_key:
        existing_key = secrets.token_urlsafe(24)
        _db_set_config("enrollment_key", existing_key)

    print(f"  {B}Enrollment key:{R}  {existing_key}")
    print(f"  {D}Give this to each machine that should connect.{R}")
    print(f"  {D}Agents use it once to register, then get their own token.{R}\n")

    # Local reporter token
    local_token = _db_get_config("local_reporter_token")
    if not local_token:
        local_token = _generate_token()
        _db_set_config("local_reporter_token", local_token)
        # Auto-enroll local agent
        import socket
        agent_id = f"nxg-local-{secrets.token_hex(4)}"
        token_hash = _hash_token(local_token)
        conn = _get_db()
        conn.execute(
            "INSERT OR REPLACE INTO agents(id, name, team, os, ip, version, status, token_hash, approved, first_seen, last_heartbeat) "
            "VALUES(?, ?, '', ?, '127.0.0.1', '2.0', 'online', ?, 1, ?, ?)",
            (agent_id, socket.gethostname(), sys.platform, token_hash, time.time(), time.time()))
        conn.commit()
        conn.close()

    print(f"  {G}OK{R} Setup complete. Start with:")
    print(f"    {D}python {__file__}{R}")
    print(f"    {D}python {__file__} --tls{R}  (with HTTPS)\n")


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

def main():
    global SERVER_SECRET

    # Fix encoding for Windows terminals (cp1252 can't handle Unicode symbols)
    try:
        sys.stdout.reconfigure(errors='replace')
        sys.stderr.reconfigure(errors='replace')
    except (AttributeError, OSError):
        pass  # Python < 3.7 or non-reconfigurable stream

    # Windows ANSI
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="Nexus Gate - Central Server")
    parser.add_argument("--port", type=int, default=7070)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--tls", action="store_true", help="Enable HTTPS (auto-generate cert)")
    parser.add_argument("--cert", help="Path to TLS certificate")
    parser.add_argument("--key", help="Path to TLS private key")
    parser.add_argument("--allow-plaintext", action="store_true",
                        help="Allow external bind without TLS (e.g. behind a reverse proxy)")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--no-reporter", action="store_true")
    parser.add_argument("--setup", action="store_true", help="Run first-time setup")
    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SERVER_SECRET = _server_secret()
    _init_db()
    _load_dashboard()

    if args.setup:
        run_setup()
        return

    # ── Admin password gate ──
    # Check env vars first (Docker)
    if not _db_get_config("admin_password"):
        env_pw = os.environ.get("NEXUS_ADMIN_PASSWORD")
        if env_pw:
            if len(env_pw) < 12:
                print(f"  NEXUS_ADMIN_PASSWORD must be at least 12 characters.")
                sys.exit(1)
            _db_set_config("admin_password", _hash_password(env_pw))
            if not _db_get_config("enrollment_key"):
                _db_set_config("enrollment_key", secrets.token_urlsafe(24))
            if not _db_get_config("local_reporter_token"):
                lt = _generate_token()
                _db_set_config("local_reporter_token", lt)
                import socket as _s
                aid = f"nxg-local-{secrets.token_hex(4)}"
                th = _hash_token(lt)
                conn = _get_db()
                conn.execute(
                    "INSERT OR REPLACE INTO agents(id,name,team,os,ip,version,status,token_hash,approved,first_seen,last_heartbeat) "
                    "VALUES(?,?,'',?,'127.0.0.1','2.0','online',?,1,?,?)",
                    (aid, _s.gethostname(), sys.platform, th, time.time(), time.time()))
                conn.commit()
                conn.close()

    # Refuse to start without an admin password unless binding to localhost only
    has_admin = _db_get_config("admin_password") is not None
    is_external = args.bind != "127.0.0.1"
    if not has_admin and is_external:
        print(f"\n  Cannot bind to {args.bind} without an admin password.")
        print(f"  Set NEXUS_ADMIN_PASSWORD or run: python {__file__} --setup\n")
        sys.exit(1)
    if not has_admin:
        print(f"  Warning: No admin password set. Dashboard is in setup-wizard mode.")
        print(f"  Binding to 127.0.0.1 only. Set a password to enable external access.\n")

    G = "\033[92m"
    B = "\033[1m"
    D = "\033[2m"
    Y = "\033[93m"
    R = "\033[0m"

    # TLS
    use_tls = args.tls or args.cert
    ssl_ctx = None
    if use_tls:
        cert = args.cert or str(CERT_PATH)
        key = args.key or str(KEY_PATH)
        if not Path(cert).exists() or not Path(key).exists():
            print(f"  {D}Generating self-signed certificate...{R}")
            if not _generate_self_signed_cert():
                print(f"  TLS was requested but certificate generation failed (openssl not found).")
                print(f"  Install openssl or provide --cert and --key.")
                sys.exit(1)
            else:
                cert = str(CERT_PATH)
                key = str(KEY_PATH)

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(cert, key)

    # ── External bind safety gate ──
    # Refuse to expose admin plane over plaintext HTTP on a network interface.
    # Allowed escapes: --tls, --allow-plaintext (reverse proxy), or localhost-only bind.
    is_external = args.bind not in ("127.0.0.1", "localhost", "::1")
    if is_external and not use_tls and not args.allow_plaintext:
        print(f"\n  Cannot bind to {args.bind} over plaintext HTTP.")
        print(f"  The admin plane carries session cookies, enrollment keys, and agent tokens.")
        print(f"")
        print(f"  Options:")
        print(f"    --tls                  Auto-generate a TLS certificate")
        print(f"    --cert FILE --key FILE Use your own certificate")
        print(f"    --allow-plaintext      I have a reverse proxy handling TLS")
        print(f"")
        sys.exit(1)

    # Server
    server = ThreadedHTTPServer((args.bind, args.port), APIHandler)
    server.use_tls = use_tls
    if ssl_ctx:
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)

    protocol = "https" if use_tls else "http"

    # Local reporter
    if not args.no_reporter:
        local_token = _db_get_config("local_reporter_token")
        if local_token:
            t = threading.Thread(target=_builtin_reporter, args=(args.port, local_token), daemon=True)
            t.start()

    # Browser
    if not args.no_browser:
        def _open():
            time.sleep(1.5)
            try:
                import webbrowser
                webbrowser.open(f"{protocol}://localhost:{args.port}")
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    bind_label = f"{args.bind}:{args.port}" if is_external else f"localhost:{args.port}"
    print(f"""
{G}>{R} {B}nexus gate{R} -- server

  Dashboard:      {B}{protocol}://{bind_label}{R}
  TLS:            {'on' if use_tls else 'off'}
  Local reporter: {'on' if not args.no_reporter else 'off'}
  Data:           {DATA_DIR}

  {D}Enrollment key: visible in dashboard Settings after login.{R}
  {D}Press Ctrl+C to stop.{R}
""")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n  {D}Stopped.{R}\n")
        server.server_close()


if __name__ == "__main__":
    main()

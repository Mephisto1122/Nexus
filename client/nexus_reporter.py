#!/usr/bin/env python3
"""
Nexus Gate — Agent Reporter

Runs on each agent machine alongside nexus_hook.py.
Watches ~/.nexus/audit.jsonl for new events, sends them to the central server.

# Fix encoding for Windows terminals
try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except (AttributeError, OSError):
    pass

Authenticates using an agent token obtained via enrollment.

First run (requires enrollment key from the server admin):
    python nexus_reporter.py --server https://host:7070 --enroll-key <KEY>

Subsequent runs (token saved locally):
    python nexus_reporter.py --server https://host:7070

Options:
    --server URL          Central server address (required)
    --enroll-key KEY      Enrollment key for first-time registration
    --name NAME           Agent display name (default: hostname)
    --team TEAM           Team label shown in dashboard
    --interval SEC        Heartbeat interval (default: 30)
    --insecure            Skip TLS certificate verification
"""

import json, os, sys, time, socket, platform, argparse, hashlib, ssl
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

NEXUS_DIR = Path.home() / ".nexus"
AUDIT_FILE = NEXUS_DIR / "audit.jsonl"
MEMORY_FILE = NEXUS_DIR / "memory.json"
TOKEN_FILE = NEXUS_DIR / "reporter_token.json"
STATE_FILE = NEXUS_DIR / "reporter_state.json"


def get_agent_id():
    hostname = socket.gethostname()
    raw = f"{hostname}-{platform.node()}-{os.getuid() if hasattr(os, 'getuid') else os.getlogin()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def load_token(server):
    """Load saved token and agent_id for this server."""
    if not TOKEN_FILE.exists():
        return None, None
    try:
        data = json.loads(TOKEN_FILE.read_text())
        entry = data.get(server, {})
        if isinstance(entry, str):
            # Legacy: plain token string, no agent_id
            return entry, None
        return entry.get("token"), entry.get("agent_id")
    except (json.JSONDecodeError, KeyError):
        return None, None


def save_token(server, token, agent_id=None):
    """Save token and agent_id for this server."""
    NEXUS_DIR.mkdir(parents=True, exist_ok=True)
    data = {}
    if TOKEN_FILE.exists():
        try:
            data = json.loads(TOKEN_FILE.read_text())
        except (json.JSONDecodeError, KeyError):
            pass
    data[server] = {"token": token, "agent_id": agent_id}
    TOKEN_FILE.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(str(TOKEN_FILE), 0o600)
    except OSError:
        pass


def clear_token(server):
    """Remove saved token for this server."""
    if not TOKEN_FILE.exists():
        return
    try:
        data = json.loads(TOKEN_FILE.read_text())
        data.pop(server, None)
        TOKEN_FILE.write_text(json.dumps(data, indent=2))
    except (json.JSONDecodeError, KeyError):
        pass


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, KeyError):
            pass
    return {"last_offset": 0}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state))


def api_post(server, path, data, token=None, ssl_ctx=None):
    url = server.rstrip("/") + path
    body = json.dumps(data).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=10, context=ssl_ctx) as resp:
            return {"status": resp.status, "data": json.loads(resp.read())}
    except HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {"error": str(e)}
        return {"status": e.code, "data": body}
    except (URLError, OSError, ConnectionError) as e:
        return {"status": 0, "data": {"error": f"Connection failed: {e}"}}
    except Exception as e:
        return {"status": 0, "data": {"error": str(e)}}


def enroll(server, enroll_key, name, team, ssl_ctx, old_token=None):
    """Enroll with the server and get a server-generated agent_id + token."""
    payload = {
        "enrollment_key": enroll_key,
        "name": name,
        "team": team,
        "os": platform.system(),
        "ip": get_local_ip(),
        "version": "2.0",
    }
    if old_token:
        payload["old_token"] = old_token
    r = api_post(server, "/api/enroll", payload, ssl_ctx=ssl_ctx)
    if r["status"] == 200 and r["data"].get("token"):
        return r["data"]["token"], r["data"].get("agent_id", "")
    return None, None


def apply_rules(rules):
    """Replace server-managed rules in local memory.
    
    Server-managed rules are tracked separately from user-local rules.
    On each sync: remove previously-pushed server rules, add current ones.
    This ensures dashboard revokes actually propagate to agents.
    """
    if not rules:
        return
    try:
        mem = json.loads(MEMORY_FILE.read_text()) if MEMORY_FILE.exists() else {}
    except (json.JSONDecodeError, KeyError):
        mem = {}

    # Track what the server previously pushed (so we can remove revoked rules)
    prev_server = mem.get("_server_managed", {})
    new_server = {}
    changed = False

    for key in ("trusted_hosts", "allowed_patterns", "blocked_patterns"):
        if key not in rules:
            continue
        # Extract server values
        server_items = []
        for item in rules[key]:
            val = item if isinstance(item, str) else (item.get("value") or item.get("host") or item.get("pattern") or "")
            if val:
                server_items.append(val)
        new_server[key] = server_items

        local = mem.get(key, [])

        # Remove previously server-managed items that are no longer in the server set
        old_items = set(prev_server.get(key, []))
        new_items = set(server_items)
        revoked = old_items - new_items
        if revoked:
            local = [v for v in local if v not in revoked]
            changed = True

        # Add new server items not already present
        for v in server_items:
            if v not in local:
                local.append(v)
                changed = True

        mem[key] = local

    mem["_server_managed"] = new_server
    if changed or new_server != prev_server:
        MEMORY_FILE.write_text(json.dumps(mem, indent=2))


def apply_config(config):
    """Apply server-pushed agent config to local config.json."""
    if not config:
        return
    config_path = NEXUS_DIR / "config.json"
    try:
        local = json.loads(config_path.read_text()) if config_path.exists() else {}
    except (json.JSONDecodeError, KeyError):
        local = {}
    changed = False
    for key in ("green", "orange", "red", "audit"):
        if key in config and config[key] != local.get(key):
            local[key] = config[key]
            changed = True
    # Custom sensitive paths go into memory, not config
    if "custom_sensitive_paths" in config:
        try:
            mem = json.loads(MEMORY_FILE.read_text()) if MEMORY_FILE.exists() else {}
        except (json.JSONDecodeError, KeyError):
            mem = {}
        server_paths = config["custom_sensitive_paths"]
        local_paths = mem.get("custom_sensitive_paths", [])
        for p in server_paths:
            if p and p not in local_paths:
                local_paths.append(p)
                changed = True
        mem["custom_sensitive_paths"] = local_paths
        MEMORY_FILE.write_text(json.dumps(mem, indent=2))
    if changed:
        config_path.write_text(json.dumps(local, indent=2))


def read_new_events(agent_name):
    if not AUDIT_FILE.exists():
        return []
    state = load_state()
    last_offset = state.get("last_offset", 0)
    file_size = AUDIT_FILE.stat().st_size
    if file_size < last_offset:
        last_offset = 0
    if file_size == last_offset:
        return []
    events = []
    with open(AUDIT_FILE, "r") as f:
        f.seek(last_offset)
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
        new_offset = f.tell()
    state["last_offset"] = new_offset
    save_state(state)
    return events


def main():
    parser = argparse.ArgumentParser(description="Nexus Gate - Agent Reporter")
    parser.add_argument("--server", required=True, help="Central server URL")
    parser.add_argument("--enroll-key", help="Enrollment key (first run only)")
    parser.add_argument("--name", default=socket.gethostname(), help="Agent name")
    parser.add_argument("--team", default="", help="Team label")
    parser.add_argument("--interval", type=int, default=30, help="Heartbeat interval")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    args = parser.parse_args()

    G = "\033[92m"
    B = "\033[1m"
    D = "\033[2m"
    Y = "\033[93m"
    R = "\033[91m"
    X = "\033[0m"

    server = args.server.rstrip("/")

    # TLS context
    ssl_ctx = None
    if server.startswith("https://"):
        ssl_ctx = ssl.create_default_context()
        if args.insecure:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    # Load saved credentials
    token, agent_id = load_token(server)

    print(f"""
{G}>{X} {B}nexus gate{X} -- reporter

  Agent:    {B}{args.name}{X}{f' ({agent_id})' if agent_id else ''}
  Server:   {server}
  Team:     {args.team or '--'}
  Interval: {args.interval}s
""")

    if not token:
        if not args.enroll_key:
            print(f"  {R}No saved token and no --enroll-key provided.{X}")
            print(f"  First run requires: --enroll-key <KEY>")
            print(f"  {D}Get the enrollment key from your server admin.{X}\n")
            sys.exit(1)

        print(f"  {D}Enrolling with server...{X}")
        token, agent_id = enroll(server, args.enroll_key, args.name, args.team, ssl_ctx)
        if not token:
            print(f"  {R}Enrollment failed. Check the enrollment key and server address.{X}\n")
            sys.exit(1)

        save_token(server, token, agent_id)
        print(f"  {G}*{X} Enrolled as {B}{agent_id}{X}. Token saved to {TOKEN_FILE}")
    else:
        print(f"  {G}*{X} Token loaded from {TOKEN_FILE}")

    # Test connection
    def heartbeat():
        return api_post(server, "/api/heartbeat", {
            "team": args.team,
            "os": platform.system(), "ip": get_local_ip(), "version": "2.0",
        }, token=token, ssl_ctx=ssl_ctx)

    r = heartbeat()

    if r["status"] == 200:
        print(f"  {G}*{X} Connected to server")
        if r["data"].get("rules"):
            apply_rules(r["data"]["rules"])
            print(f"  {G}*{X} Rules synced")
        if r["data"].get("config"):
            apply_config(r["data"]["config"])
            print(f"  {G}*{X} Config synced")
    elif r["status"] == 401:
        print(f"  {Y}!{X} Token rejected by server.")
        # Try re-enrollment with old token as proof of possession
        if args.enroll_key and token:
            print(f"  {D}Re-enrolling with proof of old token...{X}")
            new_token, new_id = enroll(server, args.enroll_key, args.name, args.team, ssl_ctx, old_token=token)
            if new_token:
                token = new_token
                agent_id = new_id or agent_id
                save_token(server, token, agent_id)
                print(f"  {G}*{X} Re-enrolled as {B}{agent_id}{X}")
            else:
                print(f"  {R}Re-enrollment failed. Check enrollment key.{X}\n")
                sys.exit(1)
        else:
            clear_token(server)
            print(f"  {R}Deleted stale token. Re-run with --enroll-key <KEY>{X}")
            print(f"  {D}Get the new key from Settings in the dashboard.{X}\n")
            sys.exit(1)
    elif r["status"] == 0:
        print(f"  {Y}!{X} Cannot reach server at {server}")
        print(f"  {D}Will retry every {args.interval} seconds...{X}")
    else:
        print(f"  {Y}!{X} Server returned {r['status']}: {r['data'].get('error', '?')}")

    print(f"\n  {D}Watching for events...{X}\n")

    last_heartbeat = time.time()

    while True:
        try:
            events = read_new_events(args.name)
            if events:
                r = api_post(server, "/api/events", events, token=token, ssl_ctx=ssl_ctx)
                ts = time.strftime("%H:%M:%S")
                if r["status"] == 200:
                    blocks = sum(1 for e in events if e.get("tier") == "block")
                    label = f"{len(events)} event{'s' if len(events) != 1 else ''}"
                    if blocks:
                        label += f" ({blocks} blocked)"
                    print(f"  {ts}  sent {label}")
                elif r["status"] == 401:
                    print(f"  {ts}  {Y}token rejected -- re-enroll with --enroll-key{X}")
                else:
                    print(f"  {ts}  {Y}send failed ({r['status']}){X}")

            now = time.time()
            if now - last_heartbeat >= args.interval:
                r = heartbeat()
                if r["status"] == 200:
                    if r["data"].get("rules"):
                        apply_rules(r["data"]["rules"])
                    if r["data"].get("config"):
                        apply_config(r["data"]["config"])
                elif r["status"] == 401:
                    # Try re-enrollment with proof of old token
                    if args.enroll_key and token:
                        new_token, new_id = enroll(server, args.enroll_key, args.name, args.team, ssl_ctx, old_token=token)
                        if new_token:
                            token = new_token
                            agent_id = new_id or agent_id
                            save_token(server, token, agent_id)
                            print(f"  {time.strftime('%H:%M:%S')}  {G}re-enrolled as {agent_id}{X}")
                last_heartbeat = now

            time.sleep(2)

        except KeyboardInterrupt:
            print(f"\n  {D}Stopped.{X}\n")
            break
        except Exception as e:
            print(f"  {R}error: {e}{X}")
            time.sleep(10)


if __name__ == "__main__":
    main()

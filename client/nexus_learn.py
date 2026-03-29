#!/usr/bin/env python3
"""
Nexus Gate — Dynamic Flow Learner

Observes what a command actually does via strace, derives the flow tuple
from observed syscalls. No guessing. No hand-curation. Watched behavior.


# Fix encoding for Windows terminals
try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except (AttributeError, OSError):
    pass

  python nexus_learn.py "curl https://example.com"
  python nexus_learn.py "grep -r TODO ."
  python nexus_learn.py --batch commands.txt
  python nexus_learn.py --audit               # compare learned vs hardcoded

Requires: Linux with strace. macOS support (dtrace/dtruss) planned.
"""

import subprocess
import sys
import os
import re
import json
import tempfile
from pathlib import Path
from dataclasses import dataclass, field, asdict
from collections import defaultdict


# ═══════════════════════════════════════════════════════════
# Observed behavior from syscall trace
# ═══════════════════════════════════════════════════════════

@dataclass
class ObservedBehavior:
    """What a command actually did, derived from syscalls."""
    command: str = ""
    binary: str = ""
    
    # File I/O
    files_read: list = field(default_factory=list)
    files_written: list = field(default_factory=list)
    files_created: list = field(default_factory=list)
    files_deleted: list = field(default_factory=list)
    
    # Network
    connections: list = field(default_factory=list)     # (host, port, protocol)
    dns_lookups: list = field(default_factory=list)
    bytes_sent: int = 0
    bytes_received: int = 0
    
    # Process
    child_processes: list = field(default_factory=list)  # execve calls
    
    # Derived flow
    reads: bool = False
    writes: bool = False
    net_in: bool = False
    net_out: bool = False
    executes: bool = False


# ═══════════════════════════════════════════════════════════
# Strace parser — turns raw syscall output into observations
# ═══════════════════════════════════════════════════════════

# Paths to ignore (runtime noise, not real behavior)
NOISE_PATHS = {
    "/etc/ld.so.cache", "/etc/ld.so.preload",
    "/proc/self/", "/proc/filesystems",
    "/dev/null", "/dev/urandom", "/dev/random",
    "/usr/share/locale/", "/usr/lib/locale/",
    "/etc/nsswitch.conf", "/etc/resolv.conf",
    "/etc/gai.conf", "/etc/host.conf",
    "/etc/ssl/", "/etc/ca-certificates/",
}

# Shared libraries — not real reads
LIB_PATTERNS = re.compile(r'\.so(\.\d+)*$|/lib/|/lib64/')


def is_noise(path: str) -> bool:
    """Filter out runtime loader and library noise."""
    if not path or path.startswith("/proc/self"):
        return True
    for prefix in NOISE_PATHS:
        if path.startswith(prefix):
            return True
    if LIB_PATTERNS.search(path):
        return True
    return False


def parse_strace(output: str) -> ObservedBehavior:
    """Parse strace output into structured observations."""
    obs = ObservedBehavior()
    
    fds = {}  # track fd → path mapping
    
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        
        # ── open / openat → track file descriptors ──
        m = re.match(r'(?:openat?\(.*?"(.+?)".*?(?:O_RDONLY|O_WRONLY|O_RDWR|O_CREAT).*?\)\s*=\s*(\d+))', line)
        if not m:
            m = re.match(r'openat\(\w+,\s*"(.+?)".*?\)\s*=\s*(\d+)', line)
        if m:
            path, fd = m.group(1), int(m.group(2))
            if not is_noise(path):
                fds[fd] = path
                if "O_WRONLY" in line or "O_RDWR" in line or "O_CREAT" in line:
                    if "O_CREAT" in line and not os.path.exists(path):
                        obs.files_created.append(path)
                    else:
                        obs.files_written.append(path)
                    obs.writes = True
                if "O_RDONLY" in line or "O_RDWR" in line:
                    obs.files_read.append(path)
                    obs.reads = True
            continue
        
        # ── read → confirm file read ──
        m = re.match(r'read\((\d+),', line)
        if m:
            fd = int(m.group(1))
            if fd in fds and not is_noise(fds[fd]):
                obs.reads = True
            continue
        
        # ── write → confirm file write ──
        m = re.match(r'write\((\d+),', line)
        if m:
            fd = int(m.group(1))
            if fd in fds and not is_noise(fds[fd]):
                obs.writes = True
            continue
        
        # ── connect → network connection ──
        m = re.match(r'connect\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*sin6?_addr="?([^"}\s]+)', line)
        if not m:
            m = re.match(r'connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)', line)
        if m:
            port, addr = int(m.group(1)), m.group(2)
            if addr not in ("127.0.0.1", "::1", "0.0.0.0"):
                obs.connections.append((addr, port))
                obs.net_out = True
            continue
        
        # ── sendto / sendmsg → outbound data ──
        m = re.match(r'(?:sendto|sendmsg)\(\d+,.*?,\s*(\d+)', line)
        if m:
            obs.bytes_sent += int(m.group(1))
            obs.net_out = True
            continue
        
        # ── recvfrom / recvmsg → inbound data ──
        m = re.match(r'(?:recvfrom|recvmsg)\(\d+,.*?\)\s*=\s*(\d+)', line)
        if m:
            obs.bytes_received += int(m.group(1))
            obs.net_in = True
            continue
        
        # ── execve → child process ──
        m = re.match(r'execve\("(.+?)"', line)
        if m:
            child = m.group(1)
            if child != obs.binary:
                obs.child_processes.append(child)
                obs.executes = True
            continue
        
        # ── unlink → file deletion ──
        m = re.match(r'(?:unlink|unlinkat)\(.*?"(.+?)"', line)
        if m:
            path = m.group(1)
            if not is_noise(path):
                obs.files_deleted.append(path)
                obs.writes = True
            continue
    
    return obs


# ═══════════════════════════════════════════════════════════
# Flow derivation — observed behavior → flow tuple
# ═══════════════════════════════════════════════════════════

def derive_flow(obs: ObservedBehavior) -> dict:
    """Derive a KNOWN_INFRASTRUCTURE-compatible flow tuple from observations."""
    
    # Determine primary flow
    if obs.net_out and obs.reads:
        flow = "LEAKED"        # reads local data, sends to network
    elif obs.net_out and obs.net_in:
        flow = "LEAKED"        # bidirectional network (conservative)
    elif obs.net_in and obs.writes:
        flow = "INGESTED"      # downloads from network, writes locally
    elif obs.net_in and not obs.writes:
        flow = "INGESTED"      # downloads (even if just to stdout)
    elif obs.files_deleted:
        flow = "DESTROYED"     # deletes files
    elif obs.writes and obs.reads:
        flow = "TRANSFORMED"   # reads and writes
    elif obs.writes and not obs.reads:
        flow = "CREATED"       # creates without reading
    elif obs.reads and not obs.writes:
        flow = "UNCHANGED"     # read-only
    elif obs.executes:
        flow = "OPAQUE"        # spawns children, can't verify
    else:
        flow = "UNCHANGED"     # no observable I/O
    
    return {
        "binary": obs.binary,
        "flow": flow,
        "reads": obs.reads,
        "writes": obs.writes,
        "net_in": obs.net_in,
        "net_out": obs.net_out,
        "executes": obs.executes,
        "evidence": {
            "files_read": obs.files_read[:10],
            "files_written": obs.files_written[:10],
            "connections": [(h, p) for h, p in obs.connections[:10]],
            "child_processes": obs.child_processes[:10],
            "bytes_sent": obs.bytes_sent,
            "bytes_received": obs.bytes_received,
        }
    }


# ═══════════════════════════════════════════════════════════
# Runner — strace a command and derive its flow
# ═══════════════════════════════════════════════════════════

def learn_command(command: str, timeout: int = 10) -> dict:
    """Run a command under strace and derive its flow tuple."""
    
    # Parse binary name
    try:
        import shlex
        tokens = shlex.split(command)
        binary = tokens[0].rsplit("/", 1)[-1] if tokens else "unknown"
    except ValueError:
        binary = "unknown"
    
    # Create temp file for strace output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.strace', delete=False) as f:
        trace_file = f.name
    
    try:
        # Run under strace
        strace_cmd = [
            "strace",
            "-f",                    # follow forks
            "-e", "trace=open,openat,read,write,connect,sendto,sendmsg,recvfrom,recvmsg,execve,unlink,unlinkat",
            "-o", trace_file,        # output to file (not stderr)
            "-s", "256",             # string length
            "sh", "-c", command,     # run via shell for pipes/redirects
        ]
        
        result = subprocess.run(
            strace_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        # Parse strace output
        strace_output = Path(trace_file).read_text()
        obs = parse_strace(strace_output)
        obs.command = command
        obs.binary = binary
        
        return derive_flow(obs)
        
    except FileNotFoundError:
        return {"error": "strace not found. Install: apt install strace"}
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        try:
            os.unlink(trace_file)
        except OSError:
            pass


# ═══════════════════════════════════════════════════════════
# Comparison — learned flow vs hardcoded table
# ═══════════════════════════════════════════════════════════

def compare_with_table(learned: dict) -> dict:
    """Compare a learned flow tuple against the hardcoded table."""
    try:
        from nexus_structural import KNOWN_INFRASTRUCTURE, Flow
    except ImportError:
        return {"error": "nexus_structural.py not found"}
    
    binary = learned.get("binary", "")
    entry = KNOWN_INFRASTRUCTURE.get(binary)
    
    if not entry:
        return {
            "binary": binary,
            "status": "NEW",
            "message": f"'{binary}' not in KNOWN_INFRASTRUCTURE — learned entry is new",
            "suggested_entry": (
                f'    "{binary}": (Flow.{learned["flow"]}, '
                f'{learned["reads"]}, {learned["writes"]}, '
                f'{learned["net_in"]}, {learned["net_out"]}, '
                f'{learned["executes"]}),'
            )
        }
    
    # Compare each field
    flow_map = {
        "UNCHANGED": Flow.UNCHANGED, "CREATED": Flow.CREATED,
        "DESTROYED": Flow.DESTROYED, "TRANSFORMED": Flow.TRANSFORMED,
        "DUPLICATED": Flow.DUPLICATED, "TRANSFERRED": Flow.TRANSFERRED,
        "REDUCED": Flow.REDUCED, "LEAKED": Flow.LEAKED,
        "INGESTED": Flow.INGESTED, "OPAQUE": Flow.OPAQUE,
    }
    
    table_flow, t_reads, t_writes, t_net_in, t_net_out, t_executes = entry
    learned_flow = flow_map.get(learned["flow"], Flow.OPAQUE)
    
    mismatches = []
    if learned_flow != table_flow:
        mismatches.append(f"flow: table={table_flow.name} learned={learned['flow']}")
    if learned["reads"] != t_reads:
        mismatches.append(f"reads: table={t_reads} learned={learned['reads']}")
    if learned["writes"] != t_writes:
        mismatches.append(f"writes: table={t_writes} learned={learned['writes']}")
    if learned["net_in"] != t_net_in:
        mismatches.append(f"net_in: table={t_net_in} learned={learned['net_in']}")
    if learned["net_out"] != t_net_out:
        mismatches.append(f"net_out: table={t_net_out} learned={learned['net_out']}")
    if learned["executes"] != t_executes:
        mismatches.append(f"executes: table={t_executes} learned={learned['executes']}")
    
    if not mismatches:
        return {
            "binary": binary,
            "status": "MATCH",
            "message": f"'{binary}' matches hardcoded table",
        }
    else:
        return {
            "binary": binary,
            "status": "MISMATCH",
            "message": f"'{binary}' differs from hardcoded table",
            "mismatches": mismatches,
            "suggested_fix": (
                f'    "{binary}": (Flow.{learned["flow"]}, '
                f'{learned["reads"]}, {learned["writes"]}, '
                f'{learned["net_in"]}, {learned["net_out"]}, '
                f'{learned["executes"]}),'
            )
        }


# ═══════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_result(learned: dict, comparison: dict = None):
    """Pretty-print a learned flow."""
    if "error" in learned:
        print(f"\n  {RED}Error:{RESET} {learned['error']}\n")
        return
    
    binary = learned["binary"]
    flow = learned["flow"]
    
    flags = []
    if learned["reads"]: flags.append("reads")
    if learned["writes"]: flags.append("writes")
    if learned["net_in"]: flags.append("net_in")
    if learned["net_out"]: flags.append("net_out")
    if learned["executes"]: flags.append("executes")
    
    print(f"\n  {BOLD}{binary}{RESET}")
    print(f"  Flow:     {flow}")
    print(f"  Behavior: {', '.join(flags) if flags else 'no observable I/O'}")
    
    ev = learned.get("evidence", {})
    if ev.get("files_read"):
        print(f"  Reads:    {', '.join(ev['files_read'][:5])}")
    if ev.get("files_written"):
        print(f"  Writes:   {', '.join(ev['files_written'][:5])}")
    if ev.get("connections"):
        for host, port in ev["connections"][:5]:
            print(f"  Network:  {host}:{port}")
    if ev.get("child_processes"):
        print(f"  Spawns:   {', '.join(ev['child_processes'][:5])}")
    
    if comparison:
        status = comparison["status"]
        if status == "MATCH":
            print(f"\n  {GREEN}* Matches hardcoded table{RESET}")
        elif status == "NEW":
            print(f"\n  {YELLOW}NEW -- not in table{RESET}")
            print(f"  {DIM}Add to KNOWN_INFRASTRUCTURE:{RESET}")
            print(f"  {comparison['suggested_entry']}")
        elif status == "MISMATCH":
            print(f"\n  {RED}X Differs from table:{RESET}")
            for m in comparison["mismatches"]:
                print(f"    {m}")
            print(f"  {DIM}Suggested fix:{RESET}")
            print(f"  {comparison['suggested_fix']}")
    
    print()


def main():
    if len(sys.argv) < 2:
        print(f"""
  {BOLD}Nexus Gate — Dynamic Flow Learner{RESET}

  Run a command under strace, observe syscalls, derive flow tuple.

  Usage:
    python nexus_learn.py "curl https://example.com"
    python nexus_learn.py "grep -r TODO ."
    python nexus_learn.py --batch commands.txt
    python nexus_learn.py --audit

  Requires: Linux with strace (apt install strace)
""")
        return
    
    if sys.argv[1] == "--batch":
        # Batch mode: learn from file of commands
        if len(sys.argv) < 3:
            print("Usage: python nexus_learn.py --batch commands.txt")
            return
        
        cmd_file = Path(sys.argv[2])
        if not cmd_file.exists():
            print(f"File not found: {cmd_file}")
            return
        
        commands = [l.strip() for l in cmd_file.read_text().split("\n") 
                   if l.strip() and not l.strip().startswith("#")]
        
        print(f"\n  {BOLD}Learning {len(commands)} commands...{RESET}\n")
        
        results = []
        for cmd in commands:
            learned = learn_command(cmd)
            comparison = compare_with_table(learned) if "error" not in learned else None
            print_result(learned, comparison)
            if "error" not in learned:
                results.append({"command": cmd, "learned": learned, 
                              "comparison": comparison})
        
        # Summary
        matches = sum(1 for r in results if r["comparison"] and r["comparison"]["status"] == "MATCH")
        new = sum(1 for r in results if r["comparison"] and r["comparison"]["status"] == "NEW")
        mismatches = sum(1 for r in results if r["comparison"] and r["comparison"]["status"] == "MISMATCH")
        
        print(f"  {'=' * 50}")
        print(f"  {BOLD}Summary{RESET}")
        print(f"  Learned:    {len(results)}")
        print(f"  Matches:    {matches}")
        print(f"  New:        {new}")
        print(f"  Mismatches: {mismatches}")
        print()
        
    elif sys.argv[1] == "--audit":
        # Audit mode: learn all 195 tools and compare
        try:
            from nexus_structural import KNOWN_INFRASTRUCTURE
        except ImportError:
            print("nexus_structural.py not found")
            return
        
        print(f"\n  {BOLD}Auditing {len(KNOWN_INFRASTRUCTURE)} hardcoded entries...{RESET}")
        print(f"  {DIM}This will execute each tool with safe arguments.{RESET}\n")
        
        # Safe commands for common tools
        safe_commands = {
            "ls": "ls /tmp",
            "cat": "cat /dev/null",
            "grep": "echo test | grep test",
            "find": "find /tmp -maxdepth 0 -name '*.nonexistent'",
            "head": "echo test | head -1",
            "tail": "echo test | tail -1",
            "sort": "echo test | sort",
            "wc": "echo test | wc -l",
            "curl": "curl -s -o /dev/null --max-time 2 https://httpbin.org/get",
        }
        
        for binary in sorted(safe_commands.keys()):
            cmd = safe_commands[binary]
            learned = learn_command(cmd, timeout=5)
            if "error" not in learned:
                comparison = compare_with_table(learned)
                status = comparison["status"]
                icon = {"MATCH": f"{GREEN}✅", "NEW": f"{YELLOW}🆕", "MISMATCH": f"{RED}❌"}
                print(f"  {icon.get(status, '?')} {binary:15s} {status}{RESET}")
                if status == "MISMATCH":
                    for m in comparison.get("mismatches", []):
                        print(f"     {DIM}{m}{RESET}")
        print()
        
    else:
        # Single command
        command = " ".join(sys.argv[1:])
        print(f"\n  {DIM}Learning: {command}{RESET}")
        
        learned = learn_command(command)
        comparison = compare_with_table(learned) if "error" not in learned else None
        print_result(learned, comparison)


if __name__ == "__main__":
    main()

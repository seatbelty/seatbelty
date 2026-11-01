#!/usr/bin/env python3
"""
Seatbelty Pre-Tool Interceptor Hook
Catches and denies destructive commands and sensitive file inspections before execution.
"""
import json
import os
import re
import sys
from datetime import datetime

BLOCKED_COMMAND_PATTERNS = [
    # Destructive filesystem operations
    (r"\brm\s+-(?:r|f|rf|fr)\s+[/~]", "Root or home directory recursive deletion"),
    (r"\bchmod\s+-R\s+777\b", "Unsafe recursive full permissions modification"),
    (r"\bmkfs\b", "Direct filesystem format utility"),
    # Destructive Git operations
    (r"\bgit\s+push\b.*(?:--force|-f)\b.*(?:main|master)", "Force push to protected branch"),
    (r"\bgit\s+checkout\b.*-B\s+(?:main|master)", "Overwriting primary branch"),
    (r"\bgit\s+reset\s+--hard\b", "Hard git state reset without backup"),
    (r"\bgit\s+branch\s+-(?:D|d)\s+(?:main|master)", "Deletion of primary repository branch"),
    # Privilege escalation & unauthorized network listeners
    (r"\bsudo\b", "Root privilege escalation"),
    (r"\b(?:ngrok|cloudflared|socat)\b", "Unauthorized network tunnel or reverse listener"),
    # Destructive database operations
    (r"\bDROP\s+TABLE\b", "Destructive SQL table drop"),
    (r"\bTRUNCATE\b", "Table truncation"),
    (r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", "Unbounded DELETE statement without WHERE clause"),
]

BLOCKED_FILE_PATTERNS = [
    r"(^|/)\.env(\.[a-zA-Z0-9_\-]+)?$",
    r"(^|/)id_(?:rsa|ed25519)$",
    r".*\.pem$",
    r".*\.key$",
    r".*credentials\.json$",
]

def log_event(action: str, target: str, reason: str, status: str):
    try:
        log_dir = os.path.expanduser("~/.seatbelty")
        os.makedirs(log_dir, exist_ok=True)
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": action,
            "target": target,
            "reason": reason,
            "status": status,
        }
        with open(os.path.join(log_dir, "audit.log"), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Never crash the hook on audit logging failure

def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            print(json.dumps({"decision": "allow"}))
            return

        payload = json.loads(raw_input)
        tool_name = payload.get("toolName", "")
        args = payload.get("args", {})

        # 1. Guard Command Line Executions
        if tool_name == "run_command":
            cmd = args.get("CommandLine", "")
            for pattern, reason in BLOCKED_COMMAND_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    log_event("run_command", cmd, reason, "DENIED")
                    banner = (
                        f"🛑 [SEATBELTY BLOCKED] Command execution halted.\n"
                        f"Target: {cmd}\n"
                        f"Reason: {reason}.\n"
                        f"Action Required: Manual developer review or explicit bypass confirmation."
                    )
                    print(json.dumps({"decision": "deny", "reason": banner}))
                    return

        # 2. Guard Direct File Reading
        if tool_name == "view_file":
            filepath = args.get("AbsolutePath", "")
            for pattern in BLOCKED_FILE_PATTERNS:
                if re.search(pattern, filepath, re.IGNORECASE):
                    log_event("view_file", filepath, "Attempted read of protected credential file", "DENIED")
                    banner = (
                        f"🛑 [SEATBELTY BLOCKED] Access to protected file denied.\n"
                        f"Target: {filepath}\n"
                        f"Reason: Direct reading of sensitive credential stores is restricted."
                    )
                    print(json.dumps({"decision": "deny", "reason": banner}))
                    return

        # Default allowed
        print(json.dumps({"decision": "allow"}))
    except Exception as exc:
        sys.stderr.write(f"Seatbelty pre-tool hook error: {exc}\n")
        print(json.dumps({"decision": "allow"}))

if __name__ == "__main__":
    main()

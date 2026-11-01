#!/usr/bin/env python3
"""
Seatbelty Post-Tool Redaction Hook
Scans tool output streams and redacts API tokens, private keys, and customer PII before context ingestion.
"""
import json
import re
import sys

REDACTION_PATTERNS = [
    # AWS Access Keys
    (r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]"),
    # Generic high-entropy secret assignments
    (r'''(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['"][A-Za-z0-9_\-\.]{16,}['"]''', r"\1: '[REDACTED_SECRET]'"),
    # JSON Web Tokens (JWT)
    (r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b", "[REDACTED_JWT_TOKEN]"),
    # Stripe Secret & Restricted Keys
    (r"\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b", "[REDACTED_STRIPE_KEY]"),
    (r"\brk_(?:live|test)_[0-9a-zA-Z]{24,}\b", "[REDACTED_STRIPE_KEY]"),
    # GitHub Personal Access & Fine-grained Tokens
    (r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b", "[REDACTED_GITHUB_TOKEN]"),
    (r"\bgithub_pat_[A-Za-z0-9_]{82}\b", "[REDACTED_GITHUB_TOKEN]"),
    # Google Cloud / Gemini API Keys
    (r"\bAIza[0-9A-Za-z-_]{35}\b", "[REDACTED_GOOGLE_API_KEY]"),
    # OpenAI project and user keys
    (r"\bsk-(?:proj-)?[A-Za-z0-9_-]{48,}\b", "[REDACTED_OPENAI_KEY]"),
    # Customer Emails
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[REDACTED_EMAIL]"),
]

def mask_text(text: str) -> str:
    modified = text
    for pattern, replacement in REDACTION_PATTERNS:
        modified = re.sub(pattern, replacement, modified)
    return modified

def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            return

        payload = json.loads(raw_input)
        output = payload.get("output", "")

        if isinstance(output, str) and output:
            cleaned = mask_text(output)
            print(json.dumps({"output": cleaned}))
        else:
            print(raw_input)
    except Exception:
        sys.exit(0)

if __name__ == "__main__":
    main()

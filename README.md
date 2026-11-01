# Seatbelty 🛡️

**Deterministic runtime guardrails, secret redaction, and PII masking for Google Antigravity autonomous agents.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Validation](https://img.shields.io/badge/Antigravity-Validated-success.svg)](plugin.json)

---

## What Seatbelty Does

Autonomous agents in modern IDEs operate with shell and tool execution privileges. Seatbelty provides a deterministic security boundary:

1. **PreToolUse Execution Tripwire:** Intercepts commands before execution to block dangerous patterns (e.g. `rm -rf /`, `git push --force origin main`, `sudo`, destructive database drops, and `.env` inspections).
2. **PostToolUse Zero-Leak Scrubber:** Masks sensitive credentials (AWS keys, Stripe secrets, GitHub tokens, JWTs, and customer emails) before terminal output enters LLM context.
3. **Repository Guardrails (`rules/AGENTS.md`):** Keeps agents aligned on branch hygiene and safe dependency management.
4. **Interactive Audit Skill (`/seatbelty-audit`):** Inspects session activity and git tree status on demand.

---

## Directory Structure

```text
seatbelty/
├── LICENSE                    # Apache 2.0 Open Source License
├── README.md                  # Documentation and usage guide
├── plugin.json                # Antigravity Marketplace plugin manifest
├── hooks.json                 # PreToolUse & PostToolUse lifecycle registrations
├── marketplace-manifest.json  # Catalog submission descriptor
├── rules/
│   └── AGENTS.md              # In-context agent guidelines
├── skills/
│   └── audit/
│       └── SKILL.md           # /seatbelty-audit command handler
├── scripts/
│   ├── pre_tool_guard.py      # Pre-execution command and file interceptor
│   └── post_tool_mask.py      # Output PII and secret redaction engine
└── tests/
    └── test_seatbelty.py      # Automated test and validation suite
```

---

## Installation

### From Marketplace
```bash
agy plugin install seatbelty
```

### Local / Development Mode
Clone or extract into your project's `.agents/plugins/` directory:
```bash
mkdir -p .agents/plugins/seatbelty
cp -r * .agents/plugins/seatbelty/
```

---

## Verification & Testing

Run the automated test suite to confirm all guardrails:
```bash
python3 tests/test_seatbelty.py
```

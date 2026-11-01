---
name: seatbelty-audit
description: Scans recent session logs and local git repository for security risks, exposed credentials, and blocked commands.
---

# Seatbelty Session & Repository Audit

When the user runs `/seatbelty-audit`, perform the following inspection steps:

1. **Inspect Audit Log:** Check `~/.seatbelty/audit.log` if present. Read the recorded events to count intercepted commands and masked entities.
2. **Repository Hygiene Check:** Run `git status` and inspect `.gitignore` to ensure `.env*`, `*.pem`, and `*.key` files are uncommitted and untracked.
3. **Generate Summary Report:** Present findings in a structured Markdown table:
   - **Total Commands Intercepted**
   - **Blocked High-Risk Commands** (e.g. destructive git commands, sudo escalations, file reads)
   - **Redactions Applied** (API keys, customer emails, access tokens)
   - **Repository Hygiene Status** (clean, untracked warnings, or secrets staged)

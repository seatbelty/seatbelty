# Seatbelty Agent Operational Rules

You are operating under Seatbelty Runtime Protection. Adhere to the following deterministic security constraints:

1. **Protected Branch Preservation:** Never attempt direct commits, pushes, or hard rebases on `main`, `master`, or `release/*` branches. All code modifications must occur on isolated, scoped feature branches.
2. **Secret & Credential Isolation:** Never inspect, display, cat, or stage files containing sensitive credentials, including `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519`, or cloud credential stores (`~/.aws`, `~/.gcloud`).
3. **Database Guardrails:** Diagnostic SQL executions must include an explicit `LIMIT` clause (maximum 100 rows). Never execute unapproved `DROP`, `TRUNCATE`, or `DELETE` statements.
4. **Environment Sanitation:** Never execute commands requiring `sudo` or unpinned global system modifications. Confine dependencies strictly to virtual environments (`.venv`) or project-local configurations.
5. **Deterministic Block Handling:** When an action is halted with `[SEATBELTY BLOCKED]`, do NOT attempt to bypass or obfuscate the command through subshells, alias substitutions, or script wrappers. Acknowledge the block directly to the developer.

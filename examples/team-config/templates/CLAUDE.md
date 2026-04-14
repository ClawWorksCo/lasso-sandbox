# Claude Code — LASSO Security Guardrails

You are operating inside a LASSO sandboxed environment. All commands you execute are validated by the LASSO command gate before execution and logged to a tamper-evident audit trail.

## Rules

1. Only run commands from the sandbox whitelist (python3, git, pip, npm, ls, cat, grep, etc.)
2. Do NOT attempt to run docker, podman, curl, wget, nc, or ncat
3. Do NOT modify files outside /workspace
4. Do NOT use git push --force, git remote add, or git remote set-url
5. Do NOT install packages globally (pip install --user is blocked)
6. Do NOT access cloud metadata endpoints
7. Do NOT print secret environment variable values to stdout
8. If a command is blocked, explain what you were trying to do and suggest an alternative

## Context

- All commands are HMAC-signed and hash-chained in the audit log
- Network access is restricted to allowed domains only
- The sandbox drops all Linux capabilities and runs as a non-root user
- File system access is limited to the workspace mount

# Agent Instructions — LASSO Secured Environment

You are operating inside a LASSO sandbox. The following constraints are enforced:

## Filesystem
- You may only read and write files within your designated working directory.
- System paths are read-only. You cannot modify system files.
- Certain sensitive paths are hidden and not accessible.

## Commands
- Only whitelisted commands are available. Attempting to run unlisted commands will be blocked and logged.
- Shell operators (pipes, redirects, subshells) may be restricted depending on profile.
- All command executions are logged with timestamps in the audit trail.

## Network
- Network access may be restricted or completely disabled.
- If restricted, only approved domains and ports are reachable.
- All network connection attempts are logged.

## Data Handling
- Do not attempt to exfiltrate data outside the sandbox.
- Do not include personally identifiable information (PII) in your outputs.
- Risk model parameters and proprietary data must not appear in logs or external communications.

## Compliance
- This sandbox is configured for regulatory compliance (DORA, GDPR).
- All your actions are recorded in a tamper-evident audit log.
- Violations of these rules will be blocked and reported.

# Workflow: Human Starts LASSO (Team-Strict Mode)

This workflow is for teams where AI agents **cannot and should not run Docker** directly. A human administrator creates the sandbox, and the agent operates inside it without ever invoking container commands.

## When to Use This Workflow

- Corporate policy prohibits AI agents from having Docker/Podman access
- The agent's host environment does not have a container runtime installed
- You want an admin to control sandbox lifecycle (creation, teardown, policy) while agents only execute work inside the sandbox
- CI/CD pipelines where the pipeline creates the sandbox and the agent runs inside it

---

## Workflow Overview

```
                    HUMAN (admin)                         AGENT
                    ─────────────                         ─────
                         │
           1. lasso create team-strict --dir .
                         │
                         ├── Container created
                         ├── Audit logging starts
                         ├── Command gate active
                         │
                         │
           ┌─────────────┼─────────────────────────────────┐
           │             │                                  │
           │  Option A:         Option B:     │
           │  lasso shell agent  lasso exec    │
           │                                  │
           └──────────┬──────────────┬────────┘
                      │              │
                      ▼              ▼
               Agent launched     Agent uses
               INSIDE sandbox     sandbox via
               (never sees        CLI commands
                Docker)            passed by
                                  human/CI
                         │
           ──────────────┼─────────────────────────────────
                         │
           N. lasso stop <id>
                         │
                    Sandbox destroyed
                    Audit log preserved
```

---

## Option A: Launch Agent Inside Sandbox with `lasso shell`

The human uses `lasso shell` to create a sandbox and get a terminal inside it. The agent process runs inside the sandbox from the start.

### Step 1: Human Launches Agent Inside Sandbox

```bash
# Launch Claude Code inside a LASSO sandbox
lasso shell --agent claude-code --dir /path/to/project

# Launch OpenCode inside a LASSO sandbox
lasso shell --agent opencode --dir /path/to/project
```

`lasso shell` performs:
1. Selects an appropriate profile based on the agent type
2. Creates the sandbox (container) with the profile's security policy
3. Injects agent-specific guardrails (e.g., `CLAUDE.md` for Claude Code)
4. Drops the human into a terminal inside the container

The agent never needs to know it is running in a sandbox. It cannot invoke Docker because:
- Docker is not installed inside the container
- The Docker socket is not mounted
- The command gate would block `docker` commands even if they were available

### Step 2: Agent Works Normally

The agent writes code, runs tests, and executes commands as usual. All commands are gated and audited.

### Step 3: Human Reviews and Stops

```bash
# Check what the agent has been doing
lasso audit view /path/to/audit/log.jsonl

# Stop the sandbox
lasso stop <sandbox-id>
```

---

## Option B: Human Mediates All Execution

For maximum control, the human runs `lasso exec` on behalf of the agent.

### Step 1: Human Creates Sandbox

```bash
lasso create strict --dir /path/to/project
```

### Step 2: Human Executes Agent's Requested Commands

```bash
# Agent requests: "run the tests"
lasso exec <sandbox-id> -- python3 -m pytest tests/ -q

# Agent requests: "install dependencies"
lasso exec <sandbox-id> -- pip install -r requirements.txt

# Agent requests: "check the build"
lasso exec <sandbox-id> -- make build
```

Each command is validated by the command gate before execution. The human reviews the agent's request, runs it through LASSO, and relays the output back to the agent.

---

## CI Pipeline Alternative

In CI/CD, the pipeline itself acts as the "human" -- it creates the sandbox, runs the agent inside it, and tears it down.

### GitHub Actions Example

```yaml
jobs:
  agent-sandbox:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install LASSO
        run: pip install lasso-sandbox

      - name: Create sandbox
        run: |
          lasso create strict --dir . --json > sandbox.json
          echo "SANDBOX_ID=$(jq -r .sandbox_id sandbox.json)" >> $GITHUB_ENV

      - name: Run agent inside sandbox
        run: lasso shell --agent opencode --dir .

      - name: Verify audit trail
        run: lasso audit verify ./audit/*.jsonl

      - name: Upload audit logs
        uses: actions/upload-artifact@v4
        with:
          name: audit-trail
          path: ./audit/

      - name: Teardown
        if: always()
        run: lasso stop ${{ env.SANDBOX_ID }}
```

### GitLab CI Example

```yaml
agent-sandbox:
  image: docker:latest
  services:
    - docker:dind
  script:
    - pip install lasso-sandbox
    - lasso create strict --dir . --json > sandbox.json
    - export SANDBOX_ID=$(jq -r .sandbox_id sandbox.json)
    - lasso shell --agent opencode --dir .
    - lasso audit verify ./audit/*.jsonl
  after_script:
    - lasso stop all
  artifacts:
    paths:
      - audit/
```

---

## Key Principles

1. **The agent never touches Docker.** The container runtime is the admin's responsibility. The agent only sees the sandboxed filesystem and the gated command interface.

2. **All agent actions are audited.** Every command, file access, and network attempt is logged with HMAC-signed entries. The admin can review the audit trail at any time.

3. **The profile defines the policy.** The admin chooses the security profile (whitelisted commands, network rules, filesystem mounts). The agent operates within those constraints.

4. **Sandbox lifecycle is human-controlled.** Only the admin (or CI pipeline) creates and destroys sandboxes. The agent cannot escalate its own privileges or modify the sandbox configuration.

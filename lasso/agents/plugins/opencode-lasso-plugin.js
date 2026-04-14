/**
 * LASSO Plugin for OpenCode
 *
 * Integrates LASSO's security controls directly into OpenCode's execution pipeline.
 * This is part of LASSO's defense-in-depth strategy — the plugin enforces command
 * gating at the agent level (Layer 2), complementing container isolation (Layer 1),
 * the LASSO command gate (Layer 3), and tamper-evident audit logging (Layer 4).
 *
 * This plugin hooks into tool.execute.before and tool.execute.after to:
 *
 * 1. Validate commands against the LASSO command whitelist/blacklist
 * 2. Block path traversal and shell operator abuse
 * 3. Log every action to LASSO's audit trail (JSONL)
 * 4. Enforce network restrictions
 * 5. Track violations
 *
 * Integration with LASSO:
 *   - Generated automatically by `lasso init --agent opencode`
 *   - Config files are placed by OpenCodeProvider.generate_config()
 *   - Environment variables are set by the LASSO sandbox orchestrator
 *   - Audit entries chain with the main LASSO audit log for tamper detection
 *
 * Install: Place in .opencode/plugins/ or reference in opencode.json:
 *   { "plugin": [".opencode/plugins/opencode-lasso-plugin.js"] }
 *
 * Reads configuration from environment variables:
 *   LASSO_SANDBOX=true
 *   LASSO_PROFILE=<profile-name>
 *   LASSO_AUDIT_DIR=<path-to-audit-dir>
 *   LASSO_COMMAND_MODE=whitelist|blacklist
 *   LASSO_WHITELIST=cmd1,cmd2,cmd3
 *   LASSO_BLACKLIST=cmd1,cmd2,cmd3
 *   LASSO_BLOCKED_ARGS={"git":["push --force","push -f"]}
 *   LASSO_NETWORK_MODE=none|restricted|full
 */

const { appendFileSync, mkdirSync, existsSync } = require("fs");
const { join } = require("path");

// -----------------------------------------------------------------------
// Configuration from environment
// -----------------------------------------------------------------------

const SANDBOX_ACTIVE = process.env.LASSO_SANDBOX === "true";
const PROFILE_NAME = process.env.LASSO_PROFILE || "unknown";
const AUDIT_DIR = process.env.LASSO_AUDIT_DIR || ".lasso/audit";
const COMMAND_MODE = process.env.LASSO_COMMAND_MODE || "whitelist";
const NETWORK_MODE = process.env.LASSO_NETWORK_MODE || "none";

const WHITELIST = new Set(
  (process.env.LASSO_WHITELIST || "").split(",").filter(Boolean)
);
const BLACKLIST = new Set(
  (process.env.LASSO_BLACKLIST || "").split(",").filter(Boolean)
);

// Parse blocked args from JSON: {"git": ["push --force", "push -f"]} → { git: ["push --force", "push -f"] }
let BLOCKED_ARGS = {};
if (process.env.LASSO_BLOCKED_ARGS) {
  try {
    BLOCKED_ARGS = JSON.parse(process.env.LASSO_BLOCKED_ARGS);
  } catch (e) {
    // If JSON parsing fails, log a warning but don't crash the plugin
    console.error("[LASSO] Failed to parse LASSO_BLOCKED_ARGS as JSON:", e.message);
  }
}

// Shell operator pattern — only match actual shell operators, not variable
// references ($VAR, ${VAR}) or find-exec placeholders ({}).
// Blocks: $( ` | && || ; >> <<
// Allows: $VARIABLE, ${VAR}, {} (find -exec placeholder)
const SHELL_OPERATORS = /\$\(|`|\|{1,2}|&&|;|>>|<</;
// Path traversal — catch ../ and ..\ and URL-encoded variants (%2e%2e)
const PATH_TRAVERSAL = /\.\.[\\/]|%2e%2e/i;

// Audit state
let auditSeq = 0;
const auditFile = join(
  AUDIT_DIR,
  `lasso-plugin-${Date.now()}.jsonl`
);

// -----------------------------------------------------------------------
// Audit logging
// -----------------------------------------------------------------------

function ensureAuditDir() {
  if (!existsSync(AUDIT_DIR)) {
    mkdirSync(AUDIT_DIR, { recursive: true });
  }
}

function auditLog(event) {
  if (!SANDBOX_ACTIVE) return;

  ensureAuditDir();
  auditSeq++;

  const entry = {
    seq: auditSeq,
    ts: new Date().toISOString(),
    profile: PROFILE_NAME,
    source: "opencode-plugin",
    ...event,
  };

  const line = JSON.stringify(entry);
  appendFileSync(auditFile, line + "\n");
}

// -----------------------------------------------------------------------
// Command validation
// -----------------------------------------------------------------------

function validateCommand(input) {
  if (!input || typeof input !== "string") {
    return { allowed: true, reason: "" };
  }

  const trimmed = input.trim();

  // Check shell operators
  if (SHELL_OPERATORS.test(trimmed)) {
    return {
      allowed: false,
      reason: "Shell operators (pipes, redirects, subshells) are blocked by LASSO.",
    };
  }

  // Parse command name
  const parts = trimmed.split(/\s+/);
  const cmdName = parts[0].split("/").pop(); // strip path prefix
  const args = parts.slice(1).join(" ");

  // Whitelist/blacklist check
  if (COMMAND_MODE === "whitelist") {
    if (!WHITELIST.has(cmdName)) {
      return {
        allowed: false,
        reason: `Command '${cmdName}' is not in the LASSO whitelist.`,
      };
    }
  } else if (COMMAND_MODE === "blacklist") {
    if (BLACKLIST.has(cmdName)) {
      return {
        allowed: false,
        reason: `Command '${cmdName}' is in the LASSO blacklist.`,
      };
    }
  }

  // Blocked argument patterns
  if (BLOCKED_ARGS[cmdName]) {
    for (const pattern of BLOCKED_ARGS[cmdName]) {
      if (args.includes(pattern)) {
        return {
          allowed: false,
          reason: `Blocked argument pattern for '${cmdName}': '${pattern}'`,
        };
      }
    }
  }

  // Path traversal
  for (const arg of parts) {
    if (PATH_TRAVERSAL.test(arg)) {
      return {
        allowed: false,
        reason: `Path traversal detected in argument: '${arg}'`,
      };
    }
  }

  return { allowed: true, reason: "" };
}

// -----------------------------------------------------------------------
// Network validation
// -----------------------------------------------------------------------

function validateNetworkAccess(url) {
  if (NETWORK_MODE === "none") {
    return {
      allowed: false,
      reason: "Network access is disabled by LASSO (mode: none).",
    };
  }
  return { allowed: true, reason: "" };
}

// -----------------------------------------------------------------------
// Plugin hooks
// -----------------------------------------------------------------------

module.exports = {
  name: "lasso-security",
  version: "0.1.0",

  setup(sdk) {
    if (!SANDBOX_ACTIVE) {
      return; // plugin is a no-op outside LASSO sandbox
    }

    auditLog({
      type: "lifecycle",
      action: "plugin_loaded",
      detail: {
        profile: PROFILE_NAME,
        command_mode: COMMAND_MODE,
        network_mode: NETWORK_MODE,
        whitelist_count: WHITELIST.size,
      },
    });

    // Hook into tool execution BEFORE it runs
    sdk.on("tool.execute.before", (event) => {
      const { tool, input } = event;

      // Validate bash commands
      if (tool === "bash" && input?.command) {
        const verdict = validateCommand(input.command);

        auditLog({
          type: "command",
          action: input.command,
          tool: "bash",
          outcome: verdict.allowed ? "allowed" : "blocked",
          reason: verdict.reason,
        });

        if (!verdict.allowed) {
          return {
            abort: true,
            message: `[LASSO] BLOCKED: ${verdict.reason}`,
          };
        }
      }

      // Validate web access
      if ((tool === "webfetch" || tool === "websearch") && NETWORK_MODE === "none") {
        const verdict = validateNetworkAccess(input?.url || "");

        auditLog({
          type: "network",
          action: tool,
          tool,
          outcome: "blocked",
          reason: verdict.reason,
        });

        return {
          abort: true,
          message: `[LASSO] BLOCKED: ${verdict.reason}`,
        };
      }

      // Log all other tool invocations
      auditLog({
        type: "tool",
        action: tool,
        outcome: "allowed",
      });
    });

    // Hook into tool execution AFTER it runs
    sdk.on("tool.execute.after", (event) => {
      const { tool, input, output, error } = event;

      auditLog({
        type: "tool_complete",
        action: tool,
        outcome: error ? "error" : "success",
        exit_code: output?.exitCode,
      });
    });

    // Log file modifications
    sdk.on("file.write", (event) => {
      auditLog({
        type: "file",
        action: "write",
        target: event.path,
        outcome: "success",
      });
    });

    sdk.on("file.edit", (event) => {
      auditLog({
        type: "file",
        action: "edit",
        target: event.path,
        outcome: "success",
      });
    });
  },
};

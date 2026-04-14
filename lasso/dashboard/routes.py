"""LASSO Dashboard — all route handlers on the dashboard blueprint."""

from __future__ import annotations

import json
import logging
import os
import platform
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from lasso import __version__
from lasso.config.defaults import BUILTIN_PROFILES
from lasso.config.profile import delete_profile, load_profile, save_profile
from lasso.config.schema import FilesystemConfig, SandboxProfile
from lasso.dashboard.auth import require_login
from lasso.dashboard.helpers import (
    AGENT_COMMANDS,
    _build_profile,
    _default_sandbox_dir,
    _enrich_sandbox,
    _get_all_profiles,
    _get_registry,
    _parse_profile_form,
    _state_color,
    _system_capabilities,
    _validate_working_dir,
    read_audit_log,
)

# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/dashboard/static",
)


# ---------------------------------------------------------------------------
# Routes -- HTML pages
# ---------------------------------------------------------------------------


@dashboard_bp.route("/")
@require_login
def index():
    """Dashboard home: sandbox list + system stats."""
    registry = _get_registry()
    sandboxes = registry.list_all()
    profiles = _get_all_profiles()

    # Enrich each sandbox with agent and security level
    sandboxes = [_enrich_sandbox(sb, registry) for sb in sandboxes]

    stats = {
        "total": len(sandboxes),
        "running": sum(1 for s in sandboxes if s["state"] == "running"),
        "stopped": sum(1 for s in sandboxes if s["state"] == "stopped"),
        "errors": sum(1 for s in sandboxes if s["state"] == "error"),
        "total_execs": sum(s.get("exec_count", 0) for s in sandboxes),
        "total_blocked": sum(s.get("blocked_count", 0) for s in sandboxes),
    }

    return render_template(
        "index.html",
        sandboxes=sandboxes,
        profiles=profiles,
        stats=stats,
        has_sandboxes=len(sandboxes) > 0,
        state_color=_state_color,
        version=__version__,
        default_dir=_default_sandbox_dir(),
    )


@dashboard_bp.route("/sandbox/<sandbox_id>")
@require_login
def sandbox_detail(sandbox_id: str):
    """Sandbox detail page."""
    registry = _get_registry()
    sb = registry.get(sandbox_id)
    if not sb:
        abort(404, description=f"Sandbox '{sandbox_id}' not found.")

    status = sb.status()
    policy = sb.command_gate.explain_policy()

    # Read recent audit entries
    audit_entries = []
    if sb.audit.log_file and sb.audit.log_file.exists():
        audit_entries = read_audit_log(sb.audit.log_file, tail=25)

    # Extract agent info from profile extra_env
    agent = sb.profile.extra_env.get("LASSO_AGENT", "")
    agent_command = AGENT_COMMANDS.get(agent, "")

    # Parse extra mounts for display
    extra_mounts = []
    extra_mounts_json = sb.profile.extra_env.get("LASSO_EXTRA_MOUNTS", "")
    if extra_mounts_json:
        try:
            extra_mounts = json.loads(extra_mounts_json)
        except (json.JSONDecodeError, TypeError):
            pass

    return render_template(
        "sandbox.html",
        sandbox=status,
        policy=policy,
        audit_entries=audit_entries,
        state_color=_state_color,
        version=__version__,
        agent=agent,
        agent_command=agent_command,
        extra_mounts=extra_mounts,
    )


@dashboard_bp.route("/sandbox/<sandbox_id>/exec", methods=["POST"])
@require_login
def sandbox_exec(sandbox_id: str):
    """Execute a command inside a sandbox. Returns HTMX partial."""
    registry = _get_registry()
    sb = registry.get(sandbox_id)
    if not sb:
        abort(404)

    command = request.form.get("command", "").strip()
    if not command:
        return render_template("partials/exec_result.html", error="No command provided.")
    if len(command) > 4096:
        return render_template("partials/exec_result.html", error="Command too long (max 4096 chars).")

    result = sb.exec(command)

    return render_template(
        "partials/exec_result.html",
        result={
            "command": result.command,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_ms": result.duration_ms,
            "blocked": result.blocked,
            "block_reason": result.block_reason if result.blocked else "",
        },
    )


@dashboard_bp.route("/sandbox/create", methods=["POST"])
@require_login
def sandbox_create():
    """Create a new sandbox from a profile."""
    registry = _get_registry()

    profile_name = request.form.get("profile", "").strip()
    working_dir = request.form.get("working_dir", _default_sandbox_dir()).strip()
    agent = request.form.get("agent", "").strip() or None

    if not profile_name:
        flash("Please select a profile.", "error")
        return redirect(url_for("dashboard.index"))

    dir_error = _validate_working_dir(working_dir)
    if dir_error:
        flash(f"Invalid working directory: {dir_error}", "error")
        return redirect(url_for("dashboard.index"))

    # Resolve profile
    if profile_name in BUILTIN_PROFILES:
        profile = BUILTIN_PROFILES[profile_name](working_dir)
    else:
        try:
            profile = load_profile(profile_name)
        except FileNotFoundError:
            abort(400, description=f"Profile '{profile_name}' not found.")

    # Store agent choice so image_builder can install it
    if agent:
        profile.extra_env["LASSO_AGENT"] = agent

    # Parse extra mounts from form (JSON-encoded hidden input)
    mounts_json = request.form.get("mounts", "").strip()
    if mounts_json:
        try:
            extra_mounts = json.loads(mounts_json)
            # Validate structure: list of {source, target, mode}
            valid_mounts = []
            for m in extra_mounts:
                src = str(m.get("source", "")).strip()
                tgt = str(m.get("target", "")).strip()
                mode = str(m.get("mode", "rw")).strip()
                if src and tgt and mode in ("ro", "rw"):
                    # Security: reject path traversal, system dirs, docker socket
                    if ".." in src or ".." in tgt:
                        abort(400, description=f"Path traversal not allowed in mount: {src}")
                    if "docker.sock" in src:
                        abort(400, description="Docker socket mount is not allowed.")
                    # Validate against forbidden mount sources (same as converter.py)
                    from lasso.backends.converter import _validate_mount_source

                    try:
                        _validate_mount_source(src)
                    except ValueError as ve:
                        abort(400, description=str(ve))
                    valid_mounts.append({"source": src, "target": tgt, "mode": mode})
            if valid_mounts:
                profile.extra_env["LASSO_EXTRA_MOUNTS"] = json.dumps(valid_mounts)
        except (json.JSONDecodeError, TypeError, AttributeError):
            logging.getLogger("lasso.dashboard").warning("Malformed mounts JSON ignored")

    sb = registry.create(profile)
    try:
        registry.start(sb)
    except RuntimeError:
        logging.getLogger("lasso.dashboard").exception("Sandbox start failed for profile %s", profile.name)
        flash(f"Sandbox created but failed to start (profile: {profile.name}). Check container runtime.", "error")

    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/sandbox/<sandbox_id>/stop", methods=["POST"])
@require_login
def sandbox_stop(sandbox_id: str):
    """Stop a running sandbox."""
    registry = _get_registry()
    if not registry.stop(sandbox_id):
        abort(404)
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/sandbox/<sandbox_id>/remove", methods=["POST"])
@require_login
def sandbox_remove(sandbox_id: str):
    """Remove a stopped sandbox."""
    registry = _get_registry()
    if not registry.remove(sandbox_id):
        abort(404)
    flash("Sandbox removed.", "success")
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/sandbox/<sandbox_id>/terminal", methods=["POST"])
@require_login
def open_terminal(sandbox_id: str):
    """Open a terminal window connected to this sandbox."""
    import re
    import shutil
    import subprocess

    # Validate sandbox_id to prevent command injection (especially AppleScript)
    if not re.match(r'^[a-f0-9]+$', sandbox_id):
        abort(400)

    registry = _get_registry()
    sb = registry.get(sandbox_id)
    if not sb:
        abort(404)

    # Determine the command to run inside the container.
    # If an agent is configured, launch it directly; otherwise open bash.
    agent = sb.profile.extra_env.get("LASSO_AGENT", "")
    agent_command = AGENT_COMMANDS.get(agent, "")
    container_name = f"lasso-{sandbox_id}"

    if agent_command:
        terminal_cmd = f"docker exec -it -w /workspace {container_name} {agent_command}"
    else:
        terminal_cmd = f"docker exec -it -w /workspace {container_name} /bin/bash"

    try:
        if platform.system() == "Windows":
            # Open Windows Terminal or cmd.exe
            wt = shutil.which("wt")  # Windows Terminal
            if wt:
                subprocess.Popen([wt, "new-tab", "cmd", "/k", terminal_cmd])
            else:
                subprocess.Popen(["cmd", "/c", "start", "cmd", "/k", terminal_cmd])
        elif platform.system() == "Darwin":
            # macOS: open Terminal.app
            subprocess.Popen([
                "osascript", "-e",
                f'tell application "Terminal" to do script "{terminal_cmd}"',
            ])
        else:
            # Linux: try common terminal emulators
            for term in ["gnome-terminal", "konsole", "xfce4-terminal", "xterm"]:
                term_path = shutil.which(term)
                if term_path:
                    if term == "gnome-terminal":
                        subprocess.Popen([term_path, "--", "bash", "-c", f"{terminal_cmd}; exec bash"])
                    elif term == "konsole":
                        subprocess.Popen([term_path, "-e", "bash", "-c", f"{terminal_cmd}; exec bash"])
                    else:
                        subprocess.Popen([term_path, "-e", f"{terminal_cmd}"])
                    break
    except Exception:
        logging.getLogger("lasso.dashboard").exception("Failed to launch terminal for sandbox %s", sandbox_id)
        flash("Failed to launch terminal. No supported terminal emulator found.", "error")

    return redirect(url_for("dashboard.sandbox_detail", sandbox_id=sandbox_id))


@dashboard_bp.route("/profiles")
@require_login
def profiles_list():
    """Profile listing page."""
    profiles = _get_all_profiles()
    return render_template(
        "profiles.html",
        profiles=profiles,
        version=__version__,
    )


@dashboard_bp.route("/profiles/<name>")
@require_login
def profile_detail(name: str):
    """Profile detail/editor page."""
    profile = None
    source = "unknown"

    if name in BUILTIN_PROFILES:
        profile = BUILTIN_PROFILES[name](_default_sandbox_dir())
        source = "builtin"
    else:
        try:
            profile = load_profile(name)
            source = "saved"
        except FileNotFoundError:
            abort(404, description=f"Profile '{name}' not found.")

    profile_data = profile.model_dump(mode="json")
    profile_json = json.dumps(profile_data, indent=2)

    return render_template(
        "profile_detail.html",
        profile=profile,
        profile_data=profile_data,
        profile_json=profile_json,
        source=source,
        version=__version__,
    )


@dashboard_bp.route("/profiles/<name>/edit")
@require_login
def profile_edit(name: str):
    """Edit a profile via the dashboard form."""
    source = "unknown"
    if name in BUILTIN_PROFILES:
        profile = BUILTIN_PROFILES[name](_default_sandbox_dir())
        source = "builtin"
    else:
        try:
            profile = load_profile(name)
            source = "saved"
        except FileNotFoundError:
            abort(404, description=f"Profile '{name}' not found.")

    profile_data = profile.model_dump(mode="json")

    # Figure out which commands from the checkbox grid are NOT in the
    # whitelist so the template can compute "extra_commands"
    grid_cmds = {
        "ls", "cat", "head", "tail", "grep", "find", "wc", "sort", "diff",
        "echo", "test", "python3", "pip", "git", "node", "npm", "make",
        "cargo", "go", "curl", "wget", "mkdir", "cp", "mv", "touch",
        "tar", "zip", "unzip",
    }
    wl = set(profile_data["commands"].get("whitelist", []))
    extra_cmds = sorted(wl - grid_cmds)
    extra_commands_str = ", ".join(extra_cmds)

    return render_template(
        "profile_edit.html",
        profile=profile,
        profile_data=profile_data,
        source=source,
        extra_commands_str=extra_commands_str,
        version=__version__,
    )


@dashboard_bp.route("/profiles/<name>/edit", methods=["POST"])
@require_login
def profile_save(name: str):
    """Save profile changes from the dashboard form."""
    # For builtins, reject direct save (must duplicate)
    if name in BUILTIN_PROFILES:
        abort(400, description="Built-in profiles cannot be modified. Duplicate them first.")

    try:
        parsed = _parse_profile_form(request.form)
        description = request.form.get("description", "").strip()
        extends = request.form.get("extends", "").strip() or None
        profile = _build_profile(name, description, parsed, extends)
        save_profile(profile)
    except (ValueError, TypeError) as e:
        # Reload and show error
        try:
            orig = load_profile(name)
        except FileNotFoundError:
            orig = SandboxProfile(
                name=name,
                filesystem=FilesystemConfig(working_dir=_default_sandbox_dir()),
            )
        return render_template(
            "profile_edit.html",
            profile=orig,
            profile_data=orig.model_dump(mode="json"),
            source="saved",
            extra_commands_str="",
            error=str(e),
            version=__version__,
        )

    return redirect(url_for("dashboard.profile_detail", name=name))


@dashboard_bp.route("/profiles/new")
@require_login
def profile_new():
    """New profile wizard page."""
    return render_template(
        "profile_new.html",
        version=__version__,
    )


@dashboard_bp.route("/profiles/new", methods=["POST"])
@require_login
def profile_create():
    """Create a new profile from the wizard form."""
    name = request.form.get("name", "").strip()
    if not name:
        return render_template(
            "profile_new.html",
            error="Profile name is required.",
            version=__version__,
        )

    # Check if profile already exists
    if name in BUILTIN_PROFILES:
        return render_template(
            "profile_new.html",
            error=f"'{name}' is a built-in profile name. Choose a different name.",
            version=__version__,
        )

    from lasso.config.profile import profile_path

    if profile_path(name).exists():
        return render_template(
            "profile_new.html",
            error=f"A profile named '{name}' already exists.",
            version=__version__,
        )

    try:
        parsed = _parse_profile_form(request.form)
        description = request.form.get("description", "").strip()
        base = request.form.get("base_profile", "").strip() or None
        profile = _build_profile(name, description, parsed, base)
        save_profile(profile)
    except (ValueError, TypeError) as e:
        return render_template(
            "profile_new.html",
            error=str(e),
            version=__version__,
        )

    return redirect(url_for("dashboard.profile_detail", name=name))


@dashboard_bp.route("/profiles/<name>/delete", methods=["POST"])
@require_login
def profile_delete(name: str):
    """Delete a saved (non-builtin) profile."""
    if name in BUILTIN_PROFILES:
        abort(400, description="Built-in profiles cannot be deleted.")

    if delete_profile(name):
        flash(f"Profile '{name}' deleted.", "success")
    else:
        flash(f"Profile '{name}' not found.", "error")
    return redirect(url_for("dashboard.profiles_list"))


@dashboard_bp.route("/audit/<sandbox_id>")
@require_login
def audit_log(sandbox_id: str):
    """Audit log viewer with filters."""
    registry = _get_registry()
    sb = registry.get(sandbox_id)
    if not sb:
        abort(404, description=f"Sandbox '{sandbox_id}' not found.")

    status = sb.status()
    event_type = request.args.get("type", "")
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = max(1, min(500, int(request.args.get("per_page", 50))))
    except (ValueError, TypeError):
        per_page = 50

    all_entries: list[dict] = []
    if sb.audit.log_file and sb.audit.log_file.exists():
        all_entries = read_audit_log(
            sb.audit.log_file,
            tail=0,  # get all
            event_type=event_type or None,
        )

    # Pagination
    total = len(all_entries)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    entries = all_entries[start : start + per_page]

    # Collect unique event types for filter dropdown
    event_types = sorted(set(e.get("type", "") for e in all_entries if e.get("type")))

    return render_template(
        "audit.html",
        sandbox=status,
        entries=entries,
        event_types=event_types,
        current_type=event_type,
        page=page,
        total_pages=total_pages,
        total=total,
        per_page=per_page,
        version=__version__,
    )


@dashboard_bp.route("/check")
@require_login
def system_check():
    """System capability check page."""
    caps = _system_capabilities()
    return render_template(
        "check.html",
        capabilities=caps,
        version=__version__,
    )


# ---------------------------------------------------------------------------
# Routes -- HTMX partials
# ---------------------------------------------------------------------------


@dashboard_bp.route("/partials/sandbox-table")
@require_login
def partial_sandbox_table():
    """HTMX partial: refreshable sandbox table body."""
    registry = _get_registry()
    sandboxes = registry.list_all()
    sandboxes = [_enrich_sandbox(sb, registry) for sb in sandboxes]
    stats = {
        "total": len(sandboxes),
        "running": sum(1 for s in sandboxes if s["state"] == "running"),
        "stopped": sum(1 for s in sandboxes if s["state"] == "stopped"),
        "errors": sum(1 for s in sandboxes if s["state"] == "error"),
        "total_execs": sum(s.get("exec_count", 0) for s in sandboxes),
        "total_blocked": sum(s.get("blocked_count", 0) for s in sandboxes),
    }
    return render_template(
        "partials/sandbox_table.html",
        sandboxes=sandboxes,
        stats=stats,
        state_color=_state_color,
    )


@dashboard_bp.route("/partials/sandbox-cards")
@require_login
def partial_sandbox_cards():
    """HTMX partial: refreshable sandbox card grid."""
    registry = _get_registry()
    sandboxes = registry.list_all()
    sandboxes = [_enrich_sandbox(sb, registry) for sb in sandboxes]
    return render_template(
        "partials/sandbox_cards.html",
        sandboxes=sandboxes,
        state_color=_state_color,
    )


@dashboard_bp.route("/partials/audit-feed/<sandbox_id>")
@require_login
def partial_audit_feed(sandbox_id: str):
    """HTMX partial: live audit feed for a sandbox."""
    registry = _get_registry()
    sb = registry.get(sandbox_id)
    if not sb:
        return "<tr><td colspan='5'>Sandbox not found.</td></tr>"

    entries = []
    if sb.audit.log_file and sb.audit.log_file.exists():
        entries = read_audit_log(sb.audit.log_file, tail=15)

    return render_template("partials/audit_feed.html", entries=entries)


@dashboard_bp.route("/partials/sandbox-status/<sandbox_id>")
@require_login
def partial_sandbox_status(sandbox_id: str):
    """HTMX partial: sandbox status badge and counters."""
    registry = _get_registry()
    sb = registry.get(sandbox_id)
    if not sb:
        return "<span>Not found</span>"
    status = sb.status()
    return render_template(
        "partials/sandbox_status.html",
        sandbox=status,
        state_color=_state_color,
    )


# ---------------------------------------------------------------------------
# Routes -- JSON API
# ---------------------------------------------------------------------------


@dashboard_bp.route("/api/sandboxes")
@require_login
def api_sandboxes():
    """JSON API: list all sandboxes."""
    registry = _get_registry()
    return jsonify(registry.list_all())


@dashboard_bp.route("/browse-dirs")
@require_login
def browse_dirs():
    """Return directory listing for the folder browser."""
    import string as _string

    # Return bookmarks (quick-access locations)
    if request.args.get("bookmarks"):
        home = Path.home()
        bookmarks = []
        # Standard user directories
        _BOOKMARK_DIRS = [
            ("Home", str(home), "\U0001f3e0"),
            ("Desktop", str(home / "Desktop"), "\U0001f5a5\ufe0f"),
            ("Documents", str(home / "Documents"), "\U0001f4c4"),
            ("Downloads", str(home / "Downloads"), "\U0001f4e5"),
            ("Projects", str(home / "Projects"), "\U0001f4bb"),
        ]
        # On Windows, add drive letters
        if platform.system() == "Windows":
            for letter in "CDEF":
                drive = f"{letter}:\\"
                if Path(drive).exists():
                    _BOOKMARK_DIRS.append((f"Drive {letter}:", drive, "\U0001f4be"))

        for name, path_str, icon in _BOOKMARK_DIRS:
            if Path(path_str).is_dir():
                bookmarks.append({"name": name, "path": path_str, "icon": icon})
        return jsonify({"bookmarks": bookmarks})

    path = request.args.get("path", "")

    # Default: show home directory (or drive list on Windows)
    if not path:
        if platform.system() == "Windows":
            drives = []
            for letter in _string.ascii_uppercase:
                drive = f"{letter}:\\"
                if Path(drive).exists():
                    drives.append({"name": f"{letter}:", "path": drive, "type": "drive"})
            return jsonify({"path": "", "parent": "", "entries": drives})
        else:
            path = str(Path.home())

    resolved = str(Path(path).resolve())
    path = os.path.normpath(resolved)

    # Security: block system directories -- check the resolved path so
    # symlinks cannot be used to bypass the block list.
    blocked = {"/proc", "/sys", "/dev", "/boot", "/etc", "/root"}
    if platform.system() == "Windows":
        blocked.update({"C:\\Windows", "C:\\Program Files", "C:\\$Recycle.Bin"})
    path_parts = Path(path).parts
    for b in blocked:
        b_parts = Path(b).parts
        # Check if path is exactly the blocked dir or a child of it
        if len(path_parts) >= len(b_parts) and all(
            p.lower() == bp.lower() for p, bp in zip(path_parts, b_parts, strict=False)
        ):
            return jsonify({"error": "System directory not accessible"}), 403

    try:
        entries = []
        for item in sorted(Path(path).iterdir()):
            if not item.is_dir():
                continue
            name = item.name
            # Hide hidden dirs: dotfiles on Unix, $-prefixed on Windows
            if name.startswith('.') or name.startswith('$'):
                continue
            entries.append({
                "name": name,
                "path": str(item),
                "type": "dir",
            })

        parent = os.path.normpath(str(Path(path).parent))
        if parent == path:  # root
            if platform.system() == "Windows":
                parent = ""  # go back to drive list
            else:
                parent = ""

        return jsonify({
            "path": path,
            "parent": parent,
            "entries": entries,
        })
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except OSError:
        # Path doesn't exist — walk up to the nearest existing parent
        fallback = Path(path)
        while fallback != fallback.parent:
            fallback = fallback.parent
            if fallback.is_dir():
                return jsonify({
                    "path": str(fallback),
                    "parent": str(fallback.parent) if fallback != fallback.parent else "",
                    "entries": [
                        {"name": item.name, "path": str(item), "type": "dir"}
                        for item in sorted(fallback.iterdir())
                        if item.is_dir() and not item.name.startswith('.') and not item.name.startswith('$')
                    ],
                    "fallback": True,
                    "message": f"Directory '{path}' does not exist. Showing '{fallback}' instead.",
                })
        # Could not find any existing parent — return home directory
        home = str(Path.home())
        return jsonify({
            "path": home,
            "parent": str(Path(home).parent),
            "entries": [
                {"name": item.name, "path": str(item), "type": "dir"}
                for item in sorted(Path(home).iterdir())
                if item.is_dir() and not item.name.startswith('.') and not item.name.startswith('$')
            ],
            "fallback": True,
            "message": f"Directory '{path}' does not exist. Showing home directory instead.",
        })


@dashboard_bp.route("/api/sandbox/<sandbox_id>/status")
@require_login
def api_sandbox_status(sandbox_id: str):
    """JSON API: sandbox status."""
    registry = _get_registry()
    sb = registry.get(sandbox_id)
    if not sb:
        return jsonify({"error": "not found"}), 404
    return jsonify(sb.status())

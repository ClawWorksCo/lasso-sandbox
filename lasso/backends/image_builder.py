"""Build custom container images per sandbox profile.

Generates Dockerfiles that install only the whitelisted tools,
creating minimal attack-surface images.
"""

from __future__ import annotations

import logging

from lasso.backends.base import ContainerBackend
from lasso.config.operational import load_config
from lasso.config.schema import CommandMode, SandboxProfile

logger = logging.getLogger("lasso.image_builder")

# Stable preset image names — these use fixed tags so they can be
# pre-built once and reused instantly across all sandbox creations.
PRESET_IMAGES: dict[str, str] = {
    "base": "lasso-preset:base",
    "claude-code": "lasso-preset:claude-code",
    "opencode": "lasso-preset:opencode",
}

# Pre-built sandbox-template base images for agent presets.
# These include the agent CLI pre-installed with user `agent` at UID 1000.
AGENT_BASE_IMAGES: dict[str, str] = {
    "opencode": "docker/sandbox-templates:opencode",
    "claude-code": "docker/sandbox-templates:claude-code",
}

# Agent CLI install instructions for Docker images — fallback for when
# sandbox-template images are not available (e.g. air-gapped environments).
# Each entry is a list of RUN commands added to the Dockerfile.
AGENT_INSTALLS: dict[str, list[str]] = {
    "claude-code": [
        "curl -fsSL https://deb.nodesource.com/setup_22.x | bash -",
        "apt-get install -y nodejs",
        "npm install -g @anthropic-ai/claude-code",
    ],
    "opencode": [
        "curl -fsSL https://opencode.ai/install | bash",
    ],
}

# Default pinned base image — digest ensures reproducible builds
DEFAULT_BASE_IMAGE = (
    "python:3.12-slim@sha256:"
    "3d5ed973e45820f5ba5e46bd065bd88b3a504ff0724d85980dcd05eab361fcf4"
)

# Map command names to apt packages
TOOL_TO_PACKAGE: dict[str, str] = {
    "python3": "python3",
    "python": "python3",
    "pip": "python3-pip",
    "pip3": "python3-pip",
    "git": "git",
    "curl": "curl",
    "wget": "wget",
    "node": "nodejs",
    "npm": "nodejs npm",
    "npx": "nodejs npm",
    "Rscript": "r-base",
    "R": "r-base",
    "make": "make",
    "cmake": "cmake",
    "gcc": "gcc",
    "g++": "g++",
    "rustc": "rustc",
    "cargo": "cargo",
    "tar": "tar",
    "gzip": "gzip",
    "gunzip": "gzip",
    "zip": "zip",
    "unzip": "unzip",
    "jq": "jq",
    "ssh": "openssh-client",
    "scp": "openssh-client",
    "rsync": "rsync",
    "sqlite3": "sqlite3",
    "iptables": "iptables",
}

# These are always available in the base image (coreutils/busybox)
def _resolve_template_image(agent: str) -> str | None:
    """Resolve the sandbox-template image for an agent.

    Checks operational config first (allows env var / TOML overrides),
    then falls back to the hardcoded AGENT_BASE_IMAGES defaults.
    Returns None if the agent has no template image.
    """
    config = load_config()
    _CONFIG_TEMPLATE_MAP: dict[str, str] = {
        "opencode": config.containers.opencode_template,
        "claude-code": config.containers.claude_code_template,
    }
    template = _CONFIG_TEMPLATE_MAP.get(agent)
    if template:
        return template
    return AGENT_BASE_IMAGES.get(agent)


BUILTIN_COMMANDS = {
    "ls", "cat", "head", "tail", "grep", "find", "wc", "sort", "uniq",
    "diff", "mkdir", "cp", "mv", "touch", "echo", "printf", "test",
    "env", "basename", "dirname", "pwd", "sleep", "true", "false",
    "sh", "bash", "date", "tee", "xargs", "tr", "cut", "sed", "awk",
}


def generate_dockerfile(
    profile: SandboxProfile,
    base_image: str | None = None,
    agent: str | None = None,
    ca_cert_path: str | None = None,
    use_sandbox_template: bool = True,
) -> str:
    """Generate a Dockerfile that installs only the whitelisted tools.

    Args:
        profile: The sandbox profile defining which tools to install.
        base_image: Optional base Docker image. Defaults to DEFAULT_BASE_IMAGE
                    (python:3.12-slim pinned to a specific digest).
        agent: Optional AI agent CLI to pre-install (e.g. "claude-code", "opencode").
        ca_cert_path: Optional path to a corporate CA certificate (PEM format).
                      When provided, the cert is installed into the system trust
                      store so TLS connections trust the corporate CA.
        use_sandbox_template: When True and agent has a sandbox-template image,
                    generate a minimal Dockerfile from that pre-built image
                    (skipping agent install and useradd since user ``agent``
                    at UID 1000 already exists). Defaults to True.
    """
    # When a sandbox-template exists for this agent, generate a minimal
    # Dockerfile: FROM + labels + optional iptables + optional CA cert.
    # The agent CLI and user are already baked into the template image.
    if use_sandbox_template and agent and _resolve_template_image(agent):
        return _generate_template_dockerfile(profile, agent, ca_cert_path)

    # Full Dockerfile build path (base preset or fallback for agents)
    base = base_image or DEFAULT_BASE_IMAGE
    packages = set()

    if profile.commands.mode == CommandMode.WHITELIST:
        for cmd in profile.commands.whitelist:
            if cmd in BUILTIN_COMMANDS:
                continue
            if cmd in TOOL_TO_PACKAGE:
                for pkg in TOOL_TO_PACKAGE[cmd].split():
                    packages.add(pkg)

    # Always include iptables when the profile requires network policy rules.
    # Without iptables the container cannot enforce firewall restrictions and
    # _apply_network_policy() will fail at startup.
    from lasso.backends.converter import needs_network_rules
    if needs_network_rules(profile):
        packages.add("iptables")

    # Agent install commands (AGENT_INSTALLS) use curl — ensure it is
    # always present as a base dependency when an agent will be installed.
    if agent and agent in AGENT_INSTALLS:
        packages.add("curl")

    packages_str = " ".join(sorted(packages)) if packages else ""

    lines = [
        f"FROM {base}",
        "",
        "LABEL managed-by=lasso",
        f"LABEL lasso-profile={profile.name}",
        "",
        "RUN apt-get update \\",
    ]

    if packages_str:
        lines.append(f"    && apt-get install -y --no-install-recommends {packages_str} \\")

    lines.extend([
        "    && apt-get clean \\",
        "    && rm -rf /var/lib/apt/lists/*",
        "",
    ])

    # Install corporate CA certificate into the system trust store
    if ca_cert_path:
        _append_ca_cert_lines(lines, ca_cert_path)

    # Insert AI agent install commands (needs root, before USER agent)
    if agent and agent in AGENT_INSTALLS:
        install_cmds = list(AGENT_INSTALLS[agent])
        # Deduplicate: if Node.js is already installed via apt packages, skip
        # the nodesource setup line (packages already provide nodejs).
        has_nodejs_pkg = "nodejs" in packages if packages else False
        if has_nodejs_pkg:
            install_cmds = [
                cmd for cmd in install_cmds
                if "nodesource" not in cmd and cmd != "apt-get install -y nodejs"
            ]

        if install_cmds:
            lines.append(f"# Install AI agent: {agent}")
            lines.append("RUN " + " \\\n    && ".join(install_cmds))
            lines.append("")

    lines.extend([
        "RUN useradd -m -u 1000 -s /bin/bash agent",
        "RUN mkdir -p /home/agent/.local/share/opencode /home/agent/.config /home/agent/.cache \\",
        "    && chown -R agent:agent /home/agent/.local /home/agent/.config /home/agent/.cache",
        "",
        "WORKDIR /workspace",
        "USER agent",
        "",
        'CMD ["sleep", "infinity"]',
    ])

    return "\n".join(lines) + "\n"


def _generate_template_dockerfile(
    profile: SandboxProfile,
    agent: str,
    ca_cert_path: str | None = None,
) -> str:
    """Generate a minimal Dockerfile layered on a sandbox-template image.

    The template image already has the agent CLI installed and a user
    ``agent`` at UID 1000. This Dockerfile only adds lasso labels,
    optional iptables, and optional CA certificate injection.
    """
    base = _resolve_template_image(agent) or AGENT_BASE_IMAGES[agent]
    lines = [
        f"FROM {base}",
        "",
        "LABEL managed-by=lasso",
        f"LABEL lasso-profile={profile.name}",
        "",
    ]

    # Check if iptables is needed — must be installed via apt as root
    from lasso.backends.converter import needs_network_rules
    if needs_network_rules(profile):
        lines.append("USER root")
        lines.append(
            "RUN apt-get update \\\n"
            "    && apt-get install -y --no-install-recommends iptables \\\n"
            "    && apt-get clean \\\n"
            "    && rm -rf /var/lib/apt/lists/*"
        )
        lines.append("")

    # Install corporate CA certificate into the system trust store
    if ca_cert_path:
        # Always add USER root — Docker ignores redundant USER directives
        lines.append("USER root")
        _append_ca_cert_lines(lines, ca_cert_path)

    # Ensure /home/agent/.local exists for session volume mount target
    if not (needs_network_rules(profile) or ca_cert_path):
        lines.append("USER root")
    lines.append("RUN mkdir -p /home/agent/.local/share/opencode /home/agent/.config /home/agent/.cache \\")
    lines.append("    && chown -R agent:agent /home/agent/.local /home/agent/.config /home/agent/.cache")
    lines.append("")

    # Drop back to non-root user
    lines.append("USER agent")
    lines.append("")

    lines.extend([
        "WORKDIR /workspace",
        "",
        'CMD ["sleep", "infinity"]',
    ])

    return "\n".join(lines) + "\n"


def _append_ca_cert_lines(lines: list[str], ca_cert_path: str) -> None:
    """Append CA certificate injection lines to a Dockerfile."""
    try:
        with open(ca_cert_path) as f:
            cert_content = f.read().strip()
    except OSError as exc:
        raise ValueError(f"Cannot read CA certificate at {ca_cert_path}: {exc}") from exc
    # Inject cert inline to avoid COPY (works with streaming builds)
    escaped = cert_content.replace("\\", "\\\\").replace('"', '\\"')
    lines.append("# Install corporate CA certificate")
    lines.append(
        f'RUN echo "{escaped}" '
        "> /usr/local/share/ca-certificates/corporate-ca.crt \\\n"
        "    && update-ca-certificates"
    )
    lines.append("")


def image_tag(profile: SandboxProfile, agent: str | None = None) -> str:
    """Return the image tag for a profile + agent combination.

    Uses stable preset names when possible (instant startup), falls back
    to hash-based tags for custom profiles.
    """
    # Use stable preset if the agent matches a known preset
    if agent and agent in PRESET_IMAGES:
        return PRESET_IMAGES[agent]
    # Base preset for standard profiles without an agent
    if not agent:
        return PRESET_IMAGES["base"]
    # Fallback: hash-based tag for custom combinations
    tag_input = profile.config_hash()[:12]
    if agent:
        tag_input += f"-{agent}"
    return f"lasso-{tag_input}"


def _try_pull_template(backend: ContainerBackend, agent: str) -> bool:
    """Attempt to pull the sandbox-template image for an agent.

    Returns True if the pull succeeded (image is now available locally).
    """
    template_image = _resolve_template_image(agent)
    if not template_image:
        return False
    try:
        # Use the backend's native client to pull
        client = backend.get_native_client()
        if client is None:
            return False
        client.images.pull(template_image)
        logger.info("Pulled sandbox-template image: %s", template_image)
        return True
    except Exception as exc:
        logger.debug("Failed to pull %s: %s", template_image, exc)
        return False


def ensure_image(
    backend: ContainerBackend,
    profile: SandboxProfile,
    force_rebuild: bool = False,
    base_image: str | None = None,
    agent: str | None = None,
    ca_cert_path: str | None = None,
) -> str:
    """Ensure a sandbox image exists for this profile. Build if needed.

    For agent presets, tries to pull the sandbox-template image first
    and layer on any needed additions. Falls back to building from
    scratch using AGENT_INSTALLS if the pull fails.

    Args:
        backend: The container backend to use for building/checking images.
        profile: The sandbox profile to build an image for.
        force_rebuild: If True, rebuild even if the image already exists.
        base_image: Optional base Docker image override. Defaults to
                    DEFAULT_BASE_IMAGE (pinned to digest).
        agent: Optional AI agent CLI to pre-install in the image.
        ca_cert_path: Optional path to a corporate CA certificate (PEM).

    Returns the image tag.
    """
    tag = image_tag(profile, agent=agent)

    if not force_rebuild and backend.image_exists(tag):
        logger.debug("Image %s already exists", tag)
        return tag

    # For agent presets, try pulling sandbox-template first
    use_template = False
    if agent and _resolve_template_image(agent):
        if _try_pull_template(backend, agent):
            use_template = True
        else:
            logger.info(
                "Sandbox-template pull failed for %s, falling back to full build",
                agent,
            )

    logger.info("Building sandbox image %s for profile '%s'", tag, profile.name)
    dockerfile = generate_dockerfile(
        profile,
        base_image=base_image,
        agent=agent,
        ca_cert_path=ca_cert_path,
        use_sandbox_template=use_template,
    )
    backend.build_image(dockerfile, tag)
    logger.info("Image %s built successfully", tag)
    return tag


def prebuild_presets(
    backend: ContainerBackend,
    force: bool = False,
    ca_cert_path: str | None = None,
    agents: list[str] | None = None,
) -> dict[str, str]:
    """Pre-build all preset images so sandbox creation is instant.

    For agent presets, pulls sandbox-template images and layers on
    any needed additions. Falls back to full build if pull fails.
    For the base preset (no agent), builds from python:3.12-slim.

    Returns a dict of {preset_name: image_tag}.

    Args:
        backend: Container backend to build images with.
        force: Rebuild even if image already exists.
        ca_cert_path: Optional path to a corporate CA certificate (PEM).
            Injected into images so curl/pip/npm trust the proxy.
        agents: Optional list of agent names to build. When provided, only
            build images for the specified agents (and skip the base image
            unless explicitly included). When None, build all presets.
    """
    from lasso.config.defaults import standard_profile

    results: dict[str, str] = {}

    # Use the standard profile as the base for all presets
    profile = standard_profile("/workspace")

    # Build base image (no agent) — skip when filtering to specific agents
    if agents is None or "base" in agents:
        tag = PRESET_IMAGES["base"]
        if force or not backend.image_exists(tag):
            logger.info("Building preset: base")
            dockerfile = generate_dockerfile(
                profile, ca_cert_path=ca_cert_path, use_sandbox_template=False,
            )
            backend.build_image(dockerfile, tag)
            logger.info("Preset base built: %s", tag)
        results["base"] = tag

    # Build agent images — pull sandbox-template + layer, or full build
    all_agents = sorted(set(AGENT_INSTALLS) | set(AGENT_BASE_IMAGES))
    if agents is not None:
        filter_set = {a for a in agents if a != "base"}
        all_agents = [a for a in all_agents if a in filter_set]
    for agent_name in all_agents:
        tag = PRESET_IMAGES.get(agent_name, f"lasso-preset:{agent_name}")
        if force or not backend.image_exists(tag):
            # Try pulling the sandbox-template image
            use_template = False
            if _resolve_template_image(agent_name):
                if _try_pull_template(backend, agent_name):
                    use_template = True
                    logger.info("Using sandbox-template for preset: %s", agent_name)
                else:
                    logger.info("Building preset: %s (full build)", agent_name)
            else:
                logger.info("Building preset: %s", agent_name)

            dockerfile = generate_dockerfile(
                profile,
                agent=agent_name,
                ca_cert_path=ca_cert_path,
                use_sandbox_template=use_template,
            )
            backend.build_image(dockerfile, tag)
            logger.info("Preset %s built: %s", agent_name, tag)
        else:
            logger.info("Preset %s already cached: %s", agent_name, tag)
        results[agent_name] = tag

    return results

# Windows Setup Guide

LASSO runs on Windows via Docker Desktop or Podman Desktop. This guide covers installation, configuration, and Windows-specific considerations.

## Prerequisites

- Windows 10 (build 19041+) or Windows 11
- Python 3.10+ ([python.org](https://www.python.org/downloads/) or `winget install Python.Python.3.12`)
- WSL 2 enabled (required by Docker Desktop and Podman)

## 1. Container Runtime

### Option A: Podman Desktop (recommended for enterprise)

Podman is rootless by default, requires no paid license, and is preferred for enterprise environments where Docker Desktop licensing is a concern.

```powershell
# Install via winget
winget install RedHat.Podman-Desktop

# Or download from https://podman-desktop.io/

# Verify installation
podman --version
podman machine init
podman machine start
```

### Option B: Docker Desktop

```powershell
# Install via winget
winget install Docker.DockerDesktop

# Verify installation
docker --version
docker info
```

Ensure WSL 2 backend is enabled in Docker Desktop settings (Settings > General > Use the WSL 2 based engine).

## 2. Install LASSO

```powershell
pip install lasso-sandbox>=1.6.3

# Verify
lasso check
```

## 3. Path Handling

Windows paths are automatically converted for Docker mounts. LASSO handles this transparently:

| Windows path | Docker mount path |
|---|---|
| `C:\Users\me\project` | `/c/Users/me/project` |
| `D:\repos\myapp` | `/d/repos/myapp` |

This conversion happens in `lasso/backends/converter.py` (`_to_docker_mount_path`). You always use native Windows paths in your commands and config files:

```powershell
# Use normal Windows paths — LASSO converts them automatically
lasso create team-development --dir C:\Users\me\project

# Relative paths work too
cd C:\Users\me\project
lasso create team-development --dir .
```

### Profile paths

In profile TOML files, use forward slashes or escaped backslashes:

```toml
[filesystem]
working_dir = "."
# Both of these work:
writable_paths = ["C:/Users/me/data"]
# writable_paths = ["C:\\Users\\me\\data"]
```

## 4. Git Worktree Paths

LASSO works with git worktrees on Windows. Use native paths:

```powershell
cd C:\repos\myproject
git worktree add C:\repos\worktrees\myproject-feature origin/main

# Point LASSO at the worktree
lasso create team-development --dir C:\repos\worktrees\myproject-feature
```

## 5. PowerShell Command Examples

### Create and use a sandbox

```powershell
# Create a sandbox
lasso create team-development --dir .

# List running sandboxes
lasso status

# Execute a command
lasso exec <sandbox-id> -- python3 test.py

# Interactive REPL
lasso shell --agent claude-code --dir .

# Stop a sandbox
lasso stop <sandbox-id>

# Stop all sandboxes
lasso stop all
```

### View audit logs

```powershell
lasso audit view .\audit\log.jsonl
lasso audit verify .\audit\log.jsonl
```

### Dashboard

```powershell
lasso dashboard
# Opens http://127.0.0.1:8080 in your browser
```

### Profile management

```powershell
# List available profiles
lasso profile list

# Show profile details
lasso profile show team-development

# Validate a profile file
lasso config validate .\profiles\team-development.toml
```

## 6. Known Windows Considerations

### NTFS chmod limitations

LASSO sets `0o600` permissions on the audit signing key file. On NTFS, `os.chmod` has limited effect — NTFS uses ACLs instead of Unix permission bits. The key file will still be created and functional, but the permission restriction is best-effort on Windows.

For production deployments on Windows, secure the signing key via NTFS ACLs:

```powershell
# Restrict audit key to current user only
$keyPath = "$env:USERPROFILE\.lasso\audit-key"
icacls $keyPath /inheritance:r /grant:r "${env:USERNAME}:(R)"
```

### ntpath handling

The command gate uses `ntpath.basename()` to correctly strip Windows-style path prefixes (e.g., `C:\Windows\System32\cmd.exe` -> `cmd.exe`) regardless of the host platform. This prevents bypass attempts using Windows paths on any OS.

### Long path support

If your project has deeply nested paths, enable Windows long path support:

```powershell
# Run as Administrator
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
    -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

### WSL 2 file system performance

For best performance, keep your project files on the Windows filesystem (e.g., `C:\Users\me\project`) rather than in the WSL 2 Linux filesystem (`\\wsl$\...`). Docker Desktop and Podman mount Windows paths directly, avoiding the WSL 2 filesystem translation overhead.

### Firewall considerations

Docker Desktop and Podman may require Windows Firewall exceptions. If `lasso check` reports network issues:

1. Open Windows Defender Firewall
2. Allow "Docker Desktop Backend" or "Podman" through the firewall
3. For the LASSO dashboard, allow inbound TCP on port 8080 (loopback only)

## 7. Troubleshooting

**`lasso check` fails with "No container runtime found"**
- Ensure Docker Desktop or Podman is running (check system tray)
- Restart the Podman machine: `podman machine stop && podman machine start`

**"permission denied" on audit key**
- Run `lasso create` from a terminal with write access to the audit directory
- Verify the directory exists: `mkdir -p $env:USERPROFILE\.lasso`

**Slow container startup**
- Pre-build the sandbox image with `lasso prebuild` so startup is faster
- Ensure WSL 2 has sufficient memory allocated (`.wslconfig`)

**Path mount errors**
- Ensure the drive is shared in Docker Desktop (Settings > Resources > File Sharing)
- For Podman, the machine must be configured to share the host directory

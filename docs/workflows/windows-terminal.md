# Windows Terminal Integration

Run LASSO sandboxes from Windows Terminal with dedicated profiles, split panes, and a launcher script.

## Prerequisites

- Windows Terminal 1.18+ (from Microsoft Store or GitHub)
- Python 3.10+ with `lasso-sandbox` installed
- Docker Desktop for Windows (or Podman)

## Terminal Profile Setup

Open Windows Terminal settings (`Ctrl+,` or Settings > Open JSON file) and add a LASSO profile to the `profiles.list` array:

```jsonc
{
    "profiles": {
        "list": [
            // ... existing profiles ...
            {
                "name": "LASSO Sandbox",
                "commandline": "cmd.exe /k lasso shell --agent claude-code",
                "icon": "ms-appx:///ProfileIcons/{9acb9455-ca41-5af7-950f-6bca1bc9722f}.png",
                "startingDirectory": "%USERPROFILE%\\projects",
                "colorScheme": "One Half Dark",
                "font": {
                    "face": "Cascadia Code NF",
                    "size": 11
                },
                "padding": "8",
                "tabTitle": "LASSO",
                "suppressApplicationTitle": true
            }
        ]
    }
}
```

### Profile Variants

You can add multiple profiles for different security levels:

```jsonc
{
    "name": "LASSO (Strict)",
    "commandline": "cmd.exe /k lasso shell --agent claude-code --profile strict",
    "startingDirectory": "%USERPROFILE%\\projects",
    "tabTitle": "LASSO Strict",
    "colorScheme": "Campbell"
},
{
    "name": "LASSO (Offline)",
    "commandline": "cmd.exe /k lasso shell --agent claude-code --profile offline",
    "startingDirectory": "%USERPROFILE%\\projects",
    "tabTitle": "LASSO Offline",
    "colorScheme": "Tango Dark"
}
```

## Multi-Pane Workflow

Windows Terminal supports split panes, which pairs well with LASSO's multi-sandbox support.

### Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Split pane right | `Alt+Shift+Plus` |
| Split pane down | `Alt+Shift+Minus` |
| Switch pane | `Alt+Arrow` |
| Close pane | `Ctrl+Shift+W` |
| Resize pane | `Alt+Shift+Arrow` |

### Recommended Layout

A productive three-pane layout:

```
+---------------------------+------------------+
|                           |                  |
|   LASSO sandbox           |  lasso status    |
|   (agent working)         |  lasso audit ... |
|                           |                  |
+---------------------------+------------------+
|                                              |
|   Host shell (git, file browsing)            |
|                                              |
+----------------------------------------------+
```

To set this up:

1. Open a LASSO Sandbox profile tab.
2. Press `Alt+Shift+Plus` to split right -- use this pane for `lasso status` and audit commands.
3. Click the left pane, press `Alt+Shift+Minus` to split down -- use this for your host shell.

### Custom Key Bindings

Add to the `actions` array in `settings.json` for one-key sandbox launch:

```jsonc
{
    "actions": [
        {
            "command": {
                "action": "newTab",
                "profile": "LASSO Sandbox"
            },
            "keys": "ctrl+shift+l"
        },
        {
            "command": {
                "action": "splitPane",
                "split": "horizontal",
                "profile": "LASSO Sandbox"
            },
            "keys": "ctrl+shift+alt+l"
        }
    ]
}
```

## Launcher Script

Save the following as `lasso-launch.cmd` somewhere on your `PATH` (e.g. `%USERPROFILE%\bin\`):

```batch
@echo off
REM lasso-launch.cmd -- Start a LASSO sandbox for the current directory.
REM Usage:
REM   lasso-launch                     (standard profile, auto-detect agent)
REM   lasso-launch strict              (strict profile)
REM   lasso-launch standard opencode   (standard profile, OpenCode agent)

setlocal

set PROFILE=%1
if "%PROFILE%"=="" set PROFILE=standard

set AGENT=%2
if "%AGENT%"=="" set AGENT=claude-code

echo Starting LASSO sandbox...
echo   Profile : %PROFILE%
echo   Agent   : %AGENT%
echo   Dir     : %CD%
echo.

lasso shell --agent %AGENT% --profile %PROFILE% --dir "%CD%"
```

### Usage Examples

```batch
REM Launch from your project directory
cd %USERPROFILE%\projects\my-app
lasso-launch

REM Launch with strict profile
lasso-launch strict

REM Launch with OpenCode agent
lasso-launch standard opencode
```

## Tips

- **Tab titles**: Set `"suppressApplicationTitle": true` in the profile to keep the tab title as "LASSO" instead of whatever the container shell reports.
- **Font**: Use a Nerd Font (e.g. Cascadia Code NF) for proper icon rendering inside the sandbox.
- **Scrollback**: Increase `"historySize"` in the profile if you need to scroll back through long agent output.
- **Bell**: Set `"bellStyle": "none"` to suppress terminal bells from the sandbox.
- **Opacity**: Windows Terminal supports `"opacity": 90` and `"useAcrylic": true` for translucent panes, useful for keeping an eye on the host desktop while the agent works.

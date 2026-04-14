"""Authentication CLI commands (lasso auth ...)."""

from __future__ import annotations

import os

import typer
from rich.table import Table

from .constants import console, err_console

auth_app = typer.Typer(help="GitHub authentication (device flow).", no_args_is_help=True)


@auth_app.command(name="login")
def auth_login(
    client_id: str | None = typer.Option(None, "--client-id", help="GitHub OAuth App client ID (overrides LASSO_GITHUB_CLIENT_ID env var)."),
):
    """Authenticate with GitHub via device flow (opens browser).

    Uses the OAuth Device Flow to authenticate with your GitHub account.
    The token is stored at ~/.lasso/github_token.json and used for
    GitHub authentication and dashboard access.

    Set LASSO_GITHUB_CLIENT_ID or pass --client-id to configure.
    Set GITHUB_TOKEN to skip the device flow entirely.
    """
    from lasso.auth.github import DeviceFlowError, GitHubAuth

    auth = GitHubAuth(client_id=client_id)

    # Check for GITHUB_TOKEN env override
    env_token = os.environ.get("GITHUB_TOKEN")
    if env_token:
        console.print("[dim]Using GITHUB_TOKEN from environment (skipping device flow).[/dim]")
        token_info = auth.login()
        user_info = auth.get_user_info()
        if user_info:
            console.print(f"[green]Authenticated as @{user_info.get('login', 'unknown')}[/green]")
        else:
            console.print("[green]Token loaded from environment.[/green]")
        console.print("[dim]Using GITHUB_TOKEN env var (not persisted to disk).[/dim]")
        return

    if not auth.has_client_id:
        err_console.print("[red]Error: No GitHub OAuth client ID configured.[/red]")
        err_console.print("[dim]Set LASSO_GITHUB_CLIENT_ID environment variable or pass --client-id.[/dim]")
        err_console.print("[dim]Alternatively, set GITHUB_TOKEN to use an existing token.[/dim]")
        raise typer.Exit(1)

    try:
        device = auth.request_device_code()
    except DeviceFlowError as e:
        err_console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    console.print("Opening browser for GitHub authentication...\n")
    console.print(f"  Enter code: [bold cyan]{device.user_code}[/bold cyan]")
    console.print(f"  URL: [bold]{device.verification_uri}[/bold]\n")

    try:
        auth._open_browser(device.verification_uri)
    except Exception:
        console.print("[dim]Could not open browser automatically. Please visit the URL above.[/dim]")

    console.print("Waiting for authorization... (press Ctrl+C to cancel)")

    try:
        token_info = auth.poll_for_token(
            device.device_code,
            interval=device.interval,
            expires_in=device.expires_in,
        )
        auth._save_token(token_info)
    except DeviceFlowError as e:
        err_console.print(f"\n[red]Error: {e}[/red]")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Authentication cancelled.[/yellow]")
        raise typer.Exit(1)

    # Fetch user info
    user_info = auth.get_user_info()
    if user_info:
        login = user_info.get("login", "unknown")
        name = user_info.get("name", "")
        display = f"@{login}"
        if name:
            display = f"{name} ({display})"
        console.print(f"\n[green]Authenticated as {display}[/green]")
    else:
        console.print("\n[green]Authentication successful.[/green]")

    console.print(f"Token saved to {auth.token_path}")


@auth_app.command(name="status")
def auth_status():
    """Show current GitHub authentication status."""
    from lasso.auth.github import GitHubAuth

    auth = GitHubAuth()

    if not auth.is_authenticated():
        console.print("[dim]Not authenticated.[/dim]")
        console.print("Run [bold]lasso auth login[/bold] to authenticate with GitHub.")
        return

    # Check source
    source = "environment (GITHUB_TOKEN)" if os.environ.get("GITHUB_TOKEN") else f"file ({auth.token_path})"

    table = Table(title="GitHub Authentication", show_header=True)
    table.add_column("Property", style="bold")
    table.add_column("Value")
    table.add_row("Status", "[green]Authenticated[/green]")
    table.add_row("Source", source)

    # Try to fetch user info
    user_info = auth.get_user_info()
    if user_info:
        table.add_row("User", f"@{user_info.get('login', 'unknown')}")
        if user_info.get("name"):
            table.add_row("Name", user_info["name"])
        if user_info.get("email"):
            table.add_row("Email", user_info["email"])

    # Show token info if from file
    token_info = auth._load_token()
    if token_info:
        from datetime import datetime, timezone
        created = datetime.fromtimestamp(token_info.created_at, tz=timezone.utc)
        table.add_row("Created", created.strftime("%Y-%m-%d %H:%M:%S UTC"))
        table.add_row("Scopes", token_info.scope or "(unknown)")

    console.print(table)


@auth_app.command(name="logout")
def auth_logout():
    """Remove stored GitHub token."""
    from lasso.auth.github import GitHubAuth

    auth = GitHubAuth()

    if auth.logout():
        console.print("[green]Logged out. Token removed.[/green]")
    else:
        console.print("[dim]No stored token found.[/dim]")

    if os.environ.get("GITHUB_TOKEN"):
        console.print("[yellow]Note: GITHUB_TOKEN environment variable is still set.[/yellow]")


@auth_app.command(name="token")
def auth_token():
    """Print the current GitHub token (for piping to other tools).

    Outputs just the raw token string with no formatting, suitable for:
        export GITHUB_TOKEN=$(lasso auth token)
    """
    from lasso.auth.github import GitHubAuth

    auth = GitHubAuth()
    token = auth.get_token()

    if not token:
        err_console.print("[red]Error: Not authenticated.[/red]")
        err_console.print("[dim]Run 'lasso auth login' first.[/dim]")
        raise typer.Exit(1)

    import sys

    if not sys.stdout.isatty():
        err_console.print(
            "[yellow]Warning: token is being written to a pipe or file. "
            "Ensure the destination is secure.[/yellow]"
        )

    # Print raw token without rich formatting
    print(token, end="")

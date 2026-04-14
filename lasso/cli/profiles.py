"""Profile management CLI commands (lasso profile ...)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table

from lasso.config.defaults import BUILTIN_PROFILES
from lasso.config.profile import (
    delete_profile,
    list_profiles,
    load_profile,
    load_profile_from_path,
    resolve_profile,
    save_profile,
)
from lasso.config.schema import SandboxProfile
from lasso.utils.paths import get_lasso_dir

from .constants import console, err_console
from .helpers import _compute_structured_diff

profile_app = typer.Typer(help="Manage sandbox profiles.", no_args_is_help=True)


@profile_app.command(name="list")
def profile_list(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON array."),
):
    """List all saved and builtin profiles."""
    if output_json:
        result = []
        for name, factory in BUILTIN_PROFILES.items():
            p = factory(str(Path(tempfile.gettempdir()) / "lasso-example"))
            result.append({
                "name": name,
                "type": "builtin",
                "description": p.description,
                "command_mode": p.commands.mode.value,
                "network_mode": p.network.mode.value,
            })
        for p in list_profiles():
            p["type"] = "saved"
            result.append(p)
        console.print_json(json.dumps(result, indent=2))
        return

    # Builtins
    console.print("[bold]Builtin Profiles:[/bold]")
    bt = Table(show_header=True)
    bt.add_column("Name", style="bold cyan")
    bt.add_column("Description")
    bt.add_column("Commands")
    bt.add_column("Network")
    for name, factory in BUILTIN_PROFILES.items():
        p = factory(str(Path(tempfile.gettempdir()) / "lasso-example"))
        bt.add_row(name, p.description[:60], p.commands.mode.value, p.network.mode.value)
    console.print(bt)

    # Saved
    profiles = list_profiles()
    if profiles:
        console.print("\n[bold]Saved Profiles:[/bold]")
        st = Table(show_header=True)
        st.add_column("Name", style="bold")
        st.add_column("Working Dir")
        st.add_column("Commands")
        st.add_column("Network")
        st.add_column("Hash")
        for p in profiles:
            if "error" in p:
                st.add_row(p["name"], f"[red]{p['error']}[/red]", "", "", "")
            else:
                st.add_row(p["name"], p["working_dir"], p["cmd_mode"], p["net_mode"], p["hash"])
        console.print(st)


@profile_app.command(name="show")
def profile_show(name: str = typer.Argument(help="Profile name.")):
    """Show profile details."""
    if name in BUILTIN_PROFILES:
        profile = BUILTIN_PROFILES[name](str(Path(tempfile.gettempdir()) / "lasso-example"))
    else:
        try:
            profile = load_profile(name)
        except FileNotFoundError:
            err_console.print(f"[red]Error: Profile '{name}' not found.[/red]")
            err_console.print("[dim]Run 'lasso profile list' to see available profiles.[/dim]")
            raise typer.Exit(1)

    console.print_json(profile.model_dump_json(indent=2))


@profile_app.command(name="save")
def profile_save_cmd(
    name: str = typer.Argument(help="Name for the profile."),
    template: str = typer.Option("evaluation", "--from", "-t", help="Builtin template."),
    working_dir: str = typer.Option(".", "--dir", "-d", help="Working directory."),
):
    """Save a new profile based on a builtin template."""
    if template not in BUILTIN_PROFILES:
        err_console.print(f"[red]Error: Unknown template '{template}'.[/red]")
        err_console.print(f"[dim]Available: {', '.join(BUILTIN_PROFILES.keys())}[/dim]")
        err_console.print("[dim]Run 'lasso profile list' to see available profiles.[/dim]")
        raise typer.Exit(1)

    working_dir = str(Path(working_dir).resolve())
    profile = BUILTIN_PROFILES[template](working_dir, name=name)
    path = save_profile(profile)
    console.print(f"[green]Profile saved:[/green] {path}")


@profile_app.command(name="delete")
def profile_delete(
    name: str = typer.Argument(help="Profile to delete."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
):
    """Delete a saved profile."""
    if not yes:
        typer.confirm(f"Delete profile '{name}'?", abort=True)

    if delete_profile(name):
        console.print(f"[green]Profile '{name}' deleted.[/green]")
    else:
        err_console.print(f"[red]Error: Profile '{name}' not found.[/red]")
        err_console.print("[dim]Run 'lasso profile list' to see available profiles.[/dim]")
        raise typer.Exit(1)


@profile_app.command(name="install")
def profile_install(
    name: str = typer.Argument(help="Community profile name to install."),
):
    """Install a community profile from the LASSO profile pack.

    Copies a bundled community profile to ~/.lasso/profiles/ so it can be
    used with 'lasso create <name>' or 'lasso shell <name>'.

    Available profiles: see the bundled TOML files in lasso/profiles/.

    Example:
        lasso profile install frontend-dev
        lasso create frontend-dev --dir .
    """
    import importlib.resources
    import shutil

    # Locate the bundled profiles directory
    try:
        profiles_pkg = importlib.resources.files("lasso") / "profiles"
    except (TypeError, AttributeError):
        # Fallback for older Python versions
        profiles_pkg = Path(__file__).resolve().parent.parent / "profiles"

    source = Path(str(profiles_pkg)) / f"{name}.toml"
    if not source.exists():
        # Also check the project-root profiles/ directory (development installs)
        project_root = Path(__file__).resolve().parent.parent.parent / "profiles"
        source = project_root / f"{name}.toml"

    if not source.exists():
        err_console.print(f"[red]Error: Community profile '{name}' not found.[/red]")
        # List available profiles
        available = []
        for search_dir in [
            Path(str(profiles_pkg)),
            Path(__file__).resolve().parent.parent.parent / "profiles",
        ]:
            if search_dir.exists():
                available.extend(p.stem for p in search_dir.glob("*.toml"))
        available = sorted(set(available))
        if available:
            err_console.print(f"[dim]Available: {', '.join(available)}[/dim]")
        raise typer.Exit(1)

    # Validate the profile before copying
    try:
        load_profile_from_path(source)  # validates the TOML
    except Exception as e:
        err_console.print(f"[red]Error: Profile '{name}' is invalid: {e}[/red]")
        raise typer.Exit(1)

    dest_dir = get_lasso_dir() / "profiles"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{name}.toml"

    shutil.copy2(str(source), str(dest))

    console.print(
        f"[green]Profile '{name}' installed to:[/green] {dest}\n"
        f"\n"
        f"  Use it:  [bold]lasso create {name} --dir .[/bold]\n"
        f"  Details: [bold]lasso profile show {name}[/bold]\n"
        f"  Edit:    {dest}"
    )


@profile_app.command(name="export")
def profile_export(
    name: str = typer.Argument(help="Profile name to export."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path (default: <name>.toml)."),
):
    """Export a profile as a standalone TOML file for sharing."""
    from lasso.config.sharing import export_profile as do_export

    if output is None:
        output = f"{name}.toml"

    try:
        path = do_export(name, output)
        console.print(f"[green]Profile '{name}' exported to:[/green] {path}")
    except FileNotFoundError as e:
        err_console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@profile_app.command(name="import")
def profile_import(
    file: str = typer.Argument(help="Path to TOML profile file."),
    name: str | None = typer.Option(None, "--name", "-n", help="Override profile name."),
    force: bool = typer.Option(False, "--force", "-f", help="Accept profiles even if integrity hash mismatches."),
):
    """Import a profile from a TOML file."""
    from lasso.config.sharing import import_profile as do_import

    try:
        profile = do_import(file, name=name, strict=not force)
        console.print(
            f"[green]Profile '{profile.name}' imported successfully.[/green]\n"
            f"  Version: {profile.profile_version}\n"
            f"  Hash:    {profile.config_hash()[:12]}"
        )
    except FileNotFoundError as e:
        err_console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    except ValueError as e:
        err_console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@profile_app.command(name="diff")
def profile_diff_cmd(
    name1: str = typer.Argument(help="First profile name."),
    name2: str = typer.Argument(help="Second profile name."),
    output_json: bool = typer.Option(False, "--json", help="Output structured diff as JSON."),
):
    """Show differences between two profiles."""
    from lasso.config.sharing import diff_profiles

    working_dir = str(Path(".").resolve())

    def _load(name: str) -> SandboxProfile:
        if name in BUILTIN_PROFILES:
            return BUILTIN_PROFILES[name](working_dir)
        try:
            return load_profile(name)
        except FileNotFoundError:
            # Try loading from a file path
            p = Path(name)
            if p.exists():
                return load_profile_from_path(p)
            err_console.print(f"[red]Error: Profile '{name}' not found.[/red]")
            err_console.print("[dim]Run 'lasso profile list' to see available profiles.[/dim]")
            raise typer.Exit(1)

    a = _load(name1)
    b = _load(name2)

    if output_json:
        a_data = a.model_dump(mode="json", exclude={"created_at", "updated_at"})
        b_data = b.model_dump(mode="json", exclude={"created_at", "updated_at"})
        diff_result = _compute_structured_diff(a_data, b_data)
        data = {
            "profile_a": name1,
            "profile_b": name2,
            "differences": diff_result,
            "identical": len(diff_result) == 0,
        }
        console.print_json(json.dumps(data, indent=2))
        return

    result = diff_profiles(a, b)
    console.print(result)


@profile_app.command("resolve")
def profile_resolve_cmd(
    name: str = typer.Argument(help="Profile name to resolve."),
    working_dir: str = typer.Option(".", "--dir", "-d", help="Working directory."),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Show a fully-resolved profile after inheritance merging."""
    from lasso.config.profile import _strip_none

    working_dir = str(Path(working_dir).resolve())
    try:
        resolved = resolve_profile(name, working_dir=working_dir)
    except FileNotFoundError:
        err_console.print(f"[red]Error: Profile '{name}' not found.[/red]")
        raise typer.Exit(1)
    except ValueError as e:
        err_console.print(f"[red]Error resolving profile '{name}': {e}[/red]")
        raise typer.Exit(1)

    if output_json:
        console.print_json(resolved.model_dump_json(indent=2))
    else:
        import tomli_w

        data = _strip_none(resolved.model_dump(mode="json"))
        console.print(Panel(
            tomli_w.dumps(data),
            title=f"Resolved profile: {resolved.name}",
            subtitle=f"extends: {name} (fully resolved)",
        ))


@profile_app.command("lock")
def profile_lock(
    name: str | None = typer.Argument(None, help="Profile name to lock."),
    verify: bool = typer.Option(False, "--verify", help="Verify all locked profiles."),
    working_dir: str = typer.Option(".", "--dir", "-d", help="Project directory."),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Lock a profile hash or verify locked profiles.

    Lock mode (default): Records the current config hash for a profile
    in .lasso/profile.lock so teams can detect configuration drift.

    Verify mode (--verify): Checks all locked profiles against their
    recorded hashes and reports any mismatches.

    Examples:
        lasso profile lock development
        lasso profile lock --verify
    """
    from lasso.config.sharing import lock_profile, verify_profile_locks

    working_dir = str(Path(working_dir).resolve())

    if verify:
        results = verify_profile_locks(working_dir)
        if not results:
            console.print("[yellow]No profile locks found.[/yellow]")
            console.print("[dim]Lock a profile first: lasso profile lock <name>[/dim]")
            return

        if output_json:
            console.print_json(json.dumps(results, indent=2))
            return

        table = Table(title="Profile Lock Verification", show_header=True)
        table.add_column("Profile", style="bold")
        table.add_column("Expected Hash")
        table.add_column("Actual Hash")
        table.add_column("Status")
        table.add_column("Locked At")

        all_match = True
        for r in results:
            if "error" in r:
                table.add_row(r["name"], "?", "?", f"[red]ERROR: {r['error']}[/red]", "")
                all_match = False
            elif r["match"]:
                table.add_row(
                    r["name"], r["expected_hash"], r["actual_hash"],
                    "[green]OK[/green]", r.get("locked_at", "")[:19],
                )
            else:
                table.add_row(
                    r["name"], r["expected_hash"], r["actual_hash"],
                    "[red]MISMATCH[/red]", r.get("locked_at", "")[:19],
                )
                all_match = False

        console.print(table)
        if not all_match:
            err_console.print("[red]Some profiles have changed since they were locked.[/red]")
            raise typer.Exit(1)
        return

    # Lock mode
    if not name:
        err_console.print("[red]Error: Profile name required.[/red]")
        err_console.print("[dim]Usage: lasso profile lock <name>[/dim]")
        raise typer.Exit(1)

    try:
        lock_data = lock_profile(name, working_dir)
    except FileNotFoundError as e:
        err_console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    if output_json:
        console.print_json(json.dumps(lock_data, indent=2))
    else:
        console.print(f"[green]Locked[/green] profile [bold]{name}[/bold]")
        console.print(f"  Hash:    {lock_data['config_hash'][:12]}")
        console.print(f"  Version: {lock_data['profile_version']}")
        console.print(f"  File:    {Path(working_dir) / '.lasso' / 'profile.lock'}")

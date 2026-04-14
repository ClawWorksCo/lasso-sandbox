"""Operational config CLI commands (lasso config ...)."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.panel import Panel

from lasso.config.profile import load_profile_from_path

from .constants import console, err_console

config_app = typer.Typer(help="Manage operational configuration.", no_args_is_help=True)


@config_app.command("show")
def config_show(
    working_dir: str = typer.Option(".", "--dir", "-d", help="Working directory."),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Show the resolved operational configuration."""
    from lasso.config.operational import load_config

    config = load_config(working_dir=working_dir)
    if output_json:
        console.print_json(config.model_dump_json(indent=2))
    else:
        import tomli_w

        from lasso.config.profile import _strip_none

        data = _strip_none(config.model_dump())
        console.print(Panel.fit("[bold]Resolved Configuration[/bold]", border_style="blue"))
        console.print(tomli_w.dumps(data))


@config_app.command("validate")
def config_validate(
    dir_path: str = typer.Option(".", "--dir", "-d", help="Directory to validate."),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Validate all config and profile files in a directory."""
    from lasso.config.operational import LassoConfig

    errors: list[dict[str, str]] = []
    validated: list[str] = []

    # Check project config
    project_config = Path(dir_path) / ".lasso" / "config.toml"
    if project_config.exists():
        try:
            import tomli

            with open(project_config, "rb") as f:
                data = tomli.load(f)
            LassoConfig(**data)
            validated.append(str(project_config))
        except Exception as e:
            errors.append({"file": str(project_config), "error": str(e)})

    # Check profile files
    profiles_dir = Path(dir_path) / ".lasso" / "profiles"
    if profiles_dir.is_dir():
        for toml_file in sorted(profiles_dir.glob("*.toml")):
            try:
                load_profile_from_path(toml_file)  # validates
                validated.append(str(toml_file))
            except Exception as e:
                errors.append({"file": str(toml_file), "error": str(e)})

    if output_json:
        console.print_json(json.dumps({"valid": validated, "errors": errors}, indent=2))
        return

    if validated:
        console.print(f"[green]{len(validated)} file(s) valid:[/green]")
        for v in validated:
            console.print(f"  [dim]{v}[/dim]")
    if errors:
        console.print(f"\n[red]{len(errors)} file(s) with errors:[/red]")
        for e in errors:
            console.print(f"  [bold]{e['file']}[/bold]: {e['error']}")
        raise typer.Exit(1)
    if not validated and not errors:
        console.print("[dim]No config or profile files found.[/dim]")


@config_app.command("init")
def config_init(
    dir_path: str = typer.Option(".", "--dir", "-d", help="Directory to create config in."),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config."),
):
    """Create a default lasso-config.toml in the project."""
    import tomli_w

    from lasso.config.operational import LassoConfig
    from lasso.config.profile import _strip_none

    config_dir = Path(dir_path) / ".lasso"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "config.toml"

    if config_file.exists() and not force:
        err_console.print(f"[yellow]Config already exists: {config_file}[/yellow]")
        err_console.print("[dim]Use --force to overwrite.[/dim]")
        raise typer.Exit(1)

    default = LassoConfig()
    data = _strip_none(default.model_dump())
    toml_output = tomli_w.dumps(data)
    # tomli_w.dumps returns str in some versions, bytes in others
    if isinstance(toml_output, bytes):
        config_file.write_bytes(toml_output)
    else:
        config_file.write_text(toml_output)
    console.print(f"[green]Created config:[/green] {config_file}")

from __future__ import annotations

import json
from pathlib import Path

import typer

from .agent import run_agent_sync
from .config import Settings
from .demo import run_demo
from .doctor import environment_report

app = typer.Typer(help="Production-shaped AI QA Automation showcase CLI", no_args_is_help=True)


@app.command()
def doctor() -> None:
    """Report what is actually executable; missing optional capabilities stay NOT_VERIFIED."""
    cfg = Settings()
    typer.echo(json.dumps(environment_report(cfg.control_root), indent=2, default=str))


@app.command()
def demo() -> None:
    """Run the deterministic offline showcase without a model/API key."""
    typer.echo(json.dumps(run_demo(Path.cwd()), indent=2, default=str))


@app.command("agent")
def agent_command(
    objective: str = typer.Argument(..., help="Bounded QA objective"),
    workspace: Path = typer.Option(..., "--workspace", exists=True, file_okay=False, resolve_path=True),
) -> None:
    """Run the live Claude Agent SDK path."""
    typer.echo(json.dumps(run_agent_sync(objective, workspace), indent=2, default=str))


if __name__ == "__main__":
    app()

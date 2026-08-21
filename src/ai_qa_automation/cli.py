from __future__ import annotations

import json
from pathlib import Path

import typer

from .agent import run_agent_sync
from .config import Settings
from .demo import run_demo
from .doctor import environment_report
from .runtime.recovery import inspect_recovery

app = typer.Typer(help="AI QA Automation command-line interface", no_args_is_help=True)


@app.command()
def doctor() -> None:
    """Report what is executable; missing optional capabilities stay NOT_VERIFIED."""
    cfg = Settings()
    typer.echo(json.dumps(environment_report(cfg.control_root), indent=2, default=str))


@app.command()
def demo() -> None:
    """Run the deterministic local scenario without a model/API key."""
    typer.echo(json.dumps(run_demo(Path.cwd()), indent=2, default=str))


@app.command("recover")
def recover_command(
    run_dir: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
) -> None:
    """Verify an interrupted run checkpoint and report whether a new session can safely continue."""
    typer.echo(json.dumps(inspect_recovery(run_dir), indent=2, default=str))


@app.command("agent")
def agent_command(
    objective: str = typer.Argument(..., help="Bounded QA objective"),
    workspace: Path = typer.Option(..., "--workspace", exists=True, file_okay=False, resolve_path=True),
    control_root: Path | None = typer.Option(None, "--control-root", exists=True, file_okay=False, resolve_path=True),
) -> None:
    """Run one bounded Claude Agent SDK session."""
    settings = Settings(control_root=control_root) if control_root is not None else Settings()
    typer.echo(json.dumps(run_agent_sync(objective, workspace, settings), indent=2, default=str))


if __name__ == "__main__":
    app()

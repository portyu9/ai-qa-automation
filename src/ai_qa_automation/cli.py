from __future__ import annotations

import json
from pathlib import Path

import typer

from .agent import run_agent_sync
from .config import Settings
from .demo import run_demo
from .doctor import environment_report
from .intelligence.contract_drift import OpenAPIContractDriftAnalyzer
from .runtime.attestation import build_run_attestation
from .runtime.lineage import build_run_lineage
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


@app.command("lineage")
def lineage_command(
    run_dir: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    output_format: str = typer.Option("json", "--format", help="json or dot"),
) -> None:
    """Export evidence, artifact, validation, hypothesis, and runtime-event lineage."""
    graph = build_run_lineage(run_dir)
    normalized = output_format.casefold().strip()
    if normalized == "dot":
        typer.echo(graph.to_dot())
        return
    if normalized != "json":
        raise typer.BadParameter("--format must be json or dot")
    typer.echo(json.dumps(graph.as_dict(), indent=2, default=str))


@app.command("attest")
def attest_command(
    run_dir: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
) -> None:
    """Emit an unsigned content-addressed integrity attestation for persisted run records."""
    typer.echo(json.dumps(build_run_attestation(run_dir), indent=2, default=str))


@app.command("contract-diff")
def contract_diff_command(
    baseline: Path = typer.Option(
        ..., "--baseline", exists=True, dir_okay=False, resolve_path=True
    ),
    current: Path = typer.Option(..., "--current", exists=True, dir_okay=False, resolve_path=True),
) -> None:
    """Deterministically report conservative OpenAPI/Swagger compatibility drift."""
    report = OpenAPIContractDriftAnalyzer().analyze(
        path=current.name,
        baseline=baseline.read_bytes(),
        current=current.read_bytes(),
    )
    typer.echo(json.dumps(report.as_dict(), indent=2, default=str))


@app.command("agent")
def agent_command(
    objective: str = typer.Argument(..., help="Bounded QA objective"),
    workspace: Path = typer.Option(
        ..., "--workspace", exists=True, file_okay=False, resolve_path=True
    ),
    control_root: Path | None = typer.Option(
        None, "--control-root", exists=True, file_okay=False, resolve_path=True
    ),
) -> None:
    """Run one bounded Claude Agent SDK session."""
    settings = Settings(control_root=control_root) if control_root is not None else Settings()
    typer.echo(json.dumps(run_agent_sync(objective, workspace, settings), indent=2, default=str))


if __name__ == "__main__":
    app()

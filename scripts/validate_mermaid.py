from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

if __package__:
    from . import mermaid_fs as _fs
    from . import mermaid_output as _output
    from . import mermaid_snapshot as _snapshot
else:
    # PYTHONSAFEPATH deliberately removes the script directory from the
    # interpreter's implicit import path. Direct execution still needs the three
    # reviewed sibling helper modules, so admit only this script's resolved
    # directory rather than relying on the ambient working directory/PYTHONPATH.
    _script_dir = str(Path(__file__).resolve(strict=True).parent)
    if _script_dir not in sys.path:
        sys.path.insert(0, _script_dir)
    import mermaid_fs as _fs
    import mermaid_output as _output
    import mermaid_snapshot as _snapshot

MERMAID_IMAGE = (
    "ghcr.io/mermaid-js/mermaid-cli/mermaid-cli@"
    "sha256:8cc6fb93037759668ac6c48d3b727da15c60419304f3bd4c69c8cd8589e2b485"
)
GITHUB_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
RENDER_TIMEOUT_SECONDS = 60
DOCKER_CLEANUP_TIMEOUT_SECONDS = 15
DOCKER_COPY_TIMEOUT_SECONDS = 30

MermaidDocumentSnapshot = _snapshot.MermaidDocumentSnapshot
PUBLIC_ROOT_MARKDOWN = _fs.PUBLIC_ROOT_MARKDOWN
MAX_MARKDOWN_FILES = _fs.MAX_MARKDOWN_FILES
MAX_MARKDOWN_BYTES = _fs.MAX_MARKDOWN_BYTES
MAX_TOTAL_MARKDOWN_BYTES = _fs.MAX_TOTAL_MARKDOWN_BYTES
MAX_MERMAID_DIAGRAMS = _fs.MAX_MERMAID_DIAGRAMS
MAX_RENDER_FILE_BYTES = _fs.MAX_RENDER_FILE_BYTES
MAX_RENDER_TOTAL_BYTES = _fs.MAX_RENDER_TOTAL_BYTES
MAX_RENDER_OUTPUT_ENTRIES = _fs.MAX_RENDER_OUTPUT_ENTRIES
READ_CHUNK_BYTES = _fs.READ_CHUNK_BYTES
_read_fd_bounded = _fs._read_fd_bounded
_read_regular_bytes = _fs._read_regular_bytes
_candidate_files = _fs._candidate_files
_read_regular_file = _fs._read_regular_file
_parse_fence_open = _snapshot._parse_fence_open
_is_fence_close = _snapshot._is_fence_close
_mermaid_block_count = _snapshot._mermaid_block_count
_write_snapshot = _snapshot._write_snapshot
_require_empty_render_root = _output._require_empty_render_root
_validate_rendered_outputs = _output._validate_rendered_outputs
_validate_generated_svgs = _output._validate_generated_svgs


def _ci_identity() -> tuple[str | None, str | None]:
    subject = os.environ.get("CI_SUBJECT_SHA")
    event = os.environ.get("GITHUB_SHA")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for name, value in (("CI_SUBJECT_SHA", subject), ("GITHUB_SHA", event)):
            if value is None or GITHUB_SHA_RE.fullmatch(value) is None:
                raise ValueError(f"{name} must be a full lowercase GitHub commit SHA in CI")
    return subject, event


def _snapshot_from_bytes(path: Path, data: bytes) -> MermaidDocumentSnapshot | None:
    count = _mermaid_block_count(data.decode("utf-8"))
    if not count:
        return None
    return MermaidDocumentSnapshot(path, count, data, hashlib.sha256(data).hexdigest())


def _discover_mermaid_snapshot(root: Path) -> list[MermaidDocumentSnapshot]:
    return _snapshot.discover_mermaid_snapshot(root, snapshot_factory=_snapshot_from_bytes)


def _discover_mermaid_documents(root: Path) -> list[tuple[Path, int]]:
    return [(item.relative_path, item.diagram_count) for item in _discover_mermaid_snapshot(root)]


def _resolve_docker_executable() -> str:
    discovered = shutil.which("docker")
    if discovered is None:
        raise RuntimeError("Docker executable is unavailable for Mermaid validation")
    try:
        resolved = Path(discovered).resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("Docker executable identity could not be resolved") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise RuntimeError("Docker executable is not an executable regular file")
    return str(resolved)


def _container_id_from_cidfile(path: Path) -> str | None:
    try:
        value = _read_regular_bytes(path, max_bytes=128, label="Mermaid renderer container id").decode(
            "ascii"
        ).strip()
    except (UnicodeDecodeError, ValueError):
        return None
    return value if CONTAINER_ID_RE.fullmatch(value) else None


def _remove_renderer_container(
    name: str, cidfile: Path, *, docker_executable: str = "docker"
) -> None:
    container_id = _container_id_from_cidfile(cidfile)
    target = container_id or name
    try:
        result = subprocess.run(
            [docker_executable, "rm", "--force", target],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=DOCKER_CLEANUP_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Mermaid renderer container cleanup could not be completed") from exc
    if container_id is None:
        raise RuntimeError(
            "Mermaid renderer exact container identity was unavailable during cleanup"
        )
    if result.returncode != 0:
        raise RuntimeError("Mermaid renderer container cleanup did not confirm removal")


def _copy_renderer_outputs(
    container_id: str, output_root: Path, *, docker_executable: str
) -> None:
    try:
        subprocess.run(
            [docker_executable, "cp", f"{container_id}:/out/.", str(output_root)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=DOCKER_COPY_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Mermaid renderer output copy could not be completed") from exc


def _run_mermaid(root: Path, relative: Path, output_root: Path, expected_count: int) -> None:
    _require_empty_render_root(output_root)
    docker_executable = _resolve_docker_executable()
    name = f"aiqa-mermaid-{os.getpid()}-{uuid.uuid4().hex}"
    cidfile = output_root.parent / f".{name}.cid"
    command = [
        docker_executable,
        "run",
        "--name",
        name,
        "--cidfile",
        str(cidfile),
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "1g",
        "--cpus",
        "2",
        "--ulimit",
        f"fsize={MAX_RENDER_FILE_BYTES}:{MAX_RENDER_FILE_BYTES}",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--env",
        "HOME=/tmp",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=256m",
        "--mount",
        f"type=bind,src={root},dst=/repo,readonly",
        "--tmpfs",
        (
            "/out:rw,noexec,nosuid,nodev,"
            f"size={MAX_RENDER_TOTAL_BYTES},nr_inodes={MAX_RENDER_OUTPUT_ENTRIES}"
        ),
        MERMAID_IMAGE,
        "-i",
        f"/repo/{relative.as_posix()}",
        "-o",
        "/out/rendered.md",
    ]
    error: RuntimeError | None = None
    cleanup_required = True
    try:
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=RENDER_TIMEOUT_SECONDS,
        )
        container_id = _container_id_from_cidfile(cidfile)
        if container_id is None:
            raise RuntimeError("Mermaid renderer did not publish an exact container identity")
        _copy_renderer_outputs(
            container_id, output_root, docker_executable=docker_executable
        )
    except subprocess.CalledProcessError as exc:
        error = RuntimeError(f"Mermaid render failed for {relative}")
        error.__cause__ = exc
    except subprocess.TimeoutExpired as exc:
        error = RuntimeError(f"Mermaid render exceeded {RENDER_TIMEOUT_SECONDS}s for {relative}")
        error.__cause__ = exc
    except OSError as exc:
        cleanup_required = False
        error = RuntimeError(f"Mermaid renderer could not be started for {relative}")
        error.__cause__ = exc
    finally:
        if cleanup_required:
            _remove_renderer_container(
                name, cidfile, docker_executable=docker_executable
            )
    if error is not None:
        raise error
    _validate_rendered_outputs(output_root, Path("rendered.md"), expected_count=expected_count)


def main() -> int:
    subject, event = _ci_identity()
    documents = _discover_mermaid_snapshot(Path.cwd().resolve())
    with tempfile.TemporaryDirectory(prefix="aiqa-mermaid-") as temp:
        temporary = Path(temp).resolve()
        source = temporary / "input"
        outputs = temporary / "output"
        source.mkdir()
        outputs.mkdir()
        for item in documents:
            _write_snapshot(source, item)
        for item in documents:
            with tempfile.TemporaryDirectory(prefix="render-", dir=outputs) as render_temp:
                output = Path(render_temp)
                _run_mermaid(source, item.relative_path, output, item.diagram_count)
    result = {
        "schema_version": 2,
        "validator": "official_mermaid_cli_container",
        "container": MERMAID_IMAGE,
        "subject_sha": subject,
        "github_event_sha": event,
        "documents": [
            {
                "path": item.relative_path.as_posix(),
                "diagram_count": item.diagram_count,
                "sha256": item.sha256,
            }
            for item in documents
        ],
        "document_count": len(documents),
        "diagram_count": sum(item.diagram_count for item in documents),
        "failures": 0,
    }
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import uuid
from collections.abc import Mapping
from pathlib import Path

from ai_qa_automation.tools.execution_env import resolve_executable, restricted_subprocess_env

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
MERMAID_EXECUTABLE = "/home/mermaidcli/node_modules/.bin/mmdc"
MERMAID_PUPPETEER_CONFIG = "/puppeteer-config.json"
RENDER_WRAPPER = (
    "status=0; "
    f'{MERMAID_EXECUTABLE} -p {MERMAID_PUPPETEER_CONFIG} -q -i "$1" '
    "-o /out/rendered.md || status=$?; "
    'if [ "$status" -eq 0 ]; then : > /tmp/aiqa-render-ok; fi; '
    ": > /tmp/aiqa-render-done; "
    "while :; do sleep 3600; done"
)
RENDER_WAIT_COMMAND = (
    "while [ ! -f /tmp/aiqa-render-done ]; do sleep 0.05; done; test -f /tmp/aiqa-render-ok"
)
GITHUB_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
DOCKER_START_TIMEOUT_SECONDS = 60
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
# The tmpfs bounds file data and inode count, but sparse files could have a
# larger logical tar representation. Cap the archive stream independently.
MAX_RENDER_ARCHIVE_BYTES = MAX_RENDER_TOTAL_BYTES + MAX_RENDER_OUTPUT_ENTRIES * 2048 + 65536
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


def _resolve_docker_executable(*, env: Mapping[str, str]) -> str:
    try:
        return resolve_executable("docker", env=env)
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "Docker executable is unavailable in trusted controller roots for Mermaid validation"
        ) from exc


def _container_id_from_cidfile(path: Path) -> str | None:
    try:
        value = (
            _read_regular_bytes(path, max_bytes=128, label="Mermaid renderer container id")
            .decode("ascii")
            .strip()
        )
    except (UnicodeDecodeError, ValueError):
        return None
    return value if CONTAINER_ID_RE.fullmatch(value) else None


def _remove_renderer_container(
    name: str,
    cidfile: Path,
    *,
    docker_executable: str,
    docker_env: Mapping[str, str],
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
            env=dict(docker_env),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Mermaid renderer container cleanup could not be completed") from exc
    if container_id is None:
        raise RuntimeError(
            "Mermaid renderer exact container identity was unavailable during cleanup"
        )
    if result.returncode != 0:
        raise RuntimeError("Mermaid renderer container cleanup did not confirm removal")


def _wait_renderer_completion(
    container_id: str,
    *,
    docker_executable: str,
    docker_env: Mapping[str, str],
) -> None:
    try:
        subprocess.run(
            [
                docker_executable,
                "exec",
                container_id,
                "/bin/sh",
                "-c",
                RENDER_WAIT_COMMAND,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=RENDER_TIMEOUT_SECONDS,
            env=dict(docker_env),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Mermaid render exceeded {RENDER_TIMEOUT_SECONDS}s") from exc
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("Mermaid renderer did not complete successfully") from exc


def _archive_member_name(member: tarfile.TarInfo) -> str | None:
    name = member.name
    while name.startswith("./"):
        name = name[2:]
    if name in {"", "."}:
        return None if member.isdir() else ""
    if name in {".."} or "/" in name or "\\" in name or Path(name).is_absolute():
        return ""
    return name


def _write_archive_member(root_fd: int, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, 0o600, dir_fd=root_fd)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view[:READ_CHUNK_BYTES])
            if written <= 0:
                raise RuntimeError("Mermaid renderer output could not be materialized")
            view = view[written:]
    finally:
        os.close(fd)


def _materialize_renderer_archive(
    archive: bytes, output_root: Path, *, expected_count: int
) -> None:
    if len(archive) > MAX_RENDER_ARCHIVE_BYTES:
        raise RuntimeError("Mermaid renderer archive exceeded the bounded output budget")
    expected_names = {"rendered.md"} | {
        f"rendered-{index}.svg" for index in range(1, expected_count + 1)
    }
    seen: set[str] = set()
    total_bytes = 0
    root_fd = os.open(
        output_root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        try:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as rendered:
                for index, member in enumerate(rendered, start=1):
                    if index > MAX_RENDER_OUTPUT_ENTRIES + 1:
                        raise RuntimeError("Mermaid renderer archive exceeded the entry budget")
                    name = _archive_member_name(member)
                    if name is None:
                        continue
                    if (
                        not name
                        or name not in expected_names
                        or name in seen
                        or not member.isfile()
                    ):
                        raise RuntimeError(
                            "Mermaid renderer archive contained an invalid output entry"
                        )
                    if member.size <= 0 or member.size > MAX_RENDER_FILE_BYTES:
                        raise RuntimeError(
                            "Mermaid renderer archive contained an invalid output size"
                        )
                    total_bytes += member.size
                    if total_bytes > MAX_RENDER_TOTAL_BYTES:
                        raise RuntimeError(
                            "Mermaid renderer archive exceeded the aggregate byte budget"
                        )
                    extracted = rendered.extractfile(member)
                    if extracted is None:
                        raise RuntimeError("Mermaid renderer archive member could not be read")
                    data = extracted.read(member.size + 1)
                    if len(data) != member.size:
                        raise RuntimeError("Mermaid renderer archive member was incomplete")
                    _write_archive_member(root_fd, name, data)
                    seen.add(name)
        except (tarfile.TarError, EOFError) as exc:
            raise RuntimeError("Mermaid renderer archive was invalid or incomplete") from exc
    finally:
        os.close(root_fd)
    if seen != expected_names:
        raise RuntimeError("Mermaid renderer archive did not contain the exact expected outputs")


def _copy_renderer_outputs(
    container_id: str,
    output_root: Path,
    *,
    expected_count: int,
    docker_executable: str,
    docker_env: Mapping[str, str],
) -> None:
    archive_command = (
        f"/bin/busybox tar -C /out -cf - . | /bin/busybox head -c {MAX_RENDER_ARCHIVE_BYTES + 1}"
    )
    try:
        result = subprocess.run(
            [docker_executable, "exec", container_id, "/bin/sh", "-c", archive_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=DOCKER_COPY_TIMEOUT_SECONDS,
            env=dict(docker_env),
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Mermaid renderer output archive could not be collected") from exc
    archive = result.stdout
    if len(archive) > MAX_RENDER_ARCHIVE_BYTES:
        raise RuntimeError("Mermaid renderer archive exceeded the bounded output budget")
    _materialize_renderer_archive(archive, output_root, expected_count=expected_count)


def _run_mermaid(root: Path, relative: Path, output_root: Path, expected_count: int) -> None:
    _require_empty_render_root(output_root)
    docker_home = output_root.parent / f".docker-home-{uuid.uuid4().hex}"
    docker_env = restricted_subprocess_env(home=docker_home)
    docker_executable = _resolve_docker_executable(env=docker_env)
    name = f"aiqa-mermaid-{os.getpid()}-{uuid.uuid4().hex}"
    cidfile = output_root.parent / f".{name}.cid"
    input_path = f"/repo/{relative.as_posix()}"
    command = [
        docker_executable,
        "run",
        "--detach",
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
        "--entrypoint",
        "/bin/sh",
        MERMAID_IMAGE,
        "-c",
        RENDER_WRAPPER,
        "aiqa-mermaid-wrapper",
        input_path,
    ]
    error: RuntimeError | None = None
    cleanup_error: RuntimeError | None = None
    cleanup_required = True
    try:
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=DOCKER_START_TIMEOUT_SECONDS,
            env=dict(docker_env),
        )
        container_id = _container_id_from_cidfile(cidfile)
        if container_id is None:
            raise RuntimeError("Mermaid renderer did not publish an exact container identity")
        _wait_renderer_completion(
            container_id,
            docker_executable=docker_executable,
            docker_env=docker_env,
        )
        # Docker's archive API cannot copy tmpfs mounts. Stream a bounded tar
        # from the exact live container and validate every member before host write.
        _copy_renderer_outputs(
            container_id,
            output_root,
            expected_count=expected_count,
            docker_executable=docker_executable,
            docker_env=docker_env,
        )
    except subprocess.CalledProcessError as exc:
        error = RuntimeError(f"Mermaid renderer could not be started for {relative}")
        error.__cause__ = exc
    except subprocess.TimeoutExpired as exc:
        error = RuntimeError(
            f"Mermaid renderer start exceeded {DOCKER_START_TIMEOUT_SECONDS}s for {relative}"
        )
        error.__cause__ = exc
    except OSError as exc:
        cleanup_required = False
        error = RuntimeError(f"Mermaid renderer could not be started for {relative}")
        error.__cause__ = exc
    except RuntimeError as exc:
        error = exc
    finally:
        if cleanup_required:
            try:
                _remove_renderer_container(
                    name,
                    cidfile,
                    docker_executable=docker_executable,
                    docker_env=docker_env,
                )
            except RuntimeError as exc:
                cleanup_error = exc
    if cleanup_error is not None:
        if error is not None:
            raise RuntimeError(
                f"{error}; renderer cleanup authority also failed"
            ) from cleanup_error
        raise cleanup_error
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

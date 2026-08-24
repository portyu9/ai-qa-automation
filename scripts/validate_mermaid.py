from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

MERMAID_IMAGE = (
    "ghcr.io/mermaid-js/mermaid-cli/mermaid-cli@"
    "sha256:8cc6fb93037759668ac6c48d3b727da15c60419304f3bd4c69c8cd8589e2b485"
)
MERMAID_FENCE_RE = re.compile(r"^\s*```mermaid\s*$", re.MULTILINE)
MAX_MARKDOWN_FILES = 128
MAX_MARKDOWN_BYTES = 4 * 1024 * 1024
MAX_TOTAL_MARKDOWN_BYTES = 16 * 1024 * 1024


def _candidate_files(root: Path) -> list[Path]:
    candidates = [root / "README.md"]
    docs = root / "docs"
    if docs.exists():
        candidates.extend(sorted(docs.rglob("*.md")))
    return candidates


def _read_regular_file(path: Path) -> str:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"documentation path must be a regular non-symlink file: {path}")
    if before.st_size > MAX_MARKDOWN_BYTES:
        raise ValueError(f"documentation file exceeds {MAX_MARKDOWN_BYTES} bytes: {path}")
    data = path.read_bytes()
    after = path.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ValueError(f"documentation file changed during validation discovery: {path}")
    return data.decode("utf-8")


def _discover_mermaid_documents(root: Path) -> list[tuple[Path, int]]:
    selected: list[tuple[Path, int]] = []
    total_bytes = 0
    observed = 0
    for path in _candidate_files(root):
        if not path.exists():
            continue
        observed += 1
        if observed > MAX_MARKDOWN_FILES:
            raise ValueError(f"documentation corpus exceeds {MAX_MARKDOWN_FILES} Markdown files")
        text = _read_regular_file(path)
        total_bytes += len(text.encode("utf-8"))
        if total_bytes > MAX_TOTAL_MARKDOWN_BYTES:
            raise ValueError(
                f"documentation corpus exceeds {MAX_TOTAL_MARKDOWN_BYTES} total Markdown bytes"
            )
        count = len(MERMAID_FENCE_RE.findall(text))
        if count:
            selected.append((path.relative_to(root), count))
    if not selected:
        raise ValueError("no Mermaid diagrams discovered in README.md or docs/**/*.md")
    return selected


def _run_mermaid(root: Path, relative_path: Path, output_root: Path) -> None:
    destination = output_root / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "docker",
        "run",
        "--rm",
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
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=256m",
        "--mount",
        f"type=bind,src={root},dst=/repo,readonly",
        "--mount",
        f"type=bind,src={output_root},dst=/out",
        MERMAID_IMAGE,
        "-i",
        f"/repo/{relative_path.as_posix()}",
        "-o",
        f"/out/{relative_path.as_posix()}",
    ]
    subprocess.run(command, check=True)
    if not destination.is_file():
        raise RuntimeError(f"Mermaid CLI did not emit transformed Markdown for {relative_path}")


def main() -> int:
    root = Path.cwd().resolve()
    documents = _discover_mermaid_documents(root)
    with tempfile.TemporaryDirectory(prefix="aiqa-mermaid-") as temp_dir:
        output_root = Path(temp_dir).resolve()
        for relative_path, _ in documents:
            _run_mermaid(root, relative_path, output_root)

    result = {
        "schema_version": 1,
        "validator": "official_mermaid_cli_container",
        "container": MERMAID_IMAGE,
        "subject_sha": os.environ.get("GITHUB_SHA"),
        "documents": [
            {"path": path.as_posix(), "diagram_count": count} for path, count in documents
        ],
        "document_count": len(documents),
        "diagram_count": sum(count for _, count in documents),
        "failures": 0,
    }
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

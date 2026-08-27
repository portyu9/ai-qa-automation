from __future__ import annotations

import hashlib
import json
import os
import stat
import tomllib
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

MAX_PYPROJECT_BYTES = 256 * 1024
EXPECTED_BUILD_SYSTEM = {
    "requires": ["hatchling==1.32.0"],
    "build-backend": "hatchling.build",
}
EXPECTED_HATCH_CONFIG = {
    "build": {
        "targets": {
            "wheel": {
                "packages": ["src/ai_qa_automation"],
            }
        }
    }
}


def _read_pyproject(path: Path) -> tuple[bytes, str]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise RuntimeError("pre-build authority verification requires no-follow file open")
    if path.is_symlink():
        raise ValueError("pyproject.toml is a symlink and has ambiguous build authority")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | nofollow
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("pyproject.toml could not be opened safely") from exc

    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("pyproject.toml must be a regular non-symlink file")
        initial = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_PYPROJECT_BYTES:
            chunk = os.read(fd, min(64 * 1024, MAX_PYPROJECT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > MAX_PYPROJECT_BYTES:
            raise ValueError(f"pyproject.toml exceeds {MAX_PYPROJECT_BYTES} byte ingestion limit")
        final = os.fstat(fd)
        final_signature = (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        )
        if final_signature != initial or not stat.S_ISREG(final.st_mode):
            raise ValueError("pyproject.toml changed during pre-build authority verification")
        content = b"".join(chunks)
    finally:
        os.close(fd)

    try:
        current = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ValueError("pyproject.toml changed identity during verification") from exc
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
        raise ValueError("pyproject.toml changed file type during verification")
    if (current.st_dev, current.st_ino) != (initial[0], initial[1]):
        raise ValueError("pyproject.toml changed identity during verification")
    return content, hashlib.sha256(content).hexdigest()


def _parse_pyproject(content: bytes) -> dict[str, Any]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("pyproject.toml is not valid UTF-8") from exc
    parsed = tomllib.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("pyproject.toml root must be a table")
    return parsed


def _installed_hatch_entry_points() -> tuple[str, ...]:
    try:
        entry_points = importlib_metadata.entry_points(group="hatch")
    except Exception as exc:
        raise RuntimeError("installed Hatch plugin metadata could not be inspected safely") from exc

    observed = tuple(
        sorted(f"{entry_point.name}={entry_point.value}" for entry_point in entry_points)
    )
    if observed:
        raise ValueError(
            "installed third-party Hatch entry points are forbidden in the automatic build "
            f"environment: {list(observed)}"
        )
    return observed


def verify_build_authority(root: Path) -> dict[str, Any]:
    root = root.resolve()
    content, digest = _read_pyproject(root / "pyproject.toml")
    pyproject = _parse_pyproject(content)

    build_system = pyproject.get("build-system")
    if build_system != EXPECTED_BUILD_SYSTEM:
        raise ValueError(
            "build-system authority must be exactly hatchling.build with hatchling==1.32.0 "
            "and no backend-path or extra keys"
        )

    project = pyproject.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml must contain a project table")
    version = project.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("project version must remain static repository metadata")
    if project.get("dynamic"):
        raise ValueError("dynamic project metadata is forbidden in the automatic build authority")

    tool = pyproject.get("tool", {})
    if not isinstance(tool, dict):
        raise ValueError("pyproject.toml tool table must be a table")
    hatch = tool.get("hatch")
    if hatch != EXPECTED_HATCH_CONFIG:
        raise ValueError(
            "Hatch authority must be exactly the reviewed static wheel package selection; "
            "custom build hooks, metadata hooks, version sources, builders, and extra Hatch "
            "configuration are forbidden"
        )

    installed_hatch_entry_points = _installed_hatch_entry_points()

    return {
        "schema_version": 1,
        "result": "PASS",
        "claim": "project build configuration and installed Hatch plugin surface are static and contain no unreviewed source-execution extension points",
        "pyproject_sha256": digest,
        "build_backend": "hatchling.build",
        "build_requirements": ["hatchling==1.32.0"],
        "dynamic_metadata": False,
        "source_execution_extensions": False,
        "installed_hatch_entry_points": list(installed_hatch_entry_points),
        "limitations": [
            "This verifier constrains repository build configuration and installed Hatch plugin entry points; it does not attest the hosted Python interpreter or dependency package bytes beyond the repository's separate hash-lock controls.",
            "A future legitimate build hook, Hatch plugin, dynamic metadata source, custom builder, or backend change requires an explicit policy revision rather than implicit authority expansion.",
        ],
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    print(json.dumps(verify_build_authority(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

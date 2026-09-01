from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tomllib
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

MAX_PYPROJECT_BYTES = 256 * 1024
MAX_PROJECT_FILE_INPUT_BYTES = 2 * 1024 * 1024
MAX_BUILD_SOURCE_ENTRIES = 1024
MAX_BUILD_SOURCE_FILE_BYTES = 8 * 1024 * 1024
MAX_BUILD_SOURCE_TOTAL_BYTES = 32 * 1024 * 1024
MAX_REQUIREMENTS_ENTRIES = 32
MAX_LOCK_BYTES = 1024 * 1024
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
EXPECTED_BUILD_SOURCE_ROOT = Path("src/ai_qa_automation")
EXPECTED_PROJECT_FILE_INPUTS = {
    "readme": "README.md",
    "license": {"file": "LICENSE"},
}
EXPECTED_PROJECT_NAME = "ai-qa-automation"
EXPECTED_PROJECT_SCRIPTS = {"ai-qa": "ai_qa_automation.cli:app"}
FORBIDDEN_PROJECT_ENTRY_POINT_KEYS = ("gui-scripts", "entry-points")
EXPECTED_LOCK_BLOB_SHAS = {
    "base-image.lock": "ba4fdd5d0944e5cefe925743d21d661f2eed0d7d",  # pragma: allowlist secret
    "build-py311.lock": "3b7da9eed4eaede5653c54133cf15da9ee06390e",  # pragma: allowlist secret
    "dev-py311.lock": "d34c0fafd46403aeb93877d19fa03628278375c4",  # pragma: allowlist secret
    "dev-py314.lock": "b03147fb5b26ddcdf426299ff46b58533a6ddca8",  # pragma: allowlist secret
    "runtime-py311.lock": "ae2856b5bde92b398454081058f6082af915b532",  # pragma: allowlist secret
}


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _file_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _directory_signature(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mtime_ns, value.st_ctime_ns


def _git_blob_sha1(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


def _read_fd_bounded(fd: int, *, max_bytes: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= max_bytes:
        chunk = os.read(fd, min(64 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} byte ingestion limit")
    return b"".join(chunks)


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
        initial = _file_signature(opened)
        content = _read_fd_bounded(fd, max_bytes=MAX_PYPROJECT_BYTES, label="pyproject.toml")
        final = os.fstat(fd)
        if _file_signature(final) != initial or not stat.S_ISREG(final.st_mode):
            raise ValueError("pyproject.toml changed during pre-build authority verification")
    finally:
        os.close(fd)

    try:
        current = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ValueError("pyproject.toml changed identity during verification") from exc
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
        raise ValueError("pyproject.toml changed file type during verification")
    if _identity(current) != initial[:2]:
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


def _assert_regular_file(path: Path, *, label: str, max_bytes: int) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise RuntimeError("pre-build authority verification requires no-follow file open")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | nofollow
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} must be a regular non-symlink build input") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"{label} must be a regular non-symlink build input")
        if opened.st_size < 0 or opened.st_size > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} byte build-input limit")
        initial = _file_signature(opened)
        try:
            current = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError(
                f"{label} changed identity during build-authority verification"
            ) from exc
        if not stat.S_ISREG(current.st_mode) or _identity(current) != _identity(opened):
            raise ValueError(f"{label} changed identity during build-authority verification")
        final = os.fstat(fd)
        if _file_signature(final) != initial:
            raise ValueError(f"{label} changed during build-authority verification")
    finally:
        os.close(fd)


def _open_directory_nofollow(path: Path, *, label: str) -> int:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow:
        raise RuntimeError(
            "pre-build source verification requires descriptor-relative no-follow traversal"
        )
    try:
        fd = os.open(path, os.O_RDONLY | directory_flag | nofollow)
    except OSError as exc:
        raise ValueError(f"{label} must be a real non-symlink directory") from exc
    opened = os.fstat(fd)
    if not stat.S_ISDIR(opened.st_mode):
        os.close(fd)
        raise ValueError(f"{label} must be a real non-symlink directory")
    return fd


def _relative_stat(name: str, directory_fd: int) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except (TypeError, NotImplementedError) as exc:
        raise RuntimeError(
            "pre-build source verification requires descriptor-relative no-follow stat"
        ) from exc


def _relative_open(name: str, directory_fd: int, *, directory: bool) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | nofollow
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        return os.open(name, flags, dir_fd=directory_fd)
    except (TypeError, NotImplementedError) as exc:
        raise RuntimeError(
            "pre-build source verification requires descriptor-relative no-follow open"
        ) from exc
    except OSError as exc:
        raise ValueError("build source entry changed identity or became a symlink") from exc


def _verify_reviewed_lock_authority(root: Path) -> dict[str, str]:
    requirements = root / "requirements"
    directory_fd = _open_directory_nofollow(requirements, label="requirements")
    opened_directory = os.fstat(directory_fd)
    initial_signature = _directory_signature(opened_directory)
    observed_names: set[str] = set()
    observed_entries = 0

    try:
        try:
            entries = os.scandir(directory_fd)
        except (TypeError, NotImplementedError, OSError) as exc:
            raise RuntimeError(
                "dependency authority verification requires descriptor-based directory enumeration"
            ) from exc
        with entries:
            for entry in entries:
                observed_entries += 1
                if observed_entries > MAX_REQUIREMENTS_ENTRIES:
                    raise ValueError(
                        f"requirements directory exceeds {MAX_REQUIREMENTS_ENTRIES} entry ingestion limit"
                    )
                name = entry.name
                if name.endswith(".lock"):
                    if Path(name).name != name or name in {".", ".."}:
                        raise ValueError("requirements directory contains an invalid lock filename")
                    observed_names.add(name)

        if observed_names != set(EXPECTED_LOCK_BLOB_SHAS):
            raise ValueError(
                "dependency lock set differs from the exact reviewed automatic-install authority"
            )

        observed_blobs: dict[str, str] = {}
        for name, expected_blob in sorted(EXPECTED_LOCK_BLOB_SHAS.items()):
            label = f"reviewed dependency lock {name}"
            before = _relative_stat(name, directory_fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"{label} must be a regular non-symlink file")
            if before.st_size < 0 or before.st_size > MAX_LOCK_BYTES:
                raise ValueError(f"{label} exceeds {MAX_LOCK_BYTES} byte ingestion limit")
            try:
                file_fd = _relative_open(name, directory_fd, directory=False)
            except ValueError as exc:
                raise ValueError(
                    f"{label} could not be opened without following a symlink"
                ) from exc
            try:
                opened = os.fstat(file_fd)
                current = _relative_stat(name, directory_fd)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or not stat.S_ISREG(current.st_mode)
                    or _identity(opened) != _identity(current)
                    or _file_signature(opened) != _file_signature(before)
                ):
                    raise ValueError(f"{label} changed identity before ingestion")
                initial_file_signature = _file_signature(opened)
                content = _read_fd_bounded(file_fd, max_bytes=MAX_LOCK_BYTES, label=label)
                final_opened = os.fstat(file_fd)
                final_current = _relative_stat(name, directory_fd)
                if (
                    _file_signature(final_opened) != initial_file_signature
                    or _identity(final_opened) != _identity(final_current)
                    or not stat.S_ISREG(final_current.st_mode)
                ):
                    raise ValueError(f"{label} changed during ingestion")
            finally:
                os.close(file_fd)
            observed_blob = _git_blob_sha1(content)
            if observed_blob != expected_blob:
                raise ValueError(
                    f"{label} bytes differ from the exact reviewed automatic-install authority"
                )
            observed_blobs[name] = observed_blob

        final_opened_directory = os.fstat(directory_fd)
        final_current_directory = requirements.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(final_current_directory.st_mode)
            or _identity(final_opened_directory) != _identity(final_current_directory)
            or _directory_signature(final_opened_directory) != initial_signature
        ):
            raise ValueError(
                "requirements directory changed during dependency authority verification"
            )
        return observed_blobs
    finally:
        os.close(directory_fd)


def _assert_regular_source_tree(path: Path) -> tuple[int, int]:
    root_fd = _open_directory_nofollow(path, label=str(EXPECTED_BUILD_SOURCE_ROOT))
    root_opened = os.fstat(root_fd)
    root_signature = _directory_signature(root_opened)
    observed_entries = 0
    observed_bytes = 0

    def scan(directory_fd: int, relative: Path) -> None:
        nonlocal observed_entries, observed_bytes
        try:
            entries = os.scandir(directory_fd)
        except (TypeError, NotImplementedError, OSError) as exc:
            raise RuntimeError(
                "pre-build source verification requires descriptor-based directory enumeration"
            ) from exc

        names: list[str] = []
        with entries:
            for entry in entries:
                observed_entries += 1
                if observed_entries > MAX_BUILD_SOURCE_ENTRIES:
                    raise ValueError(
                        f"build source tree exceeds {MAX_BUILD_SOURCE_ENTRIES} entry ingestion limit"
                    )
                name = entry.name
                if Path(name).name != name or name in {".", ".."}:
                    raise ValueError("build source tree contains an invalid entry name")
                names.append(name)

        for name in sorted(names):
            entry_label = str(relative / name)
            before = _relative_stat(name, directory_fd)
            if stat.S_ISLNK(before.st_mode):
                raise ValueError(f"build source symlink is forbidden: {entry_label}")
            if stat.S_ISREG(before.st_mode):
                if before.st_size < 0 or before.st_size > MAX_BUILD_SOURCE_FILE_BYTES:
                    raise ValueError(
                        f"build source file exceeds {MAX_BUILD_SOURCE_FILE_BYTES} byte limit: "
                        f"{entry_label}"
                    )
                observed_bytes += before.st_size
                if observed_bytes > MAX_BUILD_SOURCE_TOTAL_BYTES:
                    raise ValueError(
                        "build source tree exceeds "
                        f"{MAX_BUILD_SOURCE_TOTAL_BYTES} total byte ingestion limit"
                    )
                file_fd = _relative_open(name, directory_fd, directory=False)
                try:
                    opened = os.fstat(file_fd)
                    current = _relative_stat(name, directory_fd)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or not stat.S_ISREG(current.st_mode)
                        or _identity(opened) != _identity(current)
                        or _file_signature(opened) != _file_signature(before)
                    ):
                        raise ValueError(
                            f"build source file changed during verification: {entry_label}"
                        )
                finally:
                    os.close(file_fd)
                continue
            if stat.S_ISDIR(before.st_mode):
                child_fd = _relative_open(name, directory_fd, directory=True)
                try:
                    opened = os.fstat(child_fd)
                    current = _relative_stat(name, directory_fd)
                    if (
                        not stat.S_ISDIR(opened.st_mode)
                        or not stat.S_ISDIR(current.st_mode)
                        or _identity(opened) != _identity(current)
                        or _directory_signature(opened) != _directory_signature(before)
                    ):
                        raise ValueError(
                            f"build source directory changed during verification: {entry_label}"
                        )
                    initial_signature = _directory_signature(opened)
                    scan(child_fd, relative / name)
                    final_opened = os.fstat(child_fd)
                    final_current = _relative_stat(name, directory_fd)
                    if (
                        _directory_signature(final_opened) != initial_signature
                        or _identity(final_opened) != _identity(final_current)
                        or not stat.S_ISDIR(final_current.st_mode)
                    ):
                        raise ValueError(
                            f"build source directory changed during verification: {entry_label}"
                        )
                finally:
                    os.close(child_fd)
                continue
            raise ValueError(f"build source special filesystem node is forbidden: {entry_label}")

    try:
        current_root = path.stat(follow_symlinks=False)
        if not stat.S_ISDIR(current_root.st_mode) or _identity(current_root) != _identity(
            root_opened
        ):
            raise ValueError("build source root changed identity during verification")
        scan(root_fd, EXPECTED_BUILD_SOURCE_ROOT)
        final_opened = os.fstat(root_fd)
        final_current = path.stat(follow_symlinks=False)
        if (
            _directory_signature(final_opened) != root_signature
            or _identity(final_opened) != _identity(final_current)
            or not stat.S_ISDIR(final_current.st_mode)
        ):
            raise ValueError("build source root changed during verification")
    finally:
        os.close(root_fd)
    return observed_entries, observed_bytes


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
    if project.get("name") != EXPECTED_PROJECT_NAME:
        raise ValueError(
            "project distribution name must remain ai-qa-automation so project installation "
            "cannot replace an unrelated locked distribution"
        )
    version = project.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("project version must remain static repository metadata")
    if project.get("dynamic"):
        raise ValueError("dynamic project metadata is forbidden in the automatic build authority")
    for key, expected in EXPECTED_PROJECT_FILE_INPUTS.items():
        if project.get(key) != expected:
            raise ValueError(f"project {key} build input differs from the reviewed repository path")
    if "license-files" in project:
        raise ValueError("project license-files may not expand automatic build file authority")
    if project.get("scripts") != EXPECTED_PROJECT_SCRIPTS:
        raise ValueError(
            "project console-script authority must remain exactly the reviewed ai-qa entry point"
        )
    for key in FORBIDDEN_PROJECT_ENTRY_POINT_KEYS:
        if key in project:
            raise ValueError(
                f"project {key} may not expand automatic executable or plugin authority"
            )

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

    reviewed_lock_blobs = _verify_reviewed_lock_authority(root)
    _assert_regular_file(
        root / "README.md",
        label="project readme",
        max_bytes=MAX_PROJECT_FILE_INPUT_BYTES,
    )
    _assert_regular_file(
        root / "LICENSE",
        label="project license",
        max_bytes=MAX_PROJECT_FILE_INPUT_BYTES,
    )
    build_source_entries, build_source_bytes = _assert_regular_source_tree(
        root / EXPECTED_BUILD_SOURCE_ROOT
    )
    installed_hatch_entry_points = _installed_hatch_entry_points()

    return {
        "schema_version": 1,
        "result": "PASS",
        "claim": "project build/install configuration, exact reviewed dependency locks, file inputs, source tree, and installed Hatch plugin surface contain no unreviewed automatic execution or filesystem authority",
        "pyproject_sha256": digest,
        "build_backend": "hatchling.build",
        "build_requirements": ["hatchling==1.32.0"],
        "project_name": EXPECTED_PROJECT_NAME,
        "project_scripts": EXPECTED_PROJECT_SCRIPTS,
        "project_entry_points": False,
        "reviewed_lock_blobs": reviewed_lock_blobs,
        "project_file_inputs": EXPECTED_PROJECT_FILE_INPUTS,
        "project_file_input_max_bytes": MAX_PROJECT_FILE_INPUT_BYTES,
        "build_source_root": str(EXPECTED_BUILD_SOURCE_ROOT),
        "build_source_entries": build_source_entries,
        "build_source_bytes": build_source_bytes,
        "build_source_max_file_bytes": MAX_BUILD_SOURCE_FILE_BYTES,
        "build_source_max_total_bytes": MAX_BUILD_SOURCE_TOTAL_BYTES,
        "build_source_symlinks": False,
        "dynamic_metadata": False,
        "source_execution_extensions": False,
        "installed_hatch_entry_points": list(installed_hatch_entry_points),
        "limitations": [
            "This verifier constrains the exact reviewed automatic-install lock bytes, repository build configuration, project distribution/executable metadata, declared file inputs, selected package-tree entry/byte volume, and installed Hatch plugin entry points; it does not attest the hosted Python interpreter or the publisher identity of the already reviewed hash-locked packages.",
            "The filesystem checks reject symlinks and special nodes during bounded observation; they do not create a privileged immutable filesystem snapshot after verification.",
            "A legitimate dependency-lock change, build hook, Hatch plugin, dynamic metadata source, custom builder, backend change, distribution-name change, project executable/entry-point change, larger build-input budget, additional file-valued metadata input, or package symlink requires an explicit policy revision rather than implicit authority expansion.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify project build and automatic-install authority"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="project source root to verify",
    )
    args = parser.parse_args()
    print(json.dumps(verify_build_authority(args.root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

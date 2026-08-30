from __future__ import annotations

import ast
import errno
import hashlib
import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from ai_qa_automation.io_safety import read_text_bounded

MAX_LOCK_BYTES = 1_048_576
MAX_REQUIREMENTS_ENTRIES = 32
EXPECTED_LOCK_NAMES = {
    "base-image.lock",
    "build-py311.lock",
    "dev-py311.lock",
    "dev-py313.lock",
    "runtime-py311.lock",
}
EXPECTED_ACTION_SHAS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",  # pragma: allowlist secret
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",  # pragma: allowlist secret
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",  # pragma: allowlist secret
}
EXPECTED_PRECOMMIT_REVISIONS = {
    "https://github.com/astral-sh/ruff-pre-commit": "7c55798a78262d14b2074abf623d8a992ebb70d4",  # pragma: allowlist secret
}
EXPECTED_GITHUB_MCP_IMAGE = (
    "ghcr.io/github/github-mcp-server:v1.0.4@"
    "sha256:e3816a476a977cfb836e7d221510011436c654d11861db66ecfd826601aba6a4"
)
BUILD_ONLY_RUNTIME_DENY = {
    "hatchling",
    "pathspec",
    "pluggy",
    "tomlkit",
    "trove-classifiers",
}
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s*\\)?$")
ANY_HASH_RE = re.compile(r"--hash=([^\s\\]+)")
ACTION_RE = re.compile(r"^\s*uses:\s*([^@\s]+)@([^\s#]+)", re.MULTILINE)
FROM_RE = re.compile(r"^FROM\s+([^\s]+)(?:\s+AS\s+\S+)?\s*$", re.MULTILINE | re.IGNORECASE)
EDITABLE_INSTALL_RE = re.compile(
    r"^\s*python\s+-m\s+pip\s+install\b[^\n]*(?:\s-e(?:\s|=)|\s--editable(?:\s|=))",
    re.MULTILINE,
)
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
BASE_IMAGE_RE = re.compile(r"^python:3\.11\.16-slim@sha256:[0-9a-f]{64}$")
GITHUB_MCP_IMAGE_RE = re.compile(
    r"^ghcr\.io/github/github-mcp-server:v[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$"
)
EXPECTED_DOCKERFILE_BLOB_SHA = (
    "cb343dd763dc17ce3f22179d1e94e1618b3cde38"  # pragma: allowlist secret
)


@dataclass(frozen=True)
class LockedRequirement:
    name: str
    version: str
    hashes: tuple[str, ...]


@dataclass(frozen=True)
class LockFileSnapshot:
    text: str
    sha256: str
    size_bytes: int


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _stable_file_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stable_directory_signature(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mtime_ns, value.st_ctime_ns


def _git_blob_sha1(text: str) -> str:
    content = text.encode("utf-8")
    header = f"blob {len(content)}\0".encode()
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


def _read_fd_bounded(fd: int, *, max_bytes: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= max_bytes:
        chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} byte ingestion limit")
    return b"".join(chunks)


def _relative_stat(name: str, directory_fd: int) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except (TypeError, NotImplementedError) as exc:
        raise RuntimeError(
            "supply-chain lock verification requires descriptor-relative no-follow stat"
        ) from exc


def _relative_open(name: str, flags: int, directory_fd: int, *, label: str) -> int:
    try:
        return os.open(name, flags, dir_fd=directory_fd)
    except (TypeError, NotImplementedError) as exc:
        raise RuntimeError(
            "supply-chain lock verification requires descriptor-relative no-follow open"
        ) from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{label} became a symlink during verification") from exc
        raise


def _read_lock_set(requirements_dir: Path) -> dict[str, LockFileSnapshot]:
    """Read the exact managed lock set through one pinned no-follow directory descriptor."""

    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow:
        raise RuntimeError(
            "supply-chain lock verification requires descriptor-relative no-follow ingestion"
        )
    directory_flags = os.O_RDONLY | directory_flag | nofollow

    if requirements_dir.is_symlink():
        raise ValueError("requirements directory is a symlink and has ambiguous ownership")
    try:
        directory_fd = os.open(requirements_dir, directory_flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError("requirements directory became a symlink during verification") from exc
        raise

    try:
        opened_directory = os.fstat(directory_fd)
        if not stat.S_ISDIR(opened_directory.st_mode):
            raise ValueError("requirements path must be a directory")
        try:
            current_directory = requirements_dir.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError("requirements directory changed identity during verification") from exc
        if stat.S_ISLNK(current_directory.st_mode):
            raise ValueError("requirements directory became a symlink during verification")
        if _identity(opened_directory) != _identity(current_directory):
            raise ValueError("requirements directory changed identity during verification")
        initial_directory_signature = _stable_directory_signature(opened_directory)

        try:
            entries = os.scandir(directory_fd)
        except (TypeError, NotImplementedError, OSError) as exc:
            raise RuntimeError(
                "supply-chain lock verification requires descriptor-based directory enumeration"
            ) from exc

        snapshots: dict[str, LockFileSnapshot] = {}
        observed_entries = 0
        with entries:
            for entry in entries:
                observed_entries += 1
                if observed_entries > MAX_REQUIREMENTS_ENTRIES:
                    raise ValueError(
                        "requirements directory exceeds "
                        f"{MAX_REQUIREMENTS_ENTRIES} entry ingestion limit"
                    )
                name = entry.name
                if not name.endswith(".lock"):
                    continue
                if Path(name).name != name or name in {".", ".."}:
                    raise ValueError("requirements directory contains an invalid lock filename")

                label = f"supply-chain lock {name}"
                before = _relative_stat(name, directory_fd)
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError(f"{label} must be a regular non-symlink file")

                file_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | nofollow
                file_fd = _relative_open(name, file_flags, directory_fd, label=label)
                try:
                    opened_file = os.fstat(file_fd)
                    if not stat.S_ISREG(opened_file.st_mode):
                        raise ValueError(f"{label} must be a regular file")
                    current_file = _relative_stat(name, directory_fd)
                    if not stat.S_ISREG(current_file.st_mode):
                        raise ValueError(f"{label} changed file type during verification")
                    if _identity(opened_file) != _identity(current_file):
                        raise ValueError(f"{label} changed identity during verification")
                    initial_file_signature = _stable_file_signature(opened_file)

                    content = _read_fd_bounded(
                        file_fd,
                        max_bytes=MAX_LOCK_BYTES,
                        label=label,
                    )

                    final_opened_file = os.fstat(file_fd)
                    final_current_file = _relative_stat(name, directory_fd)
                    if (
                        _stable_file_signature(final_opened_file) != initial_file_signature
                        or _identity(final_opened_file) != _identity(final_current_file)
                        or not stat.S_ISREG(final_current_file.st_mode)
                    ):
                        raise ValueError(f"{label} changed during verification")
                finally:
                    os.close(file_fd)

                snapshots[name] = LockFileSnapshot(
                    text=content.decode("utf-8"),
                    sha256=hashlib.sha256(content).hexdigest(),
                    size_bytes=len(content),
                )

        if set(snapshots) != EXPECTED_LOCK_NAMES:
            raise ValueError(
                "unexpected lock set: expected "
                f"{sorted(EXPECTED_LOCK_NAMES)}, got {sorted(snapshots)}"
            )

        final_opened_directory = os.fstat(directory_fd)
        try:
            final_current_directory = requirements_dir.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError("requirements directory changed identity during verification") from exc
        if (
            stat.S_ISLNK(final_current_directory.st_mode)
            or not stat.S_ISDIR(final_current_directory.st_mode)
            or _identity(final_opened_directory) != _identity(final_current_directory)
            or _stable_directory_signature(final_opened_directory) != initial_directory_signature
        ):
            raise ValueError("requirements directory changed during verification")
        return snapshots
    finally:
        os.close(directory_fd)


def _read_regular_text(path: Path, *, max_bytes: int = MAX_LOCK_BYTES) -> str:
    text = read_text_bounded(path, max_bytes=max_bytes, label=str(path))
    if not text:
        raise ValueError(f"{path} must not be empty")
    return text


def _parse_hash_lock_text(text: str, *, source: str) -> dict[str, LockedRequirement]:
    lines = text.splitlines()
    requirements: dict[str, LockedRequirement] = {}
    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        if line[0].isspace():
            raise ValueError(f"{source}:{index + 1}: orphan continuation line")
        if stripped.startswith(
            ("-e ", "--editable", "--index-url", "--extra-index-url", "--find-links")
        ):
            raise ValueError(f"{source}:{index + 1}: unsupported lock directive")

        requirement_text = stripped.removesuffix("\\").rstrip()
        requirement = Requirement(requirement_text)
        if requirement.url is not None:
            raise ValueError(f"{source}:{index + 1}: direct URL/VCS requirements are forbidden")
        specifiers = list(requirement.specifier)
        if (
            len(specifiers) != 1
            or specifiers[0].operator != "=="
            or specifiers[0].version.endswith(".*")
        ):
            raise ValueError(f"{source}:{index + 1}: requirement must use one exact == pin")

        hashes: list[str] = []
        index += 1
        while index < len(lines) and (not lines[index] or lines[index][0].isspace()):
            continuation = lines[index].strip()
            if continuation and not continuation.startswith("#"):
                any_hash = ANY_HASH_RE.search(continuation)
                if any_hash and not continuation.startswith("--hash=sha256:"):
                    raise ValueError(f"{source}:{index + 1}: only SHA-256 hashes are accepted")
                match = HASH_RE.fullmatch(continuation)
                if not match:
                    raise ValueError(f"{source}:{index + 1}: unsupported lock continuation")
                hashes.append(match.group(1))
            index += 1

        if not hashes:
            raise ValueError(f"{source}: {requirement.name} is missing SHA-256 hashes")
        canonical_name = canonicalize_name(requirement.name)
        if canonical_name in requirements:
            raise ValueError(f"{source}: duplicate locked package {canonical_name}")
        requirements[canonical_name] = LockedRequirement(
            name=canonical_name,
            version=specifiers[0].version,
            hashes=tuple(hashes),
        )

    if not requirements:
        raise ValueError(f"{source} contains no locked requirements")
    return requirements


def parse_hash_lock(path: Path) -> dict[str, LockedRequirement]:
    return _parse_hash_lock_text(_read_regular_text(path), source=str(path))


def _assert_declared_requirements_satisfied(
    declared: list[str], locked: dict[str, LockedRequirement], *, context: str
) -> None:
    for raw in declared:
        requirement = Requirement(raw)
        if requirement.url is not None:
            raise ValueError(f"{context}: direct URL/VCS declaration is forbidden: {raw}")
        name = canonicalize_name(requirement.name)
        candidate = locked.get(name)
        if candidate is None:
            raise ValueError(f"{context}: declared dependency {name} is absent from the lock")
        if requirement.specifier and not requirement.specifier.contains(
            Version(candidate.version), prereleases=True
        ):
            raise ValueError(
                f"{context}: locked {name}=={candidate.version} violates declaration {raw}"
            )


def _verify_locks(root: Path, pyproject: dict[str, Any]) -> tuple[dict[str, Any], str]:
    requirements_dir = root / "requirements"
    snapshots = _read_lock_set(requirements_dir)

    runtime = _parse_hash_lock_text(
        snapshots["runtime-py311.lock"].text,
        source=str(requirements_dir / "runtime-py311.lock"),
    )
    build = _parse_hash_lock_text(
        snapshots["build-py311.lock"].text,
        source=str(requirements_dir / "build-py311.lock"),
    )
    dev311 = _parse_hash_lock_text(
        snapshots["dev-py311.lock"].text,
        source=str(requirements_dir / "dev-py311.lock"),
    )
    dev313 = _parse_hash_lock_text(
        snapshots["dev-py313.lock"].text,
        source=str(requirements_dir / "dev-py313.lock"),
    )

    project = pyproject["project"]
    runtime_declared = list(project.get("dependencies", []))
    dev_declared = runtime_declared + list(project.get("optional-dependencies", {}).get("dev", []))
    _assert_declared_requirements_satisfied(runtime_declared, runtime, context="runtime lock")
    _assert_declared_requirements_satisfied(dev_declared, dev311, context="Python 3.11 dev lock")
    _assert_declared_requirements_satisfied(dev_declared, dev313, context="Python 3.13 dev lock")

    build_requires = list(pyproject["build-system"].get("requires", []))
    if build_requires != ["hatchling==1.32.0"]:
        raise ValueError("build-system authority must be exactly hatchling==1.32.0")
    _assert_declared_requirements_satisfied(build_requires, build, context="build lock")

    leaked = BUILD_ONLY_RUNTIME_DENY.intersection(runtime)
    if leaked:
        raise ValueError(f"runtime lock contains build-only packages: {sorted(leaked)}")

    lock_summary: dict[str, Any] = {
        name: {
            "sha256": snapshot.sha256,
            "size_bytes": snapshot.size_bytes,
        }
        for name, snapshot in sorted(snapshots.items())
    }
    lock_summary["build-py311.lock"]["packages"] = len(build)
    lock_summary["runtime-py311.lock"]["packages"] = len(runtime)
    lock_summary["dev-py311.lock"]["packages"] = len(dev311)
    lock_summary["dev-py313.lock"]["packages"] = len(dev313)
    return lock_summary, snapshots["base-image.lock"].text.strip()


def _verify_docker(root: Path, base_text: str) -> str:
    if not BASE_IMAGE_RE.fullmatch(base_text):
        raise ValueError("base-image.lock does not identify the expected digest-pinned Python base")

    docker = _read_regular_text(root / "Dockerfile", max_bytes=64 * 1024)
    if _git_blob_sha1(docker) != EXPECTED_DOCKERFILE_BLOB_SHA:
        raise ValueError(
            "Dockerfile bytes differ from the exact reviewed runtime-composition definition"
        )
    from_subjects = FROM_RE.findall(docker)
    if from_subjects != [base_text, base_text]:
        raise ValueError("every Docker stage must use the exact subject in base-image.lock")
    forbidden = ("pip install --upgrade", "python -m pip install .", "pip install .")
    if any(token in docker for token in forbidden):
        raise ValueError("Dockerfile contains live/unbounded package installation")
    required_tokens = (
        "--require-hashes -r requirements/build-py311.lock",
        "--require-hashes -r requirements/runtime-py311.lock",
        "--no-deps --no-build-isolation",
        "SOURCE_DATE_EPOCH=315532800",
    )
    if not all(token in docker for token in required_tokens):
        raise ValueError("Dockerfile is missing required locked/reproducible build controls")
    return base_text


def _verify_workflow(root: Path) -> dict[str, str]:
    workflow = _read_regular_text(root / ".github" / "workflows" / "ci.yml", max_bytes=256 * 1024)
    if "ubuntu-latest" in workflow:
        raise ValueError("permanent CI must not use the moving ubuntu-latest label")
    if '"3.11.16"' not in workflow or '"3.13.15"' not in workflow:
        raise ValueError("permanent CI must name exact supported Python patch versions")
    if (
        "pip install --upgrade" in workflow
        or "-e '.[dev]'" in workflow
        or EDITABLE_INSTALL_RE.search(workflow)
    ):
        raise ValueError("permanent CI contains live or editable dependency installation")
    if "--require-hashes" not in workflow:
        raise ValueError("permanent CI does not enforce hash-required installation")

    observed: dict[str, str] = {}
    for action, revision in ACTION_RE.findall(workflow):
        if not HEX40_RE.fullmatch(revision):
            raise ValueError(f"mutable GitHub Action reference: {action}@{revision}")
        expected = EXPECTED_ACTION_SHAS.get(action)
        if expected is None:
            raise ValueError(f"unreviewed GitHub Action in permanent CI: {action}")
        if revision != expected:
            raise ValueError(f"unexpected immutable revision for {action}: {revision}")
        observed[action] = revision
    if set(observed) != set(EXPECTED_ACTION_SHAS):
        raise ValueError("permanent CI Action set differs from the reviewed immutable set")
    return observed


def _verify_precommit(root: Path) -> dict[str, str]:
    text = _read_regular_text(root / ".pre-commit-config.yaml", max_bytes=64 * 1024)
    observed: dict[str, str] = {}
    current_repo: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("- repo:"):
            current_repo = line.split(":", 1)[1].strip()
        elif line.startswith("rev:"):
            if current_repo is None:
                raise ValueError("pre-commit revision is not associated with a repository")
            revision = line.split(":", 1)[1].strip().split()[0]
            if not HEX40_RE.fullmatch(revision):
                raise ValueError(f"mutable pre-commit revision: {current_repo}@{revision}")
            expected = EXPECTED_PRECOMMIT_REVISIONS.get(current_repo)
            if expected is None or revision != expected:
                raise ValueError(f"unreviewed pre-commit revision: {current_repo}@{revision}")
            observed[current_repo] = revision
    if observed != EXPECTED_PRECOMMIT_REVISIONS:
        raise ValueError(
            "pre-commit repository/revision set differs from the reviewed immutable set"
        )
    return observed


def _validate_github_mcp_image_reference(image: str) -> str:
    if not GITHUB_MCP_IMAGE_RE.fullmatch(image):
        raise ValueError(
            "GitHub MCP image must be an immutable ghcr.io/github/github-mcp-server "
            "semantic-version reference pinned with @sha256:<64 lowercase hex>"
        )
    if image != EXPECTED_GITHUB_MCP_IMAGE:
        raise ValueError(f"unexpected immutable GitHub MCP image: {image}")
    return image


def _verify_github_mcp(root: Path) -> str:
    config_text = _read_regular_text(root / ".mcp.json", max_bytes=64 * 1024)
    try:
        config = json.loads(config_text)
        args = config["mcpServers"]["github"]["args"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(".mcp.json must define the reviewed GitHub MCP stdio configuration") from exc
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise ValueError("GitHub MCP docker args must be a string list")
    config_refs = [
        item for item in args if item.startswith("ghcr.io/github/github-mcp-server")
    ]
    if len(config_refs) != 1:
        raise ValueError(".mcp.json must contain exactly one GitHub MCP image reference")
    config_image = _validate_github_mcp_image_reference(config_refs[0])
    if args[-1] != config_image:
        raise ValueError("GitHub MCP image must be the terminal docker run argument")

    runtime_source = _read_regular_text(
        root / "src" / "ai_qa_automation" / "integrations" / "github_mcp.py",
        max_bytes=64 * 1024,
    )
    try:
        tree = ast.parse(runtime_source, filename="src/ai_qa_automation/integrations/github_mcp.py")
    except SyntaxError as exc:
        raise ValueError("GitHub MCP runtime configuration source is not valid Python") from exc
    runtime_refs = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("ghcr.io/github/github-mcp-server")
    ]
    if len(runtime_refs) != 1:
        raise ValueError("runtime GitHub MCP configuration must contain exactly one image authority")
    runtime_image = _validate_github_mcp_image_reference(runtime_refs[0])
    if runtime_image != config_image:
        raise ValueError("runtime and .mcp.json GitHub MCP image authorities differ")
    return runtime_image


def verify_repository(root: Path) -> dict[str, Any]:
    root = root.resolve()
    pyproject_path = root / "pyproject.toml"
    pyproject = tomllib.loads(_read_regular_text(pyproject_path, max_bytes=256 * 1024))
    locks, base_image_lock = _verify_locks(root, pyproject)
    base_image = _verify_docker(root, base_image_lock)
    actions = _verify_workflow(root)
    precommit = _verify_precommit(root)
    github_mcp_image = _verify_github_mcp(root)
    return {
        "schema_version": 1,
        "result": "PASS",
        "claim": "repository supply-chain inputs satisfy deterministic integrity invariants",
        "locks": locks,
        "base_image": base_image,
        "dockerfile_authority": "exact-reviewed-git-blob",
        "actions": actions,
        "precommit": precommit,
        "github_mcp_image": github_mcp_image,
        "limitations": [
            "Package hashes bind accepted bytes but do not make the public package index continuously available.",
            "ubuntu-24.04 names a stable runner family, not an immutable GitHub-hosted runner image revision.",
            "This verifier does not provide artifact identity signing or registry transparency evidence.",
        ],
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    print(json.dumps(verify_repository(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

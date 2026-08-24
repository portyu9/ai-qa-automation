from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

MAX_LOCK_BYTES = 1_048_576
EXPECTED_LOCK_NAMES = {
    "base-image.lock",
    "build-py311.lock",
    "dev-py311.lock",
    "dev-py313.lock",
    "runtime-py311.lock",
}
EXPECTED_ACTION_SHAS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
}
EXPECTED_PRECOMMIT_REVISIONS = {
    "https://github.com/astral-sh/ruff-pre-commit": "7c55798a78262d14b2074abf623d8a992ebb70d4",
}
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
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
BASE_IMAGE_RE = re.compile(r"^python:3\.11\.16-slim@sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class LockedRequirement:
    name: str
    version: str
    hashes: tuple[str, ...]


def _read_regular_text(path: Path, *, max_bytes: int = MAX_LOCK_BYTES) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path} must be a regular non-symlink file")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(f"{path} size {size} is outside the allowed range")
    return path.read_text(encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_hash_lock(path: Path) -> dict[str, LockedRequirement]:
    text = _read_regular_text(path)
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
            raise ValueError(f"{path}:{index + 1}: orphan continuation line")
        if stripped.startswith(("-e ", "--editable", "--index-url", "--extra-index-url", "--find-links")):
            raise ValueError(f"{path}:{index + 1}: unsupported lock directive")

        requirement_text = stripped.removesuffix("\\").rstrip()
        requirement = Requirement(requirement_text)
        if requirement.url is not None:
            raise ValueError(f"{path}:{index + 1}: direct URL/VCS requirements are forbidden")
        specifiers = list(requirement.specifier)
        if len(specifiers) != 1 or specifiers[0].operator != "==" or specifiers[0].version.endswith(".*"):
            raise ValueError(f"{path}:{index + 1}: requirement must use one exact == pin")

        hashes: list[str] = []
        index += 1
        while index < len(lines) and (not lines[index] or lines[index][0].isspace()):
            continuation = lines[index].strip()
            if continuation and not continuation.startswith("#"):
                any_hash = ANY_HASH_RE.search(continuation)
                if any_hash and not continuation.startswith("--hash=sha256:"):
                    raise ValueError(f"{path}:{index + 1}: only SHA-256 hashes are accepted")
                match = HASH_RE.fullmatch(continuation)
                if not match:
                    raise ValueError(f"{path}:{index + 1}: unsupported lock continuation")
                hashes.append(match.group(1))
            index += 1

        if not hashes:
            raise ValueError(f"{path}: {requirement.name} is missing SHA-256 hashes")
        canonical_name = canonicalize_name(requirement.name)
        if canonical_name in requirements:
            raise ValueError(f"{path}: duplicate locked package {canonical_name}")
        requirements[canonical_name] = LockedRequirement(
            name=canonical_name,
            version=specifiers[0].version,
            hashes=tuple(hashes),
        )

    if not requirements:
        raise ValueError(f"{path} contains no locked requirements")
    return requirements


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


def _verify_locks(root: Path, pyproject: dict[str, Any]) -> dict[str, Any]:
    requirements_dir = root / "requirements"
    observed = {path.name for path in requirements_dir.glob("*.lock")}
    if observed != EXPECTED_LOCK_NAMES:
        raise ValueError(
            f"unexpected lock set: expected {sorted(EXPECTED_LOCK_NAMES)}, got {sorted(observed)}"
        )

    runtime_path = requirements_dir / "runtime-py311.lock"
    build_path = requirements_dir / "build-py311.lock"
    dev311_path = requirements_dir / "dev-py311.lock"
    dev313_path = requirements_dir / "dev-py313.lock"

    runtime = parse_hash_lock(runtime_path)
    build = parse_hash_lock(build_path)
    dev311 = parse_hash_lock(dev311_path)
    dev313 = parse_hash_lock(dev313_path)

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

    lock_summary: dict[str, Any] = {}
    for path in sorted(requirements_dir.glob("*.lock")):
        lock_summary[path.name] = {
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
    lock_summary["build-py311.lock"]["packages"] = len(build)
    lock_summary["runtime-py311.lock"]["packages"] = len(runtime)
    lock_summary["dev-py311.lock"]["packages"] = len(dev311)
    lock_summary["dev-py313.lock"]["packages"] = len(dev313)
    return lock_summary


def _verify_docker(root: Path) -> str:
    base_text = _read_regular_text(root / "requirements" / "base-image.lock", max_bytes=256).strip()
    if not BASE_IMAGE_RE.fullmatch(base_text):
        raise ValueError("base-image.lock does not identify the expected digest-pinned Python base")

    docker = _read_regular_text(root / "Dockerfile", max_bytes=64 * 1024)
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
    if "pip install --upgrade" in workflow or "-e '.[dev]'" in workflow:
        raise ValueError("permanent CI contains live dependency resolution")
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
        raise ValueError("pre-commit repository/revision set differs from the reviewed immutable set")
    return observed


def verify_repository(root: Path) -> dict[str, Any]:
    root = root.resolve()
    pyproject_path = root / "pyproject.toml"
    pyproject = tomllib.loads(_read_regular_text(pyproject_path, max_bytes=256 * 1024))
    locks = _verify_locks(root, pyproject)
    base_image = _verify_docker(root)
    actions = _verify_workflow(root)
    precommit = _verify_precommit(root)
    return {
        "schema_version": 1,
        "result": "PASS",
        "claim": "repository supply-chain inputs satisfy deterministic integrity invariants",
        "locks": locks,
        "base_image": base_image,
        "actions": actions,
        "precommit": precommit,
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

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

MAX_PYPROJECT_BYTES = 256 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_PACKAGES = 512
MAX_REQUIREMENTS = 256
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUIREMENT_NAME = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?(?P<specifier>[^;@\s]*)$")
EXACT_BUILD_REQUIREMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[^\s;@]+$")
ALLOWED_DOWNLOAD_HOSTS = {"files.pythonhosted.org", "pypi.org"}


class LockCompileError(RuntimeError):
    pass


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _git_blob_sha1(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) > MAX_REPORT_BYTES:
        raise LockCompileError(f"pip report exceeds {MAX_REPORT_BYTES} bytes")
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        raise LockCompileError("pip report is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise LockCompileError("pip report root must be an object")
    return payload


def _resolver_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("PIP_", "PYTHONPATH", "UV_")):
            env.pop(key, None)
    env.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PIP_INDEX_URL": "https://pypi.org/simple",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return env


def _validate_requirement(raw: Any, *, context: str) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 512:
        raise LockCompileError(f"{context} requirement must be a bounded non-empty string")
    if any(token in raw for token in (";", "@", "://", "\\", "../", "./")):
        raise LockCompileError(f"{context} requirement contains forbidden URL/path/marker authority")
    match = REQUIREMENT_NAME.fullmatch(raw)
    if match is None:
        raise LockCompileError(f"{context} requirement uses unsupported syntax: {raw!r}")
    if not match.group("specifier"):
        raise LockCompileError(f"{context} requirement must constrain a version: {raw!r}")
    return raw


def _requirement_name(raw: str) -> str:
    match = REQUIREMENT_NAME.fullmatch(raw)
    if match is None:  # already validated; defensive invariant
        raise LockCompileError(f"invalid requirement syntax: {raw!r}")
    return _canonical_name(match.group("name"))


def _validated_requirements(values: Any, *, context: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise LockCompileError(f"{context} requirements must be a non-empty list")
    if len(values) > MAX_REQUIREMENTS:
        raise LockCompileError(f"{context} requirements exceed {MAX_REQUIREMENTS} entries")
    rendered = [_validate_requirement(value, context=context) for value in values]
    names = [_requirement_name(value) for value in rendered]
    if len(names) != len(set(names)):
        raise LockCompileError(f"{context} requirements contain duplicate package identities")
    return rendered


def _write_requirements(path: Path, requirements: list[str]) -> None:
    path.write_text("\n".join(sorted(requirements, key=_requirement_name)) + "\n", encoding="utf-8", newline="\n")


def _run_report(python: str, root: Path, requirements: list[str]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="dependency-report-") as temporary:
        report = Path(temporary) / "report.json"
        input_file = Path(temporary) / "requirements.in"
        _write_requirements(input_file, requirements)
        command = [
            python,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--no-input",
            "--only-binary=:all:",
            "--report",
            str(report),
            "-r",
            str(input_file),
        ]
        completed = subprocess.run(
            command,
            cwd=root,
            env=_resolver_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=300,
            check=False,
        )
        if completed.returncode != 0:
            raise LockCompileError(f"wheel-only pip resolver failed:\n{completed.stdout[-6000:]}")
        return _read_json(report)


def _report_to_lock(payload: dict[str, Any]) -> str:
    installs = payload.get("install")
    if not isinstance(installs, list):
        raise LockCompileError("pip report install field must be a list")
    if not installs or len(installs) > MAX_PACKAGES:
        raise LockCompileError(f"resolved graph must contain 1..{MAX_PACKAGES} packages")

    packages: dict[str, tuple[str, str]] = {}
    for row in installs:
        if not isinstance(row, dict):
            raise LockCompileError("pip report install entry must be an object")
        metadata = row.get("metadata")
        if not isinstance(metadata, dict):
            raise LockCompileError("pip report install entry lacks metadata")
        name = metadata.get("name")
        version = metadata.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise LockCompileError("pip report package identity/version is invalid")
        canonical = _canonical_name(name)
        download = row.get("download_info")
        if not isinstance(download, dict):
            raise LockCompileError(f"resolved package {canonical} lacks download provenance")
        url = download.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise LockCompileError(f"resolved package {canonical} is not HTTPS-backed")
        parsed = urlparse(url)
        if parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
            raise LockCompileError(
                f"resolved package {canonical} came from unreviewed host {parsed.hostname!r}"
            )
        filename = Path(parsed.path).name.lower()
        if not filename.endswith(".whl"):
            raise LockCompileError(f"resolved package {canonical} is not wheel-backed")
        archive = download.get("archive_info")
        hashes = archive.get("hashes") if isinstance(archive, dict) else None
        digest = hashes.get("sha256") if isinstance(hashes, dict) else None
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise LockCompileError(f"resolved package {canonical} lacks a canonical SHA-256 digest")
        current = (version, digest)
        previous = packages.get(canonical)
        if previous is not None and previous != current:
            raise LockCompileError(f"resolved graph contains conflicting package identity {canonical}")
        packages[canonical] = current

    lines: list[str] = []
    for canonical in sorted(packages):
        version, digest = packages[canonical]
        lines.append(f"{canonical}=={version} \\")
        lines.append(f"    --hash=sha256:{digest}")
    return "\n".join(lines) + "\n"


def _resolve_twice(python: str, root: Path, requirements: list[str]) -> str:
    first = _report_to_lock(_run_report(python, root, requirements))
    second = _report_to_lock(_run_report(python, root, requirements))
    if first != second:
        raise LockCompileError("resolver output is not deterministic across identical wheel-only runs")
    return first


def _verify_hash_lock(python: str, root: Path, lock: Path) -> None:
    completed = subprocess.run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--no-input",
            "--only-binary=:all:",
            "--require-hashes",
            "-r",
            str(lock),
        ],
        cwd=root,
        env=_resolver_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=300,
        check=False,
    )
    if completed.returncode != 0:
        raise LockCompileError(
            f"generated lock {lock.name} failed wheel-only hash verification:\n{completed.stdout[-6000:]}"
        )


def compile_locks(root: Path, python311: str, python314: str, output_dir: Path) -> dict[str, Any]:
    pyproject_path = root / "pyproject.toml"
    raw = pyproject_path.read_bytes()
    if not raw or len(raw) > MAX_PYPROJECT_BYTES:
        raise LockCompileError(f"pyproject.toml must be 1..{MAX_PYPROJECT_BYTES} bytes")
    try:
        pyproject = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise LockCompileError("pyproject.toml is not canonical UTF-8 TOML") from exc

    project = pyproject.get("project")
    build = pyproject.get("build-system")
    if not isinstance(project, dict) or not isinstance(build, dict):
        raise LockCompileError("pyproject.toml lacks project/build-system tables")
    if project.get("name") != "ai-qa-automation":
        raise LockCompileError("project identity changed")
    if build.get("build-backend") != "hatchling.build":
        raise LockCompileError("build backend identity changed")

    build_requires = build.get("requires")
    if (
        not isinstance(build_requires, list)
        or len(build_requires) != 1
        or not isinstance(build_requires[0], str)
        or EXACT_BUILD_REQUIREMENT.fullmatch(build_requires[0]) is None
        or _canonical_name(build_requires[0].split("==", 1)[0]) != "hatchling"
    ):
        raise LockCompileError("build-system.requires must be exactly one hatchling==VERSION requirement")

    runtime = _validated_requirements(project.get("dependencies"), context="runtime")
    optional = project.get("optional-dependencies")
    if not isinstance(optional, dict) or "dev" not in optional:
        raise LockCompileError("project.optional-dependencies.dev is required")
    dev = _validated_requirements(optional.get("dev"), context="dev")
    runtime_names = {_requirement_name(item) for item in runtime}
    dev_names = {_requirement_name(item) for item in dev}
    if runtime_names & dev_names:
        raise LockCompileError("dev requirements must not duplicate runtime dependency identities")

    output_dir.mkdir(parents=True, exist_ok=True)
    graphs = {
        "runtime-py311.lock": (python311, runtime),
        "dev-py311.lock": (python311, runtime + dev),
        "dev-py314.lock": (python314, runtime + dev),
        "build-py311.lock": (python311, [build_requires[0]]),
    }
    generated: dict[str, str] = {}
    for name, (python, requirements) in graphs.items():
        generated[name] = _resolve_twice(python, root, requirements)

    for name, content in generated.items():
        path = output_dir / name
        path.write_text(content, encoding="utf-8", newline="\n")
        python = python314 if name == "dev-py314.lock" else python311
        _verify_hash_lock(python, root, path)

    base_image = root / "requirements" / "base-image.lock"
    if not base_image.is_file() or base_image.is_symlink():
        raise LockCompileError("base-image.lock must be a regular non-symlink file")
    base_bytes = base_image.read_bytes()
    if len(base_bytes) > 4096:
        raise LockCompileError("base-image.lock exceeds bounded size")

    authority = {
        "base-image.lock": _git_blob_sha1(base_bytes),
        **{name: _git_blob_sha1((output_dir / name).read_bytes()) for name in sorted(generated)},
    }
    authority_payload = {
        "schemaVersion": 1,
        "sourcePyprojectSha256": hashlib.sha256(raw).hexdigest(),
        "resolverPolicy": "pypi-https-wheel-only-double-resolve-hash-replay",
        "lockBlobs": dict(sorted(authority.items())),
    }
    (output_dir / "lock-authority.json").write_text(
        json.dumps(authority_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        "schemaVersion": 1,
        "project": "ai-qa-automation",
        "pyprojectSha256": hashlib.sha256(raw).hexdigest(),
        "locks": {
            name: {
                "sha256": hashlib.sha256((output_dir / name).read_bytes()).hexdigest(),
                "gitBlobSha1": authority[name],
            }
            for name in sorted(generated)
        },
        "authority": authority_payload,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compile deterministic wheel-only hash locks for trusted dependency promotion"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--python311", required=True)
    parser.add_argument("--python314", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = compile_locks(
        args.root.resolve(), args.python311, args.python314, args.output_dir.resolve()
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

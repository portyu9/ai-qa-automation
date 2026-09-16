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

MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_PACKAGES = 512
SHA256 = re.compile(r"^[0-9a-f]{64}$")
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
        if key.startswith("PIP_") or key.startswith("PYTHONPATH") or key.startswith("UV_"):
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


def _run_report(python: str, root: Path, requirement: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="dependency-report-") as temporary:
        report = Path(temporary) / "report.json"
        command = [
            python,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--no-input",
            "--report",
            str(report),
        ]
        if requirement.startswith("requirements-file:"):
            command.extend(["-r", requirement.removeprefix("requirements-file:")])
        else:
            command.append(requirement)
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
            tail = completed.stdout[-6000:]
            raise LockCompileError(f"pip resolver failed for {requirement!r}:\n{tail}")
        return _read_json(report)


def _report_to_lock(payload: dict[str, Any], *, project_name: str) -> str:
    installs = payload.get("install")
    if not isinstance(installs, list):
        raise LockCompileError("pip report install field must be a list")
    if len(installs) > MAX_PACKAGES:
        raise LockCompileError(f"resolved graph exceeds {MAX_PACKAGES} packages")

    packages: dict[str, tuple[str, str, str]] = {}
    project_key = _canonical_name(project_name)
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
        if canonical == project_key:
            continue
        download = row.get("download_info")
        if not isinstance(download, dict):
            raise LockCompileError(f"resolved package {canonical} lacks download provenance")
        url = download.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise LockCompileError(f"resolved package {canonical} is not HTTPS-backed")
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
            raise LockCompileError(
                f"resolved package {canonical} came from unreviewed host {parsed.hostname!r}"
            )
        archive = download.get("archive_info")
        hashes = archive.get("hashes") if isinstance(archive, dict) else None
        digest = hashes.get("sha256") if isinstance(hashes, dict) else None
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise LockCompileError(f"resolved package {canonical} lacks a canonical SHA-256 digest")
        previous = packages.get(canonical)
        current = (version, digest, name)
        if previous is not None and previous != current:
            raise LockCompileError(f"resolved graph contains conflicting package identity {canonical}")
        packages[canonical] = current

    if not packages:
        raise LockCompileError("resolved graph contains no external packages")
    lines: list[str] = []
    for canonical in sorted(packages):
        version, digest, _display = packages[canonical]
        lines.append(f"{canonical}=={version} \\")
        lines.append(f"    --hash=sha256:{digest}")
    return "\n".join(lines) + "\n"


def _resolve_twice(python: str, root: Path, requirement: str, *, project_name: str) -> str:
    first = _report_to_lock(_run_report(python, root, requirement), project_name=project_name)
    second = _report_to_lock(_run_report(python, root, requirement), project_name=project_name)
    if first != second:
        raise LockCompileError(f"resolver output is not deterministic for {requirement!r}")
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
            f"generated lock {lock.name} failed hash-required verification:\n{completed.stdout[-6000:]}"
        )


def compile_locks(root: Path, python311: str, python314: str, output_dir: Path) -> dict[str, Any]:
    pyproject_path = root / "pyproject.toml"
    raw = pyproject_path.read_bytes()
    if len(raw) > 256 * 1024:
        raise LockCompileError("pyproject.toml exceeds 256 KiB")
    try:
        pyproject = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise LockCompileError("pyproject.toml is not canonical UTF-8 TOML") from exc
    project = pyproject.get("project")
    build = pyproject.get("build-system")
    if not isinstance(project, dict) or not isinstance(build, dict):
        raise LockCompileError("pyproject.toml lacks project/build-system tables")
    project_name = project.get("name")
    if project_name != "ai-qa-automation":
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
    optional = project.get("optional-dependencies", {})
    if not isinstance(optional, dict) or not optional:
        raise LockCompileError("project optional dependency groups are missing")
    if not all(isinstance(key, str) and key and isinstance(value, list) for key, value in optional.items()):
        raise LockCompileError("project optional dependency groups are malformed")

    output_dir.mkdir(parents=True, exist_ok=True)
    extras = ",".join(sorted(optional))
    runtime = _resolve_twice(python311, root, ".", project_name=project_name)
    dev311 = _resolve_twice(python311, root, f".[{extras}]", project_name=project_name)
    dev314 = _resolve_twice(python314, root, f".[{extras}]", project_name=project_name)

    with tempfile.TemporaryDirectory(prefix="build-requirement-") as temporary:
        build_input = Path(temporary) / "build-requirements.txt"
        build_input.write_text(build_requires[0] + "\n", encoding="utf-8")
        build_lock = _resolve_twice(
            python311,
            root,
            f"requirements-file:{build_input}",
            project_name=project_name,
        )

    generated = {
        "runtime-py311.lock": runtime,
        "dev-py311.lock": dev311,
        "dev-py314.lock": dev314,
        "build-py311.lock": build_lock,
    }
    for name, content in generated.items():
        path = output_dir / name
        path.write_text(content, encoding="utf-8", newline="\n")
        _verify_hash_lock(python311 if name != "dev-py314.lock" else python314, root, path)

    base_image = root / "requirements" / "base-image.lock"
    if not base_image.is_file():
        raise LockCompileError("base-image.lock is missing")
    authority: dict[str, str] = {
        "base-image.lock": _git_blob_sha1(base_image.read_bytes()),
        **{
            name: _git_blob_sha1((output_dir / name).read_bytes())
            for name in sorted(generated)
        },
    }
    authority_payload = {
        "schemaVersion": 1,
        "lockBlobs": dict(sorted(authority.items())),
    }
    (output_dir / "lock-authority.json").write_text(
        json.dumps(authority_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        "schemaVersion": 1,
        "project": project_name,
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
    parser = argparse.ArgumentParser(description="Deterministically compile hash-locked dependency graphs")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--python311", required=True)
    parser.add_argument("--python314", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = compile_locks(args.root.resolve(), args.python311, args.python314, args.output_dir.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

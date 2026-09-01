from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any

MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_WHEEL_BYTES = 64 * 1024 * 1024
_GIT_EXECUTABLE = Path("/usr/bin/git")
_RELEASE_TAG_RE = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_OBJECT_ID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_EXPECTED_PROJECT_NAME = "ai-qa-automation"
_EXPECTED_WHEEL_PREFIX = "ai_qa_automation"


def _read_stable_regular_file(path: Path, *, max_bytes: int) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("release authority requires O_NOFOLLOW file-descriptor semantics")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"release authority file must be a regular non-symlink: {path.name}") from exc

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"release authority file must be regular: {path.name}")
        if before.st_size > max_bytes:
            raise ValueError(f"release authority file exceeds {max_bytes} bytes: {path.name}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(max_bytes + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    if len(data) > max_bytes:
        raise ValueError(f"release authority file exceeds {max_bytes} bytes: {path.name}")
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or len(data) != before.st_size:
        raise ValueError(f"release authority file changed while being read: {path.name}")
    return data


def _git_output(root: Path, *args: str) -> str:
    if not _GIT_EXECUTABLE.is_file() or not os.access(_GIT_EXECUTABLE, os.X_OK):
        raise RuntimeError("reviewed release Git executable is unavailable")
    env = {
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    result = subprocess.run(
        [str(_GIT_EXECUTABLE), "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return result.stdout.strip()


def _sha256_and_size(path: Path) -> tuple[str, int]:
    data = _read_stable_regular_file(path, max_bytes=MAX_WHEEL_BYTES)
    return hashlib.sha256(data).hexdigest(), len(data)


def _project_metadata(root: Path) -> tuple[str, str]:
    raw = _read_stable_regular_file(root / "pyproject.toml", max_bytes=MAX_METADATA_BYTES)
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("pyproject.toml is not valid bounded UTF-8 TOML") from exc
    project = document.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml must contain [project]")
    if project.get("name") != _EXPECTED_PROJECT_NAME:
        raise ValueError("release project name differs from reviewed distribution identity")
    version = project.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("release project version must be static and non-empty")
    dynamic = project.get("dynamic", [])
    if not isinstance(dynamic, list) or "version" in dynamic:
        raise ValueError("dynamic project version is forbidden for release evidence")
    blob_header = b"blob " + str(len(raw)).encode() + b"\0"
    blob_sha1 = hashlib.sha1(blob_header + raw, usedforsecurity=False).hexdigest()
    return version, blob_sha1


def _validate_tag(tag: str, *, version: str) -> None:
    if _RELEASE_TAG_RE.fullmatch(tag) is None:
        raise ValueError("release tag must use stable vMAJOR.MINOR.PATCH form")
    if tag != f"v{version}":
        raise ValueError("release tag does not match static project version")


def _validate_subject(
    root: Path, *, expected_source_sha: str, expected_ref: str
) -> tuple[str, str]:
    if expected_ref != "refs/heads/main":
        raise ValueError("release candidate evidence may run only from refs/heads/main")
    if _OBJECT_ID_RE.fullmatch(expected_source_sha) is None:
        raise ValueError("expected release source SHA must be a full lowercase Git object ID")
    head = _git_output(root, "rev-parse", "HEAD^{commit}")
    tree = _git_output(root, "rev-parse", "HEAD^{tree}")
    if head != expected_source_sha:
        raise ValueError("release candidate checkout does not match expected source SHA")
    if _OBJECT_ID_RE.fullmatch(tree) is None:
        raise ValueError("release source tree is not a full lowercase Git object ID")
    if _git_output(root, "diff", "--name-only", "HEAD", "--"):
        raise ValueError("tracked worktree changes are forbidden before release evidence")
    if _git_output(root, "diff", "--cached", "--name-only", "HEAD", "--"):
        raise ValueError("staged changes are forbidden before release evidence")
    return head, tree


def _verify_wheels(*, wheel_a: Path, wheel_b: Path, version: str) -> dict[str, Any]:
    expected_name = f"{_EXPECTED_WHEEL_PREFIX}-{version}-py3-none-any.whl"
    if wheel_a.name != expected_name or wheel_b.name != expected_name:
        raise ValueError("release wheel filename does not match reviewed project/version identity")
    digest_a, size_a = _sha256_and_size(wheel_a)
    digest_b, size_b = _sha256_and_size(wheel_b)
    if digest_a != digest_b or size_a != size_b:
        raise ValueError("release wheel builds are not byte-identical")
    return {
        "filename": expected_name,
        "sha256": digest_a,
        "size_bytes": size_a,
        "reproducible_builds": 2,
    }


def verify_release_candidate(
    *,
    root: Path,
    release_tag: str,
    expected_source_sha: str,
    expected_ref: str,
    wheel_a: Path | None = None,
    wheel_b: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    version, pyproject_blob_sha1 = _project_metadata(root)
    _validate_tag(release_tag, version=version)
    source_sha, source_tree = _validate_subject(
        root,
        expected_source_sha=expected_source_sha,
        expected_ref=expected_ref,
    )
    if (wheel_a is None) != (wheel_b is None):
        raise ValueError("both release wheel paths are required together")

    result: dict[str, Any] = {
        "schema_version": 1,
        "result": "PASS",
        "claim": "release candidate metadata is bound to exact main source and reviewed package identity",
        "release_tag": release_tag,
        "project_name": _EXPECTED_PROJECT_NAME,
        "project_version": version,
        "source_ref": expected_ref,
        "source_sha": source_sha,
        "source_tree": source_tree,
        "pyproject_blob_sha1": pyproject_blob_sha1,
        "publishing_authority": "none",
        "signature_claim": "none",
    }
    if wheel_a is not None and wheel_b is not None:
        result["wheel"] = _verify_wheels(wheel_a=wheel_a, wheel_b=wheel_b, version=version)
        result["claim"] = (
            "release candidate is bound to exact main source and two byte-identical reviewed wheel builds"
        )
    return result


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify deterministic release-candidate identity")
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--expected-ref", required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--wheel-a", type=Path)
    parser.add_argument("--wheel-b", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    result = verify_release_candidate(
        root=args.root,
        release_tag=args.release_tag,
        expected_source_sha=args.expected_source_sha,
        expected_ref=args.expected_ref,
        wheel_a=args.wheel_a,
        wheel_b=args.wheel_b,
    )
    if args.output is not None:
        _atomic_write_json(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

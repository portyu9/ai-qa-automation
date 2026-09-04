from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import tempfile
from pathlib import Path
from typing import Any

from ai_qa_automation.io_safety import fsync_directory, read_bytes_bounded, sha256_file_bounded
from ai_qa_automation.tools.execution_env import (
    restricted_subprocess_env,
    run_bounded_binary_subprocess,
)

SOURCE_DATE_EPOCH = "315532800"
MAX_WHEEL_BYTES = 64 * 1024 * 1024
MAX_SBOM_BYTES = 8 * 1024 * 1024
MAX_SOURCE_INPUT_BYTES = 1024 * 1024
MAX_LOCK_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_GIT_TEXT_OUTPUT_BYTES = 1024 * 1024
MAX_GIT_STDERR_BYTES = 256 * 1024
MAX_GIT_TREE_ENTRY_BYTES = 16 * 1024
GIT_TIMEOUT_SECONDS = 30
HEX_OID_RE = re.compile(r"^[0-9a-f]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OBJECT_FORMAT_LENGTHS = {"sha1": 40, "sha256": 64}
LOCK_NAMES = (
    "base-image.lock",
    "build-py311.lock",
    "dev-py311.lock",
    "dev-py314.lock",
    "runtime-py311.lock",
)


class _GitCommandError(RuntimeError):
    pass


def _sha256(path: Path, *, max_bytes: int, label: str) -> tuple[str, int]:
    return sha256_file_bounded(path, max_bytes=max_bytes, label=label)


def _read_hashed_bytes(path: Path, *, max_bytes: int, label: str) -> tuple[bytes, str]:
    content = read_bytes_bounded(path, max_bytes=max_bytes, label=label)
    return content, hashlib.sha256(content).hexdigest()


def _git_environment(*, home: Path) -> dict[str, str]:
    return restricted_subprocess_env(
        home=home,
        extra={
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_LAZY_FETCH": "1",
        },
    )


def _run_git_bytes(
    *args: str,
    cwd: Path | None = None,
    max_stdout_bytes: int,
) -> bytes:
    try:
        with tempfile.TemporaryDirectory(prefix="aiqa-build-git-home-") as raw_home:
            result = run_bounded_binary_subprocess(
                ["git", *args],
                cwd=cwd or Path.cwd(),
                env=_git_environment(home=Path(raw_home)),
                timeout_seconds=GIT_TIMEOUT_SECONDS,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=MAX_GIT_STDERR_BYTES,
            )
    except (OSError, RuntimeError, ValueError) as exc:
        raise _GitCommandError(
            "Git build-provenance subprocess could not be executed safely"
        ) from exc
    if result.timed_out:
        raise _GitCommandError("Git build-provenance subprocess exceeded its time budget")
    if result.stdout_truncated or result.stderr_truncated:
        raise _GitCommandError("Git build-provenance subprocess exceeded its output budget")
    if result.returncode != 0:
        raise _GitCommandError(
            f"Git build-provenance subprocess failed with exit code {result.returncode}"
        )
    return result.stdout


def _git(*args: str, cwd: Path | None = None) -> str:
    raw = _run_git_bytes(
        *args,
        cwd=cwd,
        max_stdout_bytes=MAX_GIT_TEXT_OUTPUT_BYTES,
    )
    try:
        return raw.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("Git build-provenance output is not valid UTF-8") from exc


def _git_blob_oid(
    root: Path,
    *,
    source_sha: str,
    relative_path: str,
    object_format: str,
    label: str,
) -> str:
    expected_length = OBJECT_FORMAT_LENGTHS.get(object_format)
    if expected_length is None:
        raise ValueError(f"unsupported Git object format for build provenance: {object_format}")
    try:
        raw = _run_git_bytes(
            "ls-tree",
            "-z",
            "--full-tree",
            source_sha,
            "--",
            f":(literal){relative_path}",
            cwd=root,
            max_stdout_bytes=MAX_GIT_TREE_ENTRY_BYTES,
        )
    except _GitCommandError as exc:
        raise ValueError(f"{label} could not be resolved in the expected source commit") from exc
    records = [record for record in raw.split(b"\0") if record]
    if len(records) != 1:
        raise ValueError(f"{label} is not one unambiguous file in the expected source commit")
    metadata, separator, raw_path = records[0].partition(b"\t")
    if not separator:
        raise ValueError(f"{label} has malformed tree metadata in the expected source commit")
    try:
        returned_path = raw_path.decode("utf-8", errors="strict")
        fields = metadata.decode("ascii", errors="strict").split()
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"{label} has invalid tree metadata in the expected source commit"
        ) from exc
    if returned_path != relative_path or len(fields) != 3:
        raise ValueError(f"{label} has ambiguous tree metadata in the expected source commit")
    mode, object_type, object_id = fields
    if (
        mode not in {"100644", "100755"}
        or object_type != "blob"
        or len(object_id) != expected_length
        or not HEX_OID_RE.fullmatch(object_id)
    ):
        raise ValueError(
            f"{label} is not a regular content-addressed blob in the expected source commit"
        )
    return object_id


def _raw_blob_oid(data: bytes, object_format: str) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    if object_format == "sha1":
        return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()
    if object_format == "sha256":
        return hashlib.sha256(header + data).hexdigest()
    raise ValueError(f"unsupported Git object format for build provenance: {object_format}")


def _git_blob_bytes(
    root: Path,
    *,
    source_sha: str,
    relative_path: str,
    max_bytes: int,
    label: str,
) -> bytes:
    try:
        object_format = _git("rev-parse", "--show-object-format", cwd=root)
        blob_oid = _git_blob_oid(
            root,
            source_sha=source_sha,
            relative_path=relative_path,
            object_format=object_format,
            label=label,
        )
        size_text = _git("cat-file", "-s", blob_oid, cwd=root)
        size = int(size_text)
    except (_GitCommandError, ValueError) as exc:
        raise ValueError(f"{label} is not an available blob in the expected source commit") from exc
    if size < 0 or size > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} byte source-object limit")

    try:
        content = _run_git_bytes(
            "cat-file",
            "blob",
            blob_oid,
            cwd=root,
            max_stdout_bytes=max(1, size),
        )
    except _GitCommandError as exc:
        raise ValueError(f"{label} could not be read from the expected source commit") from exc
    if len(content) != size:
        raise ValueError(f"{label} source-object size changed during observation")
    if _raw_blob_oid(content, object_format) != blob_oid:
        raise ValueError(f"{label} source-object bytes do not match their Git object identity")
    return content


def _read_bound_source_input(
    root: Path,
    *,
    source_sha: str,
    relative_path: str,
    max_bytes: int,
    label: str,
) -> tuple[bytes, str]:
    observed, observed_digest = _read_hashed_bytes(
        root / relative_path,
        max_bytes=max_bytes,
        label=label,
    )
    expected = _git_blob_bytes(
        root,
        source_sha=source_sha,
        relative_path=relative_path,
        max_bytes=max_bytes,
        label=label,
    )
    if observed != expected:
        raise ValueError(f"{label} does not match the explicit expected source commit")
    return observed, observed_digest


def _resolve_expected_source(root: Path, expected_source_sha: str) -> str:
    object_format = _git("rev-parse", "--show-object-format", cwd=root)
    expected_length = OBJECT_FORMAT_LENGTHS.get(object_format)
    if expected_length is None:
        raise ValueError(f"unsupported Git object format for build provenance: {object_format}")
    if len(expected_source_sha) != expected_length or not HEX_OID_RE.fullmatch(expected_source_sha):
        raise ValueError(
            "expected source SHA must be a lowercase full object ID for the repository object format"
        )
    try:
        resolved_commit = _git(
            "rev-parse", "--verify", f"{expected_source_sha}^{{commit}}", cwd=root
        )
        resolved_tree = _git("rev-parse", "--verify", f"{expected_source_sha}^{{tree}}", cwd=root)
    except _GitCommandError as exc:
        raise ValueError("expected source SHA does not resolve to an available commit") from exc
    if resolved_commit != expected_source_sha:
        raise ValueError("expected source SHA did not resolve to itself as a commit")
    if len(resolved_tree) != expected_length or not HEX_OID_RE.fullmatch(resolved_tree):
        raise ValueError("expected source SHA resolved to an invalid original tree object ID")
    return resolved_tree


def _assert_expected_source_current(root: Path, expected_source_sha: str) -> None:
    current = _git("rev-parse", "--verify", "HEAD", cwd=root)
    if current != expected_source_sha:
        raise ValueError(
            "current Git subject does not match the explicit expected source SHA; "
            "build provenance is ambiguous"
        )


def _parse_json_object(text: str, *, label: str) -> dict[str, Any]:
    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"{label} contains non-standard JSON numeric constant: {value}")

    parsed = json.loads(
        text,
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=reject_constant,
    )
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} root must be a JSON object")
    return parsed


def _load_sbom(path: Path) -> tuple[dict[str, Any], str]:
    content, digest = _read_hashed_bytes(
        path,
        max_bytes=MAX_SBOM_BYTES,
        label="runtime CycloneDX SBOM",
    )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("runtime CycloneDX SBOM is not valid UTF-8") from exc
    data = _parse_json_object(text, label="runtime CycloneDX SBOM")
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM is not CycloneDX JSON")
    if not isinstance(data.get("components"), list) or not data["components"]:
        raise ValueError("SBOM contains no components")
    return data, digest


def _expected_sbom_sha256() -> str:
    expected = os.environ.get("RUNTIME_SBOM_SHA256", "")
    if not SHA256_RE.fullmatch(expected):
        raise ValueError("RUNTIME_SBOM_SHA256 must be a lowercase SHA-256 digest")
    return expected


def _load_lock_inputs(root: Path, *, expected_source_sha: str) -> tuple[dict[str, str], str]:
    lock_digests: dict[str, str] = {}
    base_image: str | None = None
    for name in LOCK_NAMES:
        limit = 256 if name == "base-image.lock" else MAX_LOCK_BYTES
        content, digest = _read_bound_source_input(
            root,
            source_sha=expected_source_sha,
            relative_path=f"requirements/{name}",
            max_bytes=limit,
            label=f"supply-chain lock {name}",
        )
        lock_digests[name] = digest
        if name == "base-image.lock":
            try:
                base_image = content.decode("utf-8").strip()
            except UnicodeDecodeError as exc:
                raise ValueError("container base-image lock is not valid UTF-8") from exc
    if not base_image:
        raise ValueError("container base-image lock must not be empty")
    return lock_digests, base_image


def _assert_tracked_worktree_clean(root: Path) -> None:
    if _git("status", "--porcelain", "--untracked-files=no", cwd=root):
        raise ValueError("tracked worktree is dirty; build provenance would be ambiguous")


def generate_manifest(
    root: Path,
    wheel_a: Path,
    wheel_b: Path,
    sbom: Path,
    *,
    expected_source_sha: str,
) -> dict[str, Any]:
    root = root.resolve()
    wheel_a = wheel_a.absolute()
    wheel_b = wheel_b.absolute()
    sbom = sbom.absolute()
    expected_sbom_sha256 = _expected_sbom_sha256()

    expected_tree_sha = _resolve_expected_source(root, expected_source_sha)
    _assert_expected_source_current(root, expected_source_sha)

    digest_a, wheel_a_size = _sha256(
        wheel_a, max_bytes=MAX_WHEEL_BYTES, label="first reproducible wheel"
    )
    digest_b, wheel_b_size = _sha256(
        wheel_b, max_bytes=MAX_WHEEL_BYTES, label="second reproducible wheel"
    )
    if digest_a != digest_b or wheel_a_size != wheel_b_size:
        raise ValueError("two independent wheel builds produced different SHA-256 digests or sizes")
    if wheel_a.name != wheel_b.name:
        raise ValueError("two independent wheel builds produced different artifact names")
    if os.environ.get("SOURCE_DATE_EPOCH") != SOURCE_DATE_EPOCH:
        raise ValueError(f"SOURCE_DATE_EPOCH must equal {SOURCE_DATE_EPOCH}")

    _assert_tracked_worktree_clean(root)
    _assert_expected_source_current(root, expected_source_sha)

    sbom_data, sbom_digest = _load_sbom(sbom)
    if sbom_digest != expected_sbom_sha256:
        raise ValueError("runtime CycloneDX SBOM does not match the parent-owned expected digest")
    lock_digests, base_image = _load_lock_inputs(root, expected_source_sha=expected_source_sha)
    _, dockerfile_digest = _read_bound_source_input(
        root,
        source_sha=expected_source_sha,
        relative_path="Dockerfile",
        max_bytes=MAX_SOURCE_INPUT_BYTES,
        label="Dockerfile",
    )
    _, pyproject_digest = _read_bound_source_input(
        root,
        source_sha=expected_source_sha,
        relative_path="pyproject.toml",
        max_bytes=MAX_SOURCE_INPUT_BYTES,
        label="pyproject.toml",
    )

    # Neither mutable Git metadata nor hidden worktree changes may silently retarget
    # recorded provenance away from the caller-owned event subject.
    _assert_tracked_worktree_clean(root)
    _assert_expected_source_current(root, expected_source_sha)

    return {
        "schema_version": 1,
        "kind": "unsigned_reproducible_build_manifest",
        "source": {
            "commit_sha": expected_source_sha,
            "tree_sha": expected_tree_sha,
            "tracked_worktree_clean": True,
        },
        "build": {
            "python_version": platform.python_version(),
            "source_date_epoch": SOURCE_DATE_EPOCH,
            "wheel_name": wheel_a.name,
            "wheel_sha256": digest_a,
            "wheel_size_bytes": wheel_a_size,
            "two_builds_byte_identical": True,
        },
        "inputs": {
            "base_image": base_image,
            "dockerfile_sha256": dockerfile_digest,
            "pyproject_sha256": pyproject_digest,
            "lock_sha256": lock_digests,
        },
        "sbom": {
            "format": "CycloneDX JSON",
            "spec_version": sbom_data.get("specVersion"),
            "components": len(sbom_data["components"]),
            "sha256": sbom_digest,
        },
        "identity": {
            "signed": False,
            "status": "NOT_PROVIDED",
        },
        "limitations": [
            "Byte-identical wheel reproduction proves repeatability for the recorded source and inputs, not publisher identity.",
            "The two wheel reproductions run in one CI job/environment; cross-runner or cross-OS reproducibility is not established.",
            "The SBOM describes the hash-locked Python runtime dependency subject; it does not attest external services or operating-system packages.",
            "No container-image reproducibility or registry publication claim is made by this manifest.",
        ],
    }


def _owned_output_target(path: Path) -> Path:
    requested = path.expanduser()
    if requested.is_symlink():
        raise ValueError("build manifest output is a symlink and has ambiguous ownership")
    raw_parent = requested.parent
    if raw_parent.is_symlink():
        raise ValueError("build manifest output parent is a symlink and has ambiguous ownership")
    raw_parent.mkdir(parents=True, exist_ok=True)
    if raw_parent.is_symlink():
        raise ValueError("build manifest output parent became a symlink")
    parent = raw_parent.resolve()
    target = parent / requested.name
    if target.is_symlink():
        raise ValueError("build manifest output is a symlink and has ambiguous ownership")
    if target.exists() and not target.is_file():
        raise ValueError("build manifest output must be a regular file when it already exists")
    return target


def _write_manifest(path: Path, payload: dict[str, Any]) -> None:
    target = _owned_output_target(path)
    rendered = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(rendered) > MAX_MANIFEST_BYTES:
        raise ValueError("build manifest exceeds persistence size bound")

    fd, raw = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    temp = Path(raw)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        if target.is_symlink():
            raise ValueError("build manifest output became a symlink before persistence")
        temp.replace(target)
        fsync_directory(target.parent)
    finally:
        temp.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-a", type=Path, required=True)
    parser.add_argument("--wheel-b", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    manifest = generate_manifest(
        root,
        args.wheel_a,
        args.wheel_b,
        args.sbom,
        expected_source_sha=args.expected_source_sha,
    )
    _write_manifest(args.output, manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

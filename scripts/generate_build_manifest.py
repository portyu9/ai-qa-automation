from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ai_qa_automation.io_safety import fsync_directory, read_bytes_bounded, sha256_file_bounded

SOURCE_DATE_EPOCH = "315532800"
MAX_WHEEL_BYTES = 64 * 1024 * 1024
MAX_SBOM_BYTES = 8 * 1024 * 1024
MAX_SOURCE_INPUT_BYTES = 1024 * 1024
MAX_LOCK_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
HEX_OID_RE = re.compile(r"^[0-9a-f]+$")
OBJECT_FORMAT_LENGTHS = {"sha1": 40, "sha256": 64}
LOCK_NAMES = (
    "base-image.lock",
    "build-py311.lock",
    "dev-py311.lock",
    "dev-py313.lock",
    "runtime-py311.lock",
)


def _sha256(path: Path, *, max_bytes: int, label: str) -> tuple[str, int]:
    return sha256_file_bounded(path, max_bytes=max_bytes, label=label)


def _read_hashed_bytes(path: Path, *, max_bytes: int, label: str) -> tuple[bytes, str]:
    content = read_bytes_bounded(path, max_bytes=max_bytes, label=label)
    return content, hashlib.sha256(content).hexdigest()


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    return result.stdout.strip()


def _resolve_expected_source(expected_source_sha: str) -> str:
    object_format = _git("rev-parse", "--show-object-format")
    expected_length = OBJECT_FORMAT_LENGTHS.get(object_format)
    if expected_length is None:
        raise ValueError(f"unsupported Git object format for build provenance: {object_format}")
    if len(expected_source_sha) != expected_length or not HEX_OID_RE.fullmatch(expected_source_sha):
        raise ValueError(
            "expected source SHA must be a lowercase full object ID for the repository object format"
        )
    try:
        resolved_commit = _git("rev-parse", "--verify", f"{expected_source_sha}^{{commit}}")
        resolved_tree = _git("rev-parse", "--verify", f"{expected_source_sha}^{{tree}}")
    except subprocess.CalledProcessError as exc:
        raise ValueError("expected source SHA does not resolve to an available commit") from exc
    if resolved_commit != expected_source_sha:
        raise ValueError("expected source SHA did not resolve to itself as a commit")
    return resolved_tree


def _assert_expected_source_current(expected_source_sha: str) -> None:
    current = _git("rev-parse", "--verify", "HEAD")
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


def _load_lock_inputs(root: Path) -> tuple[dict[str, str], str]:
    lock_digests: dict[str, str] = {}
    base_image: str | None = None
    for name in LOCK_NAMES:
        limit = 256 if name == "base-image.lock" else MAX_LOCK_BYTES
        content, digest = _read_hashed_bytes(
            root / "requirements" / name,
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


def _assert_tracked_worktree_clean() -> None:
    if _git("status", "--porcelain", "--untracked-files=no"):
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

    expected_tree_sha = _resolve_expected_source(expected_source_sha)
    _assert_expected_source_current(expected_source_sha)

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

    _assert_tracked_worktree_clean()
    _assert_expected_source_current(expected_source_sha)

    sbom_data, sbom_digest = _load_sbom(sbom)
    lock_digests, base_image = _load_lock_inputs(root)
    dockerfile_digest, _ = _sha256(
        root / "Dockerfile", max_bytes=MAX_SOURCE_INPUT_BYTES, label="Dockerfile"
    )
    pyproject_digest, _ = _sha256(
        root / "pyproject.toml", max_bytes=MAX_SOURCE_INPUT_BYTES, label="pyproject.toml"
    )

    # A tracked source subject changing during observation must not yield a manifest whose
    # recorded provenance silently follows mutable HEAD rather than the caller-owned subject.
    _assert_tracked_worktree_clean()
    _assert_expected_source_current(expected_source_sha)

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

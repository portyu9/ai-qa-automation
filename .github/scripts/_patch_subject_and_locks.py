from __future__ import annotations

import hashlib
import json
from pathlib import Path


def replace_one(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data, usedforsecurity=False).hexdigest()


def patch_ci() -> None:
    expr = "$" + "{{" + " github.event_name == 'workflow_dispatch' && inputs.subject_sha || github.sha " + "}}"
    ci = Path(".github/workflows/ci.yml")
    replace_one(
        ci,
        "  merge_group:\n\npermissions:",
        "  merge_group:\n  workflow_dispatch:\n    inputs:\n      subject_sha:\n        description: Exact repository commit SHA to validate\n        required: true\n        type: string\n\npermissions:",
    )
    replace_one(ci, "  CI_SUBJECT_SHA: " + "$" + "{{ github.sha }}", "  CI_SUBJECT_SHA: " + expr)


def patch_build_authority() -> None:
    path = Path("scripts/verify_build_authority.py")
    text = path.read_text(encoding="utf-8")
    start = text.index("EXPECTED_BUILD_SYSTEM = {")
    end = text.index("\nEXPECTED_HATCH_CONFIG =", start)
    text = (
        text[:start]
        + 'LOCK_AUTHORITY_FILENAME = "lock-authority.json"\n'
        + "EXPECTED_LOCK_NAMES = {\n"
        + '    "base-image.lock",\n'
        + '    "build-py311.lock",\n'
        + '    "dev-py311.lock",\n'
        + '    "dev-py314.lock",\n'
        + '    "runtime-py311.lock",\n'
        + "}\n"
        + 'EXPECTED_LOCK_RESOLVER_POLICY = "pypi-https-wheel-only-double-resolve-hash-replay"\n'
        + 'HEX40_RE = re.compile(r"^[0-9a-f]{40}$")\n'
        + text[end + 1 :]
    )
    const_start = text.index("EXPECTED_LOCK_BLOB_SHAS = {")
    const_end = text.index("\n\n\ndef _identity", const_start)
    text = text[:const_start] + text[const_end + 2 :]
    text = text.replace(
        "def _verify_reviewed_lock_authority(root: Path) -> dict[str, str]:",
        "def _verify_reviewed_lock_authority(root: Path, *, pyproject_sha256: str) -> dict[str, str]:",
        1,
    )
    old = """        if observed_names != set(EXPECTED_LOCK_BLOB_SHAS):
            raise ValueError(
                "dependency lock set differs from the exact reviewed automatic-install authority"
            )

        observed_blobs: dict[str, str] = {}
        for name, expected_blob in sorted(EXPECTED_LOCK_BLOB_SHAS.items()):"""
    new = """        if observed_names != EXPECTED_LOCK_NAMES:
            raise ValueError(
                "dependency lock set differs from the exact manifest-bound automatic-install authority"
            )

        authority_path = requirements / LOCK_AUTHORITY_FILENAME
        if authority_path.is_symlink() or not authority_path.is_file():
            raise ValueError("lock authority manifest must be a regular non-symlink file")
        authority_raw = authority_path.read_bytes()
        if len(authority_raw) > 64 * 1024:
            raise ValueError("lock authority manifest exceeds bounded ingestion limit")
        try:
            authority = json.loads(authority_raw)
        except json.JSONDecodeError as exc:
            raise ValueError("lock authority manifest is malformed JSON") from exc
        if not isinstance(authority, dict) or authority.get("schemaVersion") != 1:
            raise ValueError("lock authority manifest schema must equal 1")
        if authority.get("sourcePyprojectSha256") != pyproject_sha256:
            raise ValueError("lock authority manifest is not bound to exact pyproject.toml bytes")
        if authority.get("resolverPolicy") != EXPECTED_LOCK_RESOLVER_POLICY:
            raise ValueError("lock authority resolver policy differs from reviewed wheel-only policy")
        expected_blobs = authority.get("lockBlobs")
        if (
            not isinstance(expected_blobs, dict)
            or set(expected_blobs) != EXPECTED_LOCK_NAMES
            or not all(
                isinstance(value, str) and HEX40_RE.fullmatch(value)
                for value in expected_blobs.values()
            )
        ):
            raise ValueError("lock authority manifest does not bind the exact managed lock set")

        observed_blobs: dict[str, str] = {}
        for name, expected_blob in sorted(expected_blobs.items()):"""
    if text.count(old) != 1:
        raise SystemExit("verify_build_authority: lock authority block drifted")
    text = text.replace(old, new, 1)
    old_build = """    build_system = pyproject.get("build-system")
    if build_system != EXPECTED_BUILD_SYSTEM:
        raise ValueError(
            "build-system authority must be exactly hatchling.build with hatchling==1.32.0 "
            "and no backend-path or extra keys"
        )"""
    new_build = """    build_system = pyproject.get("build-system")
    if not isinstance(build_system, dict) or set(build_system) != {"requires", "build-backend"}:
        raise ValueError("build-system authority must contain only requires and build-backend")
    if build_system.get("build-backend") != "hatchling.build":
        raise ValueError("build-system backend authority must remain hatchling.build")
    build_requirements = build_system.get("requires")
    if (
        not isinstance(build_requirements, list)
        or len(build_requirements) != 1
        or not isinstance(build_requirements[0], str)
        or re.fullmatch(r"hatchling==[^\\s;@]+", build_requirements[0]) is None
    ):
        raise ValueError("build-system requires must remain one exact hatchling==VERSION declaration")"""
    if text.count(old_build) != 1:
        raise SystemExit("verify_build_authority: build-system block drifted")
    text = text.replace(old_build, new_build, 1)
    text = text.replace(
        "    reviewed_lock_blobs = _verify_reviewed_lock_authority(root)",
        "    reviewed_lock_blobs = _verify_reviewed_lock_authority(root, pyproject_sha256=digest)",
        1,
    )
    text = text.replace(
        '        "build_requirements": ["hatchling==1.32.0"],',
        '        "build_requirements": list(build_requirements),',
        1,
    )
    path.write_text(text, encoding="utf-8", newline="\n")


def write_initial_authority() -> None:
    req = Path("requirements")
    names = [
        "base-image.lock",
        "build-py311.lock",
        "dev-py311.lock",
        "dev-py314.lock",
        "runtime-py311.lock",
    ]
    authority = {
        "schemaVersion": 1,
        "sourcePyprojectSha256": hashlib.sha256(Path("pyproject.toml").read_bytes()).hexdigest(),
        "resolverPolicy": "pypi-https-wheel-only-double-resolve-hash-replay",
        "lockBlobs": dict(sorted((name, git_blob_sha1(req / name)) for name in names)),
    }
    (req / "lock-authority.json").write_text(
        json.dumps(authority, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    patch_ci()
    patch_build_authority()
    write_initial_authority()

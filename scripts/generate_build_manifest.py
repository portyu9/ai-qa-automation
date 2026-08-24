from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

SOURCE_DATE_EPOCH = "315532800"
LOCK_NAMES = (
    "base-image.lock",
    "build-py311.lock",
    "dev-py311.lock",
    "dev-py313.lock",
    "runtime-py311.lock",
)


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path} must be a regular non-symlink file")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    return result.stdout.strip()


def _load_sbom(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("SBOM must be a regular non-symlink file")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM is not CycloneDX JSON")
    if not isinstance(data.get("components"), list) or not data["components"]:
        raise ValueError("SBOM contains no components")
    return data


def generate_manifest(root: Path, wheel_a: Path, wheel_b: Path, sbom: Path) -> dict[str, Any]:
    root = root.resolve()
    wheel_a = wheel_a.resolve()
    wheel_b = wheel_b.resolve()
    sbom = sbom.resolve()

    digest_a = _sha256(wheel_a)
    digest_b = _sha256(wheel_b)
    if digest_a != digest_b:
        raise ValueError("two independent wheel builds produced different SHA-256 digests")
    if wheel_a.name != wheel_b.name:
        raise ValueError("two independent wheel builds produced different artifact names")
    if os.environ.get("SOURCE_DATE_EPOCH") != SOURCE_DATE_EPOCH:
        raise ValueError(f"SOURCE_DATE_EPOCH must equal {SOURCE_DATE_EPOCH}")

    tracked_status = _git("status", "--porcelain", "--untracked-files=no")
    if tracked_status:
        raise ValueError("tracked worktree is dirty; build provenance would be ambiguous")

    sbom_data = _load_sbom(sbom)
    lock_digests = {name: _sha256(root / "requirements" / name) for name in LOCK_NAMES}
    base_image = (root / "requirements" / "base-image.lock").read_text(encoding="utf-8").strip()

    return {
        "schema_version": 1,
        "kind": "unsigned_reproducible_build_manifest",
        "source": {
            "commit_sha": _git("rev-parse", "HEAD"),
            "tree_sha": _git("rev-parse", "HEAD^{tree}"),
            "tracked_worktree_clean": True,
        },
        "build": {
            "python_version": platform.python_version(),
            "source_date_epoch": SOURCE_DATE_EPOCH,
            "wheel_name": wheel_a.name,
            "wheel_sha256": digest_a,
            "wheel_size_bytes": wheel_a.stat().st_size,
            "two_builds_byte_identical": True,
        },
        "inputs": {
            "base_image": base_image,
            "dockerfile_sha256": _sha256(root / "Dockerfile"),
            "pyproject_sha256": _sha256(root / "pyproject.toml"),
            "lock_sha256": lock_digests,
        },
        "sbom": {
            "format": "CycloneDX JSON",
            "spec_version": sbom_data.get("specVersion"),
            "components": len(sbom_data["components"]),
            "sha256": _sha256(sbom),
        },
        "identity": {
            "signed": False,
            "status": "NOT_PROVIDED",
        },
        "limitations": [
            "Byte-identical wheel reproduction proves repeatability for the recorded source and inputs, not publisher identity.",
            "The SBOM describes the hash-locked Python runtime dependency subject; it does not attest external services or operating-system packages.",
            "No container-image reproducibility or registry publication claim is made by this manifest.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-a", type=Path, required=True)
    parser.add_argument("--wheel-b", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    manifest = generate_manifest(root, args.wheel_a, args.wheel_b, args.sbom)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

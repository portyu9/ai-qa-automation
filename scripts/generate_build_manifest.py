from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from ai_qa_automation.io_safety import read_text_bounded, sha256_file_bounded

SOURCE_DATE_EPOCH = "315532800"
MAX_WHEEL_BYTES = 64 * 1024 * 1024
MAX_SBOM_BYTES = 8 * 1024 * 1024
MAX_SOURCE_INPUT_BYTES = 1024 * 1024
MAX_LOCK_BYTES = 1024 * 1024
LOCK_NAMES = (
    "base-image.lock",
    "build-py311.lock",
    "dev-py311.lock",
    "dev-py313.lock",
    "runtime-py311.lock",
)


def _sha256(path: Path, *, max_bytes: int, label: str) -> tuple[str, int]:
    return sha256_file_bounded(path, max_bytes=max_bytes, label=label)


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    return result.stdout.strip()


def _load_sbom(path: Path) -> tuple[dict[str, Any], str]:
    text = read_text_bounded(path, max_bytes=MAX_SBOM_BYTES, label="runtime CycloneDX SBOM")
    data = json.loads(text)
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM is not CycloneDX JSON")
    if not isinstance(data.get("components"), list) or not data["components"]:
        raise ValueError("SBOM contains no components")
    digest, _ = _sha256(path, max_bytes=MAX_SBOM_BYTES, label="runtime CycloneDX SBOM")
    return data, digest


def generate_manifest(root: Path, wheel_a: Path, wheel_b: Path, sbom: Path) -> dict[str, Any]:
    root = root.resolve()
    wheel_a = wheel_a.absolute()
    wheel_b = wheel_b.absolute()
    sbom = sbom.absolute()

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

    tracked_status = _git("status", "--porcelain", "--untracked-files=no")
    if tracked_status:
        raise ValueError("tracked worktree is dirty; build provenance would be ambiguous")

    sbom_data, sbom_digest = _load_sbom(sbom)
    lock_digests = {
        name: _sha256(
            root / "requirements" / name,
            max_bytes=MAX_LOCK_BYTES,
            label=f"supply-chain lock {name}",
        )[0]
        for name in LOCK_NAMES
    }
    base_image = read_text_bounded(
        root / "requirements" / "base-image.lock",
        max_bytes=256,
        label="container base-image lock",
    ).strip()
    dockerfile_digest, _ = _sha256(
        root / "Dockerfile", max_bytes=MAX_SOURCE_INPUT_BYTES, label="Dockerfile"
    )
    pyproject_digest, _ = _sha256(
        root / "pyproject.toml", max_bytes=MAX_SOURCE_INPUT_BYTES, label="pyproject.toml"
    )

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

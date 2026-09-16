from __future__ import annotations

import hashlib
import json
from pathlib import Path

BASE_BLOB = "cc2304a471bccd73bee705e33d4fc17e5287051b"


def blob_sha(text: str) -> str:
    raw = text.encode("utf-8")
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False).hexdigest()


def replace_one(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


trusted = Path("scripts/ci_contract_trusted_auto.py")
replace_one(
    trusted,
    '    "bf538a2efa1f895ef0a614e8118ba1b1ad2914f5"  # pragma: allowlist secret',
    f'    "{BASE_BLOB}"  # pragma: allowlist secret',
)
trusted_sha = blob_sha(trusted.read_text(encoding="utf-8"))

verifier = Path("scripts/verify_ci_contract.py")
replace_one(
    verifier,
    '    "068537f4638fa1559c21e31cfdfd5aa99e135b2f"  # pragma: allowlist secret',
    f'    "{trusted_sha}"  # pragma: allowlist secret',
)

config_path = Path(".github/dependency-governance.json")
config = json.loads(config_path.read_text(encoding="utf-8"))
paths = config["manualReviewPaths"]
for required in (
    "scripts/ci_contract_base.py",
    "scripts/ci_contract_trusted_auto.py",
    "scripts/verify_build_authority.py",
):
    if required not in paths:
        paths.append(required)
config["manualReviewPaths"] = sorted(paths)
config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8", newline="\n")

governance = Path(".github/scripts/dependency_governance.py")
text = governance.read_text(encoding="utf-8")
anchor = '        "scripts/auto_trusted_preflight.py",\n'
addition = (
    '        "scripts/ci_contract_base.py",\n'
    '        "scripts/ci_contract_trusted_auto.py",\n'
    '        "scripts/verify_build_authority.py",\n'
)
if addition not in text:
    if text.count(anchor) != 1:
        raise SystemExit("dependency_governance.py: critical-path anchor drifted")
    text = text.replace(anchor, anchor + addition, 1)
governance.write_text(text, encoding="utf-8", newline="\n")

print(json.dumps({"base_blob": BASE_BLOB, "trusted_auto_blob": trusted_sha}, sort_keys=True))

from __future__ import annotations

import hashlib
from pathlib import Path


def git_blob_sha(text: str) -> str:
    data = text.encode("utf-8")
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


root = Path(".")
ci_path = root / ".github/workflows/ci.yml"
ci_text = ci_path.read_text(encoding="utf-8")
expected_scan = "--exclude-files '(^|/)\\.git/|^\\.github/lock-authority\\.json$'"
if ci_text.count(expected_scan) != 1:
    raise SystemExit("exact lock-authority secret-scan exclusion is not present")
expected_digest = "b2831934a610bd2141052410585e3474127bb525"
observed_digest = git_blob_sha(ci_text)
if observed_digest != expected_digest:
    raise SystemExit(
        f"ordinary CI bytes differ from reviewed repair: {observed_digest} != {expected_digest}"
    )

contract_path = root / "scripts/verify_ci_contract.py"
contract_text = contract_path.read_text(encoding="utf-8")
old_digest = "32d2538339b1a57112495b00d552e49b79594f0e"
if contract_text.count(old_digest) != 1:
    raise SystemExit("expected exactly one prior ordinary-CI workflow digest")
contract_path.write_text(
    contract_text.replace(old_digest, expected_digest, 1), encoding="utf-8", newline="\n"
)
print(f"ordinary CI rebound to {expected_digest}")

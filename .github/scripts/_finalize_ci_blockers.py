from __future__ import annotations

import hashlib
from pathlib import Path


def git_blob_sha(text: str) -> str:
    data = text.encode("utf-8")
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


root = Path(".")

# Apply the repository-pinned Ruff 0.16.2 formatting output exactly.
test_path = root / "tests/unit/test_build_authority.py"
test_text = test_path.read_text(encoding="utf-8")
old_copy = "    shutil.copyfile(ROOT / build_authority.LOCK_AUTHORITY_PATH, root / build_authority.LOCK_AUTHORITY_PATH)\n"
new_copy = (
    "    shutil.copyfile(\n"
    "        ROOT / build_authority.LOCK_AUTHORITY_PATH, root / build_authority.LOCK_AUTHORITY_PATH\n"
    "    )\n"
)
if test_text.count(old_copy) != 1:
    raise SystemExit("expected exactly one unformatted lock-authority copy")
test_text = test_text.replace(old_copy, new_copy, 1)
old_authority = (
    "    authority = json.loads(\n"
    "        (ROOT / build_authority.LOCK_AUTHORITY_PATH).read_text(\n"
    "            encoding=\"utf-8\"\n"
    "        )\n"
    "    )\n"
)
new_authority = (
    "    authority = json.loads((ROOT / build_authority.LOCK_AUTHORITY_PATH).read_text(encoding=\"utf-8\"))\n"
)
if test_text.count(old_authority) != 1:
    raise SystemExit("expected exactly one unformatted lock-authority read")
test_path.write_text(test_text.replace(old_authority, new_authority, 1), encoding="utf-8", newline="\n")

# Exclude only the independently validated integrity manifest from entropy secret scanning.
ci_path = root / ".github/workflows/ci.yml"
ci_text = ci_path.read_text(encoding="utf-8")
old_scan = "--exclude-files '(^|/)\\.git/|^requirements/lock-authority\\.json$'"
new_scan = "--exclude-files '(^|/)\\.git/|^\\.github/lock-authority\\.json$'"
if ci_text.count(old_scan) != 1:
    raise SystemExit("expected exactly one stale lock-authority secret-scan exclusion")
ci_text = ci_text.replace(old_scan, new_scan, 1)
ci_path.write_text(ci_text, encoding="utf-8", newline="\n")

# Rebind the frozen ordinary-CI authority to the exact reviewed one-line workflow repair.
contract_path = root / "scripts/verify_ci_contract.py"
contract_text = contract_path.read_text(encoding="utf-8")
old_digest = "32d2538339b1a57112495b00d552e49b79594f0e"
new_digest = git_blob_sha(ci_text)
if contract_text.count(old_digest) != 1:
    raise SystemExit("expected exactly one prior ordinary-CI workflow digest")
contract_text = contract_text.replace(old_digest, new_digest, 1)
contract_path.write_text(contract_text, encoding="utf-8", newline="\n")
print(f"ordinary CI rebound to {new_digest}")

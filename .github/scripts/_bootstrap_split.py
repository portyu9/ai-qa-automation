from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

ROOT = Path.cwd()
OLD_MANIFEST = "requirements/lock-authority.json"
NEW_MANIFEST = ".github/lock-authority.json"


def replace_exact(path: Path, old: str, new: str, *, count: int) -> None:
    text = path.read_text(encoding="utf-8")
    observed = text.count(old)
    if observed != count:
        raise SystemExit(f"{path}: expected {count} occurrences of {old!r}, found {observed}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def git_blob_sha(text: str) -> str:
    raw = text.encode("utf-8")
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw, usedforsecurity=False).hexdigest()


# Move the integrity manifest out of the pre-existing protected requirements namespace.
old_manifest = ROOT / OLD_MANIFEST
new_manifest = ROOT / NEW_MANIFEST
new_manifest.parent.mkdir(parents=True, exist_ok=True)
if not old_manifest.is_file() or old_manifest.is_symlink():
    raise SystemExit("expected regular requirements/lock-authority.json before bootstrap split")
old_manifest.replace(new_manifest)

# Rebind all literal repository references to the new authority location.
completed = subprocess.run(
    ["git", "grep", "-l", OLD_MANIFEST, "--", "."],
    cwd=ROOT,
    text=True,
    capture_output=True,
    check=False,
)
if completed.returncode not in (0, 1):
    raise SystemExit(completed.stderr)
for raw_path in filter(None, completed.stdout.splitlines()):
    path = ROOT / raw_path
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace(OLD_MANIFEST, NEW_MANIFEST), encoding="utf-8", newline="\n")

# The build verifier previously derived the authority path from requirements/.
replace_exact(
    ROOT / "scripts/verify_build_authority.py",
    'LOCK_AUTHORITY_FILENAME = "lock-authority.json"',
    'LOCK_AUTHORITY_PATH = Path(".github/lock-authority.json")',
    count=1,
)
replace_exact(
    ROOT / "scripts/verify_build_authority.py",
    "authority_path = requirements / LOCK_AUTHORITY_FILENAME",
    "authority_path = root / LOCK_AUTHORITY_PATH",
    count=1,
)

# Unit fixtures must carry the independent authority manifest as well as requirements/.
test_path = ROOT / "tests/unit/test_build_authority.py"
replace_exact(
    test_path,
    '    shutil.copytree(ROOT / "requirements", root / "requirements")\n',
    '    shutil.copytree(ROOT / "requirements", root / "requirements")\n'
    '    (root / ".github").mkdir()\n'
    '    shutil.copyfile(ROOT / build_authority.LOCK_AUTHORITY_PATH, root / build_authority.LOCK_AUTHORITY_PATH)\n',
    count=1,
)
replace_exact(
    test_path,
    '(ROOT / "requirements" / build_authority.LOCK_AUTHORITY_FILENAME).read_text(',
    '(ROOT / build_authority.LOCK_AUTHORITY_PATH).read_text(',
    count=1,
)

# Compiler output remains a temporary lock-authority.json, but generated PRs place it in .github/.
promotion = ROOT / ".github/scripts/dependency_promotion.py"
replace_exact(
    promotion,
    '            "runtime-py311.lock",\n            "lock-authority.json",\n        ):\n            result[f"requirements/{name}"] = (output / name).read_bytes()\n        return result',
    '            "runtime-py311.lock",\n        ):\n            result[f"requirements/{name}"] = (output / name).read_bytes()\n        result[".github/lock-authority.json"] = (output / "lock-authority.json").read_bytes()\n        return result',
    count=1,
)

# Restore the protected example to exact current main. The installed auto-healer will own its repair.
subprocess.run(
    ["git", "checkout", "origin/main", "--", "examples/reference_sut/app.py"],
    cwd=ROOT,
    check=True,
)

# Rebind the exact reviewed ordinary-CI blob after the manifest-path-only workflow change.
ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
ci_blob = git_blob_sha(ci)
contract = ROOT / "scripts/verify_ci_contract.py"
contract_text = contract.read_text(encoding="utf-8")
pattern = re.compile(
    r'(EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA = \(\n\s+")[0-9a-f]{40}("  # pragma: allowlist secret\n\))'
)
contract_text, replacements = pattern.subn(rf"\g<1>{ci_blob}\g<2>", contract_text, count=1)
if replacements != 1:
    raise SystemExit("unable to rebind exact ordinary CI workflow blob")
contract.write_text(contract_text, encoding="utf-8", newline="\n")

# No stale authority location may remain anywhere in tracked repository text.
left = subprocess.run(
    ["git", "grep", "-n", OLD_MANIFEST, "--", "."],
    cwd=ROOT,
    text=True,
    capture_output=True,
    check=False,
)
if left.returncode == 0:
    raise SystemExit(f"stale authority path remains:\n{left.stdout}")
if left.returncode != 1:
    raise SystemExit(left.stderr)

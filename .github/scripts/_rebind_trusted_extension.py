from pathlib import Path

path = Path("scripts/verify_ci_contract.py")
text = path.read_text(encoding="utf-8")
old = '    "1068e4382985bca48216548f240df979207e2928"  # pragma: allowlist secret'
new = '    "3ababef12f12ffcce7ddfdece61ba68f3d2e9758"  # pragma: allowlist secret'
if text.count(old) != 1:
    raise SystemExit("expected exactly one prior trusted-auto extension digest")
path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")

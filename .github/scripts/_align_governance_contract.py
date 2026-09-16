from pathlib import Path

path = Path("scripts/verify_ci_contract.py")
text = path.read_text(encoding="utf-8")
replacements = {
    "Reconcile deterministic Python dependency promotions": "Reconcile exact-subject Python dependency promotion",
    "Reconcile Dependabot merge authority": "Reconcile Dependabot action merge authority",
}
for old, new in replacements.items():
    count = text.count(old)
    if count != 2:
        raise SystemExit(f"expected two occurrences of {old!r}, found {count}")
    text = text.replace(old, new)
for fragment in (
    '        "          PROMOTION_PYTHON311: ${{ env.PROMOTION_PYTHON311 }}",\n',
    '        "          PROMOTION_PYTHON314: ${{ env.PROMOTION_PYTHON314 }}",\n',
):
    count = text.count(fragment)
    if count != 1:
        raise SystemExit(f"expected one obsolete env fragment, found {count}")
    text = text.replace(fragment, "")
path.write_text(text, encoding="utf-8", newline="\n")

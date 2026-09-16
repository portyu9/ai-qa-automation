from pathlib import Path

path = Path("scripts/verify_ci_contract.py")
text = path.read_text(encoding="utf-8")
replacements = {
    '        "          PROMOTION_PYTHON311=%s",\n': '        "printf \'PROMOTION_PYTHON311=%s\\\\n\'",\n',
    '        "          PROMOTION_PYTHON314=%s",\n': '        "printf \'PROMOTION_PYTHON314=%s\\\\n\'",\n',
}
for old, new in replacements.items():
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one contract fragment {old!r}, found {count}")
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8", newline="\n")

from pathlib import Path

preflight = Path('scripts/auto_trusted_preflight.py')
text = preflight.read_text(encoding='utf-8')
old = '    def eligible(self) -> bool:\n        return not self.protected_changes or self.maintenance\n'
new = '    def eligible(self) -> bool:\n        return not self.maintenance_trust_root_changes and (\n            not self.protected_changes or self.maintenance\n        )\n'
if text.count(old) != 1:
    raise SystemExit(f'eligible property anchor count={text.count(old)}')
preflight.write_text(text.replace(old, new), encoding='utf-8', newline='\n')

tests = Path('tests/unit/test_auto_trusted_preflight.py')
text = tests.read_text(encoding='utf-8')
needle = 'def test_maintenance_cannot_modify_its_own_trust_root() -> None:\n'
addition = '''def test_trust_root_change_alone_is_never_auto_eligible() -> None:\n    responses = _responses()\n    merge_tree = responses[\n        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/trees/{MERGE_TREE}?recursive=1"\n    ]["tree"]\n    for row in merge_tree:\n        if row["path"] == "scripts/auto_trusted_preflight.py":\n            row["sha"] = "8" * 40\n            break\n    else:\n        raise AssertionError("maintenance trust root missing from synthetic tree")\n\n    admission = preflight.evaluate_admission(FakeAPI(responses), event=_event())\n\n    assert admission.protected_changes == ()\n    assert admission.maintenance_trust_root_changes\n    assert admission.eligible is False\n    assert admission.maintenance is False\n\n\n'''
if text.count(needle) != 1:
    raise SystemExit('maintenance trust-root test anchor drifted')
tests.write_text(text.replace(needle, addition + needle), encoding='utf-8', newline='\n')

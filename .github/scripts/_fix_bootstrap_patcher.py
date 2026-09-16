from pathlib import Path

path = Path('.github/scripts/_bootstrap_trusted_maintenance.py')
text = path.read_text(encoding='utf-8')
old = """replace_once(\n    workflow,\n    '''          EXPECTED_TRUSTED_SHA: ${{ needs.preflight.outputs.trusted_sha }}\\n        run: |\\n''',\n    '''          EXPECTED_TRUSTED_SHA: ${{ needs.preflight.outputs.trusted_sha }}\\n          MAINTENANCE: ${{ needs.preflight.outputs.maintenance }}\\n        run: |\\n''',\n)\n"""
new = """replace_once(\n    workflow,\n    '''          EXPECTED_MERGE_SHA: ${{ needs.preflight.outputs.merge_sha }}\\n          EXPECTED_TRUSTED_SHA: ${{ needs.preflight.outputs.trusted_sha }}\\n        run: |\\n''',\n    '''          EXPECTED_MERGE_SHA: ${{ needs.preflight.outputs.merge_sha }}\\n          EXPECTED_TRUSTED_SHA: ${{ needs.preflight.outputs.trusted_sha }}\\n          MAINTENANCE: ${{ needs.preflight.outputs.maintenance }}\\n        run: |\\n''',\n)\n"""
if text.count(old) != 1:
    raise SystemExit(f'expected exactly one ambiguous subject-guard patch block, found {text.count(old)}')
path.write_text(text.replace(old, new), encoding='utf-8', newline='\n')

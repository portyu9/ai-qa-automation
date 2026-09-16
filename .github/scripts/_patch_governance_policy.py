from pathlib import Path

path = Path('.github/scripts/dependency_governance.py')
text = path.read_text(encoding='utf-8')
text = text.replace(
    '    if config.get("pipMode") != "manual":\n        errors.append("pipMode must equal manual")',
    '    if config.get("pipMode") != "promotion":\n        errors.append("pipMode must equal promotion")',
    1,
)
text = text.replace(
    '        ".github/dependency-recovery.json",\n        ".github/scripts/dependency_governance.py",',
    '        ".github/dependency-recovery.json",\n        ".github/security-autoheal.json",\n        ".github/scripts/dependency_governance.py",\n        ".github/scripts/dependency_lock_compiler.py",\n        ".github/scripts/dependency_promotion.py",',
    1,
)
text = text.replace(
    '        ".github/scripts/dependency_recovery_selfcheck.py",\n        ".github/workflows/dependency-governance.yml",',
    '        ".github/scripts/dependency_recovery_selfcheck.py",\n        ".github/scripts/security_autoheal.py",\n        ".github/scripts/security_autoheal_selfcheck.py",\n        ".github/workflows/dependency-governance.yml",\n        ".github/workflows/security-autoheal.yml",',
    1,
)
text = text.replace(
    '        "security-update:semver-patch",\n        "security-update:semver-minor",\n    }',
    '        "version-update:semver-major",\n        "security-update:semver-patch",\n        "security-update:semver-minor",\n        "security-update:semver-major",\n    }',
    1,
)
text = text.replace(
    '            "allowedActionUpdateTypes must be exactly patch/minor version and security updates"',
    '            "allowedActionUpdateTypes must be exactly patch/minor/major version and security updates"',
    1,
)
old = '''            old_v = next(iter(old_versions))
            new_v = next(iter(new_versions))
            if old_v[0] != new_v[0]:
                raise PolicyBlock(f"major action update requires manual review: {action}")
            if next(iter(old_shas)) == next(iter(new_shas)):
'''
new = '''            old_v = next(iter(old_versions))
            new_v = next(iter(new_versions))
            if new_v <= old_v:
                raise PolicyBlock(f"action version must advance monotonically: {action}")
            if next(iter(old_shas)) == next(iter(new_shas)):
'''
if text.count(old) != 1:
    raise SystemExit('action major guard block drifted')
text = text.replace(old, new, 1)
old_test = '''    try:
        validate_action_semantics(
            [
                {
                    "filename": ".github/workflows/ci.yml",
                    "status": "modified",
                    "patch": "@@ -1 +1 @@\\n-      - uses: actions/checkout@"
                    + "a" * 40
                    + " # v7.0.1\\n"
                    "+      - uses: actions/checkout@" + "b" * 40 + " # v8.0.0\\n",
                }
            ]
        )
    except PolicyBlock:
        pass
    else:
        raise GovernanceError("semantic validator accepted action major update")
'''
new_test = '''    validate_action_semantics(
        [
            {
                "filename": ".github/workflows/ci.yml",
                "status": "modified",
                "patch": "@@ -1 +1 @@\\n-      - uses: actions/checkout@"
                + "a" * 40
                + " # v7.0.1\\n"
                "+      - uses: actions/checkout@" + "b" * 40 + " # v8.0.0\\n",
            }
        ]
    )
    try:
        validate_action_semantics(
            [
                {
                    "filename": ".github/workflows/ci.yml",
                    "status": "modified",
                    "patch": "@@ -1 +1 @@\\n-      - uses: actions/checkout@"
                    + "a" * 40
                    + " # v8.0.0\\n"
                    "+      - uses: actions/checkout@" + "b" * 40 + " # v7.0.1\\n",
                }
            ]
        )
    except PolicyBlock:
        pass
    else:
        raise GovernanceError("semantic validator accepted action version downgrade")
'''
if text.count(old_test) != 1:
    raise SystemExit('governance self-test major block drifted')
text = text.replace(old_test, new_test, 1)
path.write_text(text, encoding='utf-8', newline='\n')

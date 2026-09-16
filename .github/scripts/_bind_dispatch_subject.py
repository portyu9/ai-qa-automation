from pathlib import Path


def replace_one(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}: {old[:100]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def replace_between(path: str, start: str, end: str, replacement: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    left = text.find(start)
    if left < 0:
        raise SystemExit(f"{path}: start marker missing")
    right = text.find(end, left)
    if right < 0:
        raise SystemExit(f"{path}: end marker missing")
    target.write_text(text[:left] + replacement + text[right:], encoding="utf-8", newline="\n")


replace_one(
    "scripts/verify_fork_cloud_authority.py",
    '    "dependency-governance.yml": Counter({"GITHUB_TOKEN": 2, "TRUSTED_GATE_APP_PRIVATE_KEY": 1}),',
    '    "dependency-governance.yml": Counter({"GITHUB_TOKEN": 3, "TRUSTED_GATE_APP_PRIVATE_KEY": 1}),',
)

replace_one(
    ".github/scripts/dependency_promotion.py",
    '''    for group in sorted(optional):\n        values = optional[group]''',
    '''    optional_specs: dict[str, str] = {}\n    for group in sorted(optional):\n        values = optional[group]''',
)
replace_one(
    ".github/scripts/dependency_promotion.py",
    '''            scoped = f"optional:{group}:{identity}"\n            if scoped in versions:\n                raise PolicyBlock(f"duplicate dependency identity in optional group: {identity}")\n            versions[scoped] = str(value)''',
    '''            scoped = f"optional:{group}:{identity}"\n            if scoped in versions:\n                raise PolicyBlock(f"duplicate dependency identity in optional group: {identity}")\n            rendered = str(value)\n            prior = optional_specs.get(identity)\n            if prior is not None and prior != rendered:\n                raise PolicyBlock(\n                    f"duplicate optional dependency specs disagree across groups: {identity}"\n                )\n            optional_specs[identity] = rendered\n            versions[scoped] = rendered''',
)

replace_between(
    ".github/scripts/dependency_promotion.py",
    "def selftest() -> None:\n",
    "\n\ndef main() -> None:\n",
    '''def selftest() -> None:\n    base_raw = b"""[build-system]\nrequires = [\"hatchling==1.32.0\"]\nbuild-backend = \"hatchling.build\"\n\n[project]\nname = \"ai-qa-automation\"\ndependencies = [\"httpx>=0.28,<1\"]\n\n[project.optional-dependencies]\nbrowser = [\"playwright>=1.51,<2\"]\ndev = [\"mypy>=1.14,<2\", \"playwright>=1.51,<2\"]\n"""\n    head_raw = b"""[build-system]\nrequires = [\"hatchling==1.33.0\"]\nbuild-backend = \"hatchling.build\"\n\n[project]\nname = \"ai-qa-automation\"\ndependencies = [\"httpx>=0.29,<1\"]\n\n[project.optional-dependencies]\nbrowser = [\"playwright>=1.52,<2\"]\ndev = [\"mypy>=2,<3\", \"playwright>=1.52,<2\"]\n"""\n    validate_pyproject_transition(base_raw, head_raw)\n\n    added_identity = head_raw.replace(\n        b'dependencies = [\"httpx>=0.29,<1\"]',\n        b'dependencies = [\"httpx>=0.29,<1\", \"requests>=2,<3\"]',\n    )\n    try:\n        validate_pyproject_transition(base_raw, added_identity)\n    except PolicyBlock:\n        pass\n    else:\n        raise GovernanceError("dependency promotion self-test accepted an added dependency identity")\n\n    semantic_drift = head_raw.replace(\n        b'name = \"ai-qa-automation\"',\n        b'name = \"ai-qa-automation-renamed\"',\n    )\n    try:\n        validate_pyproject_transition(base_raw, semantic_drift)\n    except PolicyBlock:\n        pass\n    else:\n        raise GovernanceError("dependency promotion self-test accepted non-version TOML drift")\n\n    url_authority = head_raw.replace(\n        b'\"httpx>=0.29,<1\"',\n        b'\"httpx @ https://example.invalid/httpx.whl\"',\n    )\n    try:\n        validate_pyproject_transition(base_raw, url_authority)\n    except PolicyBlock:\n        pass\n    else:\n        raise GovernanceError("dependency promotion self-test accepted URL dependency authority")\n\n    conflicting_optional = head_raw.replace(\n        b'browser = [\"playwright>=1.52,<2\"]',\n        b'browser = [\"playwright>=1.53,<2\"]',\n    )\n    try:\n        validate_pyproject_transition(base_raw, conflicting_optional)\n    except PolicyBlock:\n        pass\n    else:\n        raise GovernanceError(\n            "dependency promotion self-test accepted conflicting duplicate optional specs"\n        )\n\n    print("dependency-promotion self-test: ok")\n''',
)

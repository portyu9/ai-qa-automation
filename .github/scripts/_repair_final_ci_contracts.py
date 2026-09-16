from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_exact(path: Path, old: str, new: str, *, count: int = 1) -> None:
    text = path.read_text(encoding="utf-8")
    observed = text.count(old)
    if observed != count:
        raise SystemExit(f"{path}: expected {count} occurrence(s), found {observed}: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


replace_exact(
    ROOT / ".github" / "scripts" / "security_autoheal.py",
    "from datetime import UTC, datetime\n",
    "",
)

build_test = ROOT / "tests" / "unit" / "test_build_authority.py"
replace_exact(build_test, "import shutil\n", "import json\nimport shutil\n")
replace_exact(
    build_test,
    '    assert result["reviewed_lock_blobs"] == build_authority.EXPECTED_LOCK_BLOB_SHAS\n',
    '    authority = json.loads(\n'
    '        (ROOT / "requirements" / build_authority.LOCK_AUTHORITY_FILENAME).read_text(\n'
    '            encoding="utf-8"\n'
    '        )\n'
    '    )\n'
    '    assert result["reviewed_lock_blobs"] == authority["lockBlobs"]\n',
)
replace_exact(
    build_test,
    'with pytest.raises(ValueError, match="build-system authority"):',
    'with pytest.raises(ValueError, match=r"build-system(?: backend)? authority"):',
    count=2,
)

trusted_test = ROOT / "tests" / "unit" / "test_ci_trusted_auto_contract.py"
replace_exact(
    trusted_test,
    '    assert payload["result"] == "PASS"\n'
    '    assert payload["workflows"]["trusted_auto"]["status_writer"] == "dedicated-github-app"\n',
    '    assert payload == {\n'
    '        "schema_version": 1,\n'
    '        "result": "PASS",\n'
    '        "verifier": "ci-contract",\n'
    '    }\n',
)

supply_test = ROOT / "tests" / "unit" / "test_exact_supply_chain_definition_authority.py"
replace_exact(
    supply_test,
    '    assert (\n'
    '        ci_text.count(\n'
    '            \'git_template="$(mktemp -d "$RUNNER_TEMP/aiqa-container-git-template.XXXXXX")"\'\n'
    '        )\n'
    '        == 1\n'
    '    )\n',
    '    assert (\n'
    '        ci_text.count(\'git_template="$(mktemp -d "$RUNNER_TEMP/aiqa-git-template.XXXXXX")"\')\n'
    '        == 2\n'
    '    )\n',
)

fork_test = ROOT / "tests" / "unit" / "test_fork_cloud_authority.py"
replace_exact(
    fork_test,
    '      - name: Reconcile Dependabot merge authority\n'
    '        env:\n'
    '          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n'
    '          TRUSTED_STATUS_TOKEN: ${{ steps.trusted-app.outputs.token }}\n',
    '      - name: Reconcile exact-subject Python dependency promotion\n'
    '        env:\n'
    '          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n'
    '          TRUSTED_STATUS_TOKEN: ${{ steps.trusted-app.outputs.token }}\n'
    '      - name: Reconcile Dependabot action merge authority\n'
    '        env:\n'
    '          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n'
    '          TRUSTED_STATUS_TOKEN: ${{ steps.trusted-app.outputs.token }}\n',
)
replace_exact(
    fork_test,
    '        "GITHUB_TOKEN": 2,\n',
    '        "GITHUB_TOKEN": 3,\n',
)
replace_exact(
    fork_test,
    '        "release-candidate.yml",\n'
    '        "trusted-pr-auto.yml",\n',
    '        "release-candidate.yml",\n'
    '        "security-autoheal.yml",\n'
    '        "trusted-pr-auto.yml",\n',
)

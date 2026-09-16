from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one occurrence, found {count}: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


preflight = ROOT / "scripts" / "auto_trusted_preflight.py"
replace_once(
    preflight,
    'EXPECTED_OWNER = "portyu9"\n',
    'EXPECTED_OWNER = "portyu9"\nEXPECTED_OWNER_ID = 35150859\n',
)
replace_once(
    preflight,
    'SHA_RE = re.compile(r"^[0-9a-f]{40}$")\n',
    'SHA_RE = re.compile(r"^[0-9a-f]{40}$")\n'
    'MAINTENANCE_MARKER_RE = re.compile(r"(?m)^Trusted-Maintenance-Head: ([0-9a-f]{40})$")\n'
    'MAINTENANCE_TRUST_ROOTS = (\n'
    '    ".github/workflows/trusted-pr-auto.yml",\n'
    '    "scripts/auto_trusted_preflight.py",\n'
    ')\n',
)
replace_once(
    preflight,
    '''@dataclass(frozen=True)\nclass Admission:\n    pr_number: int\n    head_sha: str\n    base_sha: str\n    merge_sha: str\n    trusted_sha: str\n    protected_changes: tuple[dict[str, str], ...]\n\n    @property\n    def eligible(self) -> bool:\n        return not self.protected_changes\n''',
    '''@dataclass(frozen=True)\nclass Admission:\n    pr_number: int\n    head_sha: str\n    base_sha: str\n    merge_sha: str\n    trusted_sha: str\n    protected_changes: tuple[dict[str, str], ...]\n    maintenance_requested: bool\n    maintenance_trust_root_changes: tuple[dict[str, str], ...]\n\n    @property\n    def maintenance(self) -> bool:\n        return (\n            bool(self.protected_changes)\n            and self.maintenance_requested\n            and not self.maintenance_trust_root_changes\n        )\n\n    @property\n    def eligible(self) -> bool:\n        return not self.protected_changes or self.maintenance\n''',
)
replace_once(
    preflight,
    '''def _protected_changes(\n    base_tree: dict[str, str], subject_tree: dict[str, str]\n) -> tuple[dict[str, str], ...]:\n    rows: list[dict[str, str]] = []\n    for path in PROTECTED_PATHS:\n        base_oid = base_tree.get(path, "MISSING")\n        subject_oid = subject_tree.get(path, "MISSING")\n        if base_oid != subject_oid:\n            rows.append({"path": path, "base_oid": base_oid, "subject_oid": subject_oid})\n    return tuple(rows)\n''',
    '''def _changes_for_paths(\n    base_tree: dict[str, str],\n    subject_tree: dict[str, str],\n    *,\n    paths: tuple[str, ...],\n) -> tuple[dict[str, str], ...]:\n    rows: list[dict[str, str]] = []\n    for path in paths:\n        base_oid = base_tree.get(path, "MISSING")\n        subject_oid = subject_tree.get(path, "MISSING")\n        if base_oid != subject_oid:\n            rows.append({"path": path, "base_oid": base_oid, "subject_oid": subject_oid})\n    return tuple(rows)\n\n\ndef _protected_changes(\n    base_tree: dict[str, str], subject_tree: dict[str, str]\n) -> tuple[dict[str, str], ...]:\n    return _changes_for_paths(base_tree, subject_tree, paths=PROTECTED_PATHS)\n\n\ndef _maintenance_trust_root_changes(\n    base_tree: dict[str, str], subject_tree: dict[str, str]\n) -> tuple[dict[str, str], ...]:\n    return _changes_for_paths(base_tree, subject_tree, paths=MAINTENANCE_TRUST_ROOTS)\n\n\ndef _maintenance_requested(pr: dict[str, Any], *, head_sha: str) -> bool:\n    body = pr.get("body")\n    if body is None:\n        return False\n    if not isinstance(body, str):\n        raise ValueError("pull request body must be a string when present")\n    markers = MAINTENANCE_MARKER_RE.findall(body)\n    if len(markers) > 1:\n        raise ValueError("trusted maintenance request must contain at most one exact-head marker")\n    if markers != [head_sha]:\n        return False\n    author = _require_dict(pr.get("user"), label="live pull request author")\n    return (\n        author.get("login") == EXPECTED_OWNER\n        and _require_positive_int(author.get("id"), label="live pull request author id")\n        == EXPECTED_OWNER_ID\n    )\n''',
)
replace_once(
    preflight,
    '''        trusted_sha=trusted_sha,\n        protected_changes=_protected_changes(base_tree, merge_tree),\n    )\n''',
    '''        trusted_sha=trusted_sha,\n        protected_changes=_protected_changes(base_tree, merge_tree),\n        maintenance_requested=_maintenance_requested(pr, head_sha=head_sha),\n        maintenance_trust_root_changes=_maintenance_trust_root_changes(base_tree, merge_tree),\n    )\n''',
)
replace_once(
    preflight,
    '''    values = {\n        "eligible": "true" if admission.eligible else "false",\n        "pr_number": str(admission.pr_number),\n''',
    '''    values = {\n        "eligible": "true" if admission.eligible else "false",\n        "maintenance": "true" if admission.maintenance else "false",\n        "pr_number": str(admission.pr_number),\n''',
)
replace_once(
    preflight,
    '''    summary = {\n        "eligible": admission.eligible,\n        "pr_number": admission.pr_number,\n''',
    '''    summary = {\n        "eligible": admission.eligible,\n        "maintenance": admission.maintenance,\n        "pr_number": admission.pr_number,\n''',
)

workflow = ROOT / ".github" / "workflows" / "trusted-pr-auto.yml"
replace_once(
    workflow,
    '# Default-branch-owned automatic admission for routine same-repository PRs.\n',
    '# Default-branch-owned admission for routine PRs plus explicit exact-head owner maintenance.\n',
)
replace_once(
    workflow,
    '''      eligible: ${{ steps.admission.outputs.eligible }}\n      pr_number: ${{ steps.admission.outputs.pr_number }}\n''',
    '''      eligible: ${{ steps.admission.outputs.eligible }}\n      maintenance: ${{ steps.admission.outputs.maintenance }}\n      pr_number: ${{ steps.admission.outputs.pr_number }}\n''',
)
replace_once(
    workflow,
    '''          ELIGIBLE: ${{ steps.admission.outputs.eligible }}\n          TRUSTED_SHA: ${{ steps.admission.outputs.trusted_sha }}\n''',
    '''          ELIGIBLE: ${{ steps.admission.outputs.eligible }}\n          MAINTENANCE: ${{ steps.admission.outputs.maintenance }}\n          TRUSTED_SHA: ${{ steps.admission.outputs.trusted_sha }}\n''',
)
replace_once(
    workflow,
    '''          if test "$ELIGIBLE" = "true"; then\n            test "$PROTECTED_CHANGES_JSON" = "[]"\n          else\n            test "$ELIGIBLE" = "false"\n            test "$PROTECTED_CHANGES_JSON" != "[]"\n          fi\n''',
    '''          if test "$ELIGIBLE" = "true"; then\n            if test "$MAINTENANCE" = "true"; then\n              test "$PROTECTED_CHANGES_JSON" != "[]"\n            else\n              test "$MAINTENANCE" = "false"\n              test "$PROTECTED_CHANGES_JSON" = "[]"\n            fi\n          else\n            test "$ELIGIBLE" = "false"\n            test "$MAINTENANCE" = "false"\n            test "$PROTECTED_CHANGES_JSON" != "[]"\n          fi\n''',
)
replace_once(
    workflow,
    '''          EXPECTED_TRUSTED_SHA: ${{ needs.preflight.outputs.trusted_sha }}\n        run: |\n''',
    '''          EXPECTED_TRUSTED_SHA: ${{ needs.preflight.outputs.trusted_sha }}\n          MAINTENANCE: ${{ needs.preflight.outputs.maintenance }}\n        run: |\n''',
)
replace_once(
    workflow,
    '''            src/ai_qa_automation/tools/execution_env.py\n          )\n          oid_for() {\n''',
    '''            src/ai_qa_automation/tools/execution_env.py\n          )\n          maintenance_root_paths=(\n            .github/workflows/trusted-pr-auto.yml\n            scripts/auto_trusted_preflight.py\n          )\n          oid_for() {\n''',
)
replace_once(
    workflow,
    '''          for path in "${protected_paths[@]}"; do\n            base_oid="$(oid_for "$EXPECTED_BASE_SHA" "$path")"\n            subject_oid="$(oid_for "$EXPECTED_MERGE_SHA" "$path")"\n            test "$base_oid" = "$subject_oid"\n          done\n''',
    '''          if test "$MAINTENANCE" = "true"; then\n            paths_to_check=("${maintenance_root_paths[@]}")\n          else\n            test "$MAINTENANCE" = "false"\n            paths_to_check=("${protected_paths[@]}")\n          fi\n          for path in "${paths_to_check[@]}"; do\n            base_oid="$(oid_for "$EXPECTED_BASE_SHA" "$path")"\n            subject_oid="$(oid_for "$EXPECTED_MERGE_SHA" "$path")"\n            test "$base_oid" = "$subject_oid"\n          done\n''',
)
replace_once(
    workflow,
    '''          EXPECTED_TRUSTED_SHA: ${{ needs.preflight.outputs.trusted_sha }}\n          FINAL_ELIGIBLE: ${{ steps.final-admission.outputs.eligible }}\n''',
    '''          EXPECTED_TRUSTED_SHA: ${{ needs.preflight.outputs.trusted_sha }}\n          EXPECTED_MAINTENANCE: ${{ needs.preflight.outputs.maintenance }}\n          FINAL_ELIGIBLE: ${{ steps.final-admission.outputs.eligible }}\n          FINAL_MAINTENANCE: ${{ steps.final-admission.outputs.maintenance }}\n''',
)
replace_once(
    workflow,
    '''          test "$FINAL_ELIGIBLE" = "true"\n          test "$FINAL_PROTECTED_CHANGES" = "[]"\n          test "$FINAL_PR_NUMBER" = "$EXPECTED_PR_NUMBER"\n''',
    '''          test "$FINAL_ELIGIBLE" = "true"\n          test "$FINAL_MAINTENANCE" = "$EXPECTED_MAINTENANCE"\n          if test "$EXPECTED_MAINTENANCE" = "true"; then\n            test "$FINAL_PROTECTED_CHANGES" != "[]"\n          else\n            test "$EXPECTED_MAINTENANCE" = "false"\n            test "$FINAL_PROTECTED_CHANGES" = "[]"\n          fi\n          test "$FINAL_PR_NUMBER" = "$EXPECTED_PR_NUMBER"\n''',
)

tests = ROOT / "tests" / "unit" / "test_auto_trusted_preflight.py"
replace_once(
    tests,
    '''    for path in preflight.PROTECTED_PATHS:\n        sha = UNCHANGED\n''',
    '''    for path in dict.fromkeys((*preflight.PROTECTED_PATHS, *preflight.MAINTENANCE_TRUST_ROOTS)):\n        sha = UNCHANGED\n''',
)
replace_once(
    tests,
    '''    pr = {\n        **candidate,\n        "draft": False,\n''',
    '''    pr = {\n        **candidate,\n        "draft": False,\n        "body": None,\n        "user": {"login": preflight.EXPECTED_OWNER, "id": preflight.EXPECTED_OWNER_ID},\n''',
)
needle = '''def test_fork_head_is_rejected_before_pr_admission() -> None:\n'''
addition = '''def test_exact_head_owner_marker_authorizes_reviewed_protected_maintenance() -> None:\n    responses = _responses(changed_path="requirements")\n    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]["body"] = (\n        f"maintenance intent\\nTrusted-Maintenance-Head: {HEAD}\\n"\n    )\n\n    admission = preflight.evaluate_admission(FakeAPI(responses), event=_event())\n\n    assert admission.eligible is True\n    assert admission.maintenance is True\n    assert admission.maintenance_requested is True\n    assert admission.maintenance_trust_root_changes == ()\n\n\ndef test_stale_maintenance_marker_does_not_authorize_protected_change() -> None:\n    responses = _responses(changed_path="requirements")\n    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]["body"] = (\n        f"Trusted-Maintenance-Head: {'8' * 40}\\n"\n    )\n\n    admission = preflight.evaluate_admission(FakeAPI(responses), event=_event())\n\n    assert admission.eligible is False\n    assert admission.maintenance is False\n\n\ndef test_non_owner_marker_does_not_authorize_protected_change() -> None:\n    responses = _responses(changed_path="requirements")\n    pr = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]\n    pr["body"] = f"Trusted-Maintenance-Head: {HEAD}\\n"\n    pr["user"] = {"login": "attacker", "id": 999}\n\n    admission = preflight.evaluate_admission(FakeAPI(responses), event=_event())\n\n    assert admission.eligible is False\n    assert admission.maintenance is False\n\n\ndef test_maintenance_cannot_modify_its_own_trust_root() -> None:\n    responses = _responses(changed_path="requirements")\n    pr = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]\n    pr["body"] = f"Trusted-Maintenance-Head: {HEAD}\\n"\n    merge_tree = responses[\n        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/trees/{MERGE_TREE}?recursive=1"\n    ]["tree"]\n    for row in merge_tree:\n        if row["path"] == "scripts/auto_trusted_preflight.py":\n            row["sha"] = "8" * 40\n            break\n    else:\n        raise AssertionError("maintenance trust root missing from synthetic tree")\n\n    admission = preflight.evaluate_admission(FakeAPI(responses), event=_event())\n\n    assert admission.eligible is False\n    assert admission.maintenance is False\n    assert admission.maintenance_trust_root_changes\n\n\ndef test_duplicate_maintenance_markers_fail_closed() -> None:\n    responses = _responses(changed_path="requirements")\n    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]["body"] = (\n        f"Trusted-Maintenance-Head: {HEAD}\\nTrusted-Maintenance-Head: {HEAD}\\n"\n    )\n\n    with pytest.raises(ValueError, match="at most one exact-head marker"):\n        preflight.evaluate_admission(FakeAPI(responses), event=_event())\n\n\n'''
text = tests.read_text(encoding="utf-8")
if text.count(needle) != 1:
    raise SystemExit("test insertion anchor drifted")
tests.write_text(text.replace(needle, addition + needle), encoding="utf-8", newline="\n")

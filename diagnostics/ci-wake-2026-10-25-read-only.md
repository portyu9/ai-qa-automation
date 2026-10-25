# Exact-main CI wake startup diagnostic (read-only, 2026-10-25)

This file exists only to document a cleanup PR for an otherwise empty diagnostic branch; do not merge it.

- Trusted upstream `main@45e7f9b045c0707a3214b0947e397ba9df239232`.
- Existing workflow `.github/workflows/current-main-ci-wake.yml@0e621f4ef45a47f83c3a326e583d98ad14823cd0` and test `tests/policy/test_current_main_ci_wake_contract.py@85131203195fe0d9c29835f707e909964b7de07a` are already accepted, not divergent.
- Schedule wake run 40205064820 concluded startup_failure before job allocation; earlier run 40149402586 had zero jobs. Other scheduled upstream workflows have successful completed jobs.
- No upstream open PR or divergent production code to salvage.
- A hypothesis about scheduled actor/cron ownership is not an established root cause. Raw check-suite startup diagnostics are needed. Any cron change would require independently updating the exact source blob pin in `scripts/verify_ci_contract.py` and both contract/test semantic expectations.
- No workflow, permission, action token, protected rule, native evidence, or release is changed in this diagnostic.

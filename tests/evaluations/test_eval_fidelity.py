from __future__ import annotations

import evals.runner as runner


def test_runtime_prompt_boundary_requires_exact_untrusted_data_rule(monkeypatch) -> None:
    monkeypatch.setattr(
        runner,
        "RUNTIME_SYSTEM_PROMPT",
        "The word untrusted appears here, but the authority boundary contract is absent.",
    )

    assert runner.evaluate("runtime_prompt_untrusted_data_boundary") == "FAIL"

    monkeypatch.setattr(
        runner,
        "RUNTIME_SYSTEM_PROMPT",
        f"header\n{runner._RUNTIME_UNTRUSTED_DATA_RULE}\nfooter",
    )

    assert runner.evaluate("runtime_prompt_untrusted_data_boundary") == "PASS"


def test_direct_authorization_policy_cases_measure_complete_registered_denominator() -> None:
    expected = {
        "secret_file_read_policy",
        "dangerous_web_fetch_policy",
        "api_mutation_policy",
        "production_load",
        "governance_threshold_write",
        "governance_claude_write",
        "governance_mcp_write",
    }
    actual = {
        name
        for name, spec in runner.PRIMARY_EVALUATORS.items()
        if spec.family == "direct_authorization_policy"
    }

    assert actual == expected
    assert all(runner.evaluate(name) == "BLOCKED" for name in expected)


def test_prompt_boundary_case_is_not_a_duplicate_claude_path_policy_proxy() -> None:
    prompt_spec = runner.PRIMARY_EVALUATORS["runtime_prompt_untrusted_data_boundary"]
    claude_spec = runner.PRIMARY_EVALUATORS["governance_claude_write"]

    assert prompt_spec.function is not claude_spec.function
    assert prompt_spec.expected == "PASS"
    assert claude_spec.expected == "BLOCKED"
    assert prompt_spec.family == "other"
    assert claude_spec.family == "direct_authorization_policy"

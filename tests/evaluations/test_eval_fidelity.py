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


def test_authority_policy_cases_measure_concrete_policy_operations() -> None:
    assert runner.evaluate("secret_file_read_policy") == "BLOCKED"
    assert runner.evaluate("dangerous_web_fetch_policy") == "BLOCKED"
    assert runner.evaluate("api_mutation_policy") == "BLOCKED"


def test_prompt_boundary_case_is_not_a_duplicate_claude_path_policy_proxy() -> None:
    prompt_spec = runner.PRIMARY_EVALUATORS["runtime_prompt_untrusted_data_boundary"]
    claude_spec = runner.PRIMARY_EVALUATORS["governance_claude_write"]

    assert prompt_spec.function is not claude_spec.function
    assert prompt_spec.expected == "PASS"
    assert claude_spec.expected == "BLOCKED"
    assert prompt_spec.family == "other"
    assert claude_spec.family == "other"

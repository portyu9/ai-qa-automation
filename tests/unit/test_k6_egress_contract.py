from pathlib import Path

import pytest

from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.tools.performance import K6Runner


def policy(tmp_path: Path, *, egress_enforced: bool) -> PolicyEngine:
    subject = PolicyEngine(tmp_path, tmp_path)
    setattr(subject, "k6_external_egress_enforced", egress_enforced)
    return subject


def test_k6_requires_infrastructure_egress_even_for_localhost(tmp_path: Path) -> None:
    runner = K6Runner(tmp_path, policy(tmp_path, egress_enforced=False))

    with pytest.raises(PermissionError, match="infrastructure-level egress"):
        runner.run(
            Path("performance/load.js"),
            target_url="http://127.0.0.1:8000",
            environment="local",
        )


def test_k6_egress_assertion_advances_to_normal_script_validation(tmp_path: Path) -> None:
    runner = K6Runner(tmp_path, policy(tmp_path, egress_enforced=True))

    with pytest.raises(PermissionError, match="existing .js file"):
        runner.run(
            Path("performance/missing.js"),
            target_url="http://127.0.0.1:8000",
            environment="local",
        )

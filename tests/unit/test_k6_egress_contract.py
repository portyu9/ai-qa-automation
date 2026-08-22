from pathlib import Path

import pytest

from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.tools.performance import K6Runner


def policy(tmp_path: Path, *, egress_enforced: bool = False) -> PolicyEngine:
    subject = PolicyEngine(tmp_path, tmp_path)
    setattr(subject, "k6_external_egress_enforced", egress_enforced)
    return subject


def write_script(tmp_path: Path, content: str) -> Path:
    script = tmp_path / "performance" / "load.js"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(content, encoding="utf-8")
    return script.relative_to(tmp_path)


def test_k6_requires_infrastructure_egress_even_for_localhost(tmp_path: Path) -> None:
    runner = K6Runner(tmp_path, policy(tmp_path), external_egress_enforced=False)

    with pytest.raises(PermissionError, match="infrastructure-level egress"):
        runner.run(
            Path("performance/load.js"),
            target_url="http://127.0.0.1:8000",
            environment="local",
        )


def test_k6_explicit_egress_assertion_advances_to_normal_script_validation(tmp_path: Path) -> None:
    runner = K6Runner(tmp_path, policy(tmp_path), external_egress_enforced=True)

    with pytest.raises(PermissionError, match="existing .js file"):
        runner.run(
            Path("performance/missing.js"),
            target_url="http://127.0.0.1:8000",
            environment="local",
        )


def test_k6_literal_network_host_must_match_declared_target(tmp_path: Path) -> None:
    script = write_script(
        tmp_path,
        "import http from 'k6/http';\n"
        "export default function () {\n"
        "  http.get(__ENV.BASE_URL);\n"
        "  http.get('http://127.0.0.1:9999/private');\n"
        "}\n",
    )
    runner = K6Runner(tmp_path, policy(tmp_path), external_egress_enforced=True)

    with pytest.raises(PermissionError, match="unapproved literal network host"):
        runner._validate_script(script, "https://qa.example.test")


def test_k6_localhost_literal_is_allowed_when_localhost_is_the_declared_target(
    tmp_path: Path,
) -> None:
    script = write_script(
        tmp_path,
        "import http from 'k6/http';\n"
        "export default function () {\n"
        "  http.get(__ENV.BASE_URL);\n"
        "  http.get('http://127.0.0.1:8000/health');\n"
        "}\n",
    )
    runner = K6Runner(tmp_path, policy(tmp_path), external_egress_enforced=True)

    resolved = runner._validate_script(script, "http://127.0.0.1:8000")

    assert resolved == (tmp_path / script).resolve()


@pytest.mark.parametrize("timeout", [0, -1, True, 1.5])
def test_k6_rejects_invalid_timeout_bound(tmp_path: Path, timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        K6Runner(
            tmp_path,
            policy(tmp_path),
            timeout_seconds=timeout,  # type: ignore[arg-type]
            external_egress_enforced=True,
        )


@pytest.mark.parametrize("value", [1, "true", object()])
def test_k6_rejects_non_boolean_explicit_egress_assertion(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError, match="external_egress_enforced"):
        K6Runner(
            tmp_path,
            policy(tmp_path),
            external_egress_enforced=value,  # type: ignore[arg-type]
        )

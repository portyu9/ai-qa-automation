from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "dependency_lock_compiler.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dependency_lock_compiler_replay_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compiler = _load()


def _lock(*rows: tuple[str, str, str]) -> bytes:
    return "".join(
        f"{name}=={version} \\\n    --hash=sha256:{digest}\n" for name, version, digest in rows
    ).encode()


def test_parse_frozen_lock_accepts_only_canonical_sorted_entries() -> None:
    raw = _lock(
        ("alpha", "1.0", "1" * 64),
        ("bravo-two", "2.3.4", "2" * 64),
    )
    assert compiler._parse_frozen_lock(raw, name="dev.lock") == {
        "alpha": ("1.0", "1" * 64),
        "bravo-two": ("2.3.4", "2" * 64),
    }


@pytest.mark.parametrize(
    "raw",
    [
        b"alpha==1.0 \\\n    --hash=sha256:" + b"1" * 64,
        _lock(("bravo", "1", "1" * 64), ("alpha", "1", "2" * 64)),
        _lock(("alpha", "1", "1" * 64), ("alpha", "1", "1" * 64)),
        b"alpha==1.0 \\\n    --hash=sha256:" + b"1" * 64 + b"\n# comment\n",
        b"Alpha==1.0 \\\n    --hash=sha256:" + b"1" * 64 + b"\n",
        b"alpha==1.0;marker \\\n    --hash=sha256:" + b"1" * 64 + b"\n",
        b"alpha==1.0@evil \\\n    --hash=sha256:" + b"1" * 64 + b"\n",
    ],
)
def test_parse_frozen_lock_rejects_noncanonical_bytes(raw: bytes) -> None:
    with pytest.raises(compiler.LockCompileError):
        compiler._parse_frozen_lock(raw, name="dev.lock")


def _pip_report_row(
    *,
    is_yanked: object = False,
    is_direct: object = False,
    name: str = "alpha",
    version: str = "1.0",
    digest: str = "1" * 64,
) -> dict[str, object]:
    return {
        "is_yanked": is_yanked,
        "is_direct": is_direct,
        "metadata": {"name": name, "version": version},
        "download_info": {
            "url": f"https://files.pythonhosted.org/packages/{name}-{version}-py3-none-any.whl",
            "archive_info": {"hashes": {"sha256": digest}},
        },
    }


def test_report_to_lock_requires_explicit_non_yanked_artifact() -> None:
    assert compiler._report_to_lock({"version": "1", "install": [_pip_report_row()]}) == _lock(
        ("alpha", "1.0", "1" * 64)
    ).decode()

    with pytest.raises(compiler.LockCompileError, match="yanked"):
        compiler._report_to_lock({"version": "1", "install": [_pip_report_row(is_yanked=True)]})

    missing = _pip_report_row()
    missing.pop("is_yanked")
    with pytest.raises(compiler.LockCompileError, match="non-yanked provenance"):
        compiler._report_to_lock({"version": "1", "install": [missing]})


@pytest.mark.parametrize(
    ("is_yanked", "digest", "error"),
    [
        (False, "1" * 64, None),
        (True, "1" * 64, "yanked"),
        (False, "2" * 64, "exact locked artifact graph"),
    ],
)
def test_hash_replay_revalidates_terminal_artifact_provenance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    is_yanked: bool,
    digest: str,
    error: str | None,
) -> None:
    lock = tmp_path / "dev.lock"
    lock.write_bytes(_lock(("alpha", "1.0", "1" * 64)))
    observed: dict[str, object] = {}

    class Result:
        returncode = 0
        stdout = ""

    def fake_run(command: list[str], **kwargs: object) -> Result:
        observed["command"] = command
        report_path = Path(command[command.index("--report") + 1])
        report_path.write_text(
            json.dumps(
                {
                    "version": "1",
                    "install": [
                        _pip_report_row(
                            is_yanked=is_yanked,
                            digest=digest,
                        )
                    ]
                }
            )
        )
        return Result()

    monkeypatch.setattr(compiler.subprocess, "run", fake_run)
    if error is None:
        compiler._verify_hash_lock("/python", tmp_path, lock)
    else:
        with pytest.raises(compiler.LockCompileError, match=error):
            compiler._verify_hash_lock("/python", tmp_path, lock)

    command = observed["command"]
    assert isinstance(command, list)
    assert "--report" in command
    assert "--require-hashes" in command
    assert "--only-binary=:all:" in command


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("alpha\n--index-url=https://evil.invalid", "1.0"),
        ("alpha", "1.0\n--extra-index-url=https://evil.invalid"),
        ("alpha", "1.0/../../escape"),
    ],
)
def test_report_to_lock_rejects_unsafe_metadata_before_rendering(
    name: str,
    version: str,
) -> None:
    with pytest.raises(compiler.LockCompileError, match="canonical lock syntax"):
        compiler._report_to_lock(
            {
                "version": "1",
                "install": [_pip_report_row(name=name, version=version)],
            }
        )


def test_report_to_lock_requires_schema_and_index_provenance() -> None:
    with pytest.raises(compiler.LockCompileError, match="version"):
        compiler._report_to_lock({"install": [_pip_report_row()]})
    with pytest.raises(compiler.LockCompileError, match="version"):
        compiler._report_to_lock({"version": "2", "install": [_pip_report_row()]})
    with pytest.raises(compiler.LockCompileError, match="direct"):
        compiler._report_to_lock(
            {"version": "1", "install": [_pip_report_row(is_direct=True)]}
        )
    ambiguous = _pip_report_row()
    ambiguous.pop("is_direct")
    with pytest.raises(compiler.LockCompileError, match="ambiguous artifact provenance"):
        compiler._report_to_lock({"version": "1", "install": [ambiguous]})


def test_authority_bytes_bind_pyproject_base_image_and_every_lock(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "requirements").mkdir(parents=True)
    (root / "requirements" / "base-image.lock").write_bytes(b"base\n")
    locks = {
        "build-py311.lock": _lock(("alpha", "1", "1" * 64)),
        "dev-py311.lock": _lock(("bravo", "2", "2" * 64)),
    }
    first = compiler._authority_bytes(b"project-one\n", root, locks)
    assert first != compiler._authority_bytes(b"project-two\n", root, locks)
    changed = dict(locks)
    changed["dev-py311.lock"] = _lock(("bravo", "3", "3" * 64))
    assert first != compiler._authority_bytes(b"project-one\n", root, changed)
    (root / "requirements" / "base-image.lock").write_bytes(b"other\n")
    assert first != compiler._authority_bytes(b"project-one\n", root, locks)


def test_frozen_replay_rejects_dependency_closure_drift_before_hash_replay(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    frozen = {"alpha": ("1.0", "1" * 64)}
    monkeypatch.setattr(compiler, "_run_frozen_report", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        compiler,
        "_report_to_lock",
        lambda payload: _lock(("alpha", "1.1", "2" * 64)).decode(),
    )
    called = False

    def verify(*args: object, **kwargs: object) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(compiler, "_verify_hash_lock", verify)
    with pytest.raises(compiler.LockCompileError, match="exact dependency closure"):
        compiler._replay_frozen_graph(
            "/python",
            tmp_path,
            ["alpha>=1,<2"],
            tmp_path / "dev.lock",
            frozen,
        )
    assert called is False


def test_frozen_replay_requires_hash_replay_after_exact_closure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    raw = _lock(("alpha", "1.0", "1" * 64))
    frozen = compiler._parse_frozen_lock(raw, name="dev.lock")
    monkeypatch.setattr(compiler, "_run_frozen_report", lambda *args, **kwargs: {})
    monkeypatch.setattr(compiler, "_report_to_lock", lambda payload: raw.decode())
    calls: list[tuple[str, Path, Path]] = []
    monkeypatch.setattr(
        compiler,
        "_verify_hash_lock",
        lambda python, root, lock: calls.append((python, root, lock)),
    )
    compiler._replay_frozen_graph(
        "/python",
        tmp_path,
        ["alpha>=1,<2"],
        tmp_path / "dev.lock",
        frozen,
    )
    assert calls == [("/python", tmp_path, tmp_path / "dev.lock")]


def test_frozen_report_uses_exact_constraints_for_every_locked_package(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    observed: dict[str, object] = {}

    class Result:
        returncode = 0
        stdout = ""

    def fake_run(command: list[str], **kwargs: object) -> Result:
        observed["command"] = command
        constraint_path = Path(command[command.index("-c") + 1])
        observed["constraints"] = constraint_path.read_text()
        report_path = Path(command[command.index("--report") + 1])
        report_path.write_text('{"install": []}\n')
        return Result()

    monkeypatch.setattr(compiler.subprocess, "run", fake_run)
    payload = compiler._run_frozen_report(
        "/python",
        root,
        ["alpha>=1,<2"],
        {
            "alpha": ("1.0", "1" * 64),
            "bravo": ("2.0", "2" * 64),
        },
    )

    assert payload == {"install": []}
    assert observed["constraints"] == "alpha==1.0\nbravo==2.0\n"
    command = observed["command"]
    assert isinstance(command, list)
    assert "--dry-run" in command
    assert "--ignore-installed" in command
    assert "--only-binary=:all:" in command
    assert "-r" in command
    assert "-c" in command

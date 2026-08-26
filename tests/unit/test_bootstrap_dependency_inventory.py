from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import ai_qa_automation.runtime.bootstrap as bootstrap_module
from ai_qa_automation.fs_observation import scan_regular_files_confined
from ai_qa_automation.runtime.bootstrap import _dependency_inventory, bootstrap_runtime_context


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_dependency_inventory_hashes_confined_manifest_bytes(tmp_path: Path) -> None:
    content = b'[project]\nname = "example"\n'
    write(tmp_path / "pyproject.toml", content)
    write(tmp_path / "src" / "ignored.py", b"pass\n")

    rows, truncated = _dependency_inventory(tmp_path)

    assert truncated is False
    assert rows == [
        {
            "path": "pyproject.toml",
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "hashed": True,
            "reason": None,
        }
    ]


def test_dependency_inventory_marks_oversized_manifest_without_reading_it(tmp_path: Path) -> None:
    write(tmp_path / "package.json", b"x" * 32)

    rows, truncated = _dependency_inventory(tmp_path, max_file_bytes=8)

    assert truncated is True
    assert rows[0]["path"] == "package.json"
    assert rows[0]["hashed"] is False
    assert rows[0]["reason"] == "file-size-limit:8"


def test_dependency_inventory_never_follows_symlink_manifest(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    outside = tmp_path.parent / f"{tmp_path.name}-manifest-outside"
    write(outside / "real.toml", b"secret")
    (tmp_path / "pyproject.toml").symlink_to(outside / "real.toml")

    rows, truncated = _dependency_inventory(tmp_path)

    assert truncated is True
    assert rows == [
        {
            "path": "pyproject.toml",
            "size": None,
            "sha256": None,
            "hashed": False,
            "reason": "ambiguous-or-non-file",
        }
    ]


def test_dependency_inventory_parent_swap_cannot_redirect_manifest_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        pytest.skip("descriptor-relative no-follow scan is Unix-only")
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    write(workspace / "config" / "package.json", b'{"name":"inside"}')
    write(outside / "package.json", b'{"name":"outside"}')

    real_scan = scan_regular_files_confined

    def scan_then_swap(*args: object, **kwargs: object):
        result = real_scan(*args, **kwargs)
        original = workspace / "config"
        original.rename(workspace / "config-original")
        (workspace / "config").symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(bootstrap_module, "scan_regular_files_confined", scan_then_swap)

    rows, truncated = _dependency_inventory(workspace)

    assert truncated is True
    assert rows == [
        {
            "path": "config/package.json",
            "size": None,
            "sha256": None,
            "hashed": False,
            "reason": "read-failed-or-grew-during-hash",
        }
    ]


def test_dependency_inventory_root_swap_after_scan_cannot_redirect_manifest_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        pytest.skip("descriptor-relative no-follow scan is Unix-only")
    workspace = tmp_path / "workspace"
    write(workspace / "package.json", b'{"name":"inside"}')

    real_scan = scan_regular_files_confined

    def scan_then_replace_root(*args: object, **kwargs: object):
        result = real_scan(*args, **kwargs)
        workspace.rename(tmp_path / "workspace-original")
        write(workspace / "package.json", b'{"name":"outside"}')
        return result

    monkeypatch.setattr(bootstrap_module, "scan_regular_files_confined", scan_then_replace_root)

    rows, truncated = _dependency_inventory(workspace)

    assert truncated is True
    assert rows == [
        {
            "path": "package.json",
            "size": None,
            "sha256": None,
            "hashed": False,
            "reason": "read-failed-or-grew-during-hash",
        }
    ]


def test_bootstrap_rejects_workspace_identity_mismatch_before_observation(tmp_path: Path) -> None:
    current = tmp_path.stat(follow_symlinks=False)

    with pytest.raises(ValueError, match="changed identity since lease acquisition"):
        bootstrap_runtime_context(
            workspace=tmp_path,
            state=None,  # type: ignore[arg-type]
            evidence=None,  # type: ignore[arg-type]
            state_store=None,  # type: ignore[arg-type]
            control=None,  # type: ignore[arg-type]
            workspace_root_identity=(current.st_dev, current.st_ino + 1),
        )


def test_bootstrap_rejects_root_replacement_during_repository_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    current = workspace.stat(follow_symlinks=False)
    expected_identity = (current.st_dev, current.st_ino)
    real_snapshot = bootstrap_module.RepositoryInspector.snapshot

    def snapshot_then_replace(inspector: object):
        snapshot = real_snapshot(inspector)  # type: ignore[arg-type]
        workspace.rename(tmp_path / "workspace-original")
        workspace.mkdir()
        return snapshot

    monkeypatch.setattr(bootstrap_module.RepositoryInspector, "snapshot", snapshot_then_replace)

    with pytest.raises(ValueError, match="changed identity during repository inspection"):
        bootstrap_runtime_context(
            workspace=workspace,
            state=None,  # type: ignore[arg-type]
            evidence=None,  # type: ignore[arg-type]
            state_store=None,  # type: ignore[arg-type]
            control=None,  # type: ignore[arg-type]
            workspace_root_identity=expected_identity,
        )


def test_dependency_inventory_scan_limit_counts_directory_entries(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"empty-{index}").mkdir()
    write(tmp_path / "z" / "pyproject.toml", b"[project]\n")

    rows, truncated = _dependency_inventory(tmp_path, max_scan_files=2)

    assert rows == []
    assert truncated is True


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_files": 0},
        {"max_scan_files": True},
        {"max_file_bytes": 1.5},
    ],
)
def test_dependency_inventory_rejects_invalid_bounds(
    tmp_path: Path, kwargs: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        _dependency_inventory(tmp_path, **kwargs)  # type: ignore[arg-type]


def test_bootstrap_revalidates_root_before_persisting_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current = tmp_path.stat(follow_symlinks=False)
    root_identity = (current.st_dev, current.st_ino)
    pin_results = iter(
        (root_identity, root_identity, (root_identity[0], root_identity[1] + 1))
    )

    def next_pin(*args: object, **kwargs: object) -> tuple[int, int]:
        del args, kwargs
        return next(pin_results)

    monkeypatch.setattr(bootstrap_module, "pin_directory_identity", next_pin)

    class FakeEvidenceItem:
        def __init__(self, **kwargs: object) -> None:
            self.id = str(kwargs["source"])

    class FakeEvidence:
        def __init__(self) -> None:
            self.added: list[FakeEvidenceItem] = []

        def add(self, item: FakeEvidenceItem) -> FakeEvidenceItem:
            self.added.append(item)
            return item

    class FakeState:
        def __init__(self) -> None:
            self.run_id = "run-test"
            self.evidence_ids: list[str] = []
            self.target_git_sha: str | None = None

    class FakeJournal:
        def append(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    class FakeControl:
        def __init__(self) -> None:
            self.journal = FakeJournal()

        def set_workspace_fingerprint(self, value: str) -> None:
            del value

        def persist(self) -> None:
            pass

    class FakeStateStore:
        def save(self, state: object) -> None:
            del state

    class FakeRisk:
        value = "LOW"

    class FakeImpact:
        def __init__(self) -> None:
            self.risk = FakeRisk()

        def as_dict(self) -> dict[str, object]:
            return {}

    class FakeProfile:
        languages: tuple[str, ...] = ()
        test_surfaces: tuple[str, ...] = ()

        def as_dict(self) -> dict[str, object]:
            return {}

    class FakeTestImpact:
        candidates: tuple[object, ...] = ()
        confidence = 0.35

        def as_dict(self) -> dict[str, object]:
            return {}

    class FakeOwnership:
        def __init__(self) -> None:
            self.source_path = None
            self.ownership_by_file: dict[str, tuple[str, ...]] = {}
            self.unowned_files: tuple[str, ...] = ()

        def as_dict(self) -> dict[str, object]:
            return {}

    class FakeChangeImpactAnalyzer:
        def assess(self, changed_files: object) -> FakeImpact:
            del changed_files
            return FakeImpact()

    class FakeRepositoryProfiler:
        def profile(self, workspace: Path, **kwargs: object) -> FakeProfile:
            del workspace, kwargs
            return FakeProfile()

    class FakeTestImpactMapper:
        def map(
            self, workspace: Path, changed_files: object, **kwargs: object
        ) -> FakeTestImpact:
            del workspace, changed_files, kwargs
            return FakeTestImpact()

    class FakeCodeownersResolver:
        @classmethod
        def from_workspace(
            cls, workspace: Path, **kwargs: object
        ) -> FakeCodeownersResolver:
            del workspace, kwargs
            return cls()

        def resolve(self, changed_files: object) -> FakeOwnership:
            del changed_files
            return FakeOwnership()

    evidence = FakeEvidence()
    monkeypatch.setattr(bootstrap_module, "EvidenceItem", FakeEvidenceItem)

    def fake_dependency_inventory(*args: object, **kwargs: object) -> tuple[list[object], bool]:
        del args, kwargs
        return [], False

    monkeypatch.setattr(bootstrap_module, "ChangeImpactAnalyzer", FakeChangeImpactAnalyzer)
    monkeypatch.setattr(bootstrap_module, "RepositoryProfiler", FakeRepositoryProfiler)
    monkeypatch.setattr(bootstrap_module, "_dependency_inventory", fake_dependency_inventory)
    monkeypatch.setattr(bootstrap_module, "TestImpactMapper", FakeTestImpactMapper)
    monkeypatch.setattr(bootstrap_module, "CodeownersResolver", FakeCodeownersResolver)

    with pytest.raises(ValueError, match="before evidence persistence"):
        bootstrap_runtime_context(
            workspace=tmp_path,
            state=FakeState(),  # type: ignore[arg-type]
            evidence=evidence,  # type: ignore[arg-type]
            state_store=FakeStateStore(),  # type: ignore[arg-type]
            control=FakeControl(),  # type: ignore[arg-type]
        )

    assert evidence.added == []

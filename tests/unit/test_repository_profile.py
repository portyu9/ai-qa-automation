from __future__ import annotations

from pathlib import Path

from ai_qa_automation.intelligence.repository_profile import RepositoryProfiler


def write(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_repository_profile_discovers_stack_without_executing_code(tmp_path: Path) -> None:
    write(tmp_path / "src" / "service.py", "raise RuntimeError('must never execute')\n")
    write(tmp_path / "frontend" / "checkout.tsx", "export const checkout = true\n")
    write(tmp_path / "pytest.ini", "[pytest]\n")
    write(tmp_path / "tests" / "checkout.playwright.spec.ts", "test('checkout', () => {})\n")
    write(tmp_path / "performance" / "smoke.k6.js", "export default function () {}\n")
    write(tmp_path / "openapi.yaml", "openapi: 3.1.0\n")
    write(tmp_path / "migrations" / "001_create_orders.py", "# migration\n")
    write(tmp_path / "Dockerfile", "FROM scratch\n")
    write(tmp_path / ".github" / "workflows" / "ci.yml", "name: ci\n")
    write(tmp_path / "node_modules" / "ignored.js", "throw new Error('ignored')\n")

    result = RepositoryProfiler().profile(tmp_path)

    assert set(result.languages[:2]) == {"python", "typescript"}
    assert set(result.test_surfaces) >= {"pytest", "playwright", "k6"}
    assert set(result.architecture_surfaces) >= {
        "api-contract",
        "database-migrations",
        "containers",
    }
    assert result.ci_surfaces == ("github-actions",)
    assert "openapi.yaml" in result.notable_files
    assert ".github/workflows/ci.yml" in result.notable_files
    assert result.scanned_files == 9
    assert result.truncated is False


def test_repository_profile_is_bounded(tmp_path: Path) -> None:
    for index in range(5):
        write(tmp_path / "src" / f"module_{index}.py", "pass\n")

    result = RepositoryProfiler().profile(tmp_path, max_files=2)

    assert result.scanned_files == 2
    assert result.truncated is True

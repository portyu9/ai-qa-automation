from __future__ import annotations

from pathlib import Path

import pytest

from scripts.verify_docs import MAX_DOC_BYTES, MAX_DOC_ENTRIES, verify_documentation

ROOT = Path(__file__).resolve().parents[2]


def _minimal_public_docs(root: Path) -> None:
    (root / "docs").mkdir(parents=True)
    (root / "README.md").write_text(
        "# Root\n\n[Docs](docs/README.md)\n",
        encoding="utf-8",
    )
    (root / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (root / "docs" / "README.md").write_text(
        "# Docs\n\n[Production](PRODUCTION_READINESS.md)\n",
        encoding="utf-8",
    )
    (root / "docs" / "PRODUCTION_READINESS.md").write_text(
        "# Production Readiness\n",
        encoding="utf-8",
    )


def test_repository_public_documentation_contract_is_self_consistent() -> None:
    result = verify_documentation(ROOT)

    assert result["result"] == "PASS"
    assert result["schema_version"] == 1
    assert result["documents_checked"] >= 20
    assert result["local_links_checked"] > 0
    assert result["mermaid_blocks_checked"] > 0


def test_docs_verifier_rejects_missing_local_target(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    (tmp_path / "README.md").write_text(
        "# Root\n\n[Missing](docs/DOES_NOT_EXIST.md)\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing local link target"):
        verify_documentation(tmp_path)


def test_docs_verifier_ignores_footnote_definitions_as_links(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    (tmp_path / "README.md").write_text(
        "# Root\n\nEvidence-first control.[^note]\n\n"
        "[Docs](docs/README.md)\n\n"
        "[^note]: The explanatory text is not a link target.\n",
        encoding="utf-8",
    )

    result = verify_documentation(tmp_path)

    assert result["result"] == "PASS"


def test_docs_verifier_still_checks_reference_link_definitions(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    (tmp_path / "README.md").write_text(
        "# Root\n\n[Missing][target]\n\n[target]: docs/DOES_NOT_EXIST.md\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing local link target"):
        verify_documentation(tmp_path)


def test_docs_verifier_rejects_repository_escape_link(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    outside = tmp_path.parent / "outside.md"
    outside.write_text("# Outside\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "# Root\n\n[Escape](../outside.md)\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="escapes repository root"):
        verify_documentation(tmp_path)


def test_docs_verifier_rejects_missing_markdown_anchor(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    (tmp_path / "README.md").write_text(
        "# Root\n\n[Bad anchor](docs/README.md#does-not-exist)\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing Markdown anchor"):
        verify_documentation(tmp_path)


def test_docs_verifier_rejects_unaccessible_mermaid_block(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    (tmp_path / "docs" / "PRODUCTION_READINESS.md").write_text(
        "# Production Readiness\n\n```mermaid\nflowchart LR\nA --> B\n```\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="accTitle"):
        verify_documentation(tmp_path)


@pytest.mark.parametrize("blank_field", ["accTitle", "accDescr"])
def test_docs_verifier_rejects_blank_mermaid_metadata(tmp_path: Path, blank_field: str) -> None:
    _minimal_public_docs(tmp_path)
    title = "" if blank_field == "accTitle" else "Accessible title"
    description = "" if blank_field == "accDescr" else "Accessible description"
    (tmp_path / "docs" / "PRODUCTION_READINESS.md").write_text(
        "# Production Readiness\n\n"
        "~~~mermaid\n"
        "flowchart LR\n"
        f"accTitle: {title}\n"
        f"accDescr: {description}\n"
        "A --> B\n"
        "~~~\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=blank_field):
        verify_documentation(tmp_path)


def test_docs_verifier_rejects_duplicate_mermaid_metadata(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    (tmp_path / "docs" / "PRODUCTION_READINESS.md").write_text(
        "# Production Readiness\n\n"
        "````mermaid\n"
        "flowchart LR\n"
        "accTitle: First title\n"
        "accTitle: Second title\n"
        "accDescr: Accessible description\n"
        "A --> B\n"
        "````\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exactly one non-blank accTitle"):
        verify_documentation(tmp_path)


@pytest.mark.parametrize("fence", ["```", "````", "~~~", "~~~~"])
def test_docs_verifier_rejects_unterminated_fence(tmp_path: Path, fence: str) -> None:
    _minimal_public_docs(tmp_path)
    (tmp_path / "README.md").write_text(
        f"# Root\n\n{fence}bash\necho broken\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unterminated fenced code block"):
        verify_documentation(tmp_path)


@pytest.mark.parametrize(
    ("path", "heading", "match"),
    [
        ("README.md", "## Current status", "Current status"),
        (
            "docs/PRODUCTION_READINESS.md",
            "## Status vocabulary",
            "Status vocabulary",
        ),
    ],
)
def test_docs_verifier_rejects_prohibited_project_status_headings(
    tmp_path: Path, path: str, heading: str, match: str
) -> None:
    _minimal_public_docs(tmp_path)
    target = tmp_path / path
    target.write_text(target.read_text(encoding="utf-8") + f"\n{heading}\n", encoding="utf-8")

    with pytest.raises(ValueError, match=match):
        verify_documentation(tmp_path)


@pytest.mark.parametrize(
    "command",
    [
        "python -m pip install --upgrade pip",
        "python -m pip install -e '.[dev]'",
        "pip install --editable .[dev]",
    ],
)
def test_docs_verifier_rejects_live_or_editable_setup_snippets(
    tmp_path: Path, command: str
) -> None:
    _minimal_public_docs(tmp_path)
    (tmp_path / "README.md").write_text(
        f"# Root\n\n```bash\n{command}\n```\n\n[Docs](docs/README.md)\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="setup snippet"):
        verify_documentation(tmp_path)


@pytest.mark.parametrize("fence", ["````", "~~~"])
def test_docs_verifier_cannot_bypass_setup_policy_with_alternate_fence(
    tmp_path: Path, fence: str
) -> None:
    _minimal_public_docs(tmp_path)
    (tmp_path / "README.md").write_text(
        f"# Root\n\n{fence}bash\npython -m pip install --upgrade pip\n{fence}\n"
        "\n[Docs](docs/README.md)\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="setup snippet"):
        verify_documentation(tmp_path)


def test_docs_verifier_requires_docs_hub_to_cover_every_page(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    (tmp_path / "docs" / "EXTRA.md").write_text("# Extra\n", encoding="utf-8")

    with pytest.raises(ValueError, match="does not link every public docs page"):
        verify_documentation(tmp_path)


def test_docs_verifier_enforces_doc_entry_bound_during_enumeration(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    for index in range(MAX_DOC_ENTRIES):
        (tmp_path / "docs" / f"entry-{index:03}.txt").write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match=f"exceeds {MAX_DOC_ENTRIES} direct entries"):
        verify_documentation(tmp_path)


def test_docs_verifier_rejects_oversized_public_document(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    (tmp_path / "README.md").write_text("x" * (MAX_DOC_BYTES + 1), encoding="utf-8")

    with pytest.raises(ValueError):
        verify_documentation(tmp_path)


def test_docs_verifier_rejects_symlinked_public_doc(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    real = tmp_path / "real.md"
    real.write_text("# Real\n", encoding="utf-8")
    linked = tmp_path / "docs" / "LINKED.md"
    try:
        linked.symlink_to(real)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation unavailable on this platform")

    with pytest.raises(ValueError, match="non-symlink"):
        verify_documentation(tmp_path)


def test_docs_verifier_rejects_symlinked_local_link_target(tmp_path: Path) -> None:
    _minimal_public_docs(tmp_path)
    real = tmp_path / "real.txt"
    real.write_text("real\n", encoding="utf-8")
    linked = tmp_path / "docs" / "linked.txt"
    try:
        linked.symlink_to(real)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation unavailable on this platform")
    (tmp_path / "README.md").write_text(
        "# Root\n\n[Linked](docs/linked.txt)\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="local link target is a symlink"):
        verify_documentation(tmp_path)

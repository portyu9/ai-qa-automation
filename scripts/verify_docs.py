from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from ai_qa_automation.io_safety import read_text_bounded

MAX_DOC_BYTES = 128 * 1024
MAX_DOC_ENTRIES = 64
PUBLIC_ROOT_MARKDOWN = ("README.md", "CONTRIBUTING.md", "SECURITY.md")
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:")
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
REFERENCE_LINK_RE = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.MULTILINE)
HTML_ATTR_RE = re.compile(r"\b(?:href|src|srcset)=[\"']([^\"']+)[\"']", re.IGNORECASE)
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
CURRENT_STATUS_HEADING_RE = re.compile(
    r"^#{1,6}\s+Current status\s*$", re.IGNORECASE | re.MULTILINE
)
STATUS_VOCAB_HEADING_RE = re.compile(
    r"^#{1,6}\s+Status vocabulary\s*$", re.IGNORECASE | re.MULTILINE
)
LIVE_PIP_UPGRADE_RE = re.compile(r"\b(?:python\s+-m\s+)?pip\s+install\s+--upgrade\s+pip\b")
EDITABLE_DEV_INSTALL_RE = re.compile(
    r"\b(?:python\s+-m\s+)?pip\s+install\b[^\n]*(?:\s-e(?:\s|=)|\s--editable(?:\s|=))[^\n]*\.\[dev\]"
)
FENCE_OPEN_RE = re.compile(r"^(?P<fence>`{3,}|~{3,})[ \t]*(?P<info>[A-Za-z0-9_+.-]*)[ \t]*$")
MERMAID_DIAGRAM_PREFIXES = (
    "flowchart ",
    "graph ",
    "sequenceDiagram",
    "stateDiagram",
    "classDiagram",
    "erDiagram",
    "journey",
    "gantt",
    "pie",
    "mindmap",
    "timeline",
    "gitGraph",
)


@dataclass(frozen=True)
class PublicDocument:
    path: Path
    relative_path: str
    text: str


def _read_text(path: Path) -> str:
    text = read_text_bounded(path, max_bytes=MAX_DOC_BYTES, label=f"public documentation {path}")
    if not text:
        raise ValueError(f"public documentation file is empty: {path}")
    return text


def _load_public_documents(root: Path) -> dict[str, PublicDocument]:
    documents: dict[str, PublicDocument] = {}
    for name in PUBLIC_ROOT_MARKDOWN:
        path = root / name
        documents[name] = PublicDocument(path=path, relative_path=name, text=_read_text(path))

    docs_dir = root / "docs"
    if docs_dir.is_symlink() or not docs_dir.is_dir():
        raise ValueError("docs must be a real directory, not a symlink")

    entries: list[Path] = []
    for path in docs_dir.iterdir():
        if len(entries) >= MAX_DOC_ENTRIES:
            raise ValueError(f"docs exceeds {MAX_DOC_ENTRIES} direct entries")
        entries.append(path)

    for path in sorted(entries, key=lambda value: value.name):
        if path.suffix.lower() != ".md":
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(
                f"public documentation path must be a regular non-symlink file: {path}"
            )
        relative = path.relative_to(root).as_posix()
        documents[relative] = PublicDocument(
            path=path,
            relative_path=relative,
            text=_read_text(path),
        )
    return documents


def _parse_fence_open(line: str) -> tuple[str, int, str] | None:
    match = FENCE_OPEN_RE.match(line.strip())
    if match is None:
        return None
    fence = match.group("fence")
    return fence[0], len(fence), match.group("info").lower()


def _is_fence_close(line: str, *, fence_char: str, minimum_length: int) -> bool:
    stripped = line.strip()
    return (
        len(stripped) >= minimum_length
        and bool(stripped)
        and all(character == fence_char for character in stripped)
    )


def _without_fenced_code(text: str) -> str:
    output: list[str] = []
    fence_char: str | None = None
    minimum_length = 0

    for line in text.splitlines():
        if fence_char is None:
            opened = _parse_fence_open(line)
            if opened is None:
                output.append(line)
                continue
            fence_char, minimum_length, _language = opened
            output.append("")
            continue

        if _is_fence_close(line, fence_char=fence_char, minimum_length=minimum_length):
            fence_char = None
            minimum_length = 0
        output.append("")

    if fence_char is not None:
        raise ValueError("unterminated fenced code block in public documentation")
    return "\n".join(output)


def _github_heading_slugs(text: str) -> set[str]:
    slugs: set[str] = set()
    counts: dict[str, int] = {}
    source = _without_fenced_code(text)
    for line in source.splitlines():
        match = HEADING_RE.match(line)
        if not match:
            continue
        heading = re.sub(r"<[^>]+>", "", match.group(2))
        heading = re.sub(r"[`*_~]", "", heading).strip().lower()
        heading = re.sub(r"[^\w\- ]", "", heading, flags=re.UNICODE)
        base = heading.replace(" ", "-")
        ordinal = counts.get(base, 0)
        counts[base] = ordinal + 1
        slug = base if ordinal == 0 else f"{base}-{ordinal}"
        slugs.add(slug)
    return slugs


def _target_from_markdown(raw: str) -> str:
    target = raw.strip()
    if target.startswith("<") and ">" in target:
        return target[1 : target.index(">")]
    return target.split(maxsplit=1)[0]


def _iter_local_targets(text: str) -> list[str]:
    without_code = _without_fenced_code(text)
    targets = [_target_from_markdown(value) for value in MARKDOWN_LINK_RE.findall(without_code)]
    targets.extend(
        _target_from_markdown(value) for value in REFERENCE_LINK_RE.findall(without_code)
    )
    for raw in HTML_ATTR_RE.findall(without_code):
        for candidate in raw.split(","):
            target = candidate.strip().split(maxsplit=1)[0]
            if target:
                targets.append(target)
    return [target for target in targets if target]


def _validate_target(
    *,
    root: Path,
    document: PublicDocument,
    target: str,
    anchors: dict[str, set[str]],
) -> None:
    normalized = unquote(target.strip())
    lowered = normalized.lower()
    if lowered.startswith(EXTERNAL_SCHEMES) or lowered.startswith("data:"):
        return
    if normalized.startswith("//"):
        return

    path_part, separator, anchor = normalized.partition("#")
    if not path_part:
        resolved = document.path
        relative = document.relative_path
    else:
        resolved = document.path.parent / path_part
        try:
            relative = resolved.resolve().relative_to(root.resolve()).as_posix()
        except ValueError as exc:
            raise ValueError(
                f"{document.relative_path}: local link escapes repository root: {target}"
            ) from exc
        if not resolved.exists():
            raise ValueError(f"{document.relative_path}: missing local link target: {target}")
        if resolved.is_symlink():
            raise ValueError(f"{document.relative_path}: local link target is a symlink: {target}")
        if resolved.is_dir():
            return

    if separator and anchor and relative.endswith(".md"):
        known = anchors.get(relative)
        if known is None:
            target_text = _read_text(resolved)
            known = _github_heading_slugs(target_text)
            anchors[relative] = known
        if anchor.lower() not in known:
            raise ValueError(
                f"{document.relative_path}: missing Markdown anchor #{anchor} in {relative}"
            )


def _validate_links(root: Path, documents: dict[str, PublicDocument]) -> int:
    anchors = {
        relative: _github_heading_slugs(document.text) for relative, document in documents.items()
    }
    checked = 0
    for document in documents.values():
        for target in _iter_local_targets(document.text):
            _validate_target(root=root, document=document, target=target, anchors=anchors)
            checked += 1
    return checked


def _iter_fenced_blocks(text: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    fence_char: str | None = None
    minimum_length = 0
    language = ""
    lines: list[str] = []

    for line in text.splitlines():
        if fence_char is None:
            opened = _parse_fence_open(line)
            if opened is None:
                continue
            fence_char, minimum_length, language = opened
            lines = []
            continue

        if _is_fence_close(line, fence_char=fence_char, minimum_length=minimum_length):
            blocks.append((language, "\n".join(lines)))
            fence_char = None
            minimum_length = 0
            language = ""
            lines = []
            continue
        lines.append(line)

    if fence_char is not None:
        raise ValueError("unterminated fenced code block in public documentation")
    return blocks


def _nonblank_metadata(lines: list[str], prefix: str) -> list[str]:
    return [line for line in lines if line.startswith(prefix) and line[len(prefix) :].strip()]


def _validate_mermaid(document: PublicDocument) -> int:
    count = 0
    for language, block in _iter_fenced_blocks(document.text):
        if language != "mermaid":
            continue
        count += 1
        stripped = [line.strip() for line in block.splitlines() if line.strip()]
        if not stripped or not stripped[0].startswith(MERMAID_DIAGRAM_PREFIXES):
            raise ValueError(
                f"{document.relative_path}: Mermaid block has no supported diagram header"
            )

        titles = _nonblank_metadata(stripped, "accTitle:")
        descriptions = _nonblank_metadata(stripped, "accDescr:")
        if len(titles) != 1:
            raise ValueError(
                f"{document.relative_path}: Mermaid block requires exactly one non-blank accTitle"
            )
        if len(descriptions) != 1:
            raise ValueError(
                f"{document.relative_path}: Mermaid block requires exactly one non-blank accDescr"
            )
    return count


def _validate_install_snippets(document: PublicDocument) -> None:
    if document.relative_path not in {"README.md", "docs/SETUP.md"}:
        return
    for language, block in _iter_fenced_blocks(document.text):
        if language not in {"bash", "sh", "shell", "powershell", "ps1"}:
            continue
        if LIVE_PIP_UPGRADE_RE.search(block):
            raise ValueError(
                f"{document.relative_path}: executable setup snippet performs live pip upgrade"
            )
        if EDITABLE_DEV_INSTALL_RE.search(block):
            raise ValueError(
                f"{document.relative_path}: executable setup snippet uses editable live dev resolution"
            )


def _validate_docs_hub(documents: dict[str, PublicDocument]) -> None:
    hub = documents.get("docs/README.md")
    if hub is None:
        raise ValueError("docs/README.md is required")
    linked = set(_iter_local_targets(hub.text))
    linked_files = {target.split("#", 1)[0] for target in linked}
    missing = [
        Path(relative).name
        for relative in sorted(documents)
        if relative.startswith("docs/")
        and relative != "docs/README.md"
        and Path(relative).name not in linked_files
    ]
    if missing:
        raise ValueError(f"docs/README.md does not link every public docs page: {missing}")


def _validate_prohibited_headings(documents: dict[str, PublicDocument]) -> None:
    readme = documents["README.md"].text
    production = documents["docs/PRODUCTION_READINESS.md"].text
    if CURRENT_STATUS_HEADING_RE.search(readme):
        raise ValueError("README.md must not contain a project-progress 'Current status' heading")
    if STATUS_VOCAB_HEADING_RE.search(production):
        raise ValueError(
            "docs/PRODUCTION_READINESS.md must not contain a project-progress 'Status vocabulary' heading"
        )


def verify_documentation(root: Path) -> dict[str, object]:
    root = root.resolve()
    documents = _load_public_documents(root)
    _validate_prohibited_headings(documents)
    _validate_docs_hub(documents)

    mermaid_blocks = 0
    for document in documents.values():
        _validate_install_snippets(document)
        mermaid_blocks += _validate_mermaid(document)
    links_checked = _validate_links(root, documents)

    return {
        "schema_version": 1,
        "result": "PASS",
        "documents_checked": len(documents),
        "local_links_checked": links_checked,
        "mermaid_blocks_checked": mermaid_blocks,
        "claim": "public documentation satisfies repository-owned structural integrity rules",
        "limitations": [
            "This verifier checks repository structure and Mermaid accessibility metadata; it is not a full browser implementation of GitHub's Markdown/Mermaid renderer.",
            "External URLs are not fetched and therefore are not availability-certified by this verifier.",
            "Documentation consistency with provider/target/deployment behavior still requires evidence from the owning external domain.",
        ],
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    print(json.dumps(verify_documentation(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

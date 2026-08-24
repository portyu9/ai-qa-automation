from __future__ import annotations

import ast
import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from ai_qa_automation.io_safety import read_text_bounded

MAX_DOC_BYTES = 128 * 1024
MAX_DOC_ENTRIES = 64
MAX_IMPLEMENTATION_BYTES = 1024 * 1024
MAX_SKILL_ENTRIES = 16
PUBLIC_ROOT_MARKDOWN = ("README.md", "CONTRIBUTING.md", "SECURITY.md")
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:")
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
REFERENCE_LINK_RE = re.compile(r"^\s*\[(?!\^)[^\]]+\]:\s*(\S+)", re.MULTILINE)
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


def _read_implementation_text(root: Path, relative_path: str) -> str:
    return read_text_bounded(
        root / relative_path,
        max_bytes=MAX_IMPLEMENTATION_BYTES,
        label=f"documentation claim source {relative_path}",
    )


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


def _sdk_version(root: Path) -> str:
    data = tomllib.loads(_read_implementation_text(root, "pyproject.toml"))
    dependencies = data.get("project", {}).get("dependencies")
    if not isinstance(dependencies, list):
        raise ValueError("pyproject.toml project.dependencies must be a list")
    prefix = "claude-agent-sdk=="
    matches = [
        item[len(prefix) :]
        for item in dependencies
        if isinstance(item, str) and item.startswith(prefix)
    ]
    if len(matches) != 1 or not matches[0]:
        raise ValueError("pyproject.toml must contain exactly one exact claude-agent-sdk pin")
    return matches[0]


def _default_model(root: Path) -> str:
    path = "src/ai_qa_automation/config.py"
    tree = ast.parse(_read_implementation_text(root, path), filename=path)
    matches: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "Settings":
            continue
        for item in node.body:
            if (
                isinstance(item, ast.AnnAssign)
                and isinstance(item.target, ast.Name)
                and item.target.id == "model"
                and isinstance(item.value, ast.Constant)
                and isinstance(item.value.value, str)
            ):
                matches.append(item.value.value)
    if len(matches) != 1 or not matches[0]:
        raise ValueError("could not derive exactly one Settings.model default")
    return matches[0]


def _internal_tool_count(root: Path) -> int:
    path = "src/ai_qa_automation/runtime/internal_tools.py"
    tree = ast.parse(_read_implementation_text(root, path), filename=path)
    counts: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.List):
            continue
        if any(isinstance(target, ast.Name) and target.id == "tools" for target in node.targets):
            counts.append(len(node.value.elts))
    if len(counts) != 1 or counts[0] < 1:
        raise ValueError("could not derive exactly one non-empty internal QA tool list")
    return counts[0]


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _directory_signature(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mtime_ns, value.st_ctime_ns


def _trusted_skill_count(root: Path) -> int:
    skills_dir = root / ".claude" / "skills"
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if (
        not directory_flag
        or not nofollow
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
    ):
        raise RuntimeError(
            "documentation claim verification requires descriptor-relative no-follow directory ingestion"
        )
    if skills_dir.is_symlink():
        raise ValueError("trusted Skills directory is a symlink and has ambiguous ownership")

    try:
        directory_fd = os.open(skills_dir, os.O_RDONLY | directory_flag | nofollow)
    except OSError as exc:
        raise ValueError("trusted Skills directory could not be opened safely") from exc

    try:
        opened_directory = os.fstat(directory_fd)
        current_directory = skills_dir.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened_directory.st_mode)
            or stat.S_ISLNK(current_directory.st_mode)
            or not stat.S_ISDIR(current_directory.st_mode)
            or _identity(opened_directory) != _identity(current_directory)
        ):
            raise ValueError("trusted Skills directory has ambiguous ownership")
        initial_signature = _directory_signature(opened_directory)

        try:
            entries = os.scandir(directory_fd)
        except (TypeError, NotImplementedError, OSError) as exc:
            raise RuntimeError(
                "documentation claim verification requires descriptor-based Skills enumeration"
            ) from exc

        count = 0
        observed_entries = 0
        with entries:
            for entry in entries:
                observed_entries += 1
                if observed_entries > MAX_SKILL_ENTRIES:
                    raise ValueError(
                        f"trusted Skills directory exceeds {MAX_SKILL_ENTRIES} direct entries"
                    )
                name = entry.name
                if Path(name).name != name or name in {".", ".."}:
                    raise ValueError("trusted Skills directory contains an invalid direct-entry name")
                before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode):
                    raise ValueError(
                        f"trusted Skill entry must be a real directory, not a symlink or file: {name}"
                    )
                skill_fd = os.open(
                    name,
                    os.O_RDONLY | directory_flag | nofollow,
                    dir_fd=directory_fd,
                )
                try:
                    opened_skill = os.fstat(skill_fd)
                    current_skill = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (
                        not stat.S_ISDIR(opened_skill.st_mode)
                        or not stat.S_ISDIR(current_skill.st_mode)
                        or _identity(opened_skill) != _identity(current_skill)
                    ):
                        raise ValueError(f"trusted Skill directory changed identity: {name}")
                    skill_md = os.stat("SKILL.md", dir_fd=skill_fd, follow_symlinks=False)
                    if not stat.S_ISREG(skill_md.st_mode):
                        raise ValueError(
                            f"trusted Skill must contain an owned regular SKILL.md: {name}"
                        )
                    skill_file_fd = os.open(
                        "SKILL.md",
                        os.O_RDONLY | getattr(os, "O_BINARY", 0) | nofollow,
                        dir_fd=skill_fd,
                    )
                    try:
                        opened_skill_md = os.fstat(skill_file_fd)
                        current_skill_md = os.stat(
                            "SKILL.md", dir_fd=skill_fd, follow_symlinks=False
                        )
                        if (
                            not stat.S_ISREG(opened_skill_md.st_mode)
                            or not stat.S_ISREG(current_skill_md.st_mode)
                            or _identity(opened_skill_md) != _identity(current_skill_md)
                        ):
                            raise ValueError(
                                f"trusted Skill SKILL.md changed identity during verification: {name}"
                            )
                    finally:
                        os.close(skill_file_fd)
                finally:
                    os.close(skill_fd)
                count += 1

        final_opened_directory = os.fstat(directory_fd)
        final_current_directory = skills_dir.stat(follow_symlinks=False)
        if (
            stat.S_ISLNK(final_current_directory.st_mode)
            or not stat.S_ISDIR(final_current_directory.st_mode)
            or _identity(final_opened_directory) != _identity(final_current_directory)
            or _directory_signature(final_opened_directory) != initial_signature
        ):
            raise ValueError("trusted Skills directory changed during verification")
        if count < 1:
            raise ValueError("trusted Skills directory must contain at least one Skill")
        return count
    finally:
        os.close(directory_fd)


def _validate_implementation_claims(root: Path, readme: str) -> dict[str, object]:
    sdk_version = _sdk_version(root)
    default_model = _default_model(root)
    internal_tools = _internal_tool_count(root)
    trusted_skills = _trusted_skill_count(root)
    expected_claims = (
        f"`claude-agent-sdk=={sdk_version}`",
        f"default model identifier `{default_model}`",
        f"{internal_tools} least-privilege, purpose-built in-process QA tools",
        f"exactly {trusted_skills} allowlisted Claude Skills",
    )
    missing = [claim for claim in expected_claims if claim not in readme]
    if missing:
        raise ValueError(f"README implementation-coupled claims drifted: {missing}")
    if f"Claude%20Agent%20SDK-{sdk_version}-" not in readme:
        raise ValueError("README Claude Agent SDK badge version differs from pyproject.toml")
    return {
        "claude_agent_sdk": sdk_version,
        "default_model": default_model,
        "internal_qa_tools": internal_tools,
        "trusted_skills": trusted_skills,
    }


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
    implementation_claims = _validate_implementation_claims(root, documents["README.md"].text)

    return {
        "schema_version": 1,
        "result": "PASS",
        "documents_checked": len(documents),
        "local_links_checked": links_checked,
        "mermaid_blocks_checked": mermaid_blocks,
        "implementation_claims": implementation_claims,
        "claim": "public documentation satisfies repository-owned structural and implementation-coupled integrity rules",
        "limitations": [
            "This verifier checks repository structure and Mermaid accessibility metadata; it is not a full browser implementation of GitHub's Markdown/Mermaid renderer.",
            "External URLs are not fetched and therefore are not availability-certified by this verifier.",
            "Implementation-coupled checks cover selected exact README facts; broader documentation consistency with provider/target/deployment behavior still requires evidence from the owning external domain.",
        ],
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    print(json.dumps(verify_documentation(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

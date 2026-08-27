from __future__ import annotations

import errno
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_WORKFLOW_BYTES = 256 * 1024
MAX_WORKFLOW_ENTRIES = 16
EXPECTED_WORKFLOW_NAMES = {"ci.yml", "manual-validation.yml"}
EXPECTED_ACTION_SHAS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",  # pragma: allowlist secret
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",  # pragma: allowlist secret
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",  # pragma: allowlist secret
}
AUTOMATIC_REQUIRED_JOBS = (
    "quality",
    "deterministic-evals",
    "supply-chain",
    "security",
    "browser-reference-sut",
)
DOCUMENTATION_INTEGRITY_ARTIFACT = "artifacts/ci/documentation-integrity.json"
DOCUMENTATION_INTEGRITY_COMMAND = (
    f"python scripts/verify_docs.py | tee {DOCUMENTATION_INTEGRITY_ARTIFACT}"
)
MERMAID_VALIDATION_ARTIFACT = "artifacts/ci/mermaid-validation.json"
MERMAID_RENDER_COMMAND = f"python scripts/validate_mermaid.py | tee {MERMAID_VALIDATION_ARTIFACT}"
DOCUMENTATION_STEP_NAME = "Verify documentation authority contract"
MERMAID_STEP_NAME = "Render Mermaid documentation with digest-pinned official CLI"
REPRODUCIBLE_BUILD_STEP_NAME = "Build wheel twice from fresh source trees"
SUPPLY_CHAIN_UPLOAD_STEP_NAME = "Upload supply-chain evidence"
REQUIRED_GATE_STEP_NAME = "Require every automatic gate to succeed"
SUPPLY_CHAIN_ARTIFACTS = (
    "artifacts/ci/supply-chain-verification.json",
    "artifacts/ci/ci-contract-verification.json",
    DOCUMENTATION_INTEGRITY_ARTIFACT,
    MERMAID_VALIDATION_ARTIFACT,
    "artifacts/ci/runtime-sbom.cdx.json",
    "artifacts/ci/build-manifest.json",
    "artifacts/ci/build-checksums.sha256",
    "artifacts/ci/wheel-a/*.whl",
    "artifacts/ci/container-image-id.txt",
)
ACTION_RE = re.compile(r"^\s*uses:\s*([^@\s]+)@([^\s#]+)", re.MULTILINE)
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
WRITE_PERMISSION_RE = re.compile(r"^\s+[A-Za-z0-9_-]+:\s*write\s*$", re.MULTILINE)


@dataclass(frozen=True)
class WorkflowSnapshot:
    text: str
    size_bytes: int


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _file_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _directory_signature(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mtime_ns, value.st_ctime_ns


def _read_fd_bounded(fd: int, *, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_WORKFLOW_BYTES:
        chunk = os.read(fd, min(1024 * 1024, MAX_WORKFLOW_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > MAX_WORKFLOW_BYTES:
        raise ValueError(f"{label} exceeds {MAX_WORKFLOW_BYTES} byte ingestion limit")
    return b"".join(chunks)


def _relative_stat(name: str, directory_fd: int) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except (TypeError, NotImplementedError) as exc:
        raise RuntimeError("CI verification requires descriptor-relative no-follow stat") from exc


def _relative_open(name: str, directory_fd: int, *, label: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(name, flags, dir_fd=directory_fd)
    except (TypeError, NotImplementedError) as exc:
        raise RuntimeError("CI verification requires descriptor-relative no-follow open") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{label} became a symlink during verification") from exc
        raise


def _read_workflow_set(workflow_dir: Path) -> dict[str, WorkflowSnapshot]:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow:
        raise RuntimeError("CI verification requires descriptor-relative no-follow ingestion")
    if workflow_dir.is_symlink():
        raise ValueError("workflow directory is a symlink and has ambiguous ownership")

    try:
        directory_fd = os.open(workflow_dir, os.O_RDONLY | directory_flag | nofollow)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError("workflow directory became a symlink during verification") from exc
        raise

    try:
        opened_directory = os.fstat(directory_fd)
        current_directory = workflow_dir.stat(follow_symlinks=False)
        if not stat.S_ISDIR(opened_directory.st_mode):
            raise ValueError("workflow path must be a directory")
        if stat.S_ISLNK(current_directory.st_mode):
            raise ValueError("workflow directory became a symlink during verification")
        if _identity(opened_directory) != _identity(current_directory):
            raise ValueError("workflow directory changed identity during verification")
        initial_directory_signature = _directory_signature(opened_directory)

        try:
            entries = os.scandir(directory_fd)
        except (TypeError, NotImplementedError, OSError) as exc:
            raise RuntimeError(
                "CI verification requires descriptor-based directory enumeration"
            ) from exc

        observed_names: set[str] = set()
        observed_entries = 0
        with entries:
            for entry in entries:
                observed_entries += 1
                if observed_entries > MAX_WORKFLOW_ENTRIES:
                    raise ValueError(
                        f"workflow directory exceeds {MAX_WORKFLOW_ENTRIES} entry ingestion limit"
                    )
                name = entry.name
                if Path(name).name != name or name in {".", ".."}:
                    raise ValueError("workflow directory contains an invalid filename")
                if Path(name).suffix.lower() in {".yml", ".yaml"}:
                    observed_names.add(name)

        if observed_names != EXPECTED_WORKFLOW_NAMES:
            raise ValueError(
                f"unexpected workflow set: expected {sorted(EXPECTED_WORKFLOW_NAMES)}, "
                f"got {sorted(observed_names)}"
            )

        snapshots: dict[str, WorkflowSnapshot] = {}
        for name in sorted(observed_names):
            label = f"workflow {name}"
            before = _relative_stat(name, directory_fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"{label} must be a regular non-symlink file")
            file_fd = _relative_open(name, directory_fd, label=label)
            try:
                opened_file = os.fstat(file_fd)
                current_file = _relative_stat(name, directory_fd)
                if not stat.S_ISREG(opened_file.st_mode) or not stat.S_ISREG(current_file.st_mode):
                    raise ValueError(f"{label} must remain a regular file")
                if _identity(opened_file) != _identity(current_file):
                    raise ValueError(f"{label} changed identity during verification")
                initial_file_signature = _file_signature(opened_file)
                content = _read_fd_bounded(file_fd, label=label)
                final_opened_file = os.fstat(file_fd)
                final_current_file = _relative_stat(name, directory_fd)
                if (
                    _file_signature(final_opened_file) != initial_file_signature
                    or _identity(final_opened_file) != _identity(final_current_file)
                    or not stat.S_ISREG(final_current_file.st_mode)
                ):
                    raise ValueError(f"{label} changed during verification")
            finally:
                os.close(file_fd)

            text = content.decode("utf-8")
            if not text.strip():
                raise ValueError(f"{label} must not be empty")
            snapshots[name] = WorkflowSnapshot(text=text, size_bytes=len(content))

        final_opened_directory = os.fstat(directory_fd)
        final_current_directory = workflow_dir.stat(follow_symlinks=False)
        if (
            stat.S_ISLNK(final_current_directory.st_mode)
            or not stat.S_ISDIR(final_current_directory.st_mode)
            or _identity(final_opened_directory) != _identity(final_current_directory)
            or _directory_signature(final_opened_directory) != initial_directory_signature
        ):
            raise ValueError("workflow directory changed during verification")
        return snapshots
    finally:
        os.close(directory_fd)


def _semantic_text(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _top_level_block(text: str, key: str) -> str:
    lines = text.splitlines()
    marker = f"{key}:"
    starts = [index for index, line in enumerate(lines) if line == marker]
    if len(starts) != 1:
        raise ValueError(f"workflow must contain exactly one top-level {marker} block")
    start = starts[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line and not line[0].isspace() and not line.lstrip().startswith("#"):
            end = index
            break
    return "\n".join(lines[start:end])


def _top_level_keys(block: str) -> set[str]:
    keys: set[str] = set()
    for line in block.splitlines()[1:]:
        if line.startswith("  ") and not line.startswith("    "):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and ":" in stripped:
                keys.add(stripped.split(":", 1)[0])
    return keys


def _permissions(block: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in block.splitlines()[1:]:
        if line.startswith("  ") and not line.startswith("    "):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and ":" in stripped:
                key, value = stripped.split(":", 1)
                values[key] = value.strip()
    return values


def _job_block(text: str, job_id: str) -> str:
    jobs = _top_level_block(text, "jobs").splitlines()
    marker = f"  {job_id}:"
    starts = [index for index, line in enumerate(jobs) if line == marker]
    if len(starts) != 1:
        raise ValueError(f"workflow must contain exactly one job {job_id}")
    start = starts[0]
    end = len(jobs)
    for index in range(start + 1, len(jobs)):
        line = jobs[index]
        if line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
            end = index
            break
    return "\n".join(jobs[start:end])


def _step_block(job: str, step_name: str) -> str:
    lines = job.splitlines()
    marker = f"      - name: {step_name}"
    starts = [index for index, line in enumerate(lines) if line == marker]
    if len(starts) != 1:
        raise ValueError(f"job must contain exactly one step named {step_name}")
    start = starts[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("      - name: "):
            end = index
            break
    return "\n".join(lines[start:end])


def _require_exact_script_step(job: str, *, step_name: str, command: str) -> None:
    step = _semantic_text(_step_block(job, step_name)).strip("\n")
    expected = "\n".join(
        (
            f"      - name: {step_name}",
            "        run: |",
            "          set -o pipefail",
            f"          {command}",
        )
    )
    if step != expected:
        raise ValueError(f"{step_name} must be the exact reviewed fail-closed script step")


def _require_exact_reproducible_build_step(job: str) -> None:
    step = _semantic_text(_step_block(job, REPRODUCIBLE_BUILD_STEP_NAME)).strip("\n")
    continuation = chr(92)
    expected = "\n".join(
        (
            f"      - name: {REPRODUCIBLE_BUILD_STEP_NAME}",
            "        env:",
            '          SOURCE_DATE_EPOCH: "315532800"',
            '          GIT_NO_REPLACE_OBJECTS: "1"',
            "        run: |",
            "          set -euo pipefail",
            "          rm -rf /tmp/aiqa-build-a /tmp/aiqa-build-b",
            "          mkdir -p /tmp/aiqa-build-a /tmp/aiqa-build-b artifacts/ci/wheel-a artifacts/ci/wheel-b",
            '          git --no-replace-objects archive --format=tar "$GITHUB_SHA" | tar -xf - -C /tmp/aiqa-build-a',
            '          git --no-replace-objects archive --format=tar "$GITHUB_SHA" | tar -xf - -C /tmp/aiqa-build-b',
            "          python -m pip wheel --no-deps --no-build-isolation /tmp/aiqa-build-a --wheel-dir artifacts/ci/wheel-a",
            "          python -m pip wheel --no-deps --no-build-isolation /tmp/aiqa-build-b --wheel-dir artifacts/ci/wheel-b",
            "          mapfile -t wheel_a < <(find artifacts/ci/wheel-a -maxdepth 1 -type f -name '*.whl' -print)",
            "          mapfile -t wheel_b < <(find artifacts/ci/wheel-b -maxdepth 1 -type f -name '*.whl' -print)",
            '          test "${#wheel_a[@]}" -eq 1',
            '          test "${#wheel_b[@]}" -eq 1',
            f"          python scripts/generate_build_manifest.py {continuation}",
            f'            --wheel-a "${{wheel_a[0]}}" {continuation}',
            f'            --wheel-b "${{wheel_b[0]}}" {continuation}',
            f"            --sbom artifacts/ci/runtime-sbom.cdx.json {continuation}",
            f'            --expected-source-sha "$GITHUB_SHA" {continuation}',
            "            --output artifacts/ci/build-manifest.json",
            '          sha256sum "${wheel_a[0]}" artifacts/ci/runtime-sbom.cdx.json artifacts/ci/build-manifest.json > artifacts/ci/build-checksums.sha256',
        )
    )
    if step != expected:
        raise ValueError(
            "reproducible wheel build must be the exact reviewed event-subject-bound step"
        )


def _require_exact_supply_chain_upload_step(job: str) -> None:
    step = _semantic_text(_step_block(job, SUPPLY_CHAIN_UPLOAD_STEP_NAME)).strip("\n")
    artifact_lines = tuple(f"            {artifact}" for artifact in SUPPLY_CHAIN_ARTIFACTS)
    expected = "\n".join(
        (
            f"      - name: {SUPPLY_CHAIN_UPLOAD_STEP_NAME}",
            "        if: always()",
            "        uses: actions/upload-artifact@"
            f"{EXPECTED_ACTION_SHAS['actions/upload-artifact']} # v7",
            "        with:",
            "          name: supply-chain-evidence",
            "          path: |",
            *artifact_lines,
            "          if-no-files-found: error",
            "          retention-days: 30",
        )
    )
    if step != expected:
        raise ValueError(
            "supply-chain evidence upload must be the exact reviewed pinned action step"
        )


def _require_exact_required_gate_step(job: str) -> None:
    step = _semantic_text(_step_block(job, REQUIRED_GATE_STEP_NAME)).strip("\n")
    result_lines = tuple(
        f'          test "${{{{ needs.{job}.result }}}}" = "success"'
        for job in AUTOMATIC_REQUIRED_JOBS
    )
    expected = "\n".join(
        (
            f"      - name: {REQUIRED_GATE_STEP_NAME}",
            "        run: |",
            *result_lines,
        )
    )
    if step != expected:
        raise ValueError(
            "Required PR Gate result checks must be the exact reviewed fail-closed aggregate step"
        )


def _verify_action_revisions(workflows: dict[str, str]) -> dict[str, str]:
    observed: dict[str, str] = {}
    for name, raw_text in workflows.items():
        for action, revision in ACTION_RE.findall(_semantic_text(raw_text)):
            if not HEX40_RE.fullmatch(revision):
                raise ValueError(f"{name}: mutable GitHub Action reference: {action}@{revision}")
            expected = EXPECTED_ACTION_SHAS.get(action)
            if expected is None:
                raise ValueError(f"{name}: unreviewed GitHub Action: {action}")
            if revision != expected:
                raise ValueError(f"{name}: unexpected immutable revision for {action}: {revision}")
            observed[action] = revision
    if set(observed) != set(EXPECTED_ACTION_SHAS):
        raise ValueError("workflow Action set differs from the reviewed immutable set")
    return observed


def _verify_read_only_permissions(text: str, *, name: str) -> None:
    permissions = _permissions(_top_level_block(text, "permissions"))
    if permissions != {"contents": "read"}:
        raise ValueError(f"{name}: workflow permissions must be exactly contents: read")
    if WRITE_PERMISSION_RE.search(_semantic_text(text)):
        raise ValueError(f"{name}: workflow requests write permission")


def _verify_checkout_binding(text: str, *, name: str) -> int:
    semantic = _semantic_text(text)
    checkout = f"uses: actions/checkout@{EXPECTED_ACTION_SHAS['actions/checkout']}"
    checkout_count = semantic.count(checkout)
    if checkout_count < 1:
        raise ValueError(f"{name}: workflow must checkout a source subject")
    if semantic.count("ref: ${{ github.sha }}") != checkout_count:
        raise ValueError(f"{name}: every checkout must bind to github.sha")
    if semantic.count("persist-credentials: false") != checkout_count:
        raise ValueError(f"{name}: every checkout must disable persisted credentials")
    exact_check = 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"'
    if semantic.count(exact_check) != checkout_count:
        raise ValueError(f"{name}: every checkout must verify the exact GitHub event revision")
    return checkout_count


def _verify_automatic_workflow(text: str) -> dict[str, Any]:
    name = "ci.yml"
    semantic = _semantic_text(text)
    expected_triggers = {"pull_request", "push", "merge_group"}
    triggers = _top_level_keys(_top_level_block(text, "on"))
    if triggers != expected_triggers:
        raise ValueError(
            f"{name}: automatic trigger set must be exactly {sorted(expected_triggers)}, "
            f"got {sorted(triggers)}"
        )
    for forbidden in (
        "pull_request_target:",
        "${{ secrets.",
        "ANTHROPIC_API_KEY",
        "${{ inputs.",
        "continue-on-error: true",
    ):
        if forbidden in semantic:
            raise ValueError(f"{name}: forbidden automatic-CI authority token: {forbidden}")
    if "ubuntu-latest" in semantic:
        raise ValueError(f"{name}: moving ubuntu-latest runner label is forbidden")
    if '"3.11.16"' not in semantic or '"3.13.15"' not in semantic:
        raise ValueError(f"{name}: exact supported Python patch versions are required")
    if "--require-hashes" not in semantic:
        raise ValueError(f"{name}: hash-required dependency installation is required")
    if "pip install --upgrade" in semantic or " --editable" in semantic or " -e ." in semantic:
        raise ValueError(f"{name}: live/editable dependency installation is forbidden")
    if "cancel-in-progress: true" not in _top_level_block(text, "concurrency"):
        raise ValueError(f"{name}: stale PR executions must be cancelled on superseding revisions")
    _verify_read_only_permissions(text, name=name)
    checkout_count = _verify_checkout_binding(text, name=name)

    supply_chain_raw = _job_block(text, "supply-chain")
    supply_chain = _semantic_text(supply_chain_raw)
    _require_exact_script_step(
        supply_chain_raw,
        step_name=DOCUMENTATION_STEP_NAME,
        command=DOCUMENTATION_INTEGRITY_COMMAND,
    )
    _require_exact_script_step(
        supply_chain_raw,
        step_name=MERMAID_STEP_NAME,
        command=MERMAID_RENDER_COMMAND,
    )
    _require_exact_reproducible_build_step(supply_chain_raw)
    _require_exact_supply_chain_upload_step(supply_chain_raw)
    if supply_chain.count(DOCUMENTATION_INTEGRITY_COMMAND) != 1:
        raise ValueError(
            f"{name}: documentation integrity command must not appear outside its reviewed step"
        )
    if supply_chain.count(MERMAID_RENDER_COMMAND) != 1:
        raise ValueError(
            f"{name}: Mermaid render command must not appear outside its reviewed step"
        )

    required_gate_raw = _job_block(text, "required-gate")
    required_gate = _semantic_text(required_gate_raw)
    if "    name: Required PR Gate" not in required_gate:
        raise ValueError(f"{name}: stable Required PR Gate name is missing")
    if "    if: ${{ always() }}" not in required_gate:
        raise ValueError(f"{name}: Required PR Gate must execute with if: always()")
    _require_exact_required_gate_step(required_gate_raw)
    for job in AUTOMATIC_REQUIRED_JOBS:
        if f"      - {job}\n" not in required_gate:
            raise ValueError(f"{name}: Required PR Gate does not depend on {job}")

    return {
        "triggers": sorted(expected_triggers),
        "subject": "github.sha",
        "checkout_count": checkout_count,
        "required_gate": "Required PR Gate",
        "documentation_integrity": "required-via-supply-chain",
        "mermaid_render": "required-via-supply-chain",
        "build_provenance_subject": "github.sha/no-replace-objects",
        "supply_chain_evidence": "pinned-upload-action",
        "permissions": "contents:read",
        "secrets": False,
    }


def _verify_manual_workflow(text: str) -> dict[str, Any]:
    name = "manual-validation.yml"
    semantic = _semantic_text(text)
    triggers = _top_level_keys(_top_level_block(text, "on"))
    if triggers != {"workflow_dispatch"}:
        raise ValueError(
            f"{name}: trigger set must be exactly ['workflow_dispatch'], got {sorted(triggers)}"
        )
    if "pull_request_target:" in semantic:
        raise ValueError(f"{name}: pull_request_target is forbidden")
    if "ubuntu-latest" in semantic:
        raise ValueError(f"{name}: moving ubuntu-latest runner label is forbidden")
    if "${{ inputs.run_holdout }}" not in semantic or "${{ inputs.run_model }}" not in semantic:
        raise ValueError(f"{name}: explicit holdout/model dispatch controls are required")
    if "${{ secrets.ANTHROPIC_API_KEY }}" not in semantic:
        raise ValueError(f"{name}: credentialed model job must use the explicit configured secret")
    if "--require-hashes" not in semantic:
        raise ValueError(f"{name}: hash-required dependency installation is required")
    if "pip install --upgrade" in semantic or " --editable" in semantic or " -e ." in semantic:
        raise ValueError(f"{name}: live/editable dependency installation is forbidden")
    _verify_read_only_permissions(text, name=name)
    checkout_count = _verify_checkout_binding(text, name=name)
    return {
        "trigger": "workflow_dispatch",
        "subject": "github.sha",
        "checkout_count": checkout_count,
        "permissions": "contents:read",
        "credentialed_model": "manual-only",
        "holdout": "manual-separated",
    }


def verify_ci_contract(root: Path) -> dict[str, Any]:
    root = root.resolve()
    snapshots = _read_workflow_set(root / ".github" / "workflows")
    workflows = {name: snapshot.text for name, snapshot in snapshots.items()}
    actions = _verify_action_revisions(workflows)
    automatic = _verify_automatic_workflow(workflows["ci.yml"])
    manual = _verify_manual_workflow(workflows["manual-validation.yml"])
    return {
        "schema_version": 1,
        "result": "PASS",
        "claim": "repository workflow definitions satisfy deterministic CI authority invariants",
        "workflows": {"automatic": automatic, "manual": manual},
        "workflow_sizes": {
            name: snapshot.size_bytes for name, snapshot in sorted(snapshots.items())
        },
        "actions": actions,
        "limitations": [
            "Repository workflow validation does not prove GitHub branch protection or required-check settings are enabled.",
            "A green pull_request run validates GitHub's event SHA, which is normally the prospective merge subject rather than the PR head commit alone.",
            "Credential existence, environment protection, hosted-runner identity, and external service availability remain environment-owned facts.",
        ],
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    print(json.dumps(verify_ci_contract(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

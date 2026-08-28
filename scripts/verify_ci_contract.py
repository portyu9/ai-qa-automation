from __future__ import annotations

import errno
import hashlib
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
EXPECTED_AUTOMATIC_PROJECT_INSTALL_COUNT = 5
EXPECTED_AUTOMATIC_DEPENDENCY_INSTALL_COUNT = 5
EXPECTED_AUTOMATIC_SUBJECT_CHECKOUT_COUNT = 5
EXPECTED_AUTOMATIC_WORKFLOW_BLOB_SHA = (
    "9bc09d2450e7f1195b02bcb1d3736b7cbaf4670f"  # pragma: allowlist secret
)
AUTOMATIC_PROJECT_INSTALL_COMMAND = (
    "          python -m pip install --no-deps --no-build-isolation ."
)
AUTOMATIC_DEPENDENCY_INSTALL_PREFIX = "          python -m pip install --require-hashes -r "
BUILD_AUTHORITY_REVALIDATION_COMMAND = (
    "          python scripts/verify_build_authority.py > /dev/null"
)
BUILD_AUTHORITY_ARTIFACT = "artifacts/ci/build-authority-verification.json"
ARCHIVE_BUILD_AUTHORITY_ARTIFACTS = (
    "artifacts/ci/build-authority-archive-a.json",
    "artifacts/ci/build-authority-archive-b.json",
)
BUILD_AUTHORITY_COMMAND = (
    f"python scripts/verify_build_authority.py | tee {BUILD_AUTHORITY_ARTIFACT}"
)
DOCUMENTATION_INTEGRITY_ARTIFACT = "artifacts/ci/documentation-integrity.json"
DOCUMENTATION_INTEGRITY_COMMAND = (
    f"python scripts/verify_docs.py | tee {DOCUMENTATION_INTEGRITY_ARTIFACT}"
)
MERMAID_VALIDATION_ARTIFACT = "artifacts/ci/mermaid-validation.json"
MERMAID_RENDER_COMMAND = f"python scripts/validate_mermaid.py | tee {MERMAID_VALIDATION_ARTIFACT}"
BUILD_AUTHORITY_STEP_NAME = "Verify static project build authority"
VERIFICATION_INSTALL_STEP_NAME = "Install hash-locked verification environment"
SUPPLY_CHAIN_VERIFY_STEP_NAME = "Verify repository supply-chain invariants"
DOCUMENTATION_STEP_NAME = "Verify documentation authority contract"
MERMAID_STEP_NAME = "Render Mermaid documentation with digest-pinned official CLI"
RUNTIME_SBOM_STEP_NAME = "Audit hash-locked runtime graph and emit CycloneDX SBOM"
REPRODUCIBLE_BUILD_STEP_NAME = "Build wheel twice from fresh source trees"
SUPPLY_CHAIN_UPLOAD_STEP_NAME = "Upload supply-chain evidence"
HOSTED_BROWSER_STEP_NAME = "Verify hosted Chrome runtime"
HOSTED_BROWSER_EXECUTABLE = "/usr/bin/google-chrome"
REQUIRED_GATE_STEP_NAME = "Require every automatic gate to succeed"
TRUSTED_STATUS_JOB_ID = "trusted-status"
TRUSTED_STATUS_STEP_NAME = "Publish exact-subject trusted status"
PYTHON_SAFE_PATH_LINE = '  PYTHONSAFEPATH: "1"'
SUPPLY_CHAIN_ARTIFACTS = (
    BUILD_AUTHORITY_ARTIFACT,
    *ARCHIVE_BUILD_AUTHORITY_ARTIFACTS,
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
CACHE_CONFIGURATION_RE = re.compile(r"^\s+cache(?:-dependency-path)?:", re.MULTILINE)


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


def _git_blob_sha1(text: str) -> str:
    content = text.encode("utf-8")
    header = f"blob {len(content)}\0".encode()
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


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


def _require_exact_build_authority_step(job: str) -> None:
    step = _semantic_text(_step_block(job, BUILD_AUTHORITY_STEP_NAME)).strip("\n")
    expected = "\n".join(
        (
            f"      - name: {BUILD_AUTHORITY_STEP_NAME}",
            "        run: |",
            "          set -o pipefail",
            "          mkdir -p artifacts/ci",
            f"          {BUILD_AUTHORITY_COMMAND}",
        )
    )
    if step != expected:
        raise ValueError(
            "static project build authority must be the exact reviewed pre-install step"
        )


def _require_exact_verification_install_step(job: str) -> None:
    step = _semantic_text(_step_block(job, VERIFICATION_INSTALL_STEP_NAME)).strip("\n")
    expected = "\n".join(
        (
            f"      - name: {VERIFICATION_INSTALL_STEP_NAME}",
            "        run: |",
            BUILD_AUTHORITY_REVALIDATION_COMMAND,
            "          python -m pip install --require-hashes -r requirements/dev-py311.lock",
            BUILD_AUTHORITY_REVALIDATION_COMMAND,
            AUTOMATIC_PROJECT_INSTALL_COMMAND,
            "          python -m pip check",
        )
    )
    if step != expected:
        raise ValueError(
            "supply-chain dependency installation must verify exact reviewed lock authority before installation and revalidate build authority before the project build"
        )


def _require_exact_hosted_browser_step(job: str) -> None:
    step = _semantic_text(_step_block(job, HOSTED_BROWSER_STEP_NAME)).strip("\n")
    expected = "\n".join(
        (
            f"      - name: {HOSTED_BROWSER_STEP_NAME}",
            "        run: |",
            f"          test -x {HOSTED_BROWSER_EXECUTABLE}",
            f"          {HOSTED_BROWSER_EXECUTABLE} --version",
        )
    )
    if step != expected:
        raise ValueError(
            "automatic browser validation must use the exact reviewed hosted Chrome observation step"
        )


def _require_exact_runtime_sbom_step(job: str) -> None:
    step = _semantic_text(_step_block(job, RUNTIME_SBOM_STEP_NAME)).strip("\n")
    expected = "\n".join(
        (
            f"      - name: {RUNTIME_SBOM_STEP_NAME}",
            "        run: |",
            "          set -euo pipefail",
            "          pip-audit --require-hashes -r requirements/runtime-py311.lock --format cyclonedx-json --output artifacts/ci/runtime-sbom.cdx.json",
            "          python - <<'PY'",
            "          import json",
            "          from pathlib import Path",
            "          data = json.loads(Path('artifacts/ci/runtime-sbom.cdx.json').read_text())",
            "          assert data['bomFormat'] == 'CycloneDX'",
            "          assert data.get('components')",
            "          PY",
            "          read -r runtime_sbom_sha256 _ < <(/usr/bin/sha256sum artifacts/ci/runtime-sbom.cdx.json)",
            '          printf \'RUNTIME_SBOM_SHA256=%s\\n\' "$runtime_sbom_sha256" >> "$GITHUB_ENV"',
        )
    )
    if step != expected:
        raise ValueError(
            "runtime SBOM audit must be the exact reviewed digest-exporting evidence step"
        )


def _require_exact_reproducible_build_step(job: str) -> None:
    step = _semantic_text(_step_block(job, REPRODUCIBLE_BUILD_STEP_NAME)).strip("\n")
    continuation = chr(92)
    expected = "\n".join(
        (
            f"      - name: {REPRODUCIBLE_BUILD_STEP_NAME}",
            "        env:",
            '          SOURCE_DATE_EPOCH: "315532800"',
            "        run: |",
            "          set -euo pipefail",
            '          test -n "${RUNTIME_SBOM_SHA256:-}"',
            "          read -r observed_sbom_sha256 _ < <(/usr/bin/sha256sum artifacts/ci/runtime-sbom.cdx.json)",
            '          test "$observed_sbom_sha256" = "$RUNTIME_SBOM_SHA256"',
            '          build_a="$(mktemp -d "$RUNNER_TEMP/aiqa-build-a.XXXXXX")"',
            '          build_b="$(mktemp -d "$RUNNER_TEMP/aiqa-build-b.XXXXXX")"',
            '          git_view="$(mktemp -d "$RUNNER_TEMP/aiqa-git-view.XXXXXX")"',
            '          git_template="$(mktemp -d "$RUNNER_TEMP/aiqa-git-template.XXXXXX")"',
            '          trap \'rm -rf "$build_a" "$build_b" "$git_view" "$git_template"\' EXIT',
            "          mkdir -p artifacts/ci/wheel-a artifacts/ci/wheel-b",
            '          git_clean_env=(env -i PATH="$PATH" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0)',
            '          git_object_format="$("${git_clean_env[@]}" /usr/bin/git rev-parse --show-object-format)"',
            '          git_object_directory="$(cd "$("${git_clean_env[@]}" /usr/bin/git rev-parse --git-path objects)" && pwd -P)"',
            '          "${git_clean_env[@]}" /usr/bin/git init --bare --object-format="$git_object_format" --template="$git_template" "$git_view" > /dev/null',
            '          "${git_clean_env[@]}" GIT_DIR="$git_view" GIT_OBJECT_DIRECTORY="$git_object_directory" /usr/bin/git -c core.attributesFile=/dev/null archive --format=tar "$CI_SUBJECT_SHA" | env -i PATH="$PATH" /usr/bin/tar -xf - -C "$build_a"',
            '          "${git_clean_env[@]}" GIT_DIR="$git_view" GIT_OBJECT_DIRECTORY="$git_object_directory" /usr/bin/git -c core.attributesFile=/dev/null archive --format=tar "$CI_SUBJECT_SHA" | env -i PATH="$PATH" /usr/bin/tar -xf - -C "$build_b"',
            '          python scripts/verify_build_authority.py --root "$build_a" > artifacts/ci/build-authority-archive-a.json',
            '          python -m pip wheel --no-deps --no-build-isolation "$build_a" --wheel-dir artifacts/ci/wheel-a',
            '          python scripts/verify_build_authority.py --root "$build_b" > artifacts/ci/build-authority-archive-b.json',
            '          python -m pip wheel --no-deps --no-build-isolation "$build_b" --wheel-dir artifacts/ci/wheel-b',
            "          cmp -s artifacts/ci/build-authority-archive-a.json artifacts/ci/build-authority-archive-b.json",
            "          read -r observed_sbom_sha256 _ < <(/usr/bin/sha256sum artifacts/ci/runtime-sbom.cdx.json)",
            '          test "$observed_sbom_sha256" = "$RUNTIME_SBOM_SHA256"',
            "          mapfile -t wheel_a < <(find artifacts/ci/wheel-a -maxdepth 1 -type f -name '*.whl' -print)",
            "          mapfile -t wheel_b < <(find artifacts/ci/wheel-b -maxdepth 1 -type f -name '*.whl' -print)",
            '          test "${#wheel_a[@]}" -eq 1',
            '          test "${#wheel_b[@]}" -eq 1',
            f"          python scripts/generate_build_manifest.py {continuation}",
            f'            --wheel-a "${{wheel_a[0]}}" {continuation}',
            f'            --wheel-b "${{wheel_b[0]}}" {continuation}',
            f"            --sbom artifacts/ci/runtime-sbom.cdx.json {continuation}",
            f'            --expected-source-sha "$CI_SUBJECT_SHA" {continuation}',
            "            --output artifacts/ci/build-manifest.json",
            "          read -r observed_sbom_sha256 _ < <(/usr/bin/sha256sum artifacts/ci/runtime-sbom.cdx.json)",
            '          test "$observed_sbom_sha256" = "$RUNTIME_SBOM_SHA256"',
            '          sha256sum "${wheel_a[0]}" artifacts/ci/runtime-sbom.cdx.json artifacts/ci/build-manifest.json > artifacts/ci/build-checksums.sha256',
        )
    )
    if step != expected:
        raise ValueError(
            "reproducible wheel build must be the exact reviewed validation-subject-bound step"
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


def _verify_top_level_read_only_permissions(text: str, *, name: str) -> None:
    permissions = _permissions(_top_level_block(text, "permissions"))
    if permissions != {"contents": "read"}:
        raise ValueError(f"{name}: workflow permissions must be exactly contents: read")


def _verify_event_checkout_binding(text: str, *, name: str) -> int:
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


def _verify_automatic_checkout_binding(text: str, *, name: str) -> int:
    semantic = _semantic_text(text)
    checkout = f"uses: actions/checkout@{EXPECTED_ACTION_SHAS['actions/checkout']}"
    checkout_count = semantic.count(checkout)
    expected_total = EXPECTED_AUTOMATIC_SUBJECT_CHECKOUT_COUNT + 1
    if checkout_count != expected_total:
        raise ValueError(
            f"{name}: checkout count must be exactly {expected_total} including trusted reporter"
        )
    if (
        semantic.count("ref: ${{ env.CI_SUBJECT_SHA }}")
        != EXPECTED_AUTOMATIC_SUBJECT_CHECKOUT_COUNT
    ):
        raise ValueError(f"{name}: every validation checkout must bind to env.CI_SUBJECT_SHA")
    if semantic.count("ref: ${{ github.sha }}") != 1:
        raise ValueError(f"{name}: trusted reporter must be the sole github.sha checkout")
    if semantic.count("persist-credentials: false") != checkout_count:
        raise ValueError(f"{name}: every checkout must disable persisted credentials")
    if (
        semantic.count('test "$(git rev-parse HEAD)" = "$CI_SUBJECT_SHA"')
        != EXPECTED_AUTOMATIC_SUBJECT_CHECKOUT_COUNT
    ):
        raise ValueError(f"{name}: every validation checkout must verify CI_SUBJECT_SHA")
    if semantic.count('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"') != 1:
        raise ValueError(f"{name}: trusted reporter must verify its main workflow revision")
    return checkout_count


def _verify_dependency_install_authority(text: str, *, name: str) -> int:
    semantic_lines = _semantic_text(text).splitlines()
    install_indices = [
        index
        for index, line in enumerate(semantic_lines)
        if line.startswith(AUTOMATIC_DEPENDENCY_INSTALL_PREFIX)
    ]
    if len(install_indices) != EXPECTED_AUTOMATIC_DEPENDENCY_INSTALL_COUNT:
        raise ValueError(
            f"{name}: automatic dependency install count differs from the reviewed contract"
        )
    for index in install_indices:
        if (
            index == 0
            or index + 1 >= len(semantic_lines)
            or semantic_lines[index - 1] != BUILD_AUTHORITY_REVALIDATION_COMMAND
            or semantic_lines[index + 1] != BUILD_AUTHORITY_REVALIDATION_COMMAND
        ):
            raise ValueError(
                f"{name}: every automatic dependency install must be immediately bracketed by "
                "exact reviewed-lock/build authority verification"
            )
    return len(install_indices)


def _verify_project_install_authority(text: str, *, name: str) -> int:
    semantic_lines = _semantic_text(text).splitlines()
    install_indices = [
        index
        for index, line in enumerate(semantic_lines)
        if line == AUTOMATIC_PROJECT_INSTALL_COMMAND
    ]
    if len(install_indices) != EXPECTED_AUTOMATIC_PROJECT_INSTALL_COUNT:
        raise ValueError(
            f"{name}: automatic project install count differs from the reviewed contract"
        )
    for index in install_indices:
        if index == 0 or semantic_lines[index - 1] != BUILD_AUTHORITY_REVALIDATION_COMMAND:
            raise ValueError(
                f"{name}: every automatic project install must be immediately guarded by "
                "static build authority verification"
            )
    return len(install_indices)


def _verify_dispatch_contract(text: str) -> None:
    on_block = _semantic_text(_top_level_block(text, "on")).strip("\n")
    expected = "\n".join(
        (
            "on:",
            "  pull_request:",
            "    branches: [main]",
            "    types: [opened, synchronize, reopened, ready_for_review]",
            "  push:",
            "    branches: [main]",
            "  merge_group:",
            "  repository_dispatch:",
            "    types: [trusted-pr-validation]",
        )
    )
    if on_block != expected:
        raise ValueError("ci.yml: trigger/owner-dispatch contract differs from reviewed definition")
    env_block = _semantic_text(_top_level_block(text, "env"))
    expected_subject = (
        "  CI_SUBJECT_SHA: ${{ github.event_name == 'repository_dispatch' "
        "&& github.event.client_payload.expected_merge_sha || github.sha }}"
    )
    if expected_subject not in env_block:
        raise ValueError(
            "ci.yml: CI_SUBJECT_SHA must select only repository-dispatch merge SHA or github.sha"
        )


def _verify_trusted_status_job(text: str) -> dict[str, Any]:
    job = _semantic_text(_job_block(text, TRUSTED_STATUS_JOB_ID)).strip("\n")
    publish_step = _semantic_text(_step_block(job, TRUSTED_STATUS_STEP_NAME)).strip("\n")
    required_fragments = (
        "  trusted-status:",
        "    name: Trusted PR Gate Reporter",
        "    if: ${{ always() && github.event_name == 'repository_dispatch' && github.ref == 'refs/heads/main' && github.actor == github.repository_owner }}",
        "      - required-gate",
        "    permissions:\n      contents: read\n      pull-requests: read\n      statuses: write",
        "      - name: Checkout trusted workflow revision",
        f"        uses: actions/checkout@{EXPECTED_ACTION_SHAS['actions/checkout']} # v7",
        "          ref: ${{ github.sha }}",
        "          persist-credentials: false",
        "      - name: Verify trusted workflow revision",
        '        run: test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        f"      - name: {TRUSTED_STATUS_STEP_NAME}",
        "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
        "          PR_NUMBER: ${{ github.event.client_payload.pr_number }}",
        "          EXPECTED_HEAD_SHA: ${{ github.event.client_payload.expected_head_sha }}",
        "          EXPECTED_BASE_SHA: ${{ github.event.client_payload.expected_base_sha }}",
        "          EXPECTED_MERGE_SHA: ${{ github.event.client_payload.expected_merge_sha }}",
        "          AUTHORIZED: ${{ github.event.client_payload.authorized }}",
        "          VALIDATION_RESULT: ${{ needs.required-gate.result }}",
        '          printf -v job_results_json \'{"validation":"%s"}\' "$VALIDATION_RESULT"',
        "          python scripts/trusted_pr_control.py report \\",
        '            --pr-number "$PR_NUMBER" \\',
        '            --expected-head-sha "$EXPECTED_HEAD_SHA" \\',
        '            --expected-base-sha "$EXPECTED_BASE_SHA" \\',
        '            --expected-merge-sha "$EXPECTED_MERGE_SHA" \\',
        '            --authorized "$AUTHORIZED" \\',
        '            --job-results-json "$job_results_json" \\',
        '            --target-url "https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"',
    )
    for fragment in required_fragments:
        if fragment not in job:
            raise ValueError(f"ci.yml: trusted reporter is missing reviewed fragment: {fragment}")
    run_marker = "        run: |\n"
    if publish_step.count(run_marker) != 1:
        raise ValueError("ci.yml: trusted reporter must have exactly one reviewed shell body")
    run_script = publish_step.split(run_marker, 1)[1]
    if "${{ github.event.client_payload." in run_script or "${{ needs." in run_script:
        raise ValueError(
            "ci.yml: trusted reporter must pass event/result values through env as data"
        )
    if job.count("statuses: write") != 1:
        raise ValueError("ci.yml: trusted reporter must own exactly one statuses: write permission")
    if "actions: write" in job or "contents: write" in job or "pull-requests: write" in job:
        raise ValueError("ci.yml: trusted reporter requests unreviewed write authority")
    return {
        "job": "Trusted PR Gate Reporter",
        "status_context": "Trusted PR Gate",
        "authorization": "owner-default-branch-repository-dispatch-only",
        "subject_revalidation": "exact-current-pr-head-base-merge",
        "payload_authority": "runner-env-data-only",
        "write_authority": "statuses:write-only",
    }


def _verify_automatic_workflow(text: str) -> dict[str, Any]:
    name = "ci.yml"
    semantic = _semantic_text(text)
    expected_triggers = {"pull_request", "push", "merge_group", "repository_dispatch"}
    triggers = _top_level_keys(_top_level_block(text, "on"))
    if triggers != expected_triggers:
        raise ValueError(
            f"{name}: trigger set must be exactly {sorted(expected_triggers)}, "
            f"got {sorted(triggers)}"
        )
    if PYTHON_SAFE_PATH_LINE not in _semantic_text(_top_level_block(text, "env")):
        raise ValueError(f"{name}: Python safe-path mode is required")
    _verify_dispatch_contract(text)
    trusted_status_raw = _job_block(text, TRUSTED_STATUS_JOB_ID)
    semantic_without_trusted_status = semantic.replace(_semantic_text(trusted_status_raw), "")
    for forbidden in (
        "pull_request_target:",
        "${{ secrets.",
        "ANTHROPIC_API_KEY",
        "continue-on-error: true",
        "playwright install",
        "sudo ",
        "apt-get ",
        "apt install ",
    ):
        if forbidden in semantic_without_trusted_status:
            raise ValueError(f"{name}: forbidden validation authority token: {forbidden}")
    if WRITE_PERMISSION_RE.search(semantic_without_trusted_status):
        raise ValueError(f"{name}: write permission is forbidden outside trusted reporter")
    if semantic.count("${{ secrets.GITHUB_TOKEN }}") != 1:
        raise ValueError(f"{name}: trusted reporter must be the sole GITHUB_TOKEN secret consumer")
    if CACHE_CONFIGURATION_RE.search(semantic):
        raise ValueError(f"{name}: dependency caching is forbidden before reviewed lock authority")
    if "ubuntu-latest" in semantic:
        raise ValueError(f"{name}: moving ubuntu-latest runner label is forbidden")
    if '"3.11.16"' not in semantic or '"3.13.15"' not in semantic:
        raise ValueError(f"{name}: exact supported Python patch versions are required")
    if "--require-hashes" not in semantic:
        raise ValueError(f"{name}: hash-required dependency installation is required")
    if "pip install --upgrade" in semantic or " --editable" in semantic or " -e ." in semantic:
        raise ValueError(f"{name}: live/editable dependency installation is forbidden")
    if "cancel-in-progress: true" not in _top_level_block(text, "concurrency"):
        raise ValueError(f"{name}: stale executions must be cancelled on superseding revisions")
    _verify_top_level_read_only_permissions(text, name=name)
    checkout_count = _verify_automatic_checkout_binding(text, name=name)
    dependency_install_count = _verify_dependency_install_authority(text, name=name)
    project_install_count = _verify_project_install_authority(text, name=name)
    trusted_status = _verify_trusted_status_job(text)

    supply_chain_raw = _job_block(text, "supply-chain")
    supply_chain = _semantic_text(supply_chain_raw)
    _require_exact_build_authority_step(supply_chain_raw)
    _require_exact_verification_install_step(supply_chain_raw)
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
    _require_exact_runtime_sbom_step(supply_chain_raw)
    _require_exact_reproducible_build_step(supply_chain_raw)
    _require_exact_supply_chain_upload_step(supply_chain_raw)

    ordered_steps = (
        BUILD_AUTHORITY_STEP_NAME,
        VERIFICATION_INSTALL_STEP_NAME,
        SUPPLY_CHAIN_VERIFY_STEP_NAME,
        RUNTIME_SBOM_STEP_NAME,
        REPRODUCIBLE_BUILD_STEP_NAME,
    )
    positions = [supply_chain.index(f"      - name: {step_name}") for step_name in ordered_steps]
    if positions != sorted(positions):
        raise ValueError(
            "supply-chain build authority, installation, verification, SBOM, and build steps are out of reviewed order"
        )
    if supply_chain.count(BUILD_AUTHORITY_COMMAND) != 1:
        raise ValueError(
            f"{name}: build-authority evidence command must appear exactly once in its reviewed step"
        )
    if supply_chain.count(DOCUMENTATION_INTEGRITY_COMMAND) != 1:
        raise ValueError(
            f"{name}: documentation integrity command must not appear outside its reviewed step"
        )
    if supply_chain.count(MERMAID_RENDER_COMMAND) != 1:
        raise ValueError(
            f"{name}: Mermaid render command must not appear outside its reviewed step"
        )

    browser_reference_raw = _job_block(text, "browser-reference-sut")
    _require_exact_hosted_browser_step(browser_reference_raw)

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

    if _git_blob_sha1(text) != EXPECTED_AUTOMATIC_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "ci.yml bytes differ from the exact reviewed automatic/trusted workflow definition"
        )

    return {
        "triggers": sorted(expected_triggers),
        "subject": "github.sha-or-owner-default-branch-dispatch-exact-merge-sha",
        "checkout_count": checkout_count,
        "required_gate": "Required PR Gate",
        "trusted_status": trusted_status,
        "prebuild_authority": "exact-lock-and-build-authority-before-validation-installs",
        "dependency_install_count": dependency_install_count,
        "dependency_install_authority": "exact-reviewed-locks-preinstall-and-postinstall-revalidated",
        "project_install_count": project_install_count,
        "project_install_authority": "immediate-static-revalidation",
        "workflow_definition": "exact-reviewed-git-blob",
        "python_safe_path": True,
        "setup_python_cache": False,
        "browser_runtime_authority": "hosted-system-chrome-observed-without-automatic-installer",
        "archive_build_authority": "verified-and-matched-before-wheel-builds",
        "documentation_integrity": "required-via-supply-chain",
        "mermaid_render": "required-via-supply-chain",
        "build_provenance_subject": "CI_SUBJECT_SHA/isolated-git-view",
        "archive_attribute_authority": "versioned-tree-only",
        "sbom_lineage": "parent-digest-bound-and-bracketed",
        "supply_chain_evidence": "pinned-upload-action",
        "permissions": "validation=contents:read;trusted-reporter=statuses:write",
        "reporter_identity": "ephemeral-github-actions-run",
        "external_policy_required": True,
        "external_policy_invariant": "default-branch-definition-only-for-protected-identity",
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
    if CACHE_CONFIGURATION_RE.search(semantic):
        raise ValueError(f"{name}: trusted/manual workflow dependency caching is forbidden")
    if PYTHON_SAFE_PATH_LINE not in _semantic_text(_top_level_block(text, "env")):
        raise ValueError(f"{name}: Python safe-path mode is required")
    _verify_top_level_read_only_permissions(text, name=name)
    if WRITE_PERMISSION_RE.search(semantic):
        raise ValueError(f"{name}: workflow requests write permission")
    checkout_count = _verify_event_checkout_binding(text, name=name)
    return {
        "trigger": "workflow_dispatch",
        "subject": "github.sha",
        "checkout_count": checkout_count,
        "permissions": "contents:read",
        "python_safe_path": True,
        "setup_python_cache": False,
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
            (
                "Ordinary repository workflow execution remains in-subject self-consistency "
                "evidence; it is not independent merge authority while any allowed event can "
                "execute workflow definitions from a PR/feature-controlled ref under the same "
                "protected GitHub Actions identity. Denying pull_request alone is insufficient."
            ),
            (
                "The owner repository_dispatch path is designed to execute the exact supplied "
                "prospective merge subject from the default-branch workflow definition and "
                "revalidate current PR identity before posting Trusted PR Gate; repository code "
                "cannot attest that the required default-branch-definition-only external Actions "
                "Policy invariant or ruleset transition is active."
            ),
            "A green pull_request run validates GitHub's event SHA, which is normally the prospective merge subject rather than the PR head commit alone.",
            "Credential existence, environment protection, hosted-runner/browser identity, Actions Policy state, ruleset state, and external service availability remain environment-owned facts.",
        ],
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    print(json.dumps(verify_ci_contract(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

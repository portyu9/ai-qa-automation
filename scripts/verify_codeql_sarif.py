from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

MAX_SARIF_FILES = 8
MAX_SARIF_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_SARIF_BYTES = 128 * 1024 * 1024
MAX_REPORTED_FINDINGS = 20


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"SARIF contains duplicate object key: {key}")
        result[key] = value
    return result


def _read_regular_utf8(path: Path) -> str:
    info = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode), f"{path.name} must be a regular non-symlink file")
    require(
        0 < info.st_size <= MAX_SARIF_FILE_BYTES,
        f"{path.name} is outside the bounded SARIF file size",
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_SARIF_FILE_BYTES:
            chunk = os.read(fd, min(1024 * 1024, MAX_SARIF_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    require(
        len(payload) == before.st_size and len(payload) <= MAX_SARIF_FILE_BYTES,
        f"{path.name} changed or exceeded the SARIF ingestion bound",
    )
    require(
        (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ),
        f"{path.name} changed during SARIF ingestion",
    )
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path.name} is not UTF-8 SARIF") from exc


def _sarif_files(directory: Path) -> list[Path]:
    info = directory.stat(follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode), "CodeQL SARIF output must be a real directory")
    require(not directory.is_symlink(), "CodeQL SARIF output directory must not be a symlink")
    files: list[Path] = []
    total = 0
    with os.scandir(directory) as entries:
        for entry in entries:
            require(
                not entry.is_symlink(), f"unexpected symlink in CodeQL SARIF output: {entry.name}"
            )
            if not entry.is_file(follow_symlinks=False):
                continue
            if not entry.name.endswith(".sarif"):
                continue
            files.append(directory / entry.name)
            require(len(files) <= MAX_SARIF_FILES, "CodeQL SARIF output exceeds file-count bound")
            size = entry.stat(follow_symlinks=False).st_size
            require(
                0 < size <= MAX_SARIF_FILE_BYTES,
                f"{entry.name} is outside the bounded SARIF file size",
            )
            total += size
            require(total <= MAX_TOTAL_SARIF_BYTES, "CodeQL SARIF output exceeds total-byte bound")
    require(files, "CodeQL analysis produced no SARIF file")
    return sorted(files, key=lambda item: item.name)


def _location(result: dict[str, Any]) -> str:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return "<unknown>"
    first = locations[0]
    if not isinstance(first, dict):
        return "<unknown>"
    physical = first.get("physicalLocation")
    if not isinstance(physical, dict):
        return "<unknown>"
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict):
        return "<unknown>"
    uri = artifact.get("uri")
    return uri if isinstance(uri, str) and uri else "<unknown>"


def verify_zero_findings(directory: Path) -> dict[str, Any]:
    files = _sarif_files(directory)
    findings: list[dict[str, str]] = []
    run_count = 0
    tool_names: set[str] = set()

    for path in files:
        try:
            payload = json.loads(_read_regular_utf8(path), object_pairs_hook=_unique_object)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path.name} is not strict JSON SARIF") from exc
        require(isinstance(payload, dict), f"{path.name} SARIF root must be an object")
        require(payload.get("version") == "2.1.0", f"{path.name} SARIF version drifted")
        runs = payload.get("runs")
        require(isinstance(runs, list) and runs, f"{path.name} SARIF runs are missing")
        for run in runs:
            require(isinstance(run, dict), f"{path.name} SARIF run must be an object")
            tool = run.get("tool")
            driver = tool.get("driver") if isinstance(tool, dict) else None
            require(isinstance(driver, dict), f"{path.name} SARIF tool driver is missing")
            tool_name = driver.get("name")
            require(
                isinstance(tool_name, str) and "codeql" in tool_name.lower(),
                f"{path.name} SARIF is not produced by CodeQL",
            )
            tool_names.add(tool_name)
            results = run.get("results")
            require(isinstance(results, list), f"{path.name} SARIF results must be an array")
            run_count += 1
            for result in results:
                require(isinstance(result, dict), f"{path.name} SARIF result must be an object")
                rule_id = result.get("ruleId")
                require(
                    isinstance(rule_id, str) and rule_id,
                    f"{path.name} SARIF result has no ruleId",
                )
                findings.append(
                    {
                        "file": path.name,
                        "rule": rule_id,
                        "location": _location(result),
                    }
                )

    require(run_count > 0, "CodeQL SARIF contained no analysis run")
    if findings:
        for finding in findings[:MAX_REPORTED_FINDINGS]:
            print(
                f"CodeQL finding: {finding['rule']} at {finding['location']} ({finding['file']})",
                file=sys.stderr,
            )
        if len(findings) > MAX_REPORTED_FINDINGS:
            print(
                f"... and {len(findings) - MAX_REPORTED_FINDINGS} additional CodeQL findings",
                file=sys.stderr,
            )
        raise ValueError(
            f"CodeQL security-result gate rejected {len(findings)} finding(s); "
            "successful analysis execution is not a clean-security result"
        )

    return {
        "schema_version": 1,
        "result": "PASS",
        "sarif_files": len(files),
        "analysis_runs": run_count,
        "findings": 0,
        "tools": sorted(tool_names),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail closed unless exact CodeQL SARIF contains zero findings"
    )
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = verify_zero_findings(args.directory)
    except (OSError, ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

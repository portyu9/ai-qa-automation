from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import PolicyDecision, RiskLevel, ToolDecision


class PolicyEngine:
    """Deterministic, fail-closed policy for runtime tool and change authorization."""

    OFFICIAL_EXTERNAL_MCP = {
        "github": "github/github-mcp-server",
        "atlassian": "atlassian/rovo-mcp",
    }

    _DANGEROUS_TOOL_NAMES = {"Bash", "Edit", "Write", "MultiEdit", "NotebookEdit"}
    _PROTECTED_RELATIVE_PATHS = {
        "CLAUDE.md",
        ".mcp.json",
        ".env",
        ".env.local",
        ".git",
        ".claude",
        "src/ai_qa_automation/policy.py",
        "src/ai_qa_automation/runtime/runtime_hooks.py",
        "evals/thresholds.json",
    }
    _DESTRUCTIVE_COMMANDS = (
        re.compile(r"\bgit\s+push\b.*(?:--force|-f)"),
        re.compile(r"\bgit\s+reset\s+--hard\b"),
        re.compile(r"\bgit\s+clean\s+-[^\n]*f"),
        re.compile(r"\brm\s+-rf\s+/(?:\s|$)"),
        re.compile(r"\bgit\s+rebase\b"),
    )
    _UNSAFE_PATCH_PATTERNS = {
        "test_skip": re.compile(r"^\+.*(?:pytest\.skip|@pytest\.mark\.skip|unittest\.skip)", re.M),
        "xfail": re.compile(r"^\+.*pytest\.mark\.xfail", re.M),
        "arbitrary_sleep": re.compile(r"^\+.*(?:time\.sleep|asyncio\.sleep|wait_for_timeout)\(", re.M),
        "timeout_inflation": re.compile(r"^\+.*(?:timeout|default_timeout)\s*[=:]\s*(?:[6-9]\d{3,}|[1-9]\d{4,})", re.M | re.I),
        "assertion_tautology": re.compile(r"^\+\s*assert\s+(?:True|1\s*==\s*1)\b", re.M),
        "broad_exception_suppression": re.compile(r"^\+.*except\s+(?:Exception|BaseException)\s*:\s*(?:pass)?", re.M),
    }

    def __init__(self, control_root: Path, target_workspace: Path, allow_test_writes: bool = False) -> None:
        self.control_root = control_root.expanduser().resolve()
        self.target_workspace = target_workspace.expanduser().resolve()
        self.allow_test_writes = allow_test_writes

    def authorize_tool(self, tool_name: str, tool_input: dict[str, Any]) -> PolicyDecision:
        if tool_name.startswith("mcp__github__") or tool_name.startswith("mcp__atlassian__"):
            return self._authorize_external_mcp_tool(tool_name)

        if tool_name in self._DANGEROUS_TOOL_NAMES:
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="General-purpose mutation tools are not exposed to unattended runtime.",
                rule_id="TOOL-001",
                risk=RiskLevel.CRITICAL,
            )

        if tool_name == "Bash" or "command" in tool_input:
            command = str(tool_input.get("command", ""))
            for pattern in self._DESTRUCTIVE_COMMANDS:
                if pattern.search(command):
                    return PolicyDecision(
                        decision=ToolDecision.DENY,
                        reason="Destructive or history-rewriting command blocked.",
                        rule_id="GIT-001",
                        risk=RiskLevel.CRITICAL,
                    )

        path_value = tool_input.get("path") or tool_input.get("file_path")
        if path_value:
            path_decision = self.authorize_path(Path(str(path_value)), write=bool(tool_input.get("write", False)))
            if path_decision.decision != ToolDecision.ALLOW:
                return path_decision

        return PolicyDecision(
            decision=ToolDecision.ALLOW,
            reason="No deterministic deny rule matched.",
            rule_id="DEFAULT-ALLOW-NARROW-TOOL",
            risk=RiskLevel.LOW,
        )


    def _authorize_external_mcp_tool(self, tool_name: str) -> PolicyDecision:
        """Apply least privilege to approved-server tools; server approval is not blanket tool approval."""
        action = tool_name.rsplit("__", 1)[-1].lower()
        destructive = ("merge", "delete", "remove", "force", "admin", "transfer")
        write = ("create", "update", "edit", "add_comment", "comment", "close", "reopen", "assign", "label", "dispatch", "rerun", "cancel")
        read = ("get", "list", "search", "read", "view", "fetch", "download")
        if any(token in action for token in destructive):
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="Destructive/high-impact external MCP operation is denied by default.",
                rule_id="MCP-TOOL-003",
                risk=RiskLevel.CRITICAL,
            )
        if any(token in action for token in write):
            return PolicyDecision(
                decision=ToolDecision.REQUIRE_APPROVAL,
                reason="External MCP write requires explicit approval and scoped authorization.",
                rule_id="MCP-TOOL-002",
                risk=RiskLevel.HIGH,
            )
        if any(action.startswith(token) or f"_{token}_" in f"_{action}_" for token in read):
            return PolicyDecision(
                decision=ToolDecision.ALLOW,
                reason="Read-only external MCP operation allowed by tool-level policy.",
                rule_id="MCP-TOOL-READ",
                risk=RiskLevel.MEDIUM,
            )
        return PolicyDecision(
            decision=ToolDecision.REQUIRE_APPROVAL,
            reason="Unknown external MCP operation is not auto-approved.",
            rule_id="MCP-TOOL-UNKNOWN",
            risk=RiskLevel.HIGH,
        )

    def authorize_path(self, path: Path, *, write: bool) -> PolicyDecision:
        candidate = path if path.is_absolute() else self.target_workspace / path
        candidate = candidate.resolve()
        if self.target_workspace not in candidate.parents and candidate != self.target_workspace:
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="Path escapes the isolated target workspace.",
                rule_id="FS-001",
                risk=RiskLevel.CRITICAL,
            )

        relative = candidate.relative_to(self.target_workspace).as_posix()
        if self._is_protected(relative):
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="Runtime governance/security path is protected from autonomous modification.",
                rule_id="GOV-001",
                risk=RiskLevel.CRITICAL,
            )

        if write and not self.allow_test_writes:
            return PolicyDecision(
                decision=ToolDecision.REQUIRE_APPROVAL,
                reason="Autonomous test writes are disabled in current runtime configuration.",
                rule_id="WRITE-001",
                risk=RiskLevel.HIGH,
            )

        if write and not (relative.startswith("tests/") or relative.startswith("generated_tests/")):
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="Autonomous writes are restricted to approved test-code directories.",
                rule_id="WRITE-002",
                risk=RiskLevel.CRITICAL,
            )

        return PolicyDecision(
            decision=ToolDecision.ALLOW,
            reason="Path is inside target workspace and allowed by write policy.",
            rule_id="FS-ALLOW",
            risk=RiskLevel.LOW,
        )

    def validate_patch(self, diff: str) -> list[str]:
        violations = [name for name, pattern in self._UNSAFE_PATCH_PATTERNS.items() if pattern.search(diff)]
        removed_asserts = sum(1 for line in diff.splitlines() if re.match(r"^-\s*assert\b", line))
        added_asserts = sum(1 for line in diff.splitlines() if re.match(r"^\+\s*assert\b", line))
        if removed_asserts > added_asserts:
            violations.append("assertion_removal")
        return sorted(set(violations))

    def validate_mcp_server(self, name: str, vendor_identity: str) -> PolicyDecision:
        expected = self.OFFICIAL_EXTERNAL_MCP.get(name)
        if expected is None or vendor_identity != expected:
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="External MCP is not on the first-party/vendor-official allowlist.",
                rule_id="MCP-001",
                risk=RiskLevel.CRITICAL,
            )
        return PolicyDecision(
            decision=ToolDecision.ALLOW,
            reason="External MCP identity matches approved first-party vendor integration.",
            rule_id="MCP-ALLOW",
            risk=RiskLevel.MEDIUM,
        )

    def authorize_performance_target(self, target_url: str, *, environment: str) -> PolicyDecision:
        host = (urlparse(target_url).hostname or "").lower()
        if environment.lower() == "production" or host.startswith("prod.") or ".prod." in host:
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="Production load testing is denied by default.",
                rule_id="PERF-001",
                risk=RiskLevel.CRITICAL,
            )
        return PolicyDecision(
            decision=ToolDecision.ALLOW,
            reason="Target is not classified as production.",
            rule_id="PERF-ALLOW",
            risk=RiskLevel.MEDIUM,
        )

    @classmethod
    def _is_protected(cls, relative: str) -> bool:
        return any(relative == item or relative.startswith(f"{item}/") for item in cls._PROTECTED_RELATIVE_PATHS)

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

    _DANGEROUS_TOOL_NAMES = {
        "Bash",
        "Edit",
        "Write",
        "MultiEdit",
        "NotebookEdit",
        "WebFetch",
        "WebSearch",
    }
    _APPROVED_SKILLS = {
        "investigate-test-failure",
        "self-heal-test",
        "generate-test",
        "prioritize-regression",
        "performance-test",
    }
    _INTERNAL_QA_TOOLS = {
        "inspect_repository",
        "run_pytest",
        "probe_api",
        "inspect_browser",
        "classify_failure",
        "read_test_file",
        "search_test_coverage",
        "plan_tests",
        "prioritize_regression",
        "review_python_test",
        "create_test_file",
        "verify_locator_candidates",
        "propose_locator_heal",
        "apply_locator_heal",
        "validate_json_contract",
        "analyze_ci_failure",
        "inspect_mobile_runtime",
        "run_k6",
    }
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
        "test_skip": re.compile(
            r"^\+.*(?:pytest\.skip|@pytest\.mark\.skip|unittest\.skip|(?:test|it|describe)\.skip\s*\()",
            re.M,
        ),
        "focused_test": re.compile(r"^\+.*(?:test|it|describe)\.only\s*\(", re.M),
        "xfail": re.compile(r"^\+.*pytest\.mark\.xfail", re.M),
        "arbitrary_sleep": re.compile(
            r"^\+.*(?:time\.sleep|asyncio\.sleep|wait_for_timeout|waitForTimeout|cy\.wait)\(",
            re.M,
        ),
        "timeout_inflation": re.compile(
            r"^\+.*(?:"
            r"(?:timeout|default_timeout)\s*[=:]\s*(?:[6-9]\d{3,}|[1-9]\d{4,})"
            r"|(?:setTimeout|set_default_timeout|setDefaultTimeout)\s*\(\s*(?:[6-9]\d{3,}|[1-9]\d{4,})"
            r")",
            re.M | re.I,
        ),
        "assertion_tautology": re.compile(
            r"^\+.*(?:"
            r"assert\s+(?:True|1\s*==\s*1)\b|"
            r"expect\(\s*(true|false|null|undefined|[A-Za-z_$][\w$]*)\s*\)"
            r"\s*\.to(?:Be|Equal)\(\s*\1\s*\)"
            r")",
            re.M,
        ),
        "broad_exception_suppression": re.compile(
            r"^\+.*except\s+(?:Exception|BaseException)\s*:\s*(?:pass)?", re.M
        ),
    }

    def __init__(
        self, control_root: Path, target_workspace: Path, allow_test_writes: bool = False
    ) -> None:
        self.control_root = control_root.expanduser().resolve()
        self.target_workspace = target_workspace.expanduser().resolve()
        self.allow_test_writes = allow_test_writes

    def authorize_tool(self, tool_name: str, tool_input: dict[str, Any]) -> PolicyDecision:
        if tool_name == "Skill":
            skill_name = str(tool_input.get("skill") or tool_input.get("name") or "")
            if skill_name in self._APPROVED_SKILLS:
                return PolicyDecision(
                    decision=ToolDecision.ALLOW,
                    reason="Skill is in the explicit trusted project Skill inventory.",
                    rule_id="SKILL-ALLOW",
                    risk=RiskLevel.LOW,
                )
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="Skill is not in the explicit trusted project Skill inventory.",
                rule_id="SKILL-001",
                risk=RiskLevel.HIGH,
            )
        if tool_name.startswith("mcp__github__") or tool_name.startswith("mcp__atlassian__"):
            return self._authorize_external_mcp_tool(tool_name)

        if tool_name in self._DANGEROUS_TOOL_NAMES:
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="General-purpose or network-capable built-in tool is not exposed to unattended runtime.",
                rule_id="TOOL-001",
                risk=RiskLevel.CRITICAL,
            )

        command = str(tool_input.get("command", ""))
        if command:
            for pattern in self._DESTRUCTIVE_COMMANDS:
                if pattern.search(command):
                    return PolicyDecision(
                        decision=ToolDecision.DENY,
                        reason="Destructive or history-rewriting command blocked.",
                        rule_id="GIT-001",
                        risk=RiskLevel.CRITICAL,
                    )

        if tool_name.startswith("mcp__"):
            parts = tool_name.split("__", 2)
            if len(parts) != 3 or parts[1] != "qa" or parts[2] not in self._INTERNAL_QA_TOOLS:
                return PolicyDecision(
                    decision=ToolDecision.DENY,
                    reason="MCP tool is outside the approved internal/external tool inventory.",
                    rule_id="MCP-TOOL-001",
                    risk=RiskLevel.CRITICAL,
                )
            internal_name = parts[2]
            path_value = tool_input.get("path") or tool_input.get("file_path")
            if path_value:
                write = internal_name in {"create_test_file", "apply_locator_heal"}
                path_decision = self.authorize_path(Path(str(path_value)), write=write)
                if path_decision.decision != ToolDecision.ALLOW:
                    return path_decision
            if internal_name == "run_k6":
                return self.authorize_performance_target(
                    str(tool_input.get("target_url", "")),
                    environment=str(tool_input.get("environment", "")),
                )
            return PolicyDecision(
                decision=ToolDecision.ALLOW,
                reason="Tool is in the approved internal QA inventory.",
                rule_id="QA-TOOL-ALLOW",
                risk=RiskLevel.LOW,
            )

        return PolicyDecision(
            decision=ToolDecision.DENY,
            reason="Unknown tool is denied by fail-closed runtime policy.",
            rule_id="TOOL-UNKNOWN",
            risk=RiskLevel.HIGH,
        )

    @staticmethod
    def _external_action_tokens(tool_name: str) -> tuple[str, tuple[str, ...]]:
        """Normalize snake/camel/mixed MCP action names into conservative verb tokens."""
        raw_action = tool_name.rsplit("__", 1)[-1]
        snake_action = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw_action).lower()
        tokens = tuple(token for token in re.split(r"[^a-z0-9]+", snake_action) if token)
        return snake_action, tokens

    @staticmethod
    def _semantic_action_tokens(tokens: tuple[str, ...]) -> tuple[str, ...]:
        """Remove known resource-noun collisions without weakening actual action verbs."""
        semantic: list[str] = []
        for index, token in enumerate(tokens):
            # In GitHub tool names, "pull request" is a resource noun. The token
            # "request" must therefore not turn get_pull_request/pull_request_read
            # into a write. A leading request_* action remains a write verb.
            if token == "request" and index > 0 and tokens[index - 1] == "pull":
                continue
            semantic.append(token)
        return tuple(semantic)

    def _authorize_external_mcp_tool(self, tool_name: str) -> PolicyDecision:
        """Apply least privilege to approved-server tools; server approval is not blanket tool approval."""
        action, tokens = self._external_action_tokens(tool_name)
        semantic_tokens = self._semantic_action_tokens(tokens)
        destructive_verbs = {"merge", "delete", "remove", "force", "admin", "transfer"}
        write_verbs = {
            "create",
            "update",
            "edit",
            "add",
            "close",
            "reopen",
            "assign",
            "label",
            "dispatch",
            "rerun",
            "cancel",
            "submit",
            "request",
            "mark",
            "resolve",
            "dismiss",
            "lock",
            "unlock",
            "enable",
            "disable",
            "transition",
        }
        read_verbs = {"get", "list", "search", "read", "view", "fetch", "download", "lookup"}
        known_read_actions = {"atlassian_user_info"}

        # A mixed name such as getOrCreateIssue must never inherit read authority
        # from its first verb. High-impact tokens dominate, then write tokens, then read.
        if any(token in destructive_verbs for token in semantic_tokens):
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="Destructive/high-impact external MCP operation is denied by default.",
                rule_id="MCP-TOOL-003",
                risk=RiskLevel.CRITICAL,
            )
        if any(token in write_verbs for token in semantic_tokens):
            return PolicyDecision(
                decision=ToolDecision.REQUIRE_APPROVAL,
                reason="External MCP write requires explicit approval and scoped authorization.",
                rule_id="MCP-TOOL-002",
                risk=RiskLevel.HIGH,
            )
        if any(token in read_verbs for token in semantic_tokens) or action in known_read_actions:
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
        violations = [
            name for name, pattern in self._UNSAFE_PATCH_PATTERNS.items() if pattern.search(diff)
        ]
        assertion_signal = re.compile(
            r"(?:\bassert\b|\bexpect\s*\(|\bpytest\.raises\s*\(|\.assert[A-Z_a-z0-9]*\s*\()"
        )
        removed_asserts = sum(
            1
            for line in diff.splitlines()
            if line.startswith("-") and assertion_signal.search(line[1:])
        )
        added_asserts = sum(
            1
            for line in diff.splitlines()
            if line.startswith("+") and assertion_signal.search(line[1:])
        )
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

    def authorize_api_method(self, method: str, *, allow_mutating: bool = False) -> PolicyDecision:
        normalized = method.upper().strip()
        safe_methods = {"GET", "HEAD", "OPTIONS"}
        mutating_methods = {"POST", "PUT", "PATCH", "DELETE"}
        if normalized in safe_methods:
            return PolicyDecision(
                decision=ToolDecision.ALLOW,
                reason="Read-only HTTP method allowed.",
                rule_id="API-READ",
                risk=RiskLevel.LOW,
            )
        if normalized in mutating_methods and allow_mutating:
            return PolicyDecision(
                decision=ToolDecision.ALLOW,
                reason="Mutating HTTP method explicitly enabled for this runtime.",
                rule_id="API-WRITE-ALLOW",
                risk=RiskLevel.HIGH,
            )
        if normalized in mutating_methods:
            return PolicyDecision(
                decision=ToolDecision.REQUIRE_APPROVAL,
                reason="Mutating HTTP methods are disabled unless explicitly enabled.",
                rule_id="API-WRITE-001",
                risk=RiskLevel.HIGH,
            )
        return PolicyDecision(
            decision=ToolDecision.DENY,
            reason="HTTP method is outside the supported API-testing allowlist.",
            rule_id="API-METHOD-001",
            risk=RiskLevel.CRITICAL,
        )

    def authorize_performance_target(self, target_url: str, *, environment: str) -> PolicyDecision:
        parsed = urlparse(target_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or not host:
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="Performance target must be an explicit HTTP(S) URL.",
                rule_id="PERF-URL-001",
                risk=RiskLevel.CRITICAL,
            )
        normalized_environment = environment.lower().strip()
        host_labels = tuple(label for label in host.split(".") if label)
        production_like_host = any(
            label in {"prod", "production"}
            or label.startswith("prod-")
            or label.startswith("production-")
            for label in host_labels
        )
        if normalized_environment in {"prod", "production"} or production_like_host:
            return PolicyDecision(
                decision=ToolDecision.DENY,
                reason="Production load testing is denied by default.",
                rule_id="PERF-001",
                risk=RiskLevel.CRITICAL,
            )
        allowed_environments = {
            "local",
            "dev",
            "development",
            "test",
            "qa",
            "staging",
            "preprod",
            "pre-production",
        }
        if normalized_environment not in allowed_environments:
            return PolicyDecision(
                decision=ToolDecision.REQUIRE_APPROVAL,
                reason="Performance environment is not explicitly classified as non-production.",
                rule_id="PERF-ENV-001",
                risk=RiskLevel.HIGH,
            )
        return PolicyDecision(
            decision=ToolDecision.ALLOW,
            reason="Target is explicitly classified as a non-production HTTP(S) environment.",
            rule_id="PERF-ALLOW",
            risk=RiskLevel.MEDIUM,
        )

    @classmethod
    def _is_protected(cls, relative: str) -> bool:
        if any(
            relative == item or relative.startswith(f"{item}/")
            for item in cls._PROTECTED_RELATIVE_PATHS
        ):
            return True
        basename = Path(relative).name
        if basename == ".env.example":
            return False
        return basename == ".env" or basename.startswith(".env.")

from __future__ import annotations

from typing import Any

from ..policy import PolicyEngine
from ..redaction import sanitize


def build_permission_handler(policy: PolicyEngine) -> Any:
    """Handle every tool that would otherwise prompt; unattended approval-required => deny."""
    try:
        from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("claude-agent-sdk is required for live agent mode") from exc

    async def can_use_tool(tool_name: str, tool_input: dict[str, Any], _context: Any) -> Any:
        decision = policy.authorize_tool(tool_name, tool_input)
        if decision.decision.value == "ALLOW":
            return PermissionResultAllow(updated_input=tool_input)
        return PermissionResultDeny(
            message=f"{decision.rule_id}: {decision.reason}",
            interrupt=decision.risk.value == "CRITICAL",
        )

    return can_use_tool


def build_hooks(policy: PolicyEngine) -> dict[str, list[Any]]:
    """Build SDK hooks lazily so deterministic modules do not require the SDK installed."""
    try:
        from claude_agent_sdk import HookMatcher
    except ImportError as exc:  # pragma: no cover - exercised only in live runtime
        raise RuntimeError("claude-agent-sdk is required for live agent mode") from exc

    async def pre_tool_use(input_data: dict[str, Any], _tool_use_id: str | None, _context: Any) -> dict[str, Any]:
        tool_name = str(input_data.get("tool_name", ""))
        tool_input = input_data.get("tool_input") or {}
        decision = policy.authorize_tool(tool_name, tool_input)
        if decision.decision.value == "DENY":
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"{decision.rule_id}: {decision.reason}",
                }
            }
        if decision.decision.value == "REQUIRE_APPROVAL":
            # Do not pre-approve. Returning no hook decision delegates to the SDK
            # permission callback, which is configured fail-closed for unattended runs.
            return {}
        return {}

    async def post_tool_use(input_data: dict[str, Any], _tool_use_id: str | None, _context: Any) -> dict[str, Any]:
        safe = sanitize({"tool_name": input_data.get("tool_name"), "tool_input": input_data.get("tool_input", {})})
        return {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": f"Policy audit recorded sanitized metadata: {safe}",
            }
        }

    return {
        "PreToolUse": [HookMatcher(matcher=None, hooks=[pre_tool_use], timeout=10)],
        "PostToolUse": [HookMatcher(matcher=None, hooks=[post_tool_use], timeout=10)],
    }

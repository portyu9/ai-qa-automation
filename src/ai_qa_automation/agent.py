from __future__ import annotations

import asyncio
import importlib.metadata
import time
from pathlib import Path
from typing import Any

from .config import Settings
from .evidence import EvidenceStore
from .integrations.mcp_registry import build_external_mcp
from .models import AgentRunState, MCPStatus, TerminalStatus, ValidationStatus
from .policy import PolicyEngine
from .reporting import build_final_report
from .runtime.internal_tools import RuntimeServices, build_internal_mcp_server
from .runtime.runtime_hooks import build_hooks, build_permission_handler
from .runtime.system_prompt import RUNTIME_SYSTEM_PROMPT
from .state import StateStore
from .tools.test_execution import TestRunner


async def run_agent(objective: str, workspace: Path, settings: Settings | None = None) -> dict[str, Any]:
    """Run the live Claude Agent SDK path with strict, narrow runtime configuration."""
    cfg = settings or Settings()
    workspace = workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise ValueError(f"workspace does not exist: {workspace}")

    try:
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, ResultMessage
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Install project dependencies to use live agent mode") from exc

    started = time.monotonic()
    state = AgentRunState(
        objective=objective,
        model_id=cfg.model,
        sdk_version=_package_version("claude-agent-sdk"),
        workspace=str(workspace),
        phase="RUNNING",
    )
    state_store = StateStore(cfg.artifact_root / state.run_id / "state.json")
    evidence = EvidenceStore(cfg.artifact_root, state.run_id)
    policy = PolicyEngine(cfg.control_root, workspace, allow_test_writes=cfg.allow_test_writes)
    runner = TestRunner(workspace, evidence, timeout_seconds=cfg.tool_timeout_seconds)
    services = RuntimeServices(
        workspace=workspace,
        state=state,
        evidence=evidence,
        policy=policy,
        test_runner=runner,
        max_tool_calls=cfg.max_tool_calls,
        max_repeated_action=cfg.max_repeated_action,
        allowed_network_hosts={host.lower() for host in cfg.allowed_network_hosts},
        allow_external_network=cfg.allow_external_network,
    )
    internal_server, internal_tool_names = build_internal_mcp_server(services)

    external, statuses = build_external_mcp(cfg, policy)
    state.mcp_status = {name: MCPStatus(status) for name, status in statuses.items()}
    mcp_servers: dict[str, Any] = {"qa": internal_server, **external}

    options = ClaudeAgentOptions(
        model=cfg.model,
        cwd=str(cfg.control_root),
        system_prompt=RUNTIME_SYSTEM_PROMPT,
        setting_sources=["project"],
        tools=[],
        allowed_tools=internal_tool_names,
        disallowed_tools=["Bash", "Edit", "Write", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch"],
        permission_mode="default",
        can_use_tool=build_permission_handler(policy),
        mcp_servers=mcp_servers,
        strict_mcp_config=True,
        max_turns=cfg.max_turns,
        max_budget_usd=cfg.max_cost_usd,
        hooks=build_hooks(policy),
    )

    final_text = ""
    result_subtype: str | None = None
    try:
        async with asyncio.timeout(cfg.global_timeout_seconds):
            async with ClaudeSDKClient(options=options) as client:
                await client.query(objective)
                async for message in client.receive_response():
                    state.iteration += 1
                    if isinstance(message, ResultMessage):
                        final_text = str(message.result or "")
                        result_subtype = str(message.subtype)
                        state.cost = float(message.total_cost_usd or 0.0)
                        usage = message.usage or {}
                        state.token_usage = int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
    except asyncio.CancelledError:
        state.terminal_status = TerminalStatus.CANCELLED
        state.terminal_reason = "Execution cancelled"
        raise
    except TimeoutError:
        state.terminal_status = TerminalStatus.BUDGET_EXCEEDED
        state.terminal_reason = "Global execution-time budget exhausted"
    except Exception as exc:
        state.terminal_status = TerminalStatus.INFRASTRUCTURE_FAILURE
        state.terminal_reason = f"Agent SDK execution failed: {type(exc).__name__}"
    else:
        # Model completion alone is never enough to call the engineering objective PASS.
        deterministic_passes = [v for v in state.validation_results if v.status == ValidationStatus.PASS]
        if result_subtype == "success" and deterministic_passes:
            state.terminal_status = TerminalStatus.SUCCESS
            state.terminal_reason = "Agent completed and deterministic validation evidence passed."
        elif result_subtype == "success":
            state.terminal_status = TerminalStatus.NOT_VERIFIED
            state.terminal_reason = "Agent completed, but no deterministic validation gate proved success."
        else:
            state.terminal_status = TerminalStatus.FAILURE
            state.terminal_reason = f"Agent result subtype: {result_subtype or 'unknown'}"
    finally:
        state.duration = time.monotonic() - started
        state_store.save(state)

    report = build_final_report(
        state,
        limitations=[
            "A model response is not a test result; only deterministic validations can produce verified success.",
            "External MCP capability remains NOT_VERIFIED unless authenticated and exercised in this environment.",
        ],
    )
    return {"report": report.model_dump(mode="json"), "agent_result": final_text}


def run_agent_sync(objective: str, workspace: Path, settings: Settings | None = None) -> dict[str, Any]:
    return asyncio.run(run_agent(objective, workspace, settings))


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "NOT_VERIFIED"

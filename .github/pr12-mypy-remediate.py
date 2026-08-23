from __future__ import annotations

from pathlib import Path


def replace_exact(path_s: str, old: str, new: str, *, count: int = 1) -> None:
    path = Path(path_s)
    text = path.read_text(encoding="utf-8")
    observed = text.count(old)
    if observed != count:
        raise SystemExit(
            f"refusing ambiguous Mypy repair in {path}: expected {count} occurrence(s), "
            f"found {observed}: {old!r}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


# Preserve POSIX path semantics explicitly when os.walk yields platform Path objects.
replace_exact(
    "src/ai_qa_automation/intelligence/test_impact.py",
    "                if not self._is_test_file(relative):",
    "                if not self._is_test_file(PurePosixPath(relative.as_posix())):",
)

# Avoid cross-loop inference between two different immutable registry record types.
replace_exact(
    "src/ai_qa_automation/evidence.py",
    "        for evidence_id, item in self._items.items():\n"
    "            actual = self.hash_bytes(item.model_dump_json().encode(\"utf-8\"))\n"
    "            if evidence_hashes[evidence_id] != actual:\n"
    "                raise ValueError(f\"regulated evidence integrity check failed: {evidence_id}\")\n"
    "        for artifact_id, item in self._artifacts.items():\n"
    "            if artifact_hashes[artifact_id] != item.content_hash:\n"
    "                raise ValueError(\n"
    "                    f\"regulated artifact registry integrity check failed: {artifact_id}\"\n"
    "                )",
    "        for evidence_id, evidence_item in self._items.items():\n"
    "            actual = self.hash_bytes(evidence_item.model_dump_json().encode(\"utf-8\"))\n"
    "            if evidence_hashes[evidence_id] != actual:\n"
    "                raise ValueError(f\"regulated evidence integrity check failed: {evidence_id}\")\n"
    "        for artifact_id, artifact_record in self._artifacts.items():\n"
    "            if artifact_hashes[artifact_id] != artifact_record.content_hash:\n"
    "                raise ValueError(\n"
    "                    f\"regulated artifact registry integrity check failed: {artifact_id}\"\n"
    "                )",
)

# Keep exponential backoff entirely in the declared float domain.
replace_exact(
    "src/ai_qa_automation/runtime/sdk_recovery.py",
    "    return min(float(max_seconds), float(base_seconds) * (2 ** (retry_number - 1)))",
    "    delay = float(base_seconds) * (2.0 ** (retry_number - 1))\n"
    "    return min(float(max_seconds), delay)",
)

# Make the variable-length evidence-id tuple explicit rather than relying on branch inference.
replace_exact(
    "src/ai_qa_automation/tools/test_execution.py",
    "        if exit_code != 0:\n            exception = self.evidence.add(",
    "        ids: tuple[str, ...]\n"
    "        if exit_code != 0:\n            exception = self.evidence.add(",
)

# json.loads is Any; re-materialize the value as an int only after strict bool/type/range checks.
replace_exact(
    "src/ai_qa_automation/runtime/stale_recovery.py",
    "    if raw < 0 or raw > _MAX_RECOVERY_JOURNAL_EVENTS:\n"
    "        raise ValueError(\"prior runtime journal_event_count exceeds recovery safety bounds\")\n"
    "    return raw",
    "    if raw < 0 or raw > _MAX_RECOVERY_JOURNAL_EVENTS:\n"
    "        raise ValueError(\"prior runtime journal_event_count exceeds recovery safety bounds\")\n"
    "    return int(raw)",
)

# Bind the Windows-only CRT API behind a typed protocol instead of asking Linux typeshed
# to type-check direct msvcrt attributes that only exist on Windows.
replace_exact(
    "src/ai_qa_automation/runtime/workspace_lease.py",
    "import hashlib\nimport json\nimport os\nimport socket\n",
    "import hashlib\nimport importlib\nimport json\nimport os\nimport socket\n",
)
replace_exact(
    "src/ai_qa_automation/runtime/workspace_lease.py",
    "from typing import Any\n",
    "from typing import Any, Protocol, cast\n",
)
replace_exact(
    "src/ai_qa_automation/runtime/workspace_lease.py",
    "\n\nclass WorkspaceBusyError(RuntimeError):",
    "\n\nclass _MSVCRTLocking(Protocol):\n"
    "    LK_NBLCK: int\n"
    "    LK_UNLCK: int\n\n"
    "    def locking(self, fd: int, mode: int, nbytes: int) -> None: ...\n\n\n"
    "def _load_msvcrt() -> _MSVCRTLocking:\n"
    "    return cast(_MSVCRTLocking, importlib.import_module(\"msvcrt\"))\n\n\n"
    "class WorkspaceBusyError(RuntimeError):",
)
replace_exact(
    "src/ai_qa_automation/runtime/workspace_lease.py",
    "            import msvcrt",
    "            msvcrt = _load_msvcrt()",
    count=2,
)

# Consumers import runtime primitives from their owning modules rather than relying on
# accidental transitive re-exports from run_control.
replace_exact(
    "src/ai_qa_automation/agent.py",
    "from .runtime.bootstrap import bootstrap_runtime_context\n"
    "from .runtime.internal_tools import RuntimeServices, build_internal_mcp_server\n"
    "from .runtime.run_control import (\n"
    "    BudgetExceededError,\n"
    "    ExecutionBudget,\n"
    "    RunJournal,\n"
    "    RuntimeControl,\n"
    "    WorkspaceBusyError,\n"
    "    WorkspaceLease,\n"
    ")\n",
    "from .runtime.bootstrap import bootstrap_runtime_context\n"
    "from .runtime.budget import BudgetExceededError, ExecutionBudget\n"
    "from .runtime.internal_tools import RuntimeServices, build_internal_mcp_server\n"
    "from .runtime.journal import RunJournal\n"
    "from .runtime.run_control import RuntimeControl\n"
    "from .runtime.workspace_lease import WorkspaceBusyError, WorkspaceLease\n",
)
replace_exact(
    "src/ai_qa_automation/runtime/runtime_hooks.py",
    "from .run_control import (\n"
    "    BudgetExceededError,\n"
    "    CircuitOpenError,\n",
    "from .budget import BudgetExceededError\n"
    "from .run_control import (\n"
    "    CircuitOpenError,\n",
)

# Type the Claude Agent SDK boundary with the exact SDK contract. The casts below are
# limited to deterministic hook-output builders whose emitted dictionary shapes are
# covered by runtime-hook tests; no authorization decision is delegated to typing.
replace_exact(
    "src/ai_qa_automation/runtime/runtime_hooks.py",
    "from typing import Any\n\n",
    "from typing import Any, cast\n\n"
    "from claude_agent_sdk.types import (\n"
    "    HookContext,\n"
    "    HookEvent,\n"
    "    HookInput,\n"
    "    HookJSONOutput,\n"
    "    HookMatcher,\n"
    ")\n\n",
)
replace_exact(
    "src/ai_qa_automation/runtime/runtime_hooks.py",
    "def build_hooks(\n"
    "    policy: PolicyEngine,\n"
    "    *,\n"
    "    state: AgentRunState | None = None,\n"
    "    evidence: EvidenceStore | None = None,\n"
    "    state_store: StateStore | None = None,\n"
    "    control: RuntimeControl | None = None,\n"
    ") -> dict[str, list[Any]]:\n"
    "    try:\n"
    "        from claude_agent_sdk import HookMatcher\n"
    "    except ImportError as exc:  # pragma: no cover\n"
    "        raise RuntimeError(\"claude-agent-sdk is required for live agent mode\") from exc\n\n"
    "    async def pre_tool_use(\n"
    "        input_data: dict[str, Any],\n"
    "        _tool_use_id: str | None,\n"
    "        _context: Any,\n"
    "    ) -> dict[str, Any]:\n"
    "        return pretool_policy_output(\n"
    "            policy,\n"
    "            input_data,\n"
    "            state=state,\n"
    "            state_store=state_store,\n"
    "            control=control,\n"
    "        )\n\n"
    "    async def post_tool_use(\n"
    "        input_data: dict[str, Any],\n"
    "        _tool_use_id: str | None,\n"
    "        _context: Any,\n"
    "    ) -> dict[str, Any]:\n"
    "        return posttool_policy_output(\n"
    "            input_data,\n"
    "            state=state,\n"
    "            evidence=evidence,\n"
    "            state_store=state_store,\n"
    "            control=control,\n"
    "        )\n\n"
    "    async def post_tool_use_failure(\n"
    "        input_data: dict[str, Any],\n"
    "        _tool_use_id: str | None,\n"
    "        _context: Any,\n"
    "    ) -> dict[str, Any]:\n"
    "        return posttool_failure_output(\n"
    "            input_data,\n"
    "            state=state,\n"
    "            state_store=state_store,\n"
    "            control=control,\n"
    "        )\n\n"
    "    return {\n"
    "        \"PreToolUse\": [HookMatcher(matcher=None, hooks=[pre_tool_use], timeout=10)],\n"
    "        \"PostToolUse\": [HookMatcher(matcher=None, hooks=[post_tool_use], timeout=10)],\n"
    "        \"PostToolUseFailure\": [\n"
    "            HookMatcher(matcher=None, hooks=[post_tool_use_failure], timeout=10)\n"
    "        ],\n"
    "    }",
    "def build_hooks(\n"
    "    policy: PolicyEngine,\n"
    "    *,\n"
    "    state: AgentRunState | None = None,\n"
    "    evidence: EvidenceStore | None = None,\n"
    "    state_store: StateStore | None = None,\n"
    "    control: RuntimeControl | None = None,\n"
    ") -> dict[HookEvent, list[HookMatcher]]:\n"
    "    async def pre_tool_use(\n"
    "        input_data: HookInput,\n"
    "        _tool_use_id: str | None,\n"
    "        _context: HookContext,\n"
    "    ) -> HookJSONOutput:\n"
    "        return cast(\n"
    "            HookJSONOutput,\n"
    "            pretool_policy_output(\n"
    "                policy,\n"
    "                cast(dict[str, Any], input_data),\n"
    "                state=state,\n"
    "                state_store=state_store,\n"
    "                control=control,\n"
    "            ),\n"
    "        )\n\n"
    "    async def post_tool_use(\n"
    "        input_data: HookInput,\n"
    "        _tool_use_id: str | None,\n"
    "        _context: HookContext,\n"
    "    ) -> HookJSONOutput:\n"
    "        return cast(\n"
    "            HookJSONOutput,\n"
    "            posttool_policy_output(\n"
    "                cast(dict[str, Any], input_data),\n"
    "                state=state,\n"
    "                evidence=evidence,\n"
    "                state_store=state_store,\n"
    "                control=control,\n"
    "            ),\n"
    "        )\n\n"
    "    async def post_tool_use_failure(\n"
    "        input_data: HookInput,\n"
    "        _tool_use_id: str | None,\n"
    "        _context: HookContext,\n"
    "    ) -> HookJSONOutput:\n"
    "        return cast(\n"
    "            HookJSONOutput,\n"
    "            posttool_failure_output(\n"
    "                cast(dict[str, Any], input_data),\n"
    "                state=state,\n"
    "                state_store=state_store,\n"
    "                control=control,\n"
    "            ),\n"
    "        )\n\n"
    "    hooks: dict[HookEvent, list[HookMatcher]] = {\n"
    "        \"PreToolUse\": [HookMatcher(matcher=None, hooks=[pre_tool_use], timeout=10)],\n"
    "        \"PostToolUse\": [HookMatcher(matcher=None, hooks=[post_tool_use], timeout=10)],\n"
    "        \"PostToolUseFailure\": [\n"
    "            HookMatcher(matcher=None, hooks=[post_tool_use_failure], timeout=10)\n"
    "        ],\n"
    "    }\n"
    "    return hooks",
)

# Mypy requires typed jsonschema stubs for the optional API adapter; keep them in dev only.
replace_exact(
    "pyproject.toml",
    '  "mypy>=1.14,<2",\n  "pip-audit>=2.8,<3",',
    '  "mypy>=1.14,<2",\n  "types-jsonschema>=4.23,<5",\n  "pip-audit>=2.8,<3",',
)

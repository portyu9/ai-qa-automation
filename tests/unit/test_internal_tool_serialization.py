from __future__ import annotations

import asyncio
from typing import Any, cast

from ai_qa_automation.runtime import internal_tools
from ai_qa_automation.runtime.internal_tool_domains import common as common_module


def _capturing_tool_decorator(
    registry: dict[str, common_module.ToolHandler],
) -> common_module.ToolDecorator:
    def tool(
        name: str,
        _description: str,
        _input_schema: dict[str, Any],
    ) -> object:
        def decorate(handler: common_module.ToolHandler) -> object:
            registry[name] = handler
            return handler

        return decorate

    return cast(common_module.ToolDecorator, tool)


def test_internal_tool_handlers_are_serialized_across_tool_names() -> None:
    async def scenario() -> None:
        registry: dict[str, common_module.ToolHandler] = {}
        tool = internal_tools._serializing_tool_decorator(_capturing_tool_decorator(registry))
        first_entered = asyncio.Event()
        first_release = asyncio.Event()
        second_attempted = asyncio.Event()
        second_entered = asyncio.Event()
        revision = {"value": 0}
        first_observation: dict[str, int] = {}

        async def first_handler(_args: dict[str, Any]) -> dict[str, Any]:
            first_observation["start_revision"] = revision["value"]
            first_entered.set()
            await first_release.wait()
            first_observation["end_revision"] = revision["value"]
            return {"first": True}

        async def second_handler(_args: dict[str, Any]) -> dict[str, Any]:
            second_entered.set()
            revision["value"] += 1
            return {"second": True}

        tool("inspect_browser", "first", {})(first_handler)
        tool("apply_locator_heal", "second", {})(second_handler)
        first = registry["inspect_browser"]
        second = registry["apply_locator_heal"]

        first_task = asyncio.create_task(first({}))
        await first_entered.wait()

        async def invoke_second() -> dict[str, Any]:
            second_attempted.set()
            return await second({})

        second_task = asyncio.create_task(invoke_second())
        await second_attempted.wait()

        # second_attempted is set immediately before awaiting the wrapped second
        # handler. The same task then reaches the shared lock without another
        # suspension point, so this assertion proves it is queued behind the first
        # handler rather than allowed to mutate the shared revision concurrently.
        assert not second_entered.is_set()
        assert revision["value"] == 0

        first_release.set()
        first_result, second_result = await asyncio.gather(first_task, second_task)

        assert first_result == {"first": True}
        assert second_result == {"second": True}
        assert first_observation == {"start_revision": 0, "end_revision": 0}
        assert revision["value"] == 1
        assert second_entered.is_set()

    asyncio.run(scenario())


def test_cancelled_internal_tool_releases_serialization_authority() -> None:
    async def scenario() -> None:
        registry: dict[str, common_module.ToolHandler] = {}
        tool = internal_tools._serializing_tool_decorator(_capturing_tool_decorator(registry))
        first_entered = asyncio.Event()
        first_hold = asyncio.Event()
        second_attempted = asyncio.Event()
        second_entered = asyncio.Event()

        async def first_handler(_args: dict[str, Any]) -> dict[str, Any]:
            first_entered.set()
            await first_hold.wait()
            return {"first": True}

        async def second_handler(_args: dict[str, Any]) -> dict[str, Any]:
            second_entered.set()
            return {"second": True}

        tool("probe_api", "first", {})(first_handler)
        tool("inspect_repository", "second", {})(second_handler)
        first = registry["probe_api"]
        second = registry["inspect_repository"]

        first_task = asyncio.create_task(first({}))
        await first_entered.wait()

        async def invoke_second() -> dict[str, Any]:
            second_attempted.set()
            return await second({})

        second_task = asyncio.create_task(invoke_second())
        await second_attempted.wait()
        assert not second_entered.is_set()

        first_task.cancel()
        try:
            await first_task
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("cancelled serialized tool unexpectedly completed")

        assert await second_task == {"second": True}
        assert second_entered.is_set()

    asyncio.run(scenario())

from __future__ import annotations

import json
from typing import Any

from ...tools.api_testing import ApiProbe, ApiProbeTransportError
from .common import RuntimeServices, ToolDecorator


def register_network_tools(
    services: RuntimeServices,
    tool: ToolDecorator,
    *,
    api_probe_cls: Any = ApiProbe,
) -> dict[str, Any]:
    @tool(
        "probe_api",
        "Make one policy-approved read-only HTTP observation and register sanitized "
        "response evidence.",
        {"method": str, "url": str},
    )
    async def probe_api(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("probe_api", args)
        method_decision = services.policy.authorize_api_method(
            args["method"],
            url=args["url"],
        )
        services.state.policy_decisions.append(method_decision)
        if method_decision.decision.value != "ALLOW":
            services.checkpoint()
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"DENIED {method_decision.rule_id}: {method_decision.reason}",
                    }
                ],
                "is_error": True,
            }
        allow_hosts = services.network_hosts(args["url"])
        try:
            result = await api_probe_cls(
                services.evidence,
                allow_hosts=allow_hosts,
                external_egress_enforced=getattr(
                    services, "api_browser_external_egress_enforced", False
                ),
            ).request(args["method"], args["url"])
        except ApiProbeTransportError as exc:
            if exc.evidence_id not in services.state.evidence_ids:
                services.state.evidence_ids.append(exc.evidence_id)
            services.checkpoint()
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "NETWORK_ERROR",
                                "error": str(exc),
                                "evidence_id": exc.evidence_id,
                            }
                        ),
                    }
                ],
                "is_error": True,
            }
        services.state.evidence_ids.append(result.evidence_id)
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "status_code": result.status_code,
                            "elapsed_ms": result.elapsed_ms,
                            "evidence_id": result.evidence_id,
                            "body": result.body,
                            "truncated": result.truncated,
                        },
                        default=str,
                    )[:12000],
                }
            ]
        }

    return {"probe_api": probe_api}

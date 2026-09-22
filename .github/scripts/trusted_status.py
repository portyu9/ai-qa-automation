from __future__ import annotations

import re
from typing import Any

TRUSTED_STATUS_CONTEXT = "Trusted PR Gate"
TRUSTED_STATUS_BOT_LOGIN = "trusted-pr-gate[bot]"
TRUSTED_STATUS_BOT_ID = 322661847
TRUSTED_STATUS_DESCRIPTION = "Automatic exact-subject trusted validation passed"
TARGET_URL_RE = re.compile(
    r"^https://github\.com/portyu9/ai-qa-automation/actions/runs/[1-9][0-9]*$"
)


class TrustedStatusError(RuntimeError):
    """The exact dedicated-App terminal status is absent or invalid."""


def require_automatic_trusted_gate(api: Any, head_sha: str) -> dict[str, Any]:
    rows = api.list_all(f"/commits/{head_sha}/statuses", max_pages=4)
    matches: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("context") != TRUSTED_STATUS_CONTEXT:
            continue
        creator = row.get("creator") or {}
        if (
            creator.get("login") != TRUSTED_STATUS_BOT_LOGIN
            or creator.get("id") != TRUSTED_STATUS_BOT_ID
            or creator.get("type") != "Bot"
        ):
            continue
        status_id = row.get("id")
        if isinstance(status_id, bool) or not isinstance(status_id, int) or status_id < 1:
            raise TrustedStatusError("Trusted PR Gate status has an invalid id")
        matches.append(row)
    if not matches:
        raise TrustedStatusError("automatic Trusted PR Gate status has not registered")
    latest = max(matches, key=lambda row: int(row["id"]))
    if latest.get("state") != "success":
        raise TrustedStatusError(
            f"automatic Trusted PR Gate is not green: {latest.get('state')}"
        )
    if latest.get("description") != TRUSTED_STATUS_DESCRIPTION:
        raise TrustedStatusError(
            "automatic Trusted PR Gate description does not match reviewed authority"
        )
    target_url = latest.get("target_url")
    if not isinstance(target_url, str) or TARGET_URL_RE.fullmatch(target_url) is None:
        raise TrustedStatusError(
            "automatic Trusted PR Gate target URL is not an exact Actions run"
        )
    return latest

from __future__ import annotations

import pytest

from ai_qa_automation.agent import _may_recompute_terminal_outcome
from ai_qa_automation.models import TerminalStatus


@pytest.mark.parametrize("status", [None, TerminalStatus.SUCCESS])
def test_terminal_outcome_recomputation_allows_only_unset_or_candidate_success(
    status: TerminalStatus | None,
) -> None:
    assert _may_recompute_terminal_outcome(status) is True


@pytest.mark.parametrize(
    "status",
    [status for status in TerminalStatus if status is not TerminalStatus.SUCCESS],
    ids=lambda status: status.value,
)
def test_every_non_success_terminal_truth_is_latched(status: TerminalStatus) -> None:
    assert _may_recompute_terminal_outcome(status) is False


def test_workspace_freshness_infrastructure_failure_cannot_be_promoted() -> None:
    assert (
        _may_recompute_terminal_outcome(TerminalStatus.INFRASTRUCTURE_FAILURE)
        is False
    )

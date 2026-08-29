from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import scripts.validate_mermaid as mermaid


def test_validate_mermaid_direct_entrypoint_loads_siblings_with_python_safe_path(
    tmp_path: Path,
) -> None:
    for name in mermaid.PUBLIC_ROOT_MARKDOWN:
        (tmp_path / name).write_text("plain documentation\n", encoding="utf-8")

    env = os.environ.copy()
    env["PYTHONSAFEPATH"] = "1"
    env.pop("GITHUB_ACTIONS", None)
    env.pop("CI_SUBJECT_SHA", None)
    env.pop("GITHUB_SHA", None)

    completed = subprocess.run(
        [sys.executable, str(Path(mermaid.__file__).resolve())],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )

    assert completed.returncode != 0
    assert "modulenotfounderror" not in completed.stderr.lower()
    assert "docs" in completed.stderr.lower()

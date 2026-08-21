from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

_SAFE_INHERITED_ENV = {
    "PATH",
    "VIRTUAL_ENV",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "CI",
}


def restricted_subprocess_env(
    *,
    home: Path,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a minimal subprocess environment without inheriting credentials by default."""
    home = home.expanduser().resolve()
    home.mkdir(parents=True, exist_ok=True)
    env = {key: value for key, value in os.environ.items() if key in _SAFE_INHERITED_ENV}
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "PIP_CONFIG_FILE": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
        }
    )
    if extra:
        env.update({str(key): str(value) for key, value in extra.items()})
    return env

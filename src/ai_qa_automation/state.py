from __future__ import annotations

import os
import tempfile
import threading
from pathlib import Path

from pydantic import BaseModel

from .io_safety import (
    JsonSerializationBoundsError,
    fsync_directory,
    iter_json_text_bounded,
    json_preflight_scalar_default,
    parse_json_object_strict,
    read_text_bounded,
)
from .models import AgentRunState

_MAX_STATE_BYTES = 16_000_000


class _StateFieldValue:
    __slots__ = ("model", "name")

    def __init__(self, model: BaseModel, name: str) -> None:
        self.model = model
        self.name = name


def _state_model_proxy(model: BaseModel) -> dict[str, _StateFieldValue]:
    return {name: _StateFieldValue(model, name) for name in type(model).model_fields}


def _state_json_default(value: object) -> object:
    if isinstance(value, _StateFieldValue):
        payload = value.model.model_dump(include={value.name}, mode="json")
        return payload[value.name]
    if isinstance(value, BaseModel):
        return _state_model_proxy(value)
    raise TypeError(f"unsupported canonical state value: {type(value).__name__}")


def _state_json_preflight_default(value: object) -> object:
    if isinstance(value, _StateFieldValue):
        return getattr(value.model, value.name)
    if isinstance(value, BaseModel):
        return _state_model_proxy(value)
    return json_preflight_scalar_default(value)


class StateStore:
    """Canonical run state persisted independently from conversational context."""

    def __init__(self, path: Path) -> None:
        requested = path.expanduser()
        if requested.is_symlink():
            raise ValueError("state path is a symlink and has ambiguous ownership")
        raw_parent = requested.parent
        if raw_parent.is_symlink():
            raise ValueError("state directory is a symlink and has ambiguous ownership")
        parent_existed = raw_parent.exists()
        raw_parent.mkdir(parents=True, exist_ok=True)
        if raw_parent.is_symlink():
            raise ValueError("state directory became a symlink")
        if not parent_existed:
            fsync_directory(raw_parent.resolve().parent)
        self.path = raw_parent.resolve() / requested.name
        self._lock = threading.RLock()
        self._assert_owned()

    def _assert_owned(self) -> None:
        if self.path.parent.is_symlink():
            raise ValueError("state directory is a symlink and has ambiguous ownership")
        if self.path.is_symlink():
            raise ValueError("state path is a symlink and has ambiguous ownership")

    def save(self, state: AgentRunState) -> None:
        with self._lock:
            self._assert_owned()
            payload = _state_model_proxy(state)
            handle, raw_temp = tempfile.mkstemp(
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                text=True,
            )
            temp = Path(raw_temp)
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as stream:
                    try:
                        for chunk in iter_json_text_bounded(
                            payload,
                            max_bytes=_MAX_STATE_BYTES,
                            label="canonical state",
                            indent=2,
                            default=_state_json_default,
                            preflight_default=_state_json_preflight_default,
                        ):
                            stream.write(chunk)
                    except JsonSerializationBoundsError as exc:
                        if exc.code == "bytes":
                            raise ValueError(
                                "canonical state exceeds persistence size bound"
                            ) from exc
                        raise ValueError(
                            f"canonical state violates persistence serialization bound: {exc.code}"
                        ) from exc
                    stream.flush()
                    os.fsync(stream.fileno())
                self._assert_owned()
                temp.replace(self.path)
                fsync_directory(self.path.parent)
            finally:
                temp.unlink(missing_ok=True)

    def load(self) -> AgentRunState:
        with self._lock:
            self._assert_owned()
            rendered = read_text_bounded(
                self.path,
                max_bytes=_MAX_STATE_BYTES,
                label="canonical state",
            )
            # Parse once with the repository's ambiguity guard before schema validation.
            # Pydantic's JSON parser does not own duplicate-key policy; strict JSON-mode
            # validation then prevents string/number/boolean coercion in authority fields
            # while still accepting the JSON representations of enums and datetimes.
            parse_json_object_strict(rendered, label="canonical state")
            return AgentRunState.model_validate_json(rendered, strict=True)

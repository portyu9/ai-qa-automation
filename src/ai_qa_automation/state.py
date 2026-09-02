from __future__ import annotations

import os
import stat
import tempfile
import threading
from pathlib import Path

from pydantic import BaseModel

from .fs_authority import (
    atomic_write_bytes_confined,
    descriptor_relative_authority_supported,
    pin_directory_identity,
    read_bytes_confined,
)
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


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


class StateStore:
    """Canonical run state persisted independently from conversational context."""

    def __init__(
        self,
        path: Path,
        *,
        expected_parent_identity: tuple[int, int] | None = None,
    ) -> None:
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
        parent_status = self.path.parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent_status.st_mode):
            raise ValueError("state directory must remain a regular directory")
        self._descriptor_relative_parent = descriptor_relative_authority_supported()
        self._parent_identity = (
            pin_directory_identity(self.path.parent, label="state directory")
            if self._descriptor_relative_parent
            else _identity(parent_status)
        )
        if (
            expected_parent_identity is not None
            and self._parent_identity != expected_parent_identity
        ):
            raise ValueError("state directory does not match authorized run persistence root")
        self._lock = threading.RLock()
        self._assert_owned()

    @property
    def parent_identity(self) -> tuple[int, int] | None:
        """Return enforceable run-root identity, or ``None`` on the fallback path."""

        return self._parent_identity if self._descriptor_relative_parent else None

    def _revalidate_parent(self) -> None:
        try:
            current = self.path.parent.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError("state directory changed identity and ownership is ambiguous") from exc
        if not stat.S_ISDIR(current.st_mode) or _identity(current) != self._parent_identity:
            raise ValueError("state directory changed identity and ownership is ambiguous")

    def _assert_owned(self) -> None:
        self._revalidate_parent()
        if self.path.parent.is_symlink():
            raise ValueError("state directory is a symlink and has ambiguous ownership")
        if self.path.is_symlink():
            raise ValueError("state path is a symlink and has ambiguous ownership")

    @staticmethod
    def _render(state: AgentRunState) -> bytes:
        payload = _state_model_proxy(state)
        chunks: list[bytes] = []
        try:
            for chunk in iter_json_text_bounded(
                payload,
                max_bytes=_MAX_STATE_BYTES,
                label="canonical state",
                indent=2,
                default=_state_json_default,
                preflight_default=_state_json_preflight_default,
            ):
                chunks.append(chunk.encode("utf-8"))
        except JsonSerializationBoundsError as exc:
            if exc.code == "bytes":
                raise ValueError("canonical state exceeds persistence size bound") from exc
            raise ValueError(
                f"canonical state violates persistence serialization bound: {exc.code}"
            ) from exc
        return b"".join(chunks)

    def save(self, state: AgentRunState) -> None:
        with self._lock:
            self._assert_owned()
            rendered = self._render(state)
            if self._descriptor_relative_parent:
                atomic_write_bytes_confined(
                    self.path.parent,
                    self.path.name,
                    rendered,
                    create_parents=False,
                    create_only=False,
                    label="canonical state",
                    expected_root_identity=self._parent_identity,
                )
                self._revalidate_parent()
                return

            handle, raw_temp = tempfile.mkstemp(
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                text=False,
            )
            temp = Path(raw_temp)
            try:
                with os.fdopen(handle, "wb") as stream:
                    stream.write(rendered)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._assert_owned()
                temp.replace(self.path)
                fsync_directory(self.path.parent)
                self._revalidate_parent()
            finally:
                temp.unlink(missing_ok=True)

    def load(self) -> AgentRunState:
        with self._lock:
            self._assert_owned()
            if self._descriptor_relative_parent:
                raw = read_bytes_confined(
                    self.path.parent,
                    self.path.name,
                    max_bytes=_MAX_STATE_BYTES,
                    label="canonical state",
                    expected_root_identity=self._parent_identity,
                )
                rendered = raw.decode("utf-8")
                self._revalidate_parent()
            else:
                rendered = read_text_bounded(
                    self.path,
                    max_bytes=_MAX_STATE_BYTES,
                    label="canonical state",
                )
                self._revalidate_parent()
            # Parse once with the repository's ambiguity guard before schema validation.
            # Pydantic's JSON parser does not own duplicate-key policy; strict JSON-mode
            # validation then prevents string/number/boolean coercion in authority fields
            # while still accepting the JSON representations of enums and datetimes.
            parse_json_object_strict(rendered, label="canonical state")
            return AgentRunState.model_validate_json(rendered, strict=True)

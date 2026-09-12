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


def _claim_child_directory(
    root: Path,
    name: str,
    *,
    label: str,
    expected_root_identity: tuple[int, int] | None,
) -> tuple[int, int] | None:
    """Create one direct child directory without replacement under pinned root authority."""

    if not name or name in {".", ".."} or Path(name).name != name:
        raise ValueError(f"{label} must be one direct child directory")

    root = root.expanduser().absolute()
    if not descriptor_relative_authority_supported():
        (root / name).mkdir(exist_ok=False)
        fsync_directory(root)
        return None

    if expected_root_identity is None:
        raise RuntimeError(f"{label} requires pinned persistence-root identity")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root_fd = os.open(root, directory_flags)
    except OSError as exc:
        raise ValueError(f"{label} persistence root could not be opened safely") from exc

    child_fd = -1
    try:
        opened_root = os.fstat(root_fd)
        current_root = root.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or not stat.S_ISDIR(current_root.st_mode)
            or _identity(opened_root) != expected_root_identity
            or _identity(current_root) != expected_root_identity
        ):
            raise ValueError(f"{label} persistence root changed identity before run-root claim")

        os.mkdir(name, 0o755, dir_fd=root_fd)
        os.fsync(root_fd)
        try:
            child_fd = os.open(name, directory_flags, dir_fd=root_fd)
        except OSError as exc:
            raise ValueError(f"{label} could not be opened safely after claim") from exc

        opened_child = os.fstat(child_fd)
        current_child = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        child_identity = _identity(opened_child)
        if (
            not stat.S_ISDIR(opened_child.st_mode)
            or not stat.S_ISDIR(current_child.st_mode)
            or _identity(current_child) != child_identity
        ):
            raise ValueError(f"{label} changed identity during run-root claim")

        current_root = root.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(current_root.st_mode)
            or _identity(current_root) != expected_root_identity
        ):
            raise ValueError(f"{label} persistence root changed identity during run-root claim")
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        os.close(root_fd)

    try:
        current_child_identity = pin_directory_identity(root / name, label=label)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{label} could not be revalidated after run-root claim") from exc
    if current_child_identity != child_identity:
        raise ValueError(f"{label} changed identity after run-root claim")
    return child_identity


class StateStore:
    """Canonical run state persisted independently from conversational context."""

    def __init__(
        self,
        path: Path,
        *,
        expected_parent_identity: tuple[int, int] | None = None,
        claim_parent_exclusively: bool = False,
    ) -> None:
        requested = path.expanduser()
        if requested.is_symlink():
            raise ValueError("state path is a symlink and has ambiguous ownership")
        raw_parent = requested.parent
        if raw_parent.is_symlink():
            raise ValueError("state directory is a symlink and has ambiguous ownership")

        parent_created = False
        claimed_parent_identity: tuple[int, int] | None = None
        if claim_parent_exclusively:
            raw_persistence_root = raw_parent.parent
            if raw_persistence_root.is_symlink():
                raise ValueError("state persistence root is a symlink and has ambiguous ownership")
            persistence_root_existed = raw_persistence_root.exists()
            raw_persistence_root.mkdir(parents=True, exist_ok=True)
            if raw_persistence_root.is_symlink():
                raise ValueError("state persistence root became a symlink")
            if not raw_persistence_root.is_dir():
                raise ValueError("state persistence root must remain a regular directory")
            persistence_root = raw_persistence_root.resolve()
            if not persistence_root_existed:
                fsync_directory(persistence_root.parent)
            persistence_root_identity = (
                pin_directory_identity(persistence_root, label="state persistence root")
                if descriptor_relative_authority_supported()
                else None
            )

            if not raw_parent.exists():
                try:
                    # The final run-root component is the allocation boundary. Keep shared
                    # artifact-root creation separate, then create exactly this child relative
                    # to pinned persistence-root authority without replacement.
                    claimed_parent_identity = _claim_child_directory(
                        persistence_root,
                        raw_parent.name,
                        label="state directory",
                        expected_root_identity=persistence_root_identity,
                    )
                    parent_created = True
                except FileExistsError:
                    parent_created = False
        else:
            parent_existed = raw_parent.exists()
            raw_parent.mkdir(parents=True, exist_ok=True)
            if not parent_existed:
                fsync_directory(raw_parent.resolve().parent)

        if raw_parent.is_symlink():
            raise ValueError("state directory became a symlink")
        if not raw_parent.is_dir():
            raise ValueError("state directory must remain a regular directory")

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
        if claimed_parent_identity is not None and self._parent_identity != claimed_parent_identity:
            raise ValueError("state directory changed identity after exclusive run-root claim")
        if (
            expected_parent_identity is not None
            and self._parent_identity != expected_parent_identity
        ):
            raise ValueError("state directory does not match authorized run persistence root")
        self._lock = threading.RLock()
        self._claim_parent_exclusively = claim_parent_exclusively
        self._exclusive_parent_owned = parent_created
        self._state_bound = False
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

    def _save_initial_fallback(self, rendered: bytes) -> None:
        handle, raw_temp = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            text=False,
        )
        temp = Path(raw_temp)
        try:
            offset = 0
            while offset < len(rendered):
                written = os.write(handle, rendered[offset:])
                if written <= 0:
                    raise OSError("initial canonical state write made no forward progress")
                offset += written
            os.fsync(handle)
            os.close(handle)
            handle = -1
            self._assert_owned()
            os.link(temp, self.path)
            fsync_directory(self.path.parent)
            self._revalidate_parent()
        finally:
            if handle >= 0:
                os.close(handle)
            temp.unlink(missing_ok=True)

    def _reconcile_publication(self, rendered: bytes) -> bool:
        """Prove one ambiguous replacement publication without replaying the state write."""

        if not self._descriptor_relative_parent:
            return False
        expected_parent_identity = self._parent_identity
        try:
            observed = read_bytes_confined(
                self.path.parent,
                self.path.name,
                max_bytes=_MAX_STATE_BYTES,
                label="canonical state reconciliation",
                expected_root_identity=expected_parent_identity,
            )
            if observed != rendered:
                return False

            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory_fd = os.open(self.path.parent, directory_flags)
            try:
                opened = os.fstat(directory_fd)
                if _identity(opened) != expected_parent_identity:
                    return False
                # The canonical state write is never replayed. A fresh fsync on
                # the pinned directory closes rename/fsync ambiguity only after
                # the exact attempted bytes are observed at the authorized path.
                os.fsync(directory_fd)
                if (
                    pin_directory_identity(
                        self.path.parent,
                        label="canonical state reconciliation directory",
                    )
                    != expected_parent_identity
                ):
                    return False
                final_observed = read_bytes_confined(
                    self.path.parent,
                    self.path.name,
                    max_bytes=_MAX_STATE_BYTES,
                    label="canonical state reconciliation",
                    expected_root_identity=expected_parent_identity,
                )
                pinned = os.fstat(directory_fd)
                if _identity(pinned) != expected_parent_identity:
                    return False
            finally:
                os.close(directory_fd)
        except (OSError, RuntimeError, ValueError):
            return False
        return final_observed == rendered

    def save(self, state: AgentRunState) -> None:
        with self._lock:
            self._assert_owned()
            if self._claim_parent_exclusively and not self._exclusive_parent_owned:
                raise FileExistsError(
                    "run persistence root was not freshly claimed; existing canonical state "
                    "cannot be adopted by a new-run store"
                )

            rendered = self._render(state)
            initial_write = not self._state_bound
            create_only = self._claim_parent_exclusively and initial_write
            if self._descriptor_relative_parent:
                try:
                    atomic_write_bytes_confined(
                        self.path.parent,
                        self.path.name,
                        rendered,
                        create_parents=False,
                        create_only=create_only,
                        label="canonical state",
                        expected_root_identity=self._parent_identity,
                    )
                    self._revalidate_parent()
                except (OSError, RuntimeError, ValueError):
                    if create_only or not self._reconcile_publication(rendered):
                        raise
                self._state_bound = True
                return

            if create_only:
                self._save_initial_fallback(rendered)
                self._state_bound = True
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
            self._state_bound = True

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
            state = AgentRunState.model_validate_json(rendered, strict=True)
            self._state_bound = True
            return state

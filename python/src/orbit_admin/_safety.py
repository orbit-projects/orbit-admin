# Copyright 2026-present Orbit Contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Small internal helpers for protecting immutable Core model boundaries."""

from __future__ import annotations

import math
from collections.abc import Mapping
from copy import deepcopy
from typing import Any, cast

MAX_ADMIN_OPERATIONS = 1_000_000


def is_finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


_MAX_FREEZE_DEPTH = 64
_MAX_FREEZE_ITEMS = 100_000


def _validate_structured_key(key: object) -> str:
    """Return one safe JSON-object key or reject unsafe nested mapping structure.

    Top-level model fields validate their own cardinality limits before calling the freezer, but
    nested mappings reach diagnostics, events, and JSON serialization through this shared path.
    Applying the same key-shape rule here prevents a nested byte or control-bearing key from
    bypassing the public mapping boundary.
    """
    if (
        not isinstance(key, str)
        or not 1 <= len(key) <= 255
        or any(ord(character) < 32 or ord(character) == 127 for character in key)
    ):
        raise ValueError(
            "Structured mapping keys must be nonempty strings of at most 255 printable characters."
        )
    return key


class FrozenDict(dict[str, Any]):
    """A dict-compatible mapping that rejects all in-place mutation.

    A dict subclass is used instead of ``MappingProxyType`` so Pydantic can
    continue to serialize structured values as ordinary JSON objects. Values are frozen
    recursively by :func:`freeze_value` before they are placed in this type.
    """

    def _immutable(self) -> None:
        raise TypeError("This mapping is immutable.")

    def __copy__(self) -> FrozenDict:
        """Return an immutable shallow copy without invoking blocked mutators."""
        copied = dict.__new__(FrozenDict)
        for key, value in self.items():
            dict.__setitem__(copied, key, value)
        return copied

    def __deepcopy__(self, memo: dict[int, Any]) -> FrozenDict:
        """Return an immutable recursive copy compatible with Pydantic snapshots."""
        existing = memo.get(id(self))
        if isinstance(existing, FrozenDict):
            return existing
        copied = dict.__new__(FrozenDict)
        memo[id(self)] = copied
        for key, value in self.items():
            dict.__setitem__(copied, deepcopy(key, memo), deepcopy(value, memo))
        return copied

    def __delitem__(self, key: str) -> None:
        """Reject deletion of a claim."""
        self._immutable()

    def __ior__(self, value: Any) -> FrozenDict:  # type: ignore[override,misc]
        """Reject in-place union updates."""
        self._immutable()
        return self

    def __setitem__(self, key: str, value: Any) -> None:
        """Reject assignment of a claim."""
        self._immutable()

    def clear(self) -> None:
        """Reject removal of all claims."""
        self._immutable()

    def pop(self, key: str, default: Any = None) -> Any:
        """Reject removal of a claim."""
        self._immutable()
        return default

    def popitem(self) -> tuple[str, Any]:
        """Reject removal of an arbitrary claim."""
        self._immutable()
        return ("", None)

    def setdefault(self, key: str, default: Any = None) -> Any:
        """Reject insertion of a default claim."""
        self._immutable()
        return default

    def update(self, *args: Any, **kwargs: Any) -> None:
        """Reject bulk claim updates."""
        self._immutable()


def freeze_value(value: Any) -> Any:
    """Return a recursively protected copy of common mutable containers.

    Claims are provider-defined, so Core deliberately does not restrict every
    possible scalar value. Unknown values are deep-copied to prevent callers
    from retaining and mutating the original object after model creation. Structured
    containers have a depth and total-item budget; cycles are rejected instead of
    becoming an unbounded recursion or a partially mutable retained value.
    """

    return _freeze_value(
        value,
        active=set(),
        item_count=[0],
        depth=0,
        validate_mapping_keys=False,
    )


def _freeze_value(
    value: Any,
    *,
    active: set[int],
    item_count: list[int],
    depth: int,
    validate_mapping_keys: bool,
) -> Any:
    """Freeze one value while tracking the current container path and total work."""

    item_count[0] += 1
    if item_count[0] > _MAX_FREEZE_ITEMS:
        raise ValueError(f"Structured values cannot exceed {_MAX_FREEZE_ITEMS:,} items.")
    if not isinstance(value, (Mapping, list, tuple, set, frozenset)):
        return deepcopy(value)
    if depth >= _MAX_FREEZE_DEPTH:
        raise ValueError(f"Structured values cannot be nested beyond {_MAX_FREEZE_DEPTH} levels.")
    identity = id(value)
    if identity in active:
        raise ValueError("Structured values cannot contain cyclic references.")
    active.add(identity)
    try:
        if isinstance(value, Mapping):
            return FrozenDict(
                {
                    (
                        _validate_structured_key(key) if validate_mapping_keys else key
                    ): _freeze_value(
                        item,
                        active=active,
                        item_count=item_count,
                        depth=depth + 1,
                        validate_mapping_keys=validate_mapping_keys,
                    )
                    for key, item in value.items()
                }
            )
        if isinstance(value, (list, tuple)):
            return tuple(
                _freeze_value(
                    item,
                    active=active,
                    item_count=item_count,
                    depth=depth + 1,
                    validate_mapping_keys=validate_mapping_keys,
                )
                for item in value
            )
        return frozenset(
            _freeze_value(
                item,
                active=active,
                item_count=item_count,
                depth=depth + 1,
                validate_mapping_keys=validate_mapping_keys,
            )
            for item in value
        )
    finally:
        active.remove(identity)


def freeze_mapping(value: dict[str, Any]) -> FrozenDict:
    """Return a recursively protected copy of a JSON-shaped string-keyed mapping."""

    return cast(
        FrozenDict,
        _freeze_value(
            value,
            active=set(),
            item_count=[0],
            depth=0,
            validate_mapping_keys=True,
        ),
    )


def validate_mapping(
    value: object,
    *,
    name: str,
    max_entries: int = 2_048,
    max_key_length: int = 255,
) -> dict[str, Any]:
    """Validate bounded printable keys for a retained structured mapping.

    Core leaves mapping values open-ended so services and providers can attach
    domain-specific JSON data. Keys and cardinality are still constrained at
    the model boundary to keep diagnostics, events, and errors inspectable and
    resistant to accidental or malicious resource growth.
    """
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping.")
    # Walk the source incrementally: a custom Mapping may misreport its length, so copying it
    # with dict(value) before checking the limit would allow avoidable unbounded materialization.
    mapping: dict[str, Any] = {}
    for item_count, (key, item) in enumerate(value.items(), start=1):
        if item_count > max_entries:
            raise ValueError(f"{name} cannot contain more than {max_entries:,} entries.")
        if (
            not isinstance(key, str)
            or not 1 <= len(key) <= max_key_length
            or any(ord(character) < 32 or ord(character) == 127 for character in key)
        ):
            raise ValueError(
                f"{name} keys must be nonempty strings of at most "
                f"{max_key_length} printable characters."
            )
        mapping[key] = item
    return mapping


__all__ = ["FrozenDict", "freeze_mapping", "freeze_value", "validate_mapping"]

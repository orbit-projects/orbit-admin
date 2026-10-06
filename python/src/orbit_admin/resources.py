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
"""Explicitly allowlisted, typed repository resources for the Orbit Admin CRUD API."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, cast

from orbit_data import Repository
from orbit_sql import SQLDatabase, SQLRepository, SQLValue
from pydantic import BaseModel, TypeAdapter

EntityT = TypeVar("EntityT", bound=BaseModel)
KeyT = TypeVar("KeyT")
UpdateKeyT = TypeVar("UpdateKeyT")
UpdateEntityT = TypeVar("UpdateEntityT", bound=BaseModel)
_RESOURCE_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
AtomicUpdate = Callable[[UpdateKeyT, Mapping[str, Any]], Awaitable[UpdateEntityT | None]]


@dataclass(frozen=True, slots=True)
class AdminResource(Generic[EntityT, KeyT]):
    """Bind one Pydantic entity to a repository and explicit field-level permissions.

    ``read_fields`` controls response serialization. Create/update field sets are separate
    allowlists; model fields such as passwords or internal flags are never exposed or writable
    unless the application names them explicitly. Deletion is disabled by default.
    """

    name: str
    model: type[EntityT]
    repository: Repository[EntityT, KeyT]
    key_field: str
    read_fields: frozenset[str]
    create_fields: frozenset[str] = frozenset()
    update_fields: frozenset[str] = frozenset()
    update_handler: AtomicUpdate[KeyT, EntityT] | None = None
    allow_delete: bool = False

    def __post_init__(self) -> None:
        """Validate resource identity, model schema, repository surface, and field allowlists."""
        if not isinstance(self.name, str) or _RESOURCE_NAME.fullmatch(self.name) is None:
            raise ValueError("Admin resource names must be lowercase slugs.")
        if not isinstance(self.model, type) or not issubclass(self.model, BaseModel):
            raise TypeError("Admin resources require a Pydantic model class.")
        if not isinstance(self.repository, Repository):
            raise TypeError("Admin resources require an orbit-data Repository.")
        if self.key_field not in self.model.model_fields:
            raise ValueError("key_field must name a field on the resource model.")
        fields = frozenset(self.model.model_fields)
        for name, values in (
            ("read_fields", self.read_fields),
            ("create_fields", self.create_fields),
            ("update_fields", self.update_fields),
        ):
            if isinstance(values, (str, bytes)) or not isinstance(values, (set, frozenset)):
                raise TypeError(f"{name} must be a set or frozenset of model field names.")
            if not values <= fields:
                raise ValueError(f"{name} contains fields not declared by the resource model.")
        if not self.read_fields:
            raise ValueError("read_fields must expose at least one field.")
        if self.key_field in self.update_fields:
            raise ValueError("Resource keys cannot be changed through the Admin API.")
        if self.update_fields and not callable(self.update_handler):
            raise ValueError(
                "Writable update_fields require an application-supplied atomic update_handler."
            )
        if self.update_handler is not None and not self.update_fields:
            raise ValueError("update_handler requires a non-empty update_fields allowlist.")
        if not isinstance(self.allow_delete, bool):
            raise TypeError("allow_delete must be a boolean.")

    def parse_key(self, value: str) -> KeyT:
        """Validate one bounded URL key using the Pydantic field's declared type."""
        annotation = self.model.model_fields[self.key_field].annotation
        return cast(KeyT, TypeAdapter(annotation).validate_python(value))

    def serialize(self, entity: EntityT) -> dict[str, object]:
        """Return only the resource's declared readable fields in JSON-compatible form."""
        if not isinstance(entity, self.model):
            raise TypeError("Repository returned an entity of the wrong model type.")
        return cast(
            dict[str, object], entity.model_dump(mode="json", include=set(self.read_fields))
        )


def sql_resource(
    name: str,
    database: SQLDatabase,
    model: type[EntityT],
    *,
    table: str,
    key_field: str,
    read_fields: frozenset[str],
    create_fields: frozenset[str] = frozenset(),
    update_fields: frozenset[str] = frozenset(),
    update_handler: AtomicUpdate[SQLValue, EntityT] | None = None,
    allow_delete: bool = False,
) -> AdminResource[EntityT, SQLValue]:
    """Create an Admin resource backed by Orbit's validated asynchronous SQL repository."""
    if not isinstance(database, SQLDatabase):
        raise TypeError("database must implement the orbit-sql SQLDatabase contract.")
    repository = SQLRepository(database, model, table=table, primary_key=key_field)
    return AdminResource(
        name=name,
        model=model,
        repository=repository,
        key_field=key_field,
        read_fields=read_fields,
        create_fields=create_fields,
        update_fields=update_fields,
        update_handler=update_handler,
        allow_delete=allow_delete,
    )


__all__ = ["AdminResource", "sql_resource"]

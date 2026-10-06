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
"""Core plugin exposing explicit repository CRUD routes with deny-by-default role metadata."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any

from orbit import Application
from orbit.asgi import Request, Response
from orbit.asgi.request import HTTPError
from orbit.plugins import Plugin, PluginMetadata
from orbit_data import RepositoryConflictError

from orbit_admin.audit import AdminAuditLog, AdminAuditSink
from orbit_admin.resources import AdminResource

_READ = frozenset({"orbit.admin.read"})
_WRITE = frozenset({"orbit.admin.write"})
_MAX_PAGE_SIZE = 100
_MAX_KEY_CHARS = 255
_MAX_WRITE_BODY_BYTES = 1_048_576
_MAX_RESPONSE_BYTES = 2_097_152


class AdminPlugin(Plugin):
    """Register authenticated CRUD routes for explicitly declared application resources.

    Core passes bounded route-role metadata to the explicitly configured ``RouteAuthorizer`` after
    authentication. No resource is discovered from a database schema or imported implicitly.
    Mutating routes are registered only when their resource enables the corresponding operation.
    """

    metadata = PluginMetadata(
        name="orbit-admin-python",
        version="0.1.0a1",
        capabilities=frozenset({"admin.repository-crud"}),
    )

    def __init__(
        self,
        resources: Sequence[AdminResource[Any, Any]],
        *,
        prefix: str = "/admin-api/v1",
        audit_log: AdminAuditSink | None = None,
        operations: bool = True,
    ) -> None:
        """Capture a unique, immutable resource registry and a validated route prefix."""
        if isinstance(resources, (str, bytes)) or not isinstance(resources, Sequence):
            raise TypeError("Admin resources must be a sequence of AdminResource objects.")
        if not resources or any(not isinstance(item, AdminResource) for item in resources):
            raise ValueError("AdminPlugin requires at least one AdminResource.")
        detached = tuple(resources)
        names = tuple(item.name for item in detached)
        if len(names) != len(set(names)):
            raise ValueError("Admin resource names must be unique.")
        if (
            not isinstance(prefix, str)
            or not prefix.startswith("/")
            or prefix == "/"
            or prefix.endswith("/")
            or "//" in prefix
            or any(part in {".", ".."} for part in prefix.split("/"))
            or len(prefix.encode("utf-8")) > 256
        ):
            raise ValueError("Admin API prefix must be a bounded canonical absolute path.")
        self._resources = MappingProxyType({item.name: item for item in detached})
        self._prefix = prefix
        if audit_log is not None and not isinstance(audit_log, AdminAuditSink):
            raise TypeError("audit_log must implement the asynchronous AdminAuditSink contract.")
        self.audit_log: AdminAuditSink = AdminAuditLog() if audit_log is None else audit_log
        if not isinstance(operations, bool):
            raise TypeError("operations must be bool.")
        self._operations = operations

    def setup(self, application: Application) -> None:
        """Register read and explicitly enabled mutation routes during Core composition."""
        if not isinstance(application, Application):
            raise TypeError("AdminPlugin requires an Orbit Application.")
        if self._operations:
            from orbit_admin.operations import AdminOperationsPlugin

            AdminOperationsPlugin(audit_log=self.audit_log).setup(application)
        for resource in self._resources.values():
            self._register_read_routes(application, resource)
            self._register_write_routes(application, resource)

    def _register_read_routes(
        self, application: Application, resource: AdminResource[Any, Any]
    ) -> None:
        collection = f"{self._prefix}/resources/{resource.name}"
        item = f"{collection}/{{key}}"

        @application.router.route(
            collection,
            method="GET",
            name=f"admin-{resource.name}-list",
            roles=_READ,
        )
        async def list_items(request: Request) -> Response:
            """Return a bounded first page using only explicitly readable fields."""
            values = request.query_parameters.get("limit", [])
            if len(values) > 1:
                raise HTTPError(400, "admin.query", "The limit parameter must appear once.")
            limit = _page_limit(values[0] if values else None)
            entities = await resource.repository.list(limit=limit)
            return _json_response({"items": [resource.serialize(entity) for entity in entities]})

        @application.router.route(
            item,
            method="GET",
            name=f"admin-{resource.name}-get",
            roles=_READ,
        )
        async def get_item(request: Request) -> Response:
            """Return one existing resource or a stable not-found response."""
            entity = await self._get(resource, _path_key(request))
            if entity is None:
                raise HTTPError(404, "admin.not-found", "Resource was not found.")
            return _json_response({"item": resource.serialize(entity)})

    def _register_write_routes(
        self, application: Application, resource: AdminResource[Any, Any]
    ) -> None:
        collection = f"{self._prefix}/resources/{resource.name}"
        item = f"{collection}/{{key}}"
        if resource.create_fields:

            @application.router.route(
                collection,
                method="POST",
                name=f"admin-{resource.name}-create",
                roles=_WRITE,
            )
            async def create_item(request: Request) -> Response:
                """Validate allowed model fields, insert once, and record a payload-free audit."""
                values = _write_object(_json_write_body(request), resource.create_fields)
                entity = resource.model.model_validate(values)
                try:
                    await resource.repository.add(entity)
                except RepositoryConflictError:
                    await self.audit_log.record(
                        "crud.create",
                        target=resource.name,
                        success=False,
                        error_code="admin.conflict",
                    )
                    raise HTTPError(
                        409, "admin.conflict", "Resource conflicts with an existing item."
                    ) from None
                await self.audit_log.record("crud.create", target=resource.name, success=True)
                return _json_response({"item": resource.serialize(entity)}, status=201)

        if resource.update_fields:

            @application.router.route(
                item,
                method="PUT",
                name=f"admin-{resource.name}-update",
                roles=_WRITE,
            )
            async def update_item(request: Request) -> Response:
                """Update only allowlisted fields while preserving the immutable resource key."""
                key = _path_key(request)
                patch = _write_object(_json_write_body(request), resource.update_fields)
                update_handler = resource.update_handler
                if update_handler is None:
                    raise RuntimeError("Resource update handler is missing after validation.")
                try:
                    entity = await update_handler(_parse_key(resource, key), patch)
                except RepositoryConflictError:
                    await self.audit_log.record(
                        "crud.update",
                        target=resource.name,
                        success=False,
                        error_code="admin.conflict",
                    )
                    raise HTTPError(
                        409, "admin.conflict", "Resource conflicts with an existing item."
                    ) from None
                if entity is None:
                    raise HTTPError(404, "admin.not-found", "Resource was not found.")
                await self.audit_log.record("crud.update", target=resource.name, success=True)
                return _json_response({"item": resource.serialize(entity)})

        if resource.allow_delete:

            @application.router.route(
                item,
                method="DELETE",
                name=f"admin-{resource.name}-delete",
                roles=_WRITE,
            )
            async def delete_item(request: Request) -> Response:
                """Delete an existing resource and audit the outcome without storing its key."""
                deleted = await resource.repository.delete(_parse_key(resource, _path_key(request)))
                if not deleted:
                    raise HTTPError(404, "admin.not-found", "Resource was not found.")
                await self.audit_log.record("crud.delete", target=resource.name, success=True)
                return Response(status=204)

    @staticmethod
    async def _get(resource: AdminResource[Any, Any], raw_key: str) -> Any:
        """Parse the configured key type and read one entity from its repository."""
        return await resource.repository.get(_parse_key(resource, raw_key))


def _path_key(request: Request) -> str:
    """Return one bounded key parameter from Core's validated route match."""
    key = request.path_parameters.get("key")
    if not isinstance(key, str) or not 1 <= len(key) <= _MAX_KEY_CHARS:
        raise HTTPError(400, "admin.key", "Resource key is invalid.")
    return key


def _parse_key(resource: AdminResource[Any, Any], raw_key: str) -> Any:
    """Convert a bounded path segment to the model's key type or return a safe client error."""
    from pydantic import ValidationError

    try:
        return resource.parse_key(raw_key)
    except (ValidationError, TypeError, ValueError):
        raise HTTPError(400, "admin.key", "Resource key is invalid.") from None


def _page_limit(value: str | None) -> int:
    """Parse the bounded decimal list limit and reject ambiguous or coercive inputs."""
    if value is None:
        return _MAX_PAGE_SIZE
    if not value.isascii() or not value.isdecimal() or len(value) > 3:
        raise HTTPError(400, "admin.limit", "The limit parameter must be a decimal integer.")
    limit = int(value)
    if not 1 <= limit <= _MAX_PAGE_SIZE:
        raise HTTPError(400, "admin.limit", "The limit parameter must be from 1 through 100.")
    return limit


def _write_object(value: object, allowed: frozenset[str]) -> Mapping[str, Any]:
    """Require a JSON object containing only explicitly writable model fields."""
    if not isinstance(value, dict):
        raise HTTPError(400, "admin.body", "The JSON body must be an object.")
    if not value:
        raise HTTPError(400, "admin.body", "The JSON body must contain writable fields.")
    if not value.keys() <= allowed:
        raise HTTPError(400, "admin.fields", "The JSON body contains fields that are not writable.")
    return value


def _json_write_body(request: Request) -> object:
    """Reject large write bodies before JSON decoding or model validation consumes CPU/memory."""
    if len(request.body) > _MAX_WRITE_BODY_BYTES:
        raise HTTPError(413, "admin.body-too-large", "Admin write bodies are limited to 1 MiB.")
    return request.json()


def _json_response(payload: object, *, status: int = 200) -> Response:
    """Serialize one response and enforce the Admin package's independent byte ceiling."""
    response = Response.json(payload, status=status)
    if len(response.body) > _MAX_RESPONSE_BYTES:
        raise HTTPError(413, "admin.response-too-large", "Admin response exceeds the 2 MiB limit.")
    return response


__all__ = ["AdminPlugin"]

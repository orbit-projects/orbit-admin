"""Admin CRUD behavior, access rules, validation, and audit redaction."""

from __future__ import annotations

import json

import pytest
from orbit import Application, ApplicationConfig
from orbit.asgi import ASGIApplication
from orbit_auth import BasicAuthenticator, BasicCredential, RoleAuthorizer
from orbit_data import RepositoryConflictError
from orbit_sql_sqlite import SQLiteDatabase
from orbit_testing import TestClient
from pydantic import BaseModel, SecretStr

from orbit_admin import (
    AdminAuditLog,
    AdminAuditSink,
    AdminOperationsPlugin,
    AdminPlugin,
    AdminResource,
    SQLAdminAuditLog,
)


class Account(BaseModel):
    """Small test record with a field deliberately hidden from Admin responses."""

    id: int
    display_name: str
    recovery_secret: SecretStr


class MemoryRepository:
    """Deterministic typed repository used by the Admin route tests."""

    def __init__(self) -> None:
        self.items: dict[int, Account] = {}

    async def get(self, key: int) -> Account | None:
        """Look up one account."""
        return self.items.get(key)

    async def list(self, *, limit: int = 100) -> tuple[Account, ...]:
        """Return deterministic key order with the requested bound."""
        return tuple(self.items[key] for key in sorted(self.items)[:limit])

    async def add(self, entity: Account) -> None:
        """Insert one unique account."""
        if entity.id in self.items:
            raise RepositoryConflictError
        self.items[entity.id] = entity

    async def update(self, entity: Account) -> bool:
        """Replace one existing account."""
        if entity.id not in self.items:
            return False
        self.items[entity.id] = entity
        return True

    async def delete(self, key: int) -> bool:
        """Delete one account by its typed key."""
        return self.items.pop(key, None) is not None


def _resource(repository: MemoryRepository) -> AdminResource[Account, int]:
    """Create an explicit resource policy that keeps recovery secrets private."""

    async def atomic_update(key: int, patch: dict[str, object]) -> Account | None:
        """Apply the validated patch inside one fake repository operation."""
        existing = await repository.get(key)
        if existing is None:
            return None
        values = existing.model_dump(mode="python")
        values.update(patch)
        entity = Account.model_validate(values)
        await repository.update(entity)
        return entity

    return AdminResource(
        name="accounts",
        model=Account,
        repository=repository,
        key_field="id",
        read_fields=frozenset({"id", "display_name"}),
        create_fields=frozenset({"id", "display_name", "recovery_secret"}),
        update_fields=frozenset({"display_name"}),
        update_handler=atomic_update,
        allow_delete=True,
    )


def _application(
    repository: MemoryRepository,
    roles: tuple[str, ...] = ("orbit.admin.read", "orbit.admin.write"),
    max_body_bytes: int = 1_048_576,
    audit_log: AdminAuditSink | None = None,
) -> tuple[Application, ASGIApplication, AdminPlugin]:
    """Compose the plugin with explicit read/write Basic credentials and TLS enforcement."""
    application = Application(ApplicationConfig(name="admin-test", max_body_bytes=max_body_bytes))
    plugin = AdminPlugin([_resource(repository)], audit_log=audit_log)
    application.plugins.register(plugin)
    credential = BasicCredential.create(
        "operator",
        "correct horse battery staple",
        roles=roles,
    )
    runtime = ASGIApplication(
        application,
        authenticator=BasicAuthenticator([credential]),
        authorizer=RoleAuthorizer(),
    )
    return application, runtime, plugin


def _headers() -> dict[str, str]:
    """Return explicit test-only HTTPS Basic credentials."""
    import base64

    raw = base64.b64encode(b"operator:correct horse battery staple").decode("ascii")
    return {"authorization": f"Basic {raw}", "content-type": "application/json"}


async def test_read_routes_require_auth_and_only_serialize_allowed_fields() -> None:
    repository = MemoryRepository()
    repository.items[1] = Account(
        id=1,
        display_name="Ada",
        recovery_secret=SecretStr("do-not-show"),
    )
    _, runtime, _ = _application(repository)

    async with TestClient(runtime) as client:
        anonymous = await client.request("GET", "/admin-api/v1/resources/accounts")
        assert anonymous.status == 401
        listed = await client.request(
            "GET",
            "https://orbit.test/admin-api/v1/resources/accounts?limit=1",
            headers=_headers(),
        )
        item = await client.request(
            "GET",
            "https://orbit.test/admin-api/v1/resources/accounts/1",
            headers=_headers(),
        )

    assert listed.json() == {"items": [{"id": 1, "display_name": "Ada"}]}
    assert item.json() == {"item": {"id": 1, "display_name": "Ada"}}
    assert "do-not-show" not in listed.body.decode()


async def test_operations_console_is_installed_by_the_admin_plugin_and_role_protected() -> None:
    repository = MemoryRepository()
    _, runtime, _ = _application(repository)
    async with TestClient(runtime) as client:
        anonymous = await client.request("GET", "/admin")
        overview = await client.request("GET", "https://orbit.test/admin", headers=_headers())
        state = await client.request("GET", "https://orbit.test/admin/state", headers=_headers())
    assert anonymous.status == 401
    assert overview.status == 200
    assert b"Orbit Administration" in overview.body
    assert overview.headers["cache-control"] == "no-store"
    assert state.status == 200
    assert state.json()["service_names"] == []


async def test_operations_rate_limit_is_owned_by_the_admin_plugin() -> None:
    application = Application(ApplicationConfig(name="admin-rate-test"))
    application.plugins.register(AdminOperationsPlugin(rate_limit=1, rate_period=60))
    runtime = ASGIApplication(
        application,
        authenticator=BasicAuthenticator(
            [
                BasicCredential.create(
                    "operator", "correct horse battery staple", roles=("orbit.admin.read",)
                )
            ]
        ),
        authorizer=RoleAuthorizer(),
    )
    async with TestClient(runtime) as client:
        first = await client.request("GET", "https://orbit.test/admin", headers=_headers())
        second = await client.request("GET", "https://orbit.test/admin", headers=_headers())
    assert first.status == 200
    assert second.status == 429
    assert "retry-after" in second.headers


async def test_mutations_are_field_limited_and_payload_free_audited() -> None:
    repository = MemoryRepository()
    _, runtime, plugin = _application(repository)

    async with TestClient(runtime) as client:
        created = await client.request(
            "POST",
            "https://orbit.test/admin-api/v1/resources/accounts",
            headers=_headers(),
            body=json.dumps(
                {"id": 7, "display_name": "Grace", "recovery_secret": "private"}
            ).encode(),
        )
        updated = await client.request(
            "PUT",
            "https://orbit.test/admin-api/v1/resources/accounts/7",
            headers=_headers(),
            body=b'{"display_name":"Grace Hopper"}',
        )
        deleted = await client.request(
            "DELETE",
            "https://orbit.test/admin-api/v1/resources/accounts/7",
            headers=_headers(),
        )

    assert created.status == 201
    assert created.json() == {"item": {"id": 7, "display_name": "Grace"}}
    assert updated.json() == {"item": {"id": 7, "display_name": "Grace Hopper"}}
    assert deleted.status == 204
    assert len(plugin.audit_log.records) == 3
    assert [record.action for record in plugin.audit_log.records] == [
        "crud.create",
        "crud.update",
        "crud.delete",
    ]
    assert all(
        record.target == "accounts" and record.success for record in plugin.audit_log.records
    )
    assert "private" not in repr(plugin.audit_log.records)


async def test_crud_plugin_can_use_durable_sql_audit_sink() -> None:
    repository = MemoryRepository()
    database = SQLiteDatabase(":memory:")
    audit_log = SQLAdminAuditLog(database, max_records=10)
    _, runtime, _ = _application(repository, audit_log=audit_log)

    async with TestClient(runtime) as client:
        response = await client.request(
            "POST",
            "https://orbit.test/admin-api/v1/resources/accounts",
            headers=_headers(),
            body=json.dumps(
                {"id": 9, "display_name": "Katherine", "recovery_secret": "private"}
            ).encode(),
        )

    records = await audit_log.recent(limit=10)
    await database.aclose()

    assert response.status == 201
    assert len(records) == 1
    assert records[0].action == "crud.create"
    assert records[0].target == "accounts"
    assert records[0].success is True
    assert "private" not in repr(records[0])


async def test_admin_api_rejects_unknown_fields_and_unbounded_limits() -> None:
    _, runtime, _ = _application(MemoryRepository())

    async with TestClient(runtime) as client:
        unknown_field = await client.request(
            "POST",
            "https://orbit.test/admin-api/v1/resources/accounts",
            headers=_headers(),
            body=b'{"id":1,"display_name":"Lin","recovery_secret":"x","is_admin":true}',
        )
        too_large = await client.request(
            "GET",
            "https://orbit.test/admin-api/v1/resources/accounts?limit=101",
            headers=_headers(),
        )

    assert unknown_field.status == 400
    assert unknown_field.json()["code"] == "admin.fields"
    assert too_large.status == 400
    assert too_large.json()["code"] == "admin.limit"


async def test_write_body_and_serialized_response_are_bounded() -> None:
    repository = MemoryRepository()
    repository.items[9] = Account(
        id=9,
        display_name="x" * 2_100_000,
        recovery_secret=SecretStr("private"),
    )
    _, runtime, _ = _application(repository, max_body_bytes=2_000_000)

    async with TestClient(runtime) as client:
        oversized_write = await client.request(
            "POST",
            "https://orbit.test/admin-api/v1/resources/accounts",
            headers=_headers(),
            body=b" " * (1_048_577),
        )
        oversized_read = await client.request(
            "GET",
            "https://orbit.test/admin-api/v1/resources/accounts/9",
            headers=_headers(),
        )

    assert oversized_write.status == 413
    assert oversized_write.json()["code"] == "admin.body-too-large"
    assert oversized_read.status == 413
    assert oversized_read.json()["code"] == "admin.response-too-large"


async def test_read_role_cannot_mutate_resources() -> None:
    _, runtime, _ = _application(MemoryRepository(), roles=("orbit.admin.read",))

    async with TestClient(runtime) as client:
        denied = await client.request(
            "POST",
            "https://orbit.test/admin-api/v1/resources/accounts",
            headers=_headers(),
            body=b'{"id":1,"display_name":"Lin","recovery_secret":"secret"}',
        )

    assert denied.status == 403
    assert denied.json()["code"] == "security.forbidden"


def test_admin_plugin_accepts_an_explicit_shared_audit_log() -> None:
    audit_log = AdminAuditLog(capacity=2)
    plugin = AdminPlugin([_resource(MemoryRepository())], audit_log=audit_log)
    assert plugin.audit_log is audit_log


def test_read_only_resource_does_not_register_mutation_routes() -> None:
    repository = MemoryRepository()
    readonly = AdminResource(
        name="accounts",
        model=Account,
        repository=repository,
        key_field="id",
        read_fields=frozenset({"id", "display_name"}),
    )
    application = Application(ApplicationConfig(name="readonly-admin"))
    application.plugins.register(AdminPlugin([readonly]))
    application.plugins.setup(application)

    methods = application.router.allowed_methods("/admin-api/v1/resources/accounts")
    assert "GET" in methods
    assert not {"POST", "PUT", "DELETE"} & set(methods)


def test_updates_require_an_explicit_atomic_handler() -> None:
    repository = MemoryRepository()
    with pytest.raises(ValueError, match="atomic update_handler"):
        AdminResource(
            name="accounts",
            model=Account,
            repository=repository,
            key_field="id",
            read_fields=frozenset({"id", "display_name"}),
            update_fields=frozenset({"display_name"}),
        )

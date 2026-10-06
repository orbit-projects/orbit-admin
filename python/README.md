# Orbit Admin for Python

`orbit-admin-python` is the optional Admin capability package for Orbit. It installs protected
operations views, payload-free auditing, and authenticated CRUD routes for explicitly configured
Pydantic repositories. It is distributed from the `python/` subdirectory of the `orbit-admin`
repository; the TypeScript dashboard remains an independent npm package at the repository root.

```bash
python -m pip install -e '.[dev]'
python -m pytest
ruff check .
ruff format --check .
mypy
```

The package depends directly on `orbit-core`, `orbit-auth`, `orbit-security`, `orbit-data`, and `orbit-sql`.
Database drivers remain separate provider packages. Configure and install the provider that matches
the application, then pass its `SQLDatabase` resource to `sql_resource` or provide an
`orbit-data.Repository` implementation directly. Core does not activate Admin routes or carry
Admin configuration.

## Explicit resource policy

```python
from orbit import Application, ApplicationConfig
from orbit_admin import AdminPlugin, sql_resource
from orbit.runtime import Runtime
from orbit_auth import BasicAuthenticator, BasicCredential, RoleAuthorizer

application = Application(ApplicationConfig(name="admin-service"))
accounts = sql_resource(
    "accounts",
    database,
    Account,
    table="accounts",
    key_field="id",
    read_fields=frozenset({"id", "display_name"}),
    create_fields=frozenset({"id", "display_name", "recovery_secret"}),
)
application.plugins.register(AdminPlugin([accounts]))
application.plugins.setup(application)
credential = BasicCredential.create(
    operator_name,
    operator_password_from_secret_store,
    roles=("orbit.admin.read", "orbit.admin.write"),
)
runtime = Runtime(
    application,
    authenticator=BasicAuthenticator([credential]),
    authorizer=RoleAuthorizer(),
)
```

Basic authentication must be explicitly configured with hashed credentials and requires HTTPS by
default. There are no built-in users. Do not keep passwords in source code or committed settings.
The static-user mechanism does not supply account recovery, federation, MFA, or session lifecycle;
production deployments should use a suitable identity provider and secret-rotation process.

Every resource declares its response and create fields. Fields such as password hashes or internal
flags stay private unless explicitly included in `read_fields`; writes accept only the declared
allowlists. Update routes are disabled unless an application supplies an `update_handler` that
performs an atomic or optimistic-concurrency-safe update. Deletes are disabled by default. Lists
are capped at 100 rows; this initial `orbit-data.Repository` contract does not yet provide cursor
pagination. Routes require `orbit.admin.read` for reads and `orbit.admin.write` for mutations.

Mutations append bounded, payload-free records to the Admin package's process-local audit history
by default. That history is lost on process restart and differs across workers. For durable storage,
pass `SQLAdminAuditLog` backed by an application-owned `SQLDatabase`:

```python
from orbit_admin import AdminPlugin, SQLAdminAuditLog
from orbit_sql import SQL_DATABASE_KEY

database = await application.container.aresolve(SQL_DATABASE_KEY)
audit_log = SQLAdminAuditLog(database, max_records=1_000_000)
await audit_log.initialize()
application.plugins.register(AdminPlugin(resources, audit_log=audit_log))
```

The SQL sink stores no request body, entity values, resource key, credential, or secret. It keeps a
bounded newest-first history and prunes older rows transactionally. The database resource remains
owned and closed by the application. An audit insert follows its resource mutation; the shared SQL
transaction contract does not make those two operations atomic, so deployments requiring a
tamper-evident, transactionally coupled ledger need a dedicated audit design. Protect the audit
table with database permissions and backups. No live MySQL or PostgreSQL audit integration is
claimed.

## Operations API and security

`AdminPlugin(resources)` registers both the operations console and CRUD routes. Use
`AdminPlugin(resources, operations=False)` to omit the console, or install `AdminOperationsPlugin`
for operations views without CRUD resources. The operations endpoints are `/admin`, `/admin/state`,
`/admin/services`, `/admin/tasks`, `/admin/plugins`, `/admin/routes`, `/admin/dependencies`,
`/admin/config`, `/admin/lifecycle`, `/admin/health`, `/admin/diagnostics`, `/admin/events`,
`/admin/audit`, and `/admin/extensions/{name}`. Health refresh, service actions, and task restart
are explicit POST operations.

All read routes require `orbit.admin.read`; mutations require `orbit.admin.write`. Core's router
fails closed unless an authenticator and `RouteAuthorizer` are configured. Mutations require one
nonempty Authorization header and reject browser Origin headers. The operations console enforces a
bounded process-local rate limit (120 requests per 60 seconds by default) and returns `429` with
`Retry-After` when full. It is not a distributed quota. Responses are non-cacheable and mutation
audit records omit credentials, request bodies, entity values, and resource keys.

The package is pre-alpha. Python tests cover operations routes, auth/role enforcement, local rate
limits, CRUD field allowlists, and SQLite audit persistence. Open release gates include hosted CI,
live MySQL/PostgreSQL audit verification, atomic CRUD-plus-audit semantics, production browser/auth
proxy review, durable tamper-evident audit requirements, and the hosted package release process.
Local tests do not certify production readiness.

Licensed under Apache-2.0.

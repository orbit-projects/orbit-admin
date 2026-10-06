# Orbit Admin: architecture and boundaries

## Responsibility

`@orbit-projects/orbit-admin` is a small TypeScript operations dashboard for the authenticated,
read-only inspection APIs already provided by Orbit Core. The browser package is installed and
deployed separately; it does not add routes, credentials, dependencies, or a UI framework to Core.

## Declared dependencies

The following dependency declarations come from the checked-in manifests. Optional groups and development dependencies are called out separately.

### `python/pyproject.toml`
- `orbit-core>=0.1.0a1,<0.2`
- `orbit-security>=0.1.0a1,<0.2`
- `orbit-data>=0.1.0a1,<0.2`
- `orbit-sql>=0.1.0a1,<0.2`
- `pydantic>=2.8,<3`
- Optional `dev` group: `pytest>=8,<10`, `pytest-asyncio>=0.24,<2`, `ruff>=0.8,<1`, `mypy>=1.13,<2`, `orbit-testing>=0.1.0a1,<0.2`, `orbit-sql-sqlite>=0.1.0a1,<0.2`.
### `package.json`
- `typescript (development)`

Declared dependencies do not mean that optional providers or services are bundled with this package.

## Implementation layout

Representative implementation files in this checkout:

- `python/src/orbit_admin/__init__.py`
- `python/src/orbit_admin/_safety.py`
- `python/src/orbit_admin/audit.py`
- `python/src/orbit_admin/client.py`
- `python/src/orbit_admin/operations.py`
- `python/src/orbit_admin/plugin.py`
- `python/src/orbit_admin/resources.py`
- `src/admin-client.ts`
- `src/main.ts`

## Public contract and scope

## Current scope

The dashboard provides application state, services, tasks, plugins, routes, dependencies,
configuration, lifecycle, health, diagnostics, events, and administrative audit views. It is
read-only. Core deliberately rejects browser-originated operational mutations unless a client
provides explicit non-browser authorization, so the UI does not expose service controls. It is not
a business-data CRUD framework, analytics warehouse, identity manager, or replacement for Core's
server-rendered Admin fallback. Those capabilities need separate resource, authorization, audit,
and data-exposure contracts before implementation.

This repository provides two independent packages: the TypeScript dashboard at the root and an
optional Python plugin in `python/`. The Python package adds explicitly configured repository CRUD
routes and depends directly on Core, `orbit-security`, `orbit-data`, and `orbit-sql`. Core still owns
the transitional `/admin` operations API and authentication internals; their extraction remains
open under ADR 0022. The Python package does not start a separate process or add a web framework,
and supports an opt-in SQL audit sink with bounded retention.

Both packages are pre-alpha and have not been published. The Python CRUD package has local SQLite
coverage for its SQL audit sink but no live SQL provider matrix or production load evidence. Browser compatibility,
reverse-proxy behavior, and production authentication have not been exercised in this checkpoint.

## Boundary rules

Keep provider SDKs, credentials, transports, and provider-specific error translation in provider adapters. Keep reusable capability contracts in the matching capability package and lifecycle orchestration in Core. Apply the relevant layer for this repository and preserve the dependency direction shown above.

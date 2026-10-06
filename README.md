# Orbit Admin

`@orbit-projects/orbit-admin` is a small TypeScript operations dashboard for the authenticated,
read-only inspection APIs already provided by Orbit Core. The browser package is installed and
deployed separately; it does not add routes, credentials, dependencies, or a UI framework to Core.

## Build the static dashboard

```bash
npm ci
npm test
npm run typecheck
npm run build
```

The deployable site is written to `dist/`. Serve it at a same-origin path such as `/orbit-admin/`
and proxy `/admin/*` to the same Orbit Core application. Same-origin deployment avoids adding CORS
or a cross-site credential path. The package makes only allowlisted GET requests to Core's JSON
inspection endpoints and caps each response at 1 MiB by default.

Enable Core Admin explicitly with `ApplicationConfig(admin_enabled=True)` and configure an
authenticator that grants `orbit.admin.read` only to approved operators. Core enables no default
identity or credentials. The dashboard never asks for, stores, or persists passwords, bearer
tokens, or session secrets. On a 401 it links to `/admin/state`, where the configured authenticator
can perform its normal browser sign-in or challenge. Basic Auth requires HTTPS; use trusted TLS
termination and Core's documented proxy configuration when TLS ends before the app.

The UI renders returned data with DOM `textContent`, not HTML interpolation; errors do not display
remote response bodies. Its requests use `credentials: "same-origin"`, `cache: "no-store"`, reject
redirects, require JSON responses, and enforce a streamed byte limit. Keep HTTPS, Core's
authorization policy, rate limits, and response redaction enabled. The static server or reverse
proxy should also send `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, and a strict
content security policy.

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

## Documentation

The package-specific guides cover [architecture](docs/architecture/overview.md), [operations and security](docs/operations/README.md), and [development](docs/development/README.md), with [security guidance](docs/security/overview.md). The [documentation index](docs/README.md) links to the full package overview and project policies.

## License

Apache-2.0.

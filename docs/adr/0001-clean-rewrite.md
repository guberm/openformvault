# ADR 0001 — Clean rewrite architecture

## Status

Accepted for scaffold.

## Context

The previous OpenFormVault alpha split into browser, desktop, Android, sync-server, and landing repositories. That proved feature direction but also exposed problems:

- no single source of truth for contracts;
- sync semantics drifted across clients;
- stale overwrite bugs required late cross-client tests;
- desktop was a CLI shell, not a Windows GUI;
- backend used alpha storage/auth patterns.

Michael requested deletion of existing `openformvault*` repos/backups, a new public `openformvault`, and a clean rewrite with:

- WinUI 3/.NET desktop;
- ASP.NET Core/PostgreSQL backend;
- native Android;
- Chrome MV3;
- RoboForm-style feature scope in v1.

## Decision

Build a monorepo using **local-first UX with a server-ordered zero-knowledge encrypted operation log**.

Backend and Windows use .NET-first architecture:

- ASP.NET Core API;
- PostgreSQL migrations;
- shared .NET contracts and sync reducer;
- WinUI 3 desktop app;
- native Android and Chrome extension connected through generated OpenAPI/contracts.

## Consequences

Positive:

- sync semantics are designed before UI;
- contract tests can run across all clients;
- server can enforce ordering/idempotency without seeing plaintext;
- WinUI satisfies the Windows-first requirement.

Trade-offs:

- less UI code sharing than Tauri/React across desktop and Android;
- Chrome remains TypeScript with generated contracts rather than native .NET;
- Android native requires duplicated UI but lower platform risk for Autofill and biometric flows.

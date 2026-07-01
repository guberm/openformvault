# OpenFormVault

OpenFormVault is a clean-room rewrite of a RoboForm-style password vault and form-filling suite.

## Product direction

This repository intentionally starts from a clean codebase. Earlier OpenFormVault alpha repositories were deleted after verified backups and are not used as the implementation foundation.

Targets for v1:

- **Backend:** ASP.NET Core + PostgreSQL, zero-knowledge encrypted sync log, migrations, API tests.
- **Windows:** WinUI 3/.NET desktop app, not a CLI.
- **Android:** native Android app with AutofillService, Room/WorkManager/Keystore/BiometricPrompt.
- **Chrome:** Manifest V3 extension with strict content-script boundary.
- **RoboForm-style scope from v1:** logins, identities, safenotes, bookmarks, folders, TOTP, generator, imports, startup screen, lock/unlock, sync status, and explicit conflict handling.

## Architecture decision

The selected architecture is **local-first UX with a server-ordered zero-knowledge encrypted operation log**.

- Clients keep an encrypted local vault and durable outbox.
- Server stores encrypted operation envelopes, tombstones, revisions, cursors, devices, sessions, and audit metadata.
- Server never receives master password, vault keys, item plaintext, domains, usernames, TOTP seeds, notes, or item titles.
- Sync is incremental, idempotent, retry-safe, and conflict-aware.

See:

- [`docs/adr/0001-clean-rewrite.md`](docs/adr/0001-clean-rewrite.md)
- [`docs/architecture/sync.md`](docs/architecture/sync.md)
- [`docs/security/threat-model.md`](docs/security/threat-model.md)
- [`docs/product/v1-scope.md`](docs/product/v1-scope.md)

## Repository layout

```text
apps/
  server/             ASP.NET Core API foundation
  windows/            WinUI 3 desktop app scaffold
  android/            native Android scaffold
  chrome-extension/   MV3 extension scaffold
packages/
  contracts/          .NET shared contract records
  sync-core/          deterministic sync reducer/tests
docs/
  adr/
  architecture/
  product/
  security/
```

## Verified local checks

```bash
dotnet test OpenFormVault.slnx
npm --prefix apps/chrome-extension test
npm --prefix apps/chrome-extension run build
/home/mg/.local/opt/gradle-8.14.3/bin/gradle -p apps/android assembleDebug
```

Windows WinUI packaging is configured as a Windows-only build path and is verified through GitHub Actions on Windows runners, not Linux.

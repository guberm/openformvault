# OpenFormVault Windows

WinUI 3/.NET desktop app scaffold.

The Windows client is the primary desktop client for v1. It must be a real Windows GUI, not a CLI.

Planned responsibilities:

- vault list/detail/editor;
- lock/unlock with Windows Hello/DPAPI-backed local key wrapping;
- sync status/errors/conflict resolution;
- settings/startup screen/import/security center/generator;
- future explicit Windows app-login fill automation.

This project is verified on Windows runners. Linux can validate docs/contracts/server/core, but cannot fully build WinUI 3.

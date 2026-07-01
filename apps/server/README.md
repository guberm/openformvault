# OpenFormVault Server

ASP.NET Core API foundation for the new OpenFormVault.

Current scaffold exposes:

- `GET /health`
- `POST /v1/vaults/{vaultId}/sync/push`

This is intentionally in-memory for the first scaffold. PostgreSQL migrations and durable auth/session/device tables are the next implementation milestone.

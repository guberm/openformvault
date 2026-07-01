# Sync architecture

OpenFormVault sync is local-first and server-ordered.

## Client invariants

- Local encrypted vault is the UI source of truth.
- Every mutation writes local materialized state and an outbox operation in one transaction.
- Outbox operations have client-generated `opId` idempotency keys.
- Clients push queued operations and pull deltas until cursors converge.
- Manual Sync Now is a fallback; background sync is expected.

## Server invariants

- Server stores only ciphertext envelopes and metadata required for ordering/auth/sync.
- Every vault has a monotonically increasing server revision.
- Every item has a version/ETag.
- Every mutation is idempotent by `(vaultId, deviceId, opId)` and request hash.
- Tombstones are retained long enough for offline clients to observe deletes.
- Expired cursors return a typed error requiring snapshot/full resync.

## Conflict policy for v1

- non-overlapping item changes can merge client-side;
- duplicate idempotent operations replay safely;
- stale secret update vs newer remote edit creates a conflict copy or explicit conflict state;
- delete vs stale update never silently resurrects secrets;
- last-write-wins is not allowed for passwords, TOTP seeds, notes, or item bodies.

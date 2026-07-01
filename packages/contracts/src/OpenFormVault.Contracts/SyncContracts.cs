namespace OpenFormVault.Contracts;

public enum VaultOperationType
{
    Create = 1,
    Update = 2,
    Delete = 3,
    Restore = 4
}

public sealed record EncryptedVaultOperation(
    Guid OpId,
    Guid VaultId,
    Guid ItemId,
    Guid DeviceId,
    long ClientSequence,
    VaultOperationType OperationType,
    long? BaseItemVersion,
    string Ciphertext,
    string Nonce,
    string Algorithm,
    string PayloadHash,
    DateTimeOffset CreatedAtClient);

public sealed record AppliedVaultOperation(
    Guid OpId,
    Guid ItemId,
    long VaultRevision,
    long ItemVersion,
    bool IdempotentReplay);

public sealed record VaultSyncConflict(
    Guid OpId,
    Guid ItemId,
    long? ExpectedItemVersion,
    long ActualItemVersion,
    string ConflictCode);

public sealed record PushOperationsRequest(
    Guid VaultId,
    Guid DeviceId,
    IReadOnlyList<EncryptedVaultOperation> Operations);

public sealed record PushOperationsResponse(
    Guid VaultId,
    long ServerRevision,
    IReadOnlyList<AppliedVaultOperation> Applied,
    IReadOnlyList<VaultSyncConflict> Conflicts);

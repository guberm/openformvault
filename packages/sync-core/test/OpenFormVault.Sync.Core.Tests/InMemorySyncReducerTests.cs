using OpenFormVault.Contracts;
using OpenFormVault.Sync.Core;
using Xunit;

namespace OpenFormVault.Sync.Core.Tests;

public sealed class InMemorySyncReducerTests
{
    [Fact]
    public void DuplicateOperationIsIdempotentReplay()
    {
        var reducer = new InMemorySyncReducer();
        var vaultId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var op = MakeOp(vaultId, deviceId, Guid.NewGuid(), 1, VaultOperationType.Create, 0);

        var first = reducer.Push(new PushOperationsRequest(vaultId, deviceId, [op]));
        var second = reducer.Push(new PushOperationsRequest(vaultId, deviceId, [op]));

        Assert.Empty(first.Conflicts);
        Assert.Empty(second.Conflicts);
        Assert.False(first.Applied.Single().IdempotentReplay);
        Assert.True(second.Applied.Single().IdempotentReplay);
        Assert.Equal(first.Applied.Single().ItemVersion, second.Applied.Single().ItemVersion);
    }

    [Fact]
    public void StaleUpdateCreatesConflictInsteadOfOverwrite()
    {
        var reducer = new InMemorySyncReducer();
        var vaultId = Guid.NewGuid();
        var deviceA = Guid.NewGuid();
        var deviceB = Guid.NewGuid();
        var itemId = Guid.NewGuid();

        var create = MakeOp(vaultId, deviceA, itemId, 1, VaultOperationType.Create, 0);
        var updateA = MakeOp(vaultId, deviceA, itemId, 2, VaultOperationType.Update, 1);
        var staleB = MakeOp(vaultId, deviceB, itemId, 1, VaultOperationType.Update, 1);

        reducer.Push(new PushOperationsRequest(vaultId, deviceA, [create]));
        reducer.Push(new PushOperationsRequest(vaultId, deviceA, [updateA]));
        var stale = reducer.Push(new PushOperationsRequest(vaultId, deviceB, [staleB]));

        var conflict = Assert.Single(stale.Conflicts);
        Assert.Equal(itemId, conflict.ItemId);
        Assert.Equal(1, conflict.ExpectedItemVersion);
        Assert.Equal(2, conflict.ActualItemVersion);
        Assert.Empty(stale.Applied);
    }

    [Fact]
    public void DeleteThenStaleUpdateDoesNotResurrectItem()
    {
        var reducer = new InMemorySyncReducer();
        var vaultId = Guid.NewGuid();
        var deviceA = Guid.NewGuid();
        var deviceB = Guid.NewGuid();
        var itemId = Guid.NewGuid();

        reducer.Push(new PushOperationsRequest(vaultId, deviceA, [MakeOp(vaultId, deviceA, itemId, 1, VaultOperationType.Create, 0)]));
        reducer.Push(new PushOperationsRequest(vaultId, deviceA, [MakeOp(vaultId, deviceA, itemId, 2, VaultOperationType.Delete, 1)]));
        var stale = reducer.Push(new PushOperationsRequest(vaultId, deviceB, [MakeOp(vaultId, deviceB, itemId, 1, VaultOperationType.Update, 1)]));

        var conflict = Assert.Single(stale.Conflicts);
        Assert.Equal("item_deleted_or_tombstoned", conflict.ConflictCode);
        Assert.Empty(stale.Applied);
    }

    private static EncryptedVaultOperation MakeOp(Guid vaultId, Guid deviceId, Guid itemId, long seq, VaultOperationType type, long? baseVersion) =>
        new(Guid.NewGuid(), vaultId, itemId, deviceId, seq, type, baseVersion,
            Ciphertext: Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
            Nonce: Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
            Algorithm: "AES-256-GCM",
            PayloadHash: Guid.NewGuid().ToString("N"),
            CreatedAtClient: DateTimeOffset.UtcNow);
}

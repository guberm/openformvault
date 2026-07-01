using OpenFormVault.Contracts;

namespace OpenFormVault.Sync.Core;

public sealed class InMemorySyncReducer
{
    private readonly Dictionary<Guid, ItemState> _items = new();
    private readonly Dictionary<Guid, AppliedVaultOperation> _appliedByOpId = new();
    private long _revision;

    public PushOperationsResponse Push(PushOperationsRequest request)
    {
        var applied = new List<AppliedVaultOperation>();
        var conflicts = new List<VaultSyncConflict>();

        foreach (var op in request.Operations.OrderBy(o => o.ClientSequence))
        {
            if (_appliedByOpId.TryGetValue(op.OpId, out var replay))
            {
                applied.Add(replay with { IdempotentReplay = true });
                continue;
            }

            _items.TryGetValue(op.ItemId, out var current);
            var currentVersion = current?.Version ?? 0;

            if (op.BaseItemVersion is not null && op.BaseItemVersion.Value != currentVersion)
            {
                conflicts.Add(new VaultSyncConflict(
                    op.OpId,
                    op.ItemId,
                    op.BaseItemVersion,
                    currentVersion,
                    current?.Deleted == true ? "item_deleted_or_tombstoned" : "stale_item_version"));
                continue;
            }

            var nextVersion = currentVersion + 1;
            _revision++;

            var deleted = op.OperationType == VaultOperationType.Delete;
            _items[op.ItemId] = new ItemState(nextVersion, deleted, op.PayloadHash);

            var result = new AppliedVaultOperation(op.OpId, op.ItemId, _revision, nextVersion, false);
            _appliedByOpId[op.OpId] = result;
            applied.Add(result);
        }

        return new PushOperationsResponse(request.VaultId, _revision, applied, conflicts);
    }

    private sealed record ItemState(long Version, bool Deleted, string PayloadHash);
}

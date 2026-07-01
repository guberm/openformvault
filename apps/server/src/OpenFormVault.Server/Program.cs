using OpenFormVault.Contracts;
using OpenFormVault.Sync.Core;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<InMemorySyncReducer>();
builder.Services.AddProblemDetails();

var app = builder.Build();

app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    product = "OpenFormVault",
    architecture = "server-ordered zero-knowledge encrypted operation log"
}));

app.MapPost("/v1/vaults/{vaultId:guid}/sync/push", (
    Guid vaultId,
    PushOperationsRequest request,
    InMemorySyncReducer reducer) =>
{
    if (request.VaultId != vaultId)
    {
        return Results.BadRequest(new { code = "vault_id_mismatch" });
    }

    var response = reducer.Push(request);
    return response.Conflicts.Count > 0 ? Results.Conflict(response) : Results.Ok(response);
});

app.Run();

public partial class Program { }

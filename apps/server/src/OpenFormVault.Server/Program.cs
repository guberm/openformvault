using System.Security.Cryptography;
using System.Text;
using OpenFormVault.Contracts;
using OpenFormVault.Sync.Core;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("OpenFormVaultClient", policy => policy
        .AllowAnyOrigin()
        .AllowAnyHeader()
        .AllowAnyMethod());
});
builder.Services.AddSingleton<InMemorySyncReducer>();
builder.Services.AddProblemDetails();

var connectionString = builder.Configuration.GetConnectionString("OpenFormVault")
    ?? Environment.GetEnvironmentVariable("OPENFORMVAULT_DATABASE_URL")
    ?? "Host=127.0.0.1;Port=55432;Database=openformvault;Username=ofv;Password=ofv_dev_password";
var dataSource = NpgsqlDataSource.Create(connectionString);
builder.Services.AddSingleton(dataSource);

var app = builder.Build();

app.UseCors("OpenFormVaultClient");
await Database.InitializeAsync(dataSource);

app.MapGet("/", () => Results.Ok(new
{
    status = "ok",
    product = "OpenFormVault",
    service = "OpenFormVault.Server",
    domain = "https://openformvault.guber.dev"
}));

app.MapGet("/health", async (NpgsqlDataSource db) =>
{
    await using var command = db.CreateCommand("select 1");
    await command.ExecuteScalarAsync();
    return Results.Ok(new
    {
        status = "ok",
        product = "OpenFormVault",
        service = "OpenFormVault.Server",
        storage = "postgres",
        architecture = "server-ordered zero-knowledge encrypted operation log"
    });
});

app.MapPost("/v1/users/register", async (RegisterRequest request, NpgsqlDataSource db) =>
{
    var username = NormalizeUsername(request.Username);
    if (username.Length < 3 || request.Password.Length < 10)
    {
        return Results.BadRequest(new { code = "invalid_credentials", message = "Username must be at least 3 chars and password at least 10 chars." });
    }

    var password = PasswordHasher.Hash(request.Password);
    var userId = Guid.NewGuid();
    try
    {
        await using var command = db.CreateCommand("""
            insert into users (id, username, password_salt, password_hash, created_at)
            values ($1, $2, $3, $4, now())
            """);
        command.Parameters.AddWithValue(userId);
        command.Parameters.AddWithValue(username);
        command.Parameters.AddWithValue(password.Salt);
        command.Parameters.AddWithValue(password.Hash);
        await command.ExecuteNonQueryAsync();
    }
    catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
    {
        return Results.Conflict(new { code = "username_exists" });
    }

    var token = await Sessions.CreateAsync(db, userId);
    return Results.Ok(new SessionResponse(userId, username, token));
});

app.MapPost("/v1/session", async (LoginRequest request, NpgsqlDataSource db) =>
{
    var username = NormalizeUsername(request.Username);
    await using var command = db.CreateCommand("select id, password_salt, password_hash from users where username = $1");
    command.Parameters.AddWithValue(username);
    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        return Results.Unauthorized();
    }

    var userId = reader.GetGuid(0);
    var salt = (byte[])reader[1];
    var hash = (byte[])reader[2];
    if (!PasswordHasher.Verify(request.Password, salt, hash))
    {
        return Results.Unauthorized();
    }

    var token = await Sessions.CreateAsync(db, userId);
    return Results.Ok(new SessionResponse(userId, username, token));
});

app.MapGet("/v1/session", async (HttpRequest http, NpgsqlDataSource db) =>
{
    var user = await Sessions.RequireUserAsync(http, db);
    return user is null ? Results.Unauthorized() : Results.Ok(new { user.UserId, user.Username });
});

app.MapGet("/v1/vault/snapshot", async (HttpRequest http, NpgsqlDataSource db) =>
{
    var user = await Sessions.RequireUserAsync(http, db);
    if (user is null) return Results.Unauthorized();

    await using var command = db.CreateCommand("""
        select revision, ciphertext, nonce, salt, algorithm, kdf, updated_at
        from vault_snapshots where user_id = $1
        """);
    command.Parameters.AddWithValue(user.UserId);
    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync()) return Results.NotFound(new { code = "vault_snapshot_not_found" });

    return Results.Ok(new VaultSnapshotResponse(
        reader.GetInt64(0),
        reader.GetString(1),
        reader.GetString(2),
        reader.GetString(3),
        reader.GetString(4),
        reader.GetString(5),
        reader.GetDateTime(6)));
});

app.MapPut("/v1/vault/snapshot", async (HttpRequest http, VaultSnapshotRequest request, NpgsqlDataSource db) =>
{
    var user = await Sessions.RequireUserAsync(http, db);
    if (user is null) return Results.Unauthorized();
    if (string.IsNullOrWhiteSpace(request.Ciphertext) || string.IsNullOrWhiteSpace(request.Nonce) || string.IsNullOrWhiteSpace(request.Salt))
    {
        return Results.BadRequest(new { code = "invalid_encrypted_snapshot" });
    }

    await using var tx = await db.OpenConnectionAsync();
    await using var transaction = await tx.BeginTransactionAsync();

    await using (var lockCommand = new NpgsqlCommand("select revision from vault_snapshots where user_id = $1 for update", tx, transaction))
    {
        lockCommand.Parameters.AddWithValue(user.UserId);
        var current = await lockCommand.ExecuteScalarAsync();
        var currentRevision = current is null ? 0L : (long)current;
        if (request.BaseRevision is not null && request.BaseRevision.Value != currentRevision)
        {
            await transaction.RollbackAsync();
            return Results.Conflict(new { code = "stale_vault_revision", expected = request.BaseRevision, actual = currentRevision });
        }
        var nextRevision = currentRevision + 1;
        await using var upsert = new NpgsqlCommand("""
            insert into vault_snapshots (user_id, revision, ciphertext, nonce, salt, algorithm, kdf, updated_at)
            values ($1, $2, $3, $4, $5, $6, $7, now())
            on conflict (user_id) do update set
              revision = excluded.revision,
              ciphertext = excluded.ciphertext,
              nonce = excluded.nonce,
              salt = excluded.salt,
              algorithm = excluded.algorithm,
              kdf = excluded.kdf,
              updated_at = now()
            """, tx, transaction);
        upsert.Parameters.AddWithValue(user.UserId);
        upsert.Parameters.AddWithValue(nextRevision);
        upsert.Parameters.AddWithValue(request.Ciphertext);
        upsert.Parameters.AddWithValue(request.Nonce);
        upsert.Parameters.AddWithValue(request.Salt);
        upsert.Parameters.AddWithValue(request.Algorithm ?? "AES-GCM");
        upsert.Parameters.AddWithValue(request.Kdf ?? "PBKDF2-SHA256-310000");
        await upsert.ExecuteNonQueryAsync();
        await transaction.CommitAsync();
        return Results.Ok(new { revision = nextRevision });
    }
});

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

static string NormalizeUsername(string username) => username.Trim().ToLowerInvariant();

public sealed record RegisterRequest(string Username, string Password);
public sealed record LoginRequest(string Username, string Password);
public sealed record SessionResponse(Guid UserId, string Username, string Token);
public sealed record VaultSnapshotRequest(string Ciphertext, string Nonce, string Salt, string? Algorithm, string? Kdf, long? BaseRevision);
public sealed record VaultSnapshotResponse(long Revision, string Ciphertext, string Nonce, string Salt, string Algorithm, string Kdf, DateTime UpdatedAt);
public sealed record AuthenticatedUser(Guid UserId, string Username);

public static class Database
{
    public static async Task InitializeAsync(NpgsqlDataSource db)
    {
        await using var command = db.CreateCommand("""
            create table if not exists users (
              id uuid primary key,
              username text not null unique,
              password_salt bytea not null,
              password_hash bytea not null,
              created_at timestamptz not null default now()
            );
            create table if not exists sessions (
              token_hash bytea primary key,
              user_id uuid not null references users(id) on delete cascade,
              created_at timestamptz not null default now(),
              expires_at timestamptz not null
            );
            create table if not exists vault_snapshots (
              user_id uuid primary key references users(id) on delete cascade,
              revision bigint not null,
              ciphertext text not null,
              nonce text not null,
              salt text not null,
              algorithm text not null,
              kdf text not null,
              updated_at timestamptz not null default now()
            );
            """);
        await command.ExecuteNonQueryAsync();
    }
}

public static class Sessions
{
    public static async Task<string> CreateAsync(NpgsqlDataSource db, Guid userId)
    {
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToBase64String(tokenBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        await using var command = db.CreateCommand("insert into sessions (token_hash, user_id, expires_at) values ($1, $2, now() + interval '30 days')");
        command.Parameters.AddWithValue(tokenHash);
        command.Parameters.AddWithValue(userId);
        await command.ExecuteNonQueryAsync();
        return token;
    }

    public static async Task<AuthenticatedUser?> RequireUserAsync(HttpRequest request, NpgsqlDataSource db)
    {
        var header = request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
        var token = header["Bearer ".Length..].Trim();
        if (token.Length == 0) return null;
        var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        await using var command = db.CreateCommand("""
            select u.id, u.username
            from sessions s join users u on u.id = s.user_id
            where s.token_hash = $1 and s.expires_at > now()
            """);
        command.Parameters.AddWithValue(tokenHash);
        await using var reader = await command.ExecuteReaderAsync();
        return await reader.ReadAsync() ? new AuthenticatedUser(reader.GetGuid(0), reader.GetString(1)) : null;
    }
}

public static class PasswordHasher
{
    private const int Iterations = 310_000;
    public static (byte[] Salt, byte[] Hash) Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        return (salt, hash);
    }

    public static bool Verify(string password, byte[] salt, byte[] expectedHash)
    {
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, expectedHash.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
    }
}

public partial class Program { }

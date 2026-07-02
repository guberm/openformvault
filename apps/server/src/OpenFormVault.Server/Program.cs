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

app.MapPost("/v1/users/register", async (HttpRequest http, RegisterRequest request, NpgsqlDataSource db) =>
{
    var username = ResolveUsername(request.Username, request.Email, request.DisplayName);
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

    var token = await Sessions.CreateAsync(db, userId, Devices.FromRequest(http));
    return Results.Ok(new SessionResponse(userId, username, token));
});

app.MapPost("/v1/session", async (HttpRequest http, LoginRequest request, NpgsqlDataSource db) =>
{
    var username = ResolveUsername(request.Username, request.Email, request.DisplayName);
    if (username.Length < 3 || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.Unauthorized();
    }
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

    var token = await Sessions.CreateAsync(db, userId, Devices.FromRequest(http));
    return Results.Ok(new SessionResponse(userId, username, token));
});

app.MapGet("/v1/session", async (HttpRequest http, NpgsqlDataSource db) =>
{
    var user = await Sessions.RequireUserAsync(http, db);
    return user is null ? Results.Unauthorized() : Results.Ok(new { user.UserId, user.Username });
});

app.MapGet("/v1/devices", async (HttpRequest http, NpgsqlDataSource db) =>
{
    var user = await Sessions.RequireUserAsync(http, db);
    if (user is null) return Results.Unauthorized();
    var currentDeviceId = Devices.FromRequest(http)?.DeviceId;
    await using var command = db.CreateCommand("""
        select device_id, device_name, created_at, last_seen_at
        from trusted_devices
        where user_id = $1 and revoked_at is null
        order by last_seen_at desc nulls last, created_at desc
        """);
    command.Parameters.AddWithValue(user.UserId);
    await using var reader = await command.ExecuteReaderAsync();
    var devices = new List<object>();
    while (await reader.ReadAsync())
    {
        var deviceId = reader.GetGuid(0);
        devices.Add(new
        {
            deviceId,
            deviceName = reader.GetString(1),
            createdAt = reader.GetDateTime(2),
            lastSeenAt = reader.IsDBNull(3) ? (DateTime?)null : reader.GetDateTime(3),
            current = currentDeviceId == deviceId
        });
    }
    return Results.Ok(new { devices });
});

app.MapDelete("/v1/devices/{deviceId:guid}", async (Guid deviceId, HttpRequest http, NpgsqlDataSource db) =>
{
    var user = await Sessions.RequireUserAsync(http, db);
    if (user is null) return Results.Unauthorized();
    await using var tx = await db.OpenConnectionAsync();
    await using var transaction = await tx.BeginTransactionAsync();
    await using (var revoke = new NpgsqlCommand("""
        update trusted_devices
        set revoked_at = now(), last_seen_at = now()
        where user_id = $1 and device_id = $2 and revoked_at is null
        """, tx, transaction))
    {
        revoke.Parameters.AddWithValue(user.UserId);
        revoke.Parameters.AddWithValue(deviceId);
        await revoke.ExecuteNonQueryAsync();
    }
    await using (var sessions = new NpgsqlCommand("delete from sessions where user_id = $1 and device_id = $2", tx, transaction))
    {
        sessions.Parameters.AddWithValue(user.UserId);
        sessions.Parameters.AddWithValue(deviceId);
        await sessions.ExecuteNonQueryAsync();
    }
    await transaction.CommitAsync();
    return Results.Ok(new { revoked = true, deviceId });
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

    await using (var lockCommand = new NpgsqlCommand("""
        select revision, ciphertext, nonce, salt, algorithm, kdf
        from vault_snapshots where user_id = $1 for update
        """, tx, transaction))
    {
        lockCommand.Parameters.AddWithValue(user.UserId);
        long currentRevision = 0;
        string? currentCiphertext = null;
        string? currentNonce = null;
        string? currentSalt = null;
        string? currentAlgorithm = null;
        string? currentKdf = null;
        await using (var currentReader = await lockCommand.ExecuteReaderAsync())
        {
            if (await currentReader.ReadAsync())
            {
                currentRevision = currentReader.GetInt64(0);
                currentCiphertext = currentReader.GetString(1);
                currentNonce = currentReader.GetString(2);
                currentSalt = currentReader.GetString(3);
                currentAlgorithm = currentReader.GetString(4);
                currentKdf = currentReader.GetString(5);
            }
        }
        var requestedAlgorithm = request.Algorithm ?? "AES-GCM";
        var requestedKdf = request.Kdf ?? "PBKDF2-SHA256-310000";
        if (request.BaseRevision is not null && request.BaseRevision.Value != currentRevision)
        {
            var isRetryOfPreviousSuccess = request.BaseRevision.Value + 1 == currentRevision
                && currentCiphertext == request.Ciphertext
                && currentNonce == request.Nonce
                && currentSalt == request.Salt
                && currentAlgorithm == requestedAlgorithm
                && currentKdf == requestedKdf;
            if (isRetryOfPreviousSuccess)
            {
                await transaction.CommitAsync();
                return Results.Ok(new { revision = currentRevision, idempotent = true });
            }
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
        upsert.Parameters.AddWithValue(requestedAlgorithm);
        upsert.Parameters.AddWithValue(requestedKdf);
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

static string NormalizeUsername(string? username) => username?.Trim().ToLowerInvariant() ?? string.Empty;
static string ResolveUsername(string? username, string? email, string? displayName)
{
    var normalizedUsername = NormalizeUsername(username);
    if (!string.IsNullOrWhiteSpace(normalizedUsername)) return normalizedUsername;
    var normalizedEmail = NormalizeUsername(email);
    if (!string.IsNullOrWhiteSpace(normalizedEmail)) return normalizedEmail;
    return NormalizeUsername(displayName);
}

public sealed record RegisterRequest(string? Username, string Password, string? Email = null, string? DisplayName = null);
public sealed record LoginRequest(string? Username, string Password, string? Email = null, string? DisplayName = null);
public sealed record SessionResponse(Guid UserId, string Username, string Token);
public sealed record VaultSnapshotRequest(string Ciphertext, string Nonce, string Salt, string? Algorithm, string? Kdf, long? BaseRevision);
public sealed record VaultSnapshotResponse(long Revision, string Ciphertext, string Nonce, string Salt, string Algorithm, string Kdf, DateTime UpdatedAt);
public sealed record AuthenticatedUser(Guid UserId, string Username, Guid? DeviceId = null);
public sealed record DeviceContext(Guid DeviceId, string DeviceName);

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
              device_id uuid not null,
              device_name text not null,
              created_at timestamptz not null default now(),
              last_seen_at timestamptz not null default now(),
              expires_at timestamptz not null
            );
            create table if not exists trusted_devices (
              user_id uuid not null references users(id) on delete cascade,
              device_id uuid not null,
              device_name text not null,
              created_at timestamptz not null default now(),
              last_seen_at timestamptz not null default now(),
              revoked_at timestamptz null,
              primary key (user_id, device_id)
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
            alter table sessions add column if not exists device_id uuid;
            alter table sessions add column if not exists device_name text;
            alter table sessions add column if not exists last_seen_at timestamptz not null default now();
            delete from sessions where device_id is null or device_name is null;
            alter table sessions alter column device_id set not null;
            alter table sessions alter column device_name set not null;
            """);
        await command.ExecuteNonQueryAsync();
    }
}

public static class Sessions
{
    public static async Task<string> CreateAsync(NpgsqlDataSource db, Guid userId, DeviceContext? device)
    {
        var resolvedDevice = device ?? new DeviceContext(Guid.NewGuid(), "Unknown device");
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToBase64String(tokenBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        await using (var deviceUpsert = db.CreateCommand("""
            insert into trusted_devices (user_id, device_id, device_name, created_at, last_seen_at, revoked_at)
            values ($1, $2, $3, now(), now(), null)
            on conflict (user_id, device_id) do update set
              device_name = excluded.device_name,
              revoked_at = null,
              last_seen_at = now()
            """))
        {
            deviceUpsert.Parameters.AddWithValue(userId);
            deviceUpsert.Parameters.AddWithValue(resolvedDevice.DeviceId);
            deviceUpsert.Parameters.AddWithValue(resolvedDevice.DeviceName);
            await deviceUpsert.ExecuteNonQueryAsync();
        }
        await using var command = db.CreateCommand("insert into sessions (token_hash, user_id, device_id, device_name, last_seen_at, expires_at) values ($1, $2, $3, $4, now(), now() + interval '30 days')");
        command.Parameters.AddWithValue(tokenHash);
        command.Parameters.AddWithValue(userId);
        command.Parameters.AddWithValue(resolvedDevice.DeviceId);
        command.Parameters.AddWithValue(resolvedDevice.DeviceName);
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
            select u.id, u.username, s.device_id
            from sessions s join users u on u.id = s.user_id
            where s.token_hash = $1 and s.expires_at > now()
            """);
        command.Parameters.AddWithValue(tokenHash);
        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null;
        var user = new AuthenticatedUser(reader.GetGuid(0), reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetGuid(2));
        await reader.DisposeAsync();
        await using (var touchSession = db.CreateCommand("update sessions set last_seen_at = now() where token_hash = $1"))
        {
            touchSession.Parameters.AddWithValue(tokenHash);
            await touchSession.ExecuteNonQueryAsync();
        }
        if (user.DeviceId is Guid deviceId)
        {
            await using var touchDevice = db.CreateCommand("update trusted_devices set last_seen_at = now() where user_id = $1 and device_id = $2 and revoked_at is null");
            touchDevice.Parameters.AddWithValue(user.UserId);
            touchDevice.Parameters.AddWithValue(deviceId);
            await touchDevice.ExecuteNonQueryAsync();
        }
        return user;
    }
}

public static class Devices
{
    public static DeviceContext? FromRequest(HttpRequest request)
    {
        var rawId = request.Headers["X-OpenFormVault-Device-Id"].ToString().Trim();
        var rawName = request.Headers["X-OpenFormVault-Device-Name"].ToString().Trim();
        if (!Guid.TryParse(rawId, out var deviceId)) return null;
        var deviceName = string.IsNullOrWhiteSpace(rawName) ? "OpenFormVault device" : rawName[..Math.Min(rawName.Length, 80)];
        return new DeviceContext(deviceId, deviceName);
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

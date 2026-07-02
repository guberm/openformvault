using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace OpenFormVault.Windows;

public sealed partial class MainWindow : Window
{
    private const int Pbkdf2Iterations = 310_000;
    private static readonly HttpClient HttpClient = new() { Timeout = TimeSpan.FromSeconds(15) };
    private static readonly JsonSerializerOptions VaultJsonOptions = new(JsonSerializerDefaults.Web);

    private readonly TextBlock _statusText = new() { Text = "Ready to sign in or create an account.", TextWrapping = TextWrapping.Wrap, Opacity = 0.92 };
    private readonly TextBox _serverBox = new() { Header = "Server", Text = "https://openformvault.guber.dev" };
    private readonly TextBox _usernameBox = new() { Header = "Email or username", PlaceholderText = "you@example.com" };
    private readonly PasswordBox _passwordBox = new() { Header = "Master password", PasswordRevealMode = PasswordRevealMode.Hidden };
    private readonly PasswordBox _confirmPasswordBox = new() { Header = "Confirm master password", PasswordRevealMode = PasswordRevealMode.Hidden, Visibility = Visibility.Collapsed };
    private readonly CheckBox _showAuthPasswordsBox = new() { Content = "Show passwords" };
    private readonly Button _loginButton = new() { Content = "Log in", HorizontalAlignment = HorizontalAlignment.Left };
    private readonly Button _createAccountButton = new() { Content = "Create account", HorizontalAlignment = HorizontalAlignment.Left };
    private readonly Button _backToLoginButton = new() { Content = "Back to sign in", HorizontalAlignment = HorizontalAlignment.Left, Visibility = Visibility.Collapsed };
    private readonly TextBlock _authTitle = Section("Sign in");
    private Border? _authCard;
    private readonly TextBox _titleBox = new() { Header = "Title" };
    private readonly ComboBox _itemTypeBox = new() { Header = "Item type" };
    private readonly TextBox _folderBox = new() { Header = "Folder" };
    private readonly CheckBox _pinnedBox = new() { Content = "Pinned" };
    private readonly TextBox _urlBox = new() { Header = "URL" };
    private readonly TextBox _loginUsernameBox = new() { Header = "Login username" };
    private readonly TextBox _searchBox = new() { Header = "Search vault", PlaceholderText = "Search logins, websites, usernames" };
    private readonly PasswordBox _loginPasswordBox = new() { Header = "Login password" };
    private readonly TextBox _identityFullNameBox = new() { Header = "Identity full name" };
    private readonly TextBox _identityEmailBox = new() { Header = "Identity email" };
    private readonly TextBox _identityPhoneBox = new() { Header = "Identity phone" };
    private readonly TextBox _identityAddressBox = new() { Header = "Identity address", AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 72 };
    private readonly TextBox _bookmarkDescriptionBox = new() { Header = "Bookmark description", AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 72 };
    private readonly TextBox _otpSecretBox = new() { Header = "OTP/TOTP secret (Base32, optional)" };
    private readonly TextBox _passkeyRpIdBox = new() { Header = "Passkey RP ID (optional)" };
    private readonly TextBox _passkeyCredentialIdBox = new() { Header = "Passkey credential ID (optional)" };
    private readonly TextBox _notesBox = new() { Header = "Notes", AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 72 };
    private readonly TextBox _importBox = new() { Header = "RoboForm/CSV import", AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 96, PlaceholderText = "Paste CSV with Name, URL, Login, Password, Note, Folder, TOTP" };
    private readonly ComboBox _themeBox = new() { Header = "Theme" };
    private readonly ComboBox _startupBox = new() { Header = "Startup screen" };
    private readonly ComboBox _autoLockBox = new() { Header = "Auto-lock" };
    private readonly TextBlock _trustedDevicesText = new() { TextWrapping = TextWrapping.Wrap, Opacity = 0.78 };
    private readonly StackPanel _itemsPanel = new() { Spacing = 8 };
    private readonly StackPanel _authPanel = new() { Spacing = 12 };
    private readonly StackPanel _vaultPanel = new() { Spacing = 12 };
    private readonly StackPanel _formPanel = new() { Spacing = 12, Visibility = Visibility.Collapsed };
    private readonly StackPanel _settingsPanel = new() { Spacing = 12, Visibility = Visibility.Collapsed };

    private readonly List<LoginItem> _items = [];
    private readonly HashSet<Guid> _revealedPasswords = [];
    private string _token = string.Empty;
    private string _masterPassword = string.Empty;
    private long _revision;
    private string? _salt;
    private Guid? _editingItemId;
    private bool _registerMode;
    private Guid _deviceId = Guid.Empty;
    private string _deviceName = Environment.MachineName;
    private DateTimeOffset? _lastActivatedAt;

    public MainWindow()
    {
        // Build the visual tree in code instead of loading MainWindow.xaml. The unpackaged
        // WinUI publish path on the Windows test host was crashing inside LoadComponent
        // with a generic XamlParseException before any user code could run.
        Title = "OpenFormVault";
        _deviceId = LoadOrCreateDeviceId();
        _deviceName = LoadOrCreateDeviceName();
        Activated += OnActivated;
        Content = BuildContent();
        RenderItems();
        _ = CheckServerHealthAsync();
    }

    private string ServerUrl => _serverBox.Text.Trim().TrimEnd('/');

    private ScrollViewer BuildContent()
    {
        var root = new StackPanel { Margin = new Thickness(40, 36, 40, 36), Spacing = 16, MaxWidth = 760, HorizontalAlignment = HorizontalAlignment.Left };
        root.Children.Add(new TextBlock { Text = "OpenFormVault", FontSize = 34, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        root.Children.Add(new TextBlock { Text = "Private password vault for logins, passkeys, authenticator codes, and secure notes.", TextWrapping = TextWrapping.Wrap, Opacity = 0.76, MaxWidth = 620 });
        var statusCard = new Border { Padding = new Thickness(12, 10, 12, 10), CornerRadius = new CornerRadius(12), Background = new SolidColorBrush(Colors.AliceBlue), Child = _statusText, MaxWidth = 620 };
        root.Children.Add(statusCard);

        _authPanel.Spacing = 10;
        _authPanel.Children.Add(_authTitle);
        _authPanel.Children.Add(new TextBlock { Text = "Server", Opacity = 0.70 });
        _authPanel.Children.Add(_serverBox);
        _authPanel.Children.Add(_usernameBox);
        _authPanel.Children.Add(_passwordBox);
        _authPanel.Children.Add(_confirmPasswordBox);
        _showAuthPasswordsBox.Checked += (_, _) => SetPasswordReveal(true);
        _showAuthPasswordsBox.Unchecked += (_, _) => SetPasswordReveal(false);
        _authPanel.Children.Add(_showAuthPasswordsBox);
        var accountButtons = new StackPanel { Orientation = Orientation.Vertical, Spacing = 10 };
        _loginButton.Click += async (_, _) => await RunAsync(() => AuthenticateAsync(register: false));
        _createAccountButton.Click += async (_, _) => { if (_registerMode) await RunAsync(() => AuthenticateAsync(register: true)); else ShowRegister(); };
        _backToLoginButton.Click += (_, _) => ShowLogin();
        StyleAuthPrimary(_loginButton);
        StyleAuthPrimary(_createAccountButton);
        StyleAuthSecondary(_backToLoginButton);
        accountButtons.Children.Add(_loginButton);
        accountButtons.Children.Add(_createAccountButton);
        accountButtons.Children.Add(_backToLoginButton);
        _authPanel.Children.Add(accountButtons);
        _authCard = new Border { Padding = new Thickness(24), CornerRadius = new CornerRadius(18), BorderThickness = new Thickness(1), BorderBrush = new SolidColorBrush(Colors.LightGray), Background = new SolidColorBrush(Colors.White), Child = _authPanel, MaxWidth = 560 };
        root.Children.Add(_authCard);

        var vaultHeader = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        vaultHeader.Children.Add(Button("+ Add", () => ShowForm(clear: true)));
        vaultHeader.Children.Add(Button("Settings", ToggleSettings));
        _searchBox.TextChanged += (_, _) => RenderItems();
        _vaultPanel.Children.Add(Section("Vault"));
        _vaultPanel.Children.Add(vaultHeader);
        _vaultPanel.Children.Add(_searchBox);
        _vaultPanel.Children.Add(_itemsPanel);
        root.Children.Add(_vaultPanel);

        _itemTypeBox.Items.Add("login"); _itemTypeBox.Items.Add("identity"); _itemTypeBox.Items.Add("note"); _itemTypeBox.Items.Add("bookmark"); _itemTypeBox.Items.Add("passkey"); _itemTypeBox.SelectedItem = "login";
        _formPanel.Children.Add(Section("Add or edit item"));
        _formPanel.Children.Add(_itemTypeBox);
        _formPanel.Children.Add(_folderBox);
        _formPanel.Children.Add(_pinnedBox);
        _formPanel.Children.Add(_titleBox);
        _formPanel.Children.Add(_urlBox);
        _formPanel.Children.Add(_loginUsernameBox);
        _formPanel.Children.Add(_loginPasswordBox);
        _formPanel.Children.Add(_identityFullNameBox);
        _formPanel.Children.Add(_identityEmailBox);
        _formPanel.Children.Add(_identityPhoneBox);
        _formPanel.Children.Add(_identityAddressBox);
        _formPanel.Children.Add(_bookmarkDescriptionBox);
        _formPanel.Children.Add(new TextBlock { Text = "More fields", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, Opacity = 0.78 });
        _formPanel.Children.Add(_otpSecretBox);
        _formPanel.Children.Add(_passkeyRpIdBox);
        _formPanel.Children.Add(_passkeyCredentialIdBox);
        _formPanel.Children.Add(_notesBox);
        var formButtons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        formButtons.Children.Add(Button("Save", SaveLogin));
        formButtons.Children.Add(Button("Generate password", GeneratePassword));
        formButtons.Children.Add(Button("Cancel", () => { ClearForm(); ShowVault(); }));
        _formPanel.Children.Add(formButtons);
        root.Children.Add(_formPanel);

        _settingsPanel.Children.Add(Section("Settings"));
        _startupBox.Items.Add("Vault"); _startupBox.Items.Add("Add item"); _startupBox.Items.Add("Settings"); _startupBox.SelectedItem = LoadSetting("startupScreen", "Vault");
        _settingsPanel.Children.Add(_startupBox);
        _autoLockBox.Items.Add("Off"); _autoLockBox.Items.Add("30 sec"); _autoLockBox.Items.Add("1 min"); _autoLockBox.Items.Add("5 min"); _autoLockBox.SelectedItem = LoadSetting("autoLock", "Off");
        _settingsPanel.Children.Add(_autoLockBox);
        _themeBox.Items.Add("System"); _themeBox.Items.Add("Light"); _themeBox.Items.Add("Dark"); _themeBox.SelectedIndex = 0;
        _settingsPanel.Children.Add(_themeBox);
        var miscButtons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        miscButtons.Children.Add(Button("Apply theme", ApplyTheme));
        miscButtons.Children.Add(Button("Save startup", SaveStartupScreen));
        miscButtons.Children.Add(Button("Save auto-lock", SaveAutoLock));
        miscButtons.Children.Add(Button("Security report", ShowSecurityReport));
        miscButtons.Children.Add(Button("Lock", Lock));
        _settingsPanel.Children.Add(miscButtons);
        var syncButtons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        syncButtons.Children.Add(Button("Test connection", async () => await RunAsync(CheckServerHealthAsync)));
        syncButtons.Children.Add(Button("Sync now", async () => await RunAsync(PullAsync)));
        syncButtons.Children.Add(Button("Force upload", async () => await RunAsync(PushAsync)));
        syncButtons.Children.Add(Button("Trusted devices", async () => await RunAsync(LoadTrustedDevicesAsync)));
        _settingsPanel.Children.Add(syncButtons);
        _settingsPanel.Children.Add(_trustedDevicesText);
        _settingsPanel.Children.Add(new TextBlock { Text = "Import from RoboForm / CSV", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, Opacity = 0.78 });
        _settingsPanel.Children.Add(_importBox);
        var importButtons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        importButtons.Children.Add(Button("Preview import", PreviewImport));
        importButtons.Children.Add(Button("Import and sync", ImportCsv));
        _settingsPanel.Children.Add(importButtons);
        root.Children.Add(_settingsPanel);

        ShowLogin();
        return new ScrollViewer { Content = root };
    }

    private void OnActivated(object sender, WindowActivatedEventArgs args)
    {
        if (args.WindowActivationState == WindowActivationState.Deactivated)
        {
            _lastActivatedAt = DateTimeOffset.UtcNow;
            return;
        }
        var delay = AutoLockDelay();
        if (delay <= TimeSpan.Zero || _lastActivatedAt is null || string.IsNullOrWhiteSpace(_masterPassword)) return;
        if (DateTimeOffset.UtcNow - _lastActivatedAt.Value >= delay)
        {
            Lock();
            _statusText.Text = "Auto-locked after inactivity.";
        }
    }

    private void ShowAuth()
    {
        _authPanel.Visibility = Visibility.Visible;
        _vaultPanel.Visibility = Visibility.Collapsed;
        _formPanel.Visibility = Visibility.Collapsed;
        _settingsPanel.Visibility = Visibility.Collapsed;
    }

    private void ShowLogin()
    {
        _registerMode = false;
        _authTitle.Text = "Sign in";
        _statusText.Text = "Ready to sign in or create an account.";
        _confirmPasswordBox.Visibility = Visibility.Collapsed;
        _loginButton.Visibility = Visibility.Visible;
        _backToLoginButton.Visibility = Visibility.Collapsed;
        ShowAuth();
    }

    private void ShowRegister()
    {
        _registerMode = true;
        _authTitle.Text = "Create account";
        _statusText.Text = "Create a new account to start your private vault.";
        _confirmPasswordBox.Visibility = Visibility.Visible;
        _loginButton.Visibility = Visibility.Collapsed;
        _backToLoginButton.Visibility = Visibility.Visible;
        ShowAuth();
    }

    private void SetPasswordReveal(bool visible)
    {
        _passwordBox.PasswordRevealMode = visible ? PasswordRevealMode.Visible : PasswordRevealMode.Hidden;
        _confirmPasswordBox.PasswordRevealMode = visible ? PasswordRevealMode.Visible : PasswordRevealMode.Hidden;
    }

    private void ShowVault()
    {
        _authPanel.Visibility = Visibility.Collapsed;
        _vaultPanel.Visibility = Visibility.Visible;
        _formPanel.Visibility = Visibility.Collapsed;
        _settingsPanel.Visibility = Visibility.Collapsed;
    }

    private void ShowStartupDestination()
    {
        var startup = (_startupBox.SelectedItem as string) ?? LoadSetting("startupScreen", "Vault");
        if (startup == "Add item")
        {
            ShowForm(clear: true);
            return;
        }
        if (startup == "Settings")
        {
            _authPanel.Visibility = Visibility.Collapsed;
            _vaultPanel.Visibility = Visibility.Visible;
            _formPanel.Visibility = Visibility.Collapsed;
            _settingsPanel.Visibility = Visibility.Visible;
            return;
        }
        ShowVault();
    }

    private void ShowForm(bool clear = false)
    {
        if (clear) ClearForm();
        _authPanel.Visibility = Visibility.Collapsed;
        _vaultPanel.Visibility = Visibility.Visible;
        _formPanel.Visibility = Visibility.Visible;
        _settingsPanel.Visibility = Visibility.Collapsed;
    }

    private void ToggleSettings()
    {
        _authPanel.Visibility = Visibility.Collapsed;
        _vaultPanel.Visibility = Visibility.Visible;
        _formPanel.Visibility = Visibility.Collapsed;
        _settingsPanel.Visibility = _settingsPanel.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible;
    }

    private static TextBlock Section(string text) => new() { Text = text, FontSize = 22, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, Margin = new Thickness(0, 6, 0, 4) };

    private static Button Button(string content, Action action)
    {
        var button = new Button { Content = content, HorizontalAlignment = HorizontalAlignment.Left, MinHeight = 40 };
        button.Click += (_, _) => action();
        return button;
    }

    private static Button Button(string content, Func<Task> action)
    {
        var button = new Button { Content = content, MinHeight = 40 };
        button.Click += async (_, _) => await action();
        return button;
    }

    private static void StyleAuthPrimary(Button button)
    {
        button.HorizontalAlignment = HorizontalAlignment.Stretch;
        button.MinWidth = 220;
    }

    private static void StyleAuthSecondary(Button button)
    {
        button.HorizontalAlignment = HorizontalAlignment.Stretch;
        button.MinWidth = 220;
    }

    private void Lock()
    {
        _token = string.Empty;
        _masterPassword = string.Empty;
        _items.Clear();
        RenderItems();
        _trustedDevicesText.Text = string.Empty;
        _statusText.Text = "Locked.";
        ShowLogin();
    }

    private async void SaveLogin()
    {
        if (string.IsNullOrWhiteSpace(_masterPassword))
        {
            _statusText.Text = "Log in first.";
            return;
        }

        var passkey = string.IsNullOrWhiteSpace(_passkeyRpIdBox.Text) && string.IsNullOrWhiteSpace(_passkeyCredentialIdBox.Text)
            ? null
            : new PasskeyItem(_passkeyRpIdBox.Text.Trim(), _passkeyCredentialIdBox.Text.Trim(), string.Empty);
        var type = (_itemTypeBox.SelectedItem as string) ?? "login";
        var now = DateTimeOffset.UtcNow;
        var prior = _editingItemId is Guid editingId ? _items.FirstOrDefault(x => x.Id == editingId) : null;
        var item = new LoginItem(
            _editingItemId ?? Guid.NewGuid(),
            type,
            _titleBox.Text.Trim(),
            _urlBox.Text.Trim(),
            _loginUsernameBox.Text.Trim(),
            _loginPasswordBox.Password,
            _otpSecretBox.Text.Trim().Replace(" ", string.Empty),
            _notesBox.Text,
            _folderBox.Text.Trim(),
            _pinnedBox.IsChecked == true,
            _identityFullNameBox.Text.Trim(),
            _identityEmailBox.Text.Trim(),
            _identityPhoneBox.Text.Trim(),
            _identityAddressBox.Text.Trim(),
            _bookmarkDescriptionBox.Text.Trim(),
            passkey,
            prior?.CreatedAt ?? now,
            now,
            prior?.LastUsedAt);
        var existing = _items.FindIndex(x => x.Id == item.Id);
        if (existing >= 0) _items[existing] = item;
        else _items.Add(item);
        ClearForm();
        RenderItems();
        ShowVault();
        await AutoPushAsync(existing >= 0 ? "Item updated. Auto-syncing…" : "Item saved. Auto-syncing…");
    }


    private void GeneratePassword()
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+";
        Span<byte> bytes = stackalloc byte[24];
        RandomNumberGenerator.Fill(bytes);
        _loginPasswordBox.Password = new string(bytes.ToArray().Select(b => alphabet[b % alphabet.Length]).ToArray());
        _statusText.Text = "Generated a strong password.";
    }

    private void ApplyTheme()
    {
        _statusText.Text = $"Theme set to {_themeBox.SelectedItem ?? "System"}.";
    }

    private void SaveStartupScreen()
    {
        SaveSetting("startupScreen", (_startupBox.SelectedItem as string) ?? "Vault");
        _statusText.Text = $"Startup screen set to {_startupBox.SelectedItem ?? "Vault"}.";
    }

    private void SaveAutoLock()
    {
        SaveSetting("autoLock", (_autoLockBox.SelectedItem as string) ?? "Off");
        _statusText.Text = $"Auto-lock set to {_autoLockBox.SelectedItem ?? "Off"}.";
    }

    private TimeSpan AutoLockDelay()
    {
        return ((_autoLockBox.SelectedItem as string) ?? LoadSetting("autoLock", "Off")) switch
        {
            "30 sec" => TimeSpan.FromSeconds(30),
            "1 min" => TimeSpan.FromMinutes(1),
            "5 min" => TimeSpan.FromMinutes(5),
            _ => TimeSpan.Zero
        };
    }

    private void ShowSecurityReport()
    {
        var weak = _items.Count(x => x.Password.Length < 12);
        var missingOtp = _items.Count(x => string.IsNullOrWhiteSpace(x.OtpSecret));
        var httpOnly = _items.Count(x => x.Url.StartsWith("http://", StringComparison.OrdinalIgnoreCase));
        var reused = _items.GroupBy(x => x.Password).Where(g => !string.IsNullOrWhiteSpace(g.Key) && g.Count() > 1).Sum(g => g.Count());
        _statusText.Text = $"Security: {weak} weak, {reused} reused, {httpOnly} HTTP-only, {missingOtp} missing OTP.";
    }

    private void ClearForm()
    {
        _editingItemId = null;
        _itemTypeBox.SelectedItem = "login";
        _folderBox.Text = string.Empty;
        _pinnedBox.IsChecked = false;
        _titleBox.Text = _urlBox.Text = _loginUsernameBox.Text = _otpSecretBox.Text = _passkeyRpIdBox.Text = _passkeyCredentialIdBox.Text = _notesBox.Text = string.Empty;
        _identityFullNameBox.Text = _identityEmailBox.Text = _identityPhoneBox.Text = _identityAddressBox.Text = _bookmarkDescriptionBox.Text = string.Empty;
        _loginPasswordBox.Password = string.Empty;
    }

    private void EditLogin(LoginItem item)
    {
        _editingItemId = item.Id;
        _itemTypeBox.SelectedItem = item.Type;
        _folderBox.Text = item.Folder;
        _pinnedBox.IsChecked = item.Pinned;
        _titleBox.Text = item.Title;
        _urlBox.Text = item.Url;
        _loginUsernameBox.Text = item.Username;
        _loginPasswordBox.Password = item.Password;
        _identityFullNameBox.Text = item.IdentityFullName;
        _identityEmailBox.Text = item.IdentityEmail;
        _identityPhoneBox.Text = item.IdentityPhone;
        _identityAddressBox.Text = item.IdentityAddress;
        _bookmarkDescriptionBox.Text = item.BookmarkDescription;
        _otpSecretBox.Text = item.OtpSecret;
        _notesBox.Text = item.Notes;
        _passkeyRpIdBox.Text = item.Passkey?.RpId ?? string.Empty;
        _passkeyCredentialIdBox.Text = item.Passkey?.CredentialId ?? string.Empty;
        _statusText.Text = $"Editing {item.Title}.";
        ShowForm();
    }

    private async Task AutoPushAsync(string message)
    {
        _statusText.Text = message;
        if (string.IsNullOrWhiteSpace(_token) || string.IsNullOrWhiteSpace(_masterPassword)) return;
        await RunAsync(PushAsync);
    }

    private async Task CheckServerHealthAsync()
    {
        _statusText.Text = "Checking connection…";
        using var response = await HttpClient.GetAsync($"{ServerUrl}/health");
        var body = await response.Content.ReadAsStringAsync();
        _statusText.Text = response.IsSuccessStatusCode ? "Connected to OpenFormVault." : $"Connection failed: HTTP {(int)response.StatusCode}.";
    }

    private async Task AuthenticateAsync(bool register)
    {
        _masterPassword = _passwordBox.Password;
        if (register && _masterPassword != _confirmPasswordBox.Password) throw new InvalidOperationException("Passwords do not match.");
        var payload = JsonSerializer.Serialize(new { username = _usernameBox.Text.Trim(), password = _masterPassword });
        var result = await JsonAsync<SessionResponse>(register ? "/v1/users/register" : "/v1/session", HttpMethod.Post, payload, auth: false);
        _token = result.Token;
        try
        {
            await PullAsync();
            await LoadTrustedDevicesAsync();
        }
        catch
        {
            _statusText.Text = "Signed in. Add your first login; it will sync automatically.";
            ShowStartupDestination();
        }
    }

    private async Task PullAsync()
    {
        EnsureLoggedIn();
        var snapshot = await JsonAsync<VaultSnapshotResponse>("/v1/vault/snapshot", HttpMethod.Get, body: null, auth: true);
        DecryptSnapshot(snapshot);
        _revision = snapshot.Revision;
        RenderItems();
        _statusText.Text = $"Pulled revision {_revision}.";
        ShowStartupDestination();
    }

    private async Task PushAsync()
    {
        EnsureLoggedIn();
        var encrypted = EncryptSnapshot();
        var payload = JsonSerializer.Serialize(new
        {
            encrypted.Ciphertext,
            encrypted.Nonce,
            encrypted.Salt,
            encrypted.Algorithm,
            encrypted.Kdf,
            BaseRevision = _revision == 0 ? null : (long?)_revision
        });
        var result = await JsonAsync<RevisionResponse>("/v1/vault/snapshot", HttpMethod.Put, payload, auth: true);
        _revision = result.Revision;
        _statusText.Text = $"Pushed revision {_revision}.";
    }

    private async Task<T> JsonAsync<T>(string path, HttpMethod method, string? body, bool auth)
    {
        using var request = new HttpRequestMessage(method, $"{ServerUrl}{path}");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Add("X-OpenFormVault-Device-Id", _deviceId.ToString());
        request.Headers.Add("X-OpenFormVault-Device-Name", _deviceName);
        if (auth) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        using var response = await HttpClient.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"HTTP {(int)response.StatusCode}: {text}");
        return JsonSerializer.Deserialize<T>(text, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? throw new InvalidOperationException("Empty response.");
    }

    private async Task LoadTrustedDevicesAsync()
    {
        EnsureLoggedIn();
        var response = await JsonAsync<TrustedDevicesResponse>("/v1/devices", HttpMethod.Get, body: null, auth: true);
        _trustedDevicesText.Text = response.Devices is { Count: > 0 }
            ? string.Join("\n", response.Devices.Select(device => $"{device.DeviceName}{(device.Current ? " (this device)" : string.Empty)}"))
            : "No trusted devices yet.";
    }

    private Guid LoadOrCreateDeviceId()
    {
        var text = LoadSetting("deviceId", string.Empty);
        if (Guid.TryParse(text, out var existing)) return existing;
        var created = Guid.NewGuid();
        SaveSetting("deviceId", created.ToString());
        return created;
    }

    private string LoadOrCreateDeviceName()
    {
        var value = LoadSetting("deviceName", string.Empty);
        if (!string.IsNullOrWhiteSpace(value)) return value;
        value = Environment.MachineName;
        SaveSetting("deviceName", value);
        return value;
    }

    private string LoadSetting(string key, string fallback)
    {
        if (App.Current is App app && app.LocalSettings.Values.TryGetValue(key, out var text) && !string.IsNullOrWhiteSpace(text)) return text;
        return fallback;
    }

    private void SaveSetting(string key, string value)
    {
        if (App.Current is App app)
        {
            app.LocalSettings.Values[key] = value;
            app.LocalSettings.Save();
        }
    }

    private EncryptedSnapshot EncryptSnapshot()
    {
        var saltBytes = _salt is null ? RandomNumberGenerator.GetBytes(16) : Convert.FromBase64String(_salt);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var key = Rfc2898DeriveBytes.Pbkdf2(_masterPassword, saltBytes, Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
        var plaintext = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new VaultData(_items), VaultJsonOptions));
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        _salt = Convert.ToBase64String(saltBytes);
        return new EncryptedSnapshot(Convert.ToBase64String(ciphertext.Concat(tag).ToArray()), Convert.ToBase64String(nonce), _salt, "AES-GCM", "PBKDF2-SHA256-310000");
    }

    private void DecryptSnapshot(VaultSnapshotResponse snapshot)
    {
        var combined = Convert.FromBase64String(snapshot.Ciphertext);
        var ciphertext = combined[..^16];
        var tag = combined[^16..];
        var nonce = Convert.FromBase64String(snapshot.Nonce);
        var key = Rfc2898DeriveBytes.Pbkdf2(_masterPassword, Convert.FromBase64String(snapshot.Salt), Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, tag.Length);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        var data = JsonSerializer.Deserialize<VaultData>(Encoding.UTF8.GetString(plaintext), VaultJsonOptions);
        _items.Clear();
        if (data?.Items is not null) _items.AddRange(data.Items);
        _salt = snapshot.Salt;
    }

    private void RenderItems()
    {
        _itemsPanel.Children.Clear();
        var query = _searchBox.Text?.Trim() ?? string.Empty;
        var visibleItems = _items.Where(item => string.IsNullOrWhiteSpace(query) || $"{item.Type} {item.Title} {item.Url} {item.Username} {item.Notes} {item.Folder} {item.IdentityFullName} {item.IdentityEmail} {item.IdentityPhone} {item.IdentityAddress} {item.BookmarkDescription}".Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (_items.Count == 0)
        {
            _itemsPanel.Children.Add(new TextBlock { Text = "No saved items yet. Click + Add to add one." });
            return;
        }
        if (visibleItems.Length == 0)
        {
            _itemsPanel.Children.Add(new TextBlock { Text = "No matching items." });
            return;
        }

        foreach (var item in visibleItems)
        {
            var panel = new StackPanel { Spacing = 6, Margin = new Thickness(8) };
            panel.Children.Add(new TextBlock { Text = item.Title, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            panel.Children.Add(new TextBlock { Text = SummaryText(item), TextWrapping = TextWrapping.Wrap });
            if (!string.IsNullOrWhiteSpace(item.Folder) || item.Pinned)
            {
                panel.Children.Add(new TextBlock { Text = $"{(item.Folder.Length > 0 ? $"Folder: {item.Folder}" : string.Empty)}{(item.Folder.Length > 0 && item.Pinned ? " · " : string.Empty)}{(item.Pinned ? "Pinned" : string.Empty)}", Opacity = 0.78, TextWrapping = TextWrapping.Wrap });
            }
            var secret = new TextBlock
            {
                Text = _revealedPasswords.Contains(item.Id) ? SecretText(item) : "Secret hidden",
                TextWrapping = TextWrapping.Wrap,
                FontFamily = new FontFamily("Consolas")
            };
            panel.Children.Add(secret);
            var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            row.Children.Add(Button(_revealedPasswords.Contains(item.Id) ? "Hide" : "View", () =>
            {
                if (!_revealedPasswords.Add(item.Id)) _revealedPasswords.Remove(item.Id);
                else if (item.Type is "login" or "passkey") MarkLastUsed(item.Id);
                RenderItems();
            }));
            row.Children.Add(Button("Edit", () => EditLogin(item)));
            if (!string.IsNullOrWhiteSpace(item.OtpSecret)) row.Children.Add(Button("Show OTP", () => _statusText.Text = $"OTP for {item.Title}: {GenerateTotp(item.OtpSecret)}"));
            var delete = new Button { Content = "Delete" };
            delete.Click += async (_, _) => { _items.Remove(item); RenderItems(); await AutoPushAsync("Deleted. Auto-syncing…"); };
            row.Children.Add(delete);
            panel.Children.Add(row);
            _itemsPanel.Children.Add(new Border
            {
                BorderBrush = new SolidColorBrush(Colors.Gray),
                BorderThickness = new Thickness(1),
                Child = panel
            });
        }
    }

    private static string SummaryText(LoginItem item) => item.Type switch
    {
        "identity" => $"{item.IdentityFullName}\n{item.IdentityEmail}\n{item.IdentityPhone}".Trim(),
        "note" => string.IsNullOrWhiteSpace(item.Notes) ? "Encrypted note" : item.Notes,
        "bookmark" => $"{item.Url}\n{item.BookmarkDescription}".Trim(),
        _ => $"{item.Url} — {item.Username}{(string.IsNullOrWhiteSpace(item.OtpSecret) ? string.Empty : "\nOTP enabled")}{(string.IsNullOrWhiteSpace(item.Passkey?.CredentialId) ? string.Empty : $"\nPasskey: {item.Passkey.RpId}")}".Trim()
    };

    private static string SecretText(LoginItem item) => item.Type switch
    {
        "identity" => $"Full name: {item.IdentityFullName}\nEmail: {item.IdentityEmail}\nPhone: {item.IdentityPhone}\nAddress: {item.IdentityAddress}",
        "note" => $"Safenote:\n{item.Notes}",
        "bookmark" => $"Bookmark: {item.Url}\n{item.BookmarkDescription}".Trim(),
        _ => $"Password: {item.Password}"
    };

    private void MarkLastUsed(Guid id)
    {
        var index = _items.FindIndex(x => x.Id == id);
        if (index < 0) return;
        _items[index] = _items[index] with { LastUsedAt = DateTimeOffset.UtcNow };
    }

    private void PreviewImport()
    {
        var parsed = ParseCsvImport(_importBox.Text).ToList();
        _statusText.Text = $"{parsed.Count} importable item(s): " + string.Join(", ", parsed.Take(5).Select(x => x.Title));
    }

    private async void ImportCsv()
    {
        var imported = ParseCsvImport(_importBox.Text).ToList();
        var existing = _items.Select(x => $"{x.Url}|{x.Username}|{x.Title}").ToHashSet(StringComparer.OrdinalIgnoreCase);
        var fresh = imported.Where(x => existing.Add($"{x.Url}|{x.Username}|{x.Title}")).ToList();
        _items.AddRange(fresh);
        RenderItems();
        await AutoPushAsync($"Imported {fresh.Count}; skipped {imported.Count - fresh.Count}. Auto-syncing…");
    }

    private static IEnumerable<LoginItem> ParseCsvImport(string csv)
    {
        var rows = ParseCsv(csv).ToList();
        if (rows.Count < 2) yield break;
        var headers = rows[0].Select(x => x.Trim().ToLowerInvariant()).ToList();
        foreach (var row in rows.Skip(1))
        {
            var record = headers.Select((h, i) => new { h, v = i < row.Count ? row[i] : string.Empty }).ToDictionary(x => x.h, x => x.v);
            var extra = row.Skip(headers.Count).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
            string Pick(params string[] names) => names.Select(n => record.TryGetValue(n.ToLowerInvariant(), out var v) ? v : string.Empty).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? string.Empty;
            var notes = string.Join("\n\n", new[] { Pick("note", "notes", "memo"), Pick("rffieldsv2", "rf fields v2", "roboform fields"), string.Join("\n", extra) }.Where(x => !string.IsNullOrWhiteSpace(x)));
            var item = new LoginItem(
                Guid.NewGuid(),
                "login",
                Pick("name", "title", "login name"),
                Pick("url", "matchurl", "match url", "web site", "website", "site"),
                Pick("login", "username", "user name", "user id"),
                Pick("password", "pwd", "pass"),
                Pick("totp", "otp", "otp secret", "authenticator key"),
                notes,
                Pick("folder"),
                false,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                null,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                null);
            item = ApplyRoboFormFieldFallback(Pick("rffieldsv2", "rf fields v2", "roboform fields"), extra, item);
            if (!string.IsNullOrWhiteSpace(item.Title + item.Url + item.Username + item.Password)) yield return item;
        }
    }

    private static LoginItem ApplyRoboFormFieldFallback(string rfFieldsV2, IReadOnlyCollection<string> extra, LoginItem item)
    {
        var fieldCells = new[] { rfFieldsV2 }.Concat(extra).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
        var password = item.Password;
        var username = item.Username;
        var otpSecret = item.OtpSecret;
        for (var i = 0; i + 4 < fieldCells.Count; i += 5)
        {
            var label = fieldCells[i].ToLowerInvariant();
            var htmlName = fieldCells[i + 2].ToLowerInvariant();
            var type = fieldCells[i + 3].ToLowerInvariant();
            var value = fieldCells[i + 4].Trim();
            var key = $"{label} {htmlName}";
            if (string.IsNullOrWhiteSpace(value)) continue;
            if (string.IsNullOrWhiteSpace(password) && (type == "pwd" || key.Contains("pass", StringComparison.OrdinalIgnoreCase))) password = value;
            else if (string.IsNullOrWhiteSpace(otpSecret) && (key.Contains("otp", StringComparison.OrdinalIgnoreCase) || key.Contains("totp", StringComparison.OrdinalIgnoreCase) || key.Contains("authenticator", StringComparison.OrdinalIgnoreCase) || key.Contains("verification", StringComparison.OrdinalIgnoreCase))) otpSecret = value.Replace(" ", string.Empty);
            else if (string.IsNullOrWhiteSpace(username) && (key.Contains("login", StringComparison.OrdinalIgnoreCase) || key.Contains("user", StringComparison.OrdinalIgnoreCase) || key.Contains("email", StringComparison.OrdinalIgnoreCase) || type == "email" || type == "txt")) username = value;
        }
        return item with { Username = username, Password = password, OtpSecret = otpSecret, UpdatedAt = DateTimeOffset.UtcNow };
    }

    private static List<List<string>> ParseCsv(string text)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var cell = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            var n = i + 1 < text.Length ? text[i + 1] : '\0';
            if (quoted && c == '"' && n == '"') { cell.Append('"'); i++; }
            else if (c == '"') quoted = !quoted;
            else if (!quoted && c == ',') { row.Add(cell.ToString()); cell.Clear(); }
            else if (!quoted && (c == '\n' || c == '\r'))
            {
                if (c == '\r' && n == '\n') i++;
                row.Add(cell.ToString()); cell.Clear();
                if (row.Any(x => !string.IsNullOrWhiteSpace(x))) rows.Add(row);
                row = [];
            }
            else cell.Append(c);
        }
        row.Add(cell.ToString());
        if (row.Any(x => !string.IsNullOrWhiteSpace(x))) rows.Add(row);
        return rows;
    }

    private static string GenerateTotp(string base32)
    {
        var key = Base32Decode(base32);
        var counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        Span<byte> msg = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(msg, counter);
        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(msg.ToArray());
        var offset = hash[^1] & 0x0f;
        var code = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (code % 1_000_000).ToString("D6");
    }

    private static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = new StringBuilder();
        foreach (var ch in input.ToUpperInvariant().Where(c => alphabet.Contains(c))) bits.Append(Convert.ToString(alphabet.IndexOf(ch), 2).PadLeft(5, '0'));
        var bytes = new List<byte>();
        for (var i = 0; i + 8 <= bits.Length; i += 8) bytes.Add(Convert.ToByte(bits.ToString(i, 8), 2));
        return bytes.ToArray();
    }

    private void EnsureLoggedIn()
    {
        if (string.IsNullOrWhiteSpace(_token) || string.IsNullOrWhiteSpace(_masterPassword)) throw new InvalidOperationException("Log in first.");
    }

    private async Task RunAsync(Func<Task> action)
    {
        try { await action(); }
        catch (Exception ex) { _statusText.Text = ex.Message; }
    }

    private sealed record SessionResponse(Guid UserId, string Username, string Token);
    private sealed record RevisionResponse(long Revision);
    private sealed record TrustedDevicesResponse(List<TrustedDevice> Devices);
    private sealed record TrustedDevice(Guid DeviceId, string DeviceName, DateTime CreatedAt, DateTime? LastSeenAt, bool Current);
    private sealed record VaultSnapshotResponse(long Revision, string Ciphertext, string Nonce, string Salt, string Algorithm, string Kdf, DateTime UpdatedAt);
    private sealed record EncryptedSnapshot(string Ciphertext, string Nonce, string Salt, string Algorithm, string Kdf);
    private sealed record VaultData(List<LoginItem> Items);
    private sealed record PasskeyItem(string RpId, string CredentialId, string UserHandle);
    private sealed record LoginItem(
        Guid Id,
        string Type,
        string Title,
        string Url,
        string Username,
        string Password,
        string OtpSecret = "",
        string Notes = "",
        string Folder = "",
        bool Pinned = false,
        string IdentityFullName = "",
        string IdentityEmail = "",
        string IdentityPhone = "",
        string IdentityAddress = "",
        string BookmarkDescription = "",
        PasskeyItem? Passkey = null,
        DateTimeOffset? CreatedAt = null,
        DateTimeOffset? UpdatedAt = null,
        DateTimeOffset? LastUsedAt = null);
}

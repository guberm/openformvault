using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.UI.Xaml;

namespace OpenFormVault.Windows;

public partial class App : Application
{
    private Window? _window;
    public LocalSettingsStore LocalSettings { get; } = new();

    public App()
    {
        InitializeComponent();
        UnhandledException += (_, e) => WriteLog($"UnhandledException: {e.Exception}\n");
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            WriteLog($"Launching at {DateTimeOffset.Now:O}\n");
            _window = new MainWindow();
            _window.Activate();
            WriteLog("Window activated.\n");
        }
        catch (Exception ex)
        {
            WriteLog($"Launch failed: {ex}\n");
            throw;
        }
    }

    private static string LogPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "OpenFormVault",
        "windows-app.log");

    private static void WriteLog(string message)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
        File.AppendAllText(LogPath, message);
    }
}

public sealed class LocalSettingsStore
{
    private readonly string _path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpenFormVault", "settings.json");
    public Dictionary<string, string> Values { get; }

    public LocalSettingsStore()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        if (File.Exists(_path))
        {
            try
            {
                Values = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(_path)) ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
            catch
            {
                Values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
        }
        else
        {
            Values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, System.Text.Json.JsonSerializer.Serialize(Values));
    }
}

using System;
using System.IO;
using Microsoft.UI.Xaml;

namespace OpenFormVault.Windows;

public partial class App : Application
{
    private Window? _window;

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

using Microsoft.Win32;
using static TwoPassword.App.UiText;

namespace TwoPassword.App;

/// <summary>
/// Per-user Explorer verbs under HKCU\Software\Classes. Windows 11 lists them under "Show more options".
/// Entries are owned by the executable they point to, so a portable copy and an installed copy never remove each other's.
/// </summary>
internal static class ExplorerMenu
{
    private const string Classes = @"Software\Classes\";
    private const string EncryptFiles = Classes + @"*\shell\2Password";
    private const string EncryptFolders = Classes + @"Directory\shell\2Password";
    private const string DecryptData = Classes + @"SystemFileAssociations\.2pw\shell\2Password";
    private static readonly string[] Keys = [EncryptFiles, EncryptFolders, DecryptData];

    internal static bool IsEnabled(string executable)
    {
        using var command = Registry.CurrentUser.OpenSubKey(EncryptFolders + @"\command");
        return IsEncryptCommand(command?.GetValue(null) as string, executable);
    }

    /// <summary>Writes every verb in the current interface language; call again after the language changes.</summary>
    internal static void Enable(string executable)
    {
        Write(EncryptFiles, L("用 2Password 加密"), executable, EncryptCommand(executable), multiSelect: true, excludeOwnFiles: true);
        Write(EncryptFolders, L("用 2Password 加密"), executable, EncryptCommand(executable), multiSelect: true);
        Write(DecryptData, L("用 2Password 解密"), executable, OpenCommand(executable));
    }

    internal static void Disable(string executable)
    {
        foreach (var key in Keys)
        {
            using var command = Registry.CurrentUser.OpenSubKey(key + @"\command");
            var current = command?.GetValue(null) as string;
            var owned = key == DecryptData
                ? string.Equals(current, OpenCommand(executable), StringComparison.OrdinalIgnoreCase)
                : IsEncryptCommand(current, executable);
            if (owned) Registry.CurrentUser.DeleteSubKeyTree(key, throwOnMissingSubKey: false);
        }
    }

    /// <summary>Preserves an existing opt-in when updating an older copy at the same path.</summary>
    internal static void UpgradeIfNeeded(string executable)
    {
        foreach (var path in new[] { EncryptFiles, EncryptFolders })
        {
            using var command = Registry.CurrentUser.OpenSubKey(path + @"\command");
            if (string.Equals(command?.GetValue(null) as string, LegacyEncryptCommand(executable), StringComparison.OrdinalIgnoreCase))
                Write(path, L("用 2Password 加密"), executable, EncryptCommand(executable),
                    multiSelect: true, excludeOwnFiles: path == EncryptFiles);
        }
    }

    private static bool IsEncryptCommand(string? command, string executable) =>
        string.Equals(command, EncryptCommand(executable), StringComparison.OrdinalIgnoreCase) ||
        string.Equals(command, LegacyEncryptCommand(executable), StringComparison.OrdinalIgnoreCase);

    private static string EncryptCommand(string executable) => $"\"{executable}\" --explorer-encrypt \"%1\"";
    private static string LegacyEncryptCommand(string executable) => $"\"{executable}\" --encrypt \"%1\"";
    private static string OpenCommand(string executable) => $"\"{executable}\" \"%1\"";

    private static void Write(string path, string label, string executable, string command, bool multiSelect = false, bool excludeOwnFiles = false)
    {
        using var verb = Registry.CurrentUser.CreateSubKey(path);
        verb.SetValue("MUIVerb", label);
        verb.SetValue("Icon", $"\"{executable}\",0");
        // Legacy Player verbs support up to 100 selected items. Explorer may invoke the
        // command separately for each item; the application joins these using a named pipe.
        verb.SetValue("MultiSelectModel", multiSelect ? "Player" : "Single");
        if (excludeOwnFiles) verb.SetValue("AppliesTo", "NOT System.FileExtension:=.2pw");
        using var target = verb.CreateSubKey("command");
        target.SetValue(null, command);
    }
}

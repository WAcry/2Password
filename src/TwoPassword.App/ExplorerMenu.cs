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
        return string.Equals(command?.GetValue(null) as string, EncryptCommand(executable), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Writes every verb in the current interface language; call again after the language changes.</summary>
    internal static void Enable(string executable)
    {
        Write(EncryptFiles, L("用 2Password 加密"), executable, EncryptCommand(executable), excludeOwnFiles: true);
        Write(EncryptFolders, L("用 2Password 加密"), executable, EncryptCommand(executable));
        Write(DecryptData, L("用 2Password 解密"), executable, OpenCommand(executable));
    }

    internal static void Disable(string executable)
    {
        if (!IsEnabled(executable)) return;
        foreach (var key in Keys) Registry.CurrentUser.DeleteSubKeyTree(key, throwOnMissingSubKey: false);
    }

    private static string EncryptCommand(string executable) => $"\"{executable}\" --encrypt \"%1\"";
    private static string OpenCommand(string executable) => $"\"{executable}\" \"%1\"";

    private static void Write(string path, string label, string executable, string command, bool excludeOwnFiles = false)
    {
        using var verb = Registry.CurrentUser.CreateSubKey(path);
        verb.SetValue("MUIVerb", label);
        verb.SetValue("Icon", $"\"{executable}\",0");
        verb.SetValue("MultiSelectModel", "Single");
        if (excludeOwnFiles) verb.SetValue("AppliesTo", "NOT System.FileExtension:=.2pw");
        using var target = verb.CreateSubKey("command");
        target.SetValue(null, command);
    }
}

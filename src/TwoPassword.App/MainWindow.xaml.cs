using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using TwoPassword.Core;
using TwoPassword.Recovery;
using static TwoPassword.App.UiText;

namespace TwoPassword.App;

public partial class MainWindow : Window
{
    private readonly string? _embeddedPackage;
    private readonly string? _stubOverride;
    private readonly string? _initialPackage;
    private readonly List<PasswordEntry> _passwordEntries = [];
    private readonly DispatcherTimer _progressTimer;
    private CancellationTokenSource? _operationCancellation;
    private PackageProgress? _latestProgress;
    private RecoveryProgress? _latestRecoveryProgress;
    private string? _sourcePath;
    private string? _packagePath;
    private string? _selectedPackagePath;
    private string? _lastResultPath;
    private PackageInfo? _packageInfo;
    private PackageResult? _createdPackage;
    private RecoveryResult? _createdRecovery;
    private bool _createdRecoveryIncomplete;
    private bool _busy;
    private bool _inspecting;
    private bool _closeWhenFinished;
    private bool _initialized;
    private bool _advancedRecovery;
    private readonly Stopwatch _stopwatch = new();

    public MainWindow(string? embeddedPackage = null, string? stubOverride = null, string? initialPackage = null)
    {
        _embeddedPackage = embeddedPackage;
        _stubOverride = stubOverride;
        _initialPackage = initialPackage;
        InitializeComponent();
        UiText.Apply(Resources);
        LanguageSelector.SelectedIndex = UiText.Language == "zh-CN" ? 0 : 1;
        Language = System.Windows.Markup.XmlLanguage.GetLanguage(UiText.Language);
        FontFamily = new FontFamily(UiText.Language == "en" ? "Segoe UI, Microsoft YaHei UI" : "Microsoft YaHei UI, Segoe UI");
        VersionLabel.Text = L("版本 {0}", typeof(App).Assembly.GetName().Version?.ToString(3) ?? "1.0.0");
        var available = SystemParameters.WorkArea;
        MinWidth = Math.Min(MinWidth, Math.Max(660, available.Width - 24));
        MinHeight = Math.Min(MinHeight, Math.Max(420, available.Height - 24));
        Width = Math.Min(Width, available.Width - 24);
        Height = Math.Min(Height, available.Height - 24);
        AddPasswordRow();
        AddPasswordRow();
        _progressTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(120) };
        _progressTimer.Tick += (_, _) =>
        {
            var update = Interlocked.Exchange(ref _latestProgress, null);
            if (update is not null) UpdateProgress(update);
            var recoveryUpdate = Interlocked.Exchange(ref _latestRecoveryProgress, null);
            if (recoveryUpdate is not null) UpdateRecoveryProgress(recoveryUpdate);
        };
        _initialized = true;
        if (_embeddedPackage is not null)
        {
            CreateNav.Visibility = Visibility.Collapsed;
            CreatePanel.Visibility = Visibility.Collapsed;
            ExtractPanel.Visibility = Visibility.Visible;
            ExtractNav.IsChecked = true;
            ChoosePackageButton.Visibility = Visibility.Collapsed;
            ExtractEyebrow.Text = L("YOUR SECURE PACKAGE.");
            ExtractHeading.Text = L("你的文件，已安全封存。");
            ExtractIntro.Text = L("这是一个独立加密包。输入有效密码，即可离线解密并完整还原。");
            ActionButton.Content = L("解密并还原   →");
            AutomationProperties.SetName(ActionButton, L("解密并还原"));
            StatusDetail.Text = L("输入密码，选择一个新的还原文件夹。");
            Title = L("2Password · 解密加密包");
        }
    }

    private void Language_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_initialized || _busy || _inspecting) return;
        var language = SelectedTag(LanguageSelector);
        if (language is not ("en" or "zh-CN") || language == UiText.Language) return;
        UiText.UseLanguage(language);
        UiText.Apply(Resources);
        Language = System.Windows.Markup.XmlLanguage.GetLanguage(UiText.Language);
        FontFamily = new FontFamily(UiText.Language == "en" ? "Segoe UI, Microsoft YaHei UI" : "Microsoft YaHei UI, Segoe UI");
        VersionLabel.Text = L("版本 {0}", typeof(App).Assembly.GetName().Version?.ToString(3) ?? "1.0.0");
        RefreshPasswordRows();
        if (_embeddedPackage is not null)
        {
            ExtractEyebrow.Text = L("YOUR SECURE PACKAGE.");
            ExtractHeading.Text = L("你的文件，已安全封存。");
            ExtractIntro.Text = L("这是一个独立加密包。输入有效密码，即可离线解密并完整还原。");
            Title = L("2Password · 解密加密包");
        }
        RefreshPackageDetails();
        if (_createdPackage is not null) ShowCreatedFiles(_createdPackage, _createdRecovery, _createdRecoveryIncomplete, scrollToTop: false);
        if (RecoverySummaryCard.Visibility == Visibility.Visible)
        {
            RecoverySummaryTitle.Text = L("操作记录");
            RecoverySummaryText.Text = L("语言已切换。请重新校验，以当前语言查看详细结果。");
        }
        ApplyNavigation(scrollToTop: false);
        try { UiText.SaveLanguage(); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { ShowError(error, L("语言已切换，但设置无法保存")); }
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var handle = new WindowInteropHelper(this).Handle;
            var preference = 2;
            DwmSetWindowAttribute(handle, 33, ref preference, sizeof(int));
            var dark = 1;
            DwmSetWindowAttribute(handle, 20, ref dark, sizeof(int));
        }
        catch { /* Cosmetic integration is optional on older Windows. */ }
        if (_embeddedPackage is not null) await SelectPackageAsync(_embeddedPackage);
        else if (!string.IsNullOrWhiteSpace(_initialPackage) && File.Exists(_initialPackage))
        {
            if (_initialPackage.EndsWith(".par2", StringComparison.OrdinalIgnoreCase))
            {
                ShowRecoveryTools();
                SelectRecoveryFile(_initialPackage);
            }
            else
            {
                ExtractNav.IsChecked = true;
                await SelectPackageAsync(_initialPackage);
            }
        }
    }

    private void Navigation_Checked(object sender, RoutedEventArgs e)
    {
        if (!_initialized || _busy) return;
        _advancedRecovery = false;
        ApplyNavigation();
    }

    private void Navigation_Click(object sender, RoutedEventArgs e)
    {
        if (!_initialized || _busy || !_advancedRecovery) return;
        _advancedRecovery = false;
        ApplyNavigation();
    }

    private void ApplyNavigation(bool resetStatus = true, bool scrollToTop = true)
    {
        var extracting = ExtractNav.IsChecked == true;
        var recovering = _advancedRecovery;
        CreatePanel.Visibility = !extracting && !recovering ? Visibility.Visible : Visibility.Collapsed;
        ExtractPanel.Visibility = extracting && !recovering ? Visibility.Visible : Visibility.Collapsed;
        RecoveryPanel.Visibility = recovering ? Visibility.Visible : Visibility.Collapsed;
        RepairButton.Visibility = recovering ? Visibility.Visible : Visibility.Collapsed;
        ActionButton.Content = recovering ? L("校验文件   →") : extracting ? L("解密并还原   →") : L("创建加密包   →");
        AutomationProperties.SetName(ActionButton, recovering ? L("校验文件") : extracting ? L("解密并还原") : L("创建加密包"));
        if (scrollToTop) ContentScroll.ScrollToTop();
        if (resetStatus) SetStatus(L("准备就绪"), recovering ? L("选择 PAR2 恢复记录，校验文件或尝试修复。") : extracting ? L("输入密码，选择一个新的还原文件夹。") : L("选择内容，设置密码，然后生成加密包。"));
    }

    private void ShowRecoveryTools_Click(object sender, RoutedEventArgs e) => ShowRecoveryTools();
    private void ShowRecoveryTools()
    {
        if (_busy || _inspecting) return;
        ExtractNav.IsChecked = true;
        _advancedRecovery = true;
        ApplyNavigation();
    }

    private void BackToExtract_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        _advancedRecovery = false;
        ExtractNav.IsChecked = true;
        ApplyNavigation();
    }

    private void ChooseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = L("选择要加密的文件"), CheckFileExists = true, Multiselect = false, Filter = L("所有文件|*.*") };
        if (dialog.ShowDialog(this) == true) SelectSource(dialog.FileName);
    }

    private void ChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = L("选择要加密的文件夹"), Multiselect = false };
        if (dialog.ShowDialog(this) == true) SelectSource(dialog.FolderName);
    }

    private void SelectSource(string path)
    {
        try
        {
            path = Path.GetFullPath(path);
            if (!File.Exists(path) && !Directory.Exists(path)) throw new IOException(L("找不到此文件或文件夹。"));
            _sourcePath = path;
            var name = Path.GetFileName(Path.TrimEndingDirectorySeparator(path));
            SourceName.Text = string.IsNullOrEmpty(name) ? path : name;
            SourceName.ToolTip = path;
            SourcePathLabel.Text = path;
            SourcePathLabel.ToolTip = path;
            var parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(path));
            if (string.IsNullOrEmpty(parent)) parent = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var outputName = string.IsNullOrEmpty(name) ? L("加密文件") : name;
            OutputPathBox.Text = NextAvailablePackagePath(Path.Combine(parent, outputName + ".protected.exe"));
            SetStatus(L("内容已选择"), Directory.Exists(path) ? L("将保留文件夹结构、文件内容与多语言名称。") : L("已准备保护所选文件。"));
        }
        catch (Exception error) { ShowError(error, L("无法选择内容")); }
    }

    private static string NextAvailablePath(string path, bool directory)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return path;
        var parent = Path.GetDirectoryName(path) ?? "";
        var stem = directory ? Path.GetFileName(path) : Path.GetFileNameWithoutExtension(path);
        var extension = directory ? "" : Path.GetExtension(path);
        for (var i = 2; i < 10000; i++)
        {
            var candidate = Path.Combine(parent, stem + " (" + i + "" + extension);
            if (!File.Exists(candidate) && !Directory.Exists(candidate)) return candidate;
        }
        throw new IOException(L("无法选择空闲的输出名称，请手动指定新的路径。"));
    }

    private void ChooseOutput_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Title = L("保存独立加密包"), Filter = L("独立加密包 (*.exe)|*.exe"), AddExtension = true, DefaultExt = ".exe", OverwritePrompt = false, FileName = SafeFileName(OutputPathBox.Text, L("加密文件.protected.exe")) };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var available = NextAvailablePackagePath(dialog.FileName);
            OutputPathBox.Text = available;
            if (!string.Equals(available, dialog.FileName, StringComparison.OrdinalIgnoreCase))
                SetStatus(L("已选择新的文件名"), L("原名称或配套文件已存在。已在路径框中选择新名称，现有文件不会被覆盖。"));
        }
        catch (Exception error) { ShowError(error, L("无法选择输出位置")); }
    }

    private static string NextAvailablePackagePath(string path)
    {
        if (!PackageOutputCollision(path)) return path;
        var parent = Path.GetDirectoryName(path) ?? "";
        var stem = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        for (var index = 2; index < 10000; index++)
        {
            var candidate = Path.Combine(parent, stem + " (" + index + "" + extension);
            if (!PackageOutputCollision(candidate)) return candidate;
        }
        throw new IOException(L("无法选择空闲的输出名称，请手动指定新的路径。"));
    }

    private static bool PackageOutputCollision(string path)
    {
        path = Path.GetFullPath(path);
        var dataPath = Path.ChangeExtension(path, ".2pw");
        if (File.Exists(path) || Directory.Exists(path) || File.Exists(dataPath) || Directory.Exists(dataPath)) return true;
        var parent = Path.GetDirectoryName(path);
        if (parent is null || !Directory.Exists(parent)) return false;
        foreach (var baseName in new[] { Path.GetFileName(path), Path.GetFileName(dataPath) })
        {
            foreach (var existing in Directory.EnumerateFileSystemEntries(parent, baseName + ".*", SearchOption.TopDirectoryOnly))
            {
                var name = Path.GetFileName(existing);
                if (name.Equals(baseName + ".par2", StringComparison.OrdinalIgnoreCase) ||
                    (name.StartsWith(baseName + ".vol", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".par2", StringComparison.OrdinalIgnoreCase))) return true;
            }
        }
        return false;
    }

    private static string SafeFileName(string path, string fallback)
    {
        try { var name = Path.GetFileName(path); return string.IsNullOrEmpty(name) ? fallback : name; }
        catch { return fallback; }
    }

    private void Source_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = !_busy && e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void Source_Drop(object sender, DragEventArgs e)
    {
        e.Handled = true;
        if (_busy) return;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length == 1) SelectSource(paths[0]);
        else SetStatus(L("一次选择一个项目"), L("可将多个文件先放进同一个文件夹，再拖入整个文件夹。"), error: true);
    }

    private void Package_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = !_busy && _embeddedPackage is null && e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private async void Package_Drop(object sender, DragEventArgs e)
    {
        e.Handled = true;
        if (_busy || _embeddedPackage is not null) return;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length == 1)
            await SelectPackageAsync(paths[0]);
    }

    private void AddPassword_Click(object sender, RoutedEventArgs e)
    {
        AddPasswordRow();
        if (_passwordEntries.Count > 0) _passwordEntries[^1].Password.Focus();
    }

    private void AddPasswordRow()
    {
        if (_passwordEntries.Count >= 16) return;
        var entry = new PasswordEntry();
        var container = new Border { Background = Brush("#141D2A"), CornerRadius = new CornerRadius(8), Padding = new Thickness(13), Margin = new Thickness(0, 0, 0, 9) };
        var layout = new Grid();
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(39) });
        var passwordStack = new StackPanel();
        entry.Label = new TextBlock { FontSize = 10, Foreground = Brush("#9AAEC6"), Margin = new Thickness(0, 0, 0, 7) };
        passwordStack.Children.Add(entry.Label);
        entry.Password = new PasswordBox { MaxLength = 1024 };
        passwordStack.Children.Add(entry.Password);
        layout.Children.Add(passwordStack);
        var confirmationStack = new StackPanel();
        entry.ConfirmationLabel = new TextBlock { Text = L("再次输入"), FontSize = 10, Foreground = Brush("#9AAEC6"), Margin = new Thickness(0, 0, 0, 7) };
        confirmationStack.Children.Add(entry.ConfirmationLabel);
        entry.Confirmation = new PasswordBox { MaxLength = 1024 };
        confirmationStack.Children.Add(entry.Confirmation);
        Grid.SetColumn(confirmationStack, 2);
        layout.Children.Add(confirmationStack);
        entry.Remove = new Button { Content = "×", FontSize = 18, Padding = new Thickness(5), MinHeight = 29, Height = 32, Margin = new Thickness(7, 18, 0, 0), ToolTip = L("移除此密码"), Style = (Style)FindResource("QuietButton") };
        AutomationProperties.SetName(entry.Remove, L("移除此密码"));
        entry.Remove.Click += (_, _) =>
        {
            if (_passwordEntries.Count <= 1) return;
            entry.Password.Clear();
            entry.Confirmation.Clear();
            _passwordEntries.Remove(entry);
            PasswordRows.Children.Remove(container);
            RefreshPasswordRows();
        };
        Grid.SetColumn(entry.Remove, 3);
        layout.Children.Add(entry.Remove);
        container.Child = layout;
        _passwordEntries.Add(entry);
        PasswordRows.Children.Add(container);
        RefreshPasswordRows();
    }

    private void RefreshPasswordRows()
    {
        for (var i = 0; i < _passwordEntries.Count; i++)
        {
            _passwordEntries[i].Label.Text = L("独立密码 {0}", i + 1);
            _passwordEntries[i].ConfirmationLabel.Text = L("再次输入");
            _passwordEntries[i].Remove.ToolTip = L("移除此密码");
            AutomationProperties.SetName(_passwordEntries[i].Remove, L("移除此密码"));
            AutomationProperties.SetName(_passwordEntries[i].Password, L("独立密码 {0}", i + 1));
            AutomationProperties.SetAutomationId(_passwordEntries[i].Password, "Password" + (i + 1));
            AutomationProperties.SetName(_passwordEntries[i].Confirmation, L("确认密码 {0}", i + 1));
            AutomationProperties.SetAutomationId(_passwordEntries[i].Confirmation, "ConfirmPassword" + (i + 1));
            _passwordEntries[i].Remove.IsEnabled = _passwordEntries.Count > 1;
        }
        AddPasswordButton.IsEnabled = _passwordEntries.Count < 16;
        AddPasswordButton.Content = L("＋  添加密码  {0}/16", _passwordEntries.Count);
    }

    private async void ChoosePackage_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = L("选择 2Password 加密包"), Filter = L("2Password 加密包|*.exe;*.2pw|所有文件|*.*"), CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog(this) == true) await SelectPackageAsync(dialog.FileName);
    }

    private async Task SelectPackageAsync(string path)
    {
        if (_inspecting || _busy) return;
        _inspecting = true;
        ActionButton.IsEnabled = false;
        Navigation.IsEnabled = false;
        ChoosePackageButton.IsEnabled = false;
        LanguageSelector.IsEnabled = false;
        _packageInfo = null;
        try
        {
            var fullPath = Path.GetFullPath(path);
            _selectedPackagePath = fullPath;
            ReloadPackageButton.Visibility = Visibility.Visible;
            _packagePath = fullPath;
            PackageNameLabel.Text = Path.GetFileName(fullPath);
            PackageNameLabel.ToolTip = fullPath;
            var parent = Path.GetDirectoryName(fullPath) ?? Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var stem = Path.GetFileNameWithoutExtension(fullPath);
            if (stem.EndsWith(".protected", StringComparison.OrdinalIgnoreCase)) stem = stem[..^10];
            ExtractDestinationBox.Text = NextAvailablePath(Path.Combine(parent, L("{0}_已还原", stem)), directory: true);
            ExtractPasswordBox.Clear();
            var info = await Task.Run(() => PackageService.InspectAsync(fullPath));
            _packageInfo = info;
            RefreshPackageDetails();
            SetStatus(L("加密包已就绪"), L("输入任意一个有效密码，即可还原全部内容。"));
            ExtractPasswordBox.Focus();
        }
        catch (Exception error)
        {
            if (_selectedPackagePath is null || !File.Exists(_selectedPackagePath)) _packagePath = null;
            PackageDetailsLabel.Text = L("无法读取包信息。若有匹配的 PAR2，开始解包时会尝试恢复损坏的数据。双文件包需要配套 .2pw；补齐后可点击“重新读取”。");
            ShowError(error, L("无法读取加密包"));
        }
        finally
        {
            _inspecting = false;
            ActionButton.IsEnabled = true;
            Navigation.IsEnabled = true;
            ChoosePackageButton.IsEnabled = true;
            LanguageSelector.IsEnabled = true;
        }
    }

    private void RefreshPackageDetails()
    {
        if (_packageInfo is { } info)
        {
            var compressionName = info.Compression switch { PackageCompression.Zstd => "Zstd", PackageCompression.Brotli => "Brotli", _ => L("未压缩") };
            PackageDetailsLabel.Text = L("{0}  ·  {1} 个独立密码  ·  {2}", FormatSize(info.EncryptedBytes), info.PasswordSlots, compressionName);
            if (info.IsDetached && info.DataPath is not null)
                PackageDetailsLabel.Text += "\n" + L("外置加密数据：{0}", Path.GetFileName(info.DataPath));
        }
        else if (_selectedPackagePath is not null)
            PackageDetailsLabel.Text = L("无法读取包信息。若有匹配的 PAR2，开始解包时会尝试恢复损坏的数据。双文件包需要配套 .2pw；补齐后可点击“重新读取”。");
    }

    private async void ReloadPackage_Click(object sender, RoutedEventArgs e)
    {
        var path = _embeddedPackage ?? _selectedPackagePath;
        if (path is not null) await SelectPackageAsync(path);
    }

    private void ChooseDestination_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = L("选择还原文件夹的上级位置"), Multiselect = false };
        if (dialog.ShowDialog(this) != true) return;
        var name = SafeFileName(ExtractDestinationBox.Text, L("2Password_已还原"));
        ExtractDestinationBox.Text = NextAvailablePath(Path.Combine(dialog.FolderName, name), directory: true);
    }

    private async void Action_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _inspecting) return;
        if (RecoveryPanel.Visibility == Visibility.Visible) await RunRecoveryAsync(repair: false);
        else if (ExtractPanel.Visibility == Visibility.Visible) await ExtractAsync();
        else await CreateAsync();
    }

    private async Task CreateAsync()
    {
        var passwords = new List<string>();
        try
        {
            if (string.IsNullOrEmpty(_sourcePath)) throw new ArgumentException(L("请先选择一个文件或文件夹。"));
            var output = OutputPathBox.Text;
            if (string.IsNullOrWhiteSpace(output)) throw new ArgumentException(L("请选择加密 EXE 的保存位置。"));
            if (!output.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException(L("独立加密包的文件名应以 .exe 结尾。"));
            if (PackageOutputCollision(output)) throw new ArgumentException(L("输出名称或配套的 .2pw / PAR2 文件已存在。请点击“浏览”选择新的名称；现有文件不会被覆盖。"));
            foreach (var entry in _passwordEntries)
            {
                var password = entry.Password.Password;
                if (password.Length < 8) throw new ArgumentException(L("{0} 至少需要 8 个字符；建议使用 12 个以上字符的长密码。", entry.Label.Text));
                if (!string.Equals(password, entry.Confirmation.Password, StringComparison.Ordinal))
                    throw new ArgumentException(L("{0} 两次输入不一致，请重新检查。", entry.Label.Text));
                if (passwords.Contains(password, StringComparer.Ordinal)) throw new ArgumentException(L("各个密码必须不同，请移除重复密码。"));
                passwords.Add(password);
            }
            var stub = _stubOverride ?? CommandLine.StandaloneStub();
            var layout = SelectedTag(LayoutSelector) switch { "embedded" => PackageLayout.Embedded, "detached" => PackageLayout.Detached, _ => PackageLayout.Auto };
            var compression = SelectedTag(CompressionSelector) switch { "brotli" => PackageCompression.Brotli, "none" => PackageCompression.None, _ => PackageCompression.Zstd };
            var redundancy = int.Parse(SelectedTag(RecoveryPercentSelector));
            var options = new CreateOptions(_sourcePath, output, passwords, compression, stub, layout);
            CreatedFilesCard.Visibility = Visibility.Collapsed;
            await RunOperationAsync(L("正在准备加密"), async (progress, token) =>
                await PackageService.CreateAsync(options, progress, token), L("加密包已创建"), creating: true, redundancyPercent: redundancy);
        }
        catch (Exception error) { ShowError(error, L("请检查创建设置")); }
        finally { passwords.Clear(); }
    }

    private static string SelectedTag(ComboBox selector) => (selector.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "0";

    private async Task ExtractAsync()
    {
        try
        {
            if (string.IsNullOrEmpty(_packagePath)) throw new ArgumentException(L("请先选择一个有效的 2Password 加密包。"));
            if (ExtractPasswordBox.Password.Length == 0) throw new ArgumentException(L("请输入解密密码。"));
            if (string.IsNullOrWhiteSpace(ExtractDestinationBox.Text)) throw new ArgumentException(L("请选择新的还原文件夹。"));
            var destination = Path.GetFullPath(ExtractDestinationBox.Text);
            if (File.Exists(destination) || Directory.Exists(destination))
                throw new ArgumentException(L("还原位置已经存在。请使用一个尚不存在的新文件夹，避免覆盖现有内容。"));
            var options = new ExtractOptions(_packagePath, destination, ExtractPasswordBox.Password);
            var verifyFirst = VerifyFirstCheckBox.IsChecked == true;
            await RunOperationAsync(L("正在检查加密文件"), async (progress, token) =>
                await RecoveryService.ExtractAsync(options, progress, RecoveryProgressSink(), token, verifyFirst), L("文件已完整还原"));
        }
        catch (Exception error) { ShowError(error, L("请检查解密设置")); }
    }

    private async Task RunOperationAsync(string initial, Func<IProgress<PackageProgress>, CancellationToken, Task<PackageResult>> operation, string successTitle, bool creating = false, int redundancyPercent = 0)
    {
        BeginOperation(initial);
        var token = _operationCancellation!.Token;
        PackageResult? completedPackage = null;
        try
        {
            var progress = new ForwardProgress(value => Interlocked.Exchange(ref _latestProgress, value));
            var result = await Task.Run(() => operation(progress, token), token);
            completedPackage = result;
            _lastResultPath = result.OutputPath;
            OpenResultButton.Visibility = Visibility.Visible;
            ClearPasswords();
            RecoveryResult? recovery = null;
            if (creating)
            {
                ShowCreatedFiles(result, null);
                if (redundancyPercent > 0)
                {
                    Interlocked.Exchange(ref _latestProgress, null);
                    OperationProgress.Value = 0;
                    SetStatus(L("加密包已完成，正在创建恢复记录"), L("{0}% PAR2 恢复记录；加密包会保留。", redundancyPercent));
                    recovery = await Task.Run(() => RecoveryService.CreateAsync(result.OutputPath, redundancyPercent, RecoveryProgressSink(), token), token);
                    ShowCreatedFiles(result, recovery);
                }
            }
            OperationProgress.Value = 100;
            var description = L("{0} 个文件 · {1} · {2:0.0} 秒", result.FileCount, FormatSize(result.TotalBytes), _stopwatch.Elapsed.TotalSeconds);
            if (creating && result.DataPath is not null) description += L(" · 请一起复制 EXE 和 .2pw");
            if (recovery is not null) description += L(" · PAR2 恢复记录已创建");
            SetStatus(successTitle, description);
        }
        catch (OperationCanceledException)
        {
            if (creating && completedPackage is not null)
            {
                ShowCreatedFiles(completedPackage, null, recoveryIncomplete: true);
                SetStatus(L("加密包已保留，恢复记录已取消"), L("加密文件已完整创建；尚未完成 PAR2 恢复记录。"), error: true);
            }
            else SetStatus(L("已取消"), L("操作已停止，未发布不完整的输出。"));
            OperationProgress.Value = 0;
        }
        catch (Exception error)
        {
            if (creating && completedPackage is not null)
            {
                ShowCreatedFiles(completedPackage, null, recoveryIncomplete: true);
                SetStatus(L("加密包已保留，恢复记录未完成"), L("加密文件已成功创建并保留。") + error.Message, error: true);
                MessageBox.Show(this, L("加密包已成功创建并保留在：\n{0}\n\nPAR2 恢复记录未完成：\n{1}", completedPackage.OutputPath, error.Message), L("2Password · 恢复记录未完成"), MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else ShowError(error, L("操作未完成"));
        }
        finally { EndOperation(); }
    }

    private void BeginOperation(string initial)
    {
        _busy = true;
        _operationCancellation = new CancellationTokenSource();
        _lastResultPath = null;
        OpenResultButton.Visibility = Visibility.Collapsed;
        Navigation.IsEnabled = false;
        CreatePanel.IsEnabled = false;
        ExtractPanel.IsEnabled = false;
        RecoveryPanel.IsEnabled = false;
        LanguageSelector.IsEnabled = false;
        ActionButton.IsEnabled = false;
        RepairButton.IsEnabled = false;
        CancelButton.IsEnabled = true;
        CancelButton.Visibility = Visibility.Visible;
        OperationProgress.Visibility = Visibility.Visible;
        OperationProgress.Value = 0;
        SetStatus(initial, L("正在安全处理，请稍候…"));
        _stopwatch.Restart();
        _progressTimer.Start();
    }

    private void EndOperation()
    {
            _progressTimer.Stop();
            Interlocked.Exchange(ref _latestProgress, null);
            Interlocked.Exchange(ref _latestRecoveryProgress, null);
            _stopwatch.Stop();
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            _busy = false;
            Navigation.IsEnabled = true;
            CreatePanel.IsEnabled = true;
            ExtractPanel.IsEnabled = true;
            RecoveryPanel.IsEnabled = true;
            LanguageSelector.IsEnabled = true;
            ActionButton.IsEnabled = true;
            RepairButton.IsEnabled = true;
            CancelButton.Visibility = Visibility.Collapsed;
            if (_closeWhenFinished) Close();
    }

    private void ShowCreatedFiles(PackageResult package, RecoveryResult? recovery, bool recoveryIncomplete = false, bool scrollToTop = true)
    {
        _createdPackage = package;
        _createdRecovery = recovery;
        _createdRecoveryIncomplete = recoveryIncomplete;
        var files = new List<string> { package.OutputPath };
        if (package.DataPath is not null) files.Add(package.DataPath);
        if (recovery is not null)
            files.AddRange(recovery.Files.Where(path => !files.Contains(path, StringComparer.OrdinalIgnoreCase)));
        CreatedFilesList.ItemsSource = files;
        CreatedFilesTitle.Text = recoveryIncomplete ? L("加密包已创建；恢复记录未完成") : recovery is not null ? L("加密包与恢复记录已创建") : L("加密包已创建");
        CreatedFilesNote.Text = package.DataPath is not null
            ? L("请一起复制 EXE 与 .2pw，并保持同一目录和原文件名。")
            : L("复制加密 EXE，即可在其他 Windows 电脑离线解密。");
        if (recovery is not null) CreatedFilesNote.Text += L(" 同时保留以下全部 .par2 文件，才能使用恢复记录校验或修复。");
        if (recoveryIncomplete) CreatedFilesNote.Text += L(" 加密内容已保留，当前没有一套已完成的恢复记录。");
        CreatedFilesCard.Visibility = Visibility.Visible;
        if (scrollToTop) ContentScroll.ScrollToTop();
    }

    private void ChooseRecovery_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = L("选择 PAR2 恢复记录"), Filter = L("PAR2 恢复记录 (*.par2)|*.par2"), CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog(this) == true) SelectRecoveryFile(dialog.FileName);
    }

    private void SelectRecoveryFile(string path)
    {
        try
        {
            path = Path.GetFullPath(path);
            if (!path.EndsWith(".par2", StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
                throw new ArgumentException(L("请选择一个已存在的 .par2 恢复记录文件。"));
            RecoveryPathBox.Text = path;
            RecoverySummaryCard.Visibility = Visibility.Collapsed;
            SetStatus(L("恢复记录已选择"), L("先校验文件，查看是否需要修复以及恢复记录是否足够。"));
        }
        catch (Exception error) { ShowError(error, L("无法选择恢复记录")); }
    }

    private void Recovery_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = !_busy && e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void Recovery_Drop(object sender, DragEventArgs e)
    {
        e.Handled = true;
        if (!_busy && e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length == 1)
            SelectRecoveryFile(paths[0]);
    }

    private async void Repair_Click(object sender, RoutedEventArgs e)
    {
        if (!_busy && !_inspecting) await RunRecoveryAsync(repair: true);
    }

    private async Task RunRecoveryAsync(bool repair)
    {
        var path = RecoveryPathBox.Text;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path) || !path.EndsWith(".par2", StringComparison.OrdinalIgnoreCase))
        {
            ShowError(new ArgumentException(L("请选择一个有效的 .par2 恢复记录文件。")), L("请检查恢复记录"));
            return;
        }
        BeginOperation(repair ? L("正在修复加密文件") : L("正在校验加密文件"));
        RecoverySummaryCard.Visibility = Visibility.Collapsed;
        try
        {
            var token = _operationCancellation!.Token;
            var result = await Task.Run(() => repair
                ? RecoveryService.RepairAsync(path, RecoveryProgressSink(), token)
                : RecoveryService.VerifyAsync(path, RecoveryProgressSink(), token), token);
            var title = result.Success ? (repair ? L("文件已修复") : L("文件完整，无需修复"))
                : result.Repairable ? (repair ? L("仍有损坏需要修复") : L("发现损坏，恢复记录足够修复"))
                : L("当前恢复记录不足以完成修复");
            RecoverySummaryTitle.Text = title;
            RecoverySummaryText.Text = result.Summary;
            RecoverySummaryCard.Visibility = Visibility.Visible;
            OperationProgress.Value = 100;
            _lastResultPath = result.RecoveryFile;
            OpenResultButton.Visibility = Visibility.Visible;
            SetStatus(title, result.Success ? L("完成后可返回“解密与还原”打开加密包。") : result.Repairable ? L("点击“修复文件”尝试恢复；完成后重新校验。") : L("请补齐其余恢复记录或从可靠副本重新取得缺失数据。"), error: !result.Success && !result.Repairable);
        }
        catch (OperationCanceledException)
        {
            SetStatus(L("已取消"), L("本次操作已停止，可再次校验确认文件的当前状态。"));
            OperationProgress.Value = 0;
        }
        catch (Exception error) { ShowError(error, repair ? L("修复未完成") : L("校验未完成")); }
        finally { EndOperation(); }
    }

    private IProgress<RecoveryProgress> RecoveryProgressSink() =>
        new RecoveryForwardProgress(value => Interlocked.Exchange(ref _latestRecoveryProgress, value));

    private void UpdateRecoveryProgress(RecoveryProgress update)
    {
        if (!_busy) return;
        if (update.Percent is int percent) OperationProgress.Value = Math.Clamp(percent, 0, 99);
        var stage = update.Stage.ToLowerInvariant();
        var title = stage.Contains("repair") ? L("正在修复加密文件")
            : stage.Contains("creat") || stage.Contains("generat") ? L("正在创建恢复记录")
            : stage.Contains("verif") || stage.Contains("check") ? L("正在校验加密文件")
            : string.IsNullOrEmpty(update.Stage) ? L("正在处理恢复记录") : update.Stage;
        SetStatus(title, update.Message);
    }

    private void ShowNotices_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            using var stream = typeof(App).Assembly.GetManifestResourceStream("TwoPassword.ThirdPartyNotices.txt")
                ?? throw new IOException(L("未能读取此版本内的第三方许可文件。"));
            using var reader = new StreamReader(stream);
            var notices = reader.ReadToEnd();
            var dialog = new Window
            {
                Title = L("2Password · 开源组件与许可"), Owner = this,
                Width = Math.Min(820, SystemParameters.WorkArea.Width - 40), Height = Math.Min(650, SystemParameters.WorkArea.Height - 40),
                MinWidth = 520, MinHeight = 360, WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Background = Brush("#111925"), Foreground = Brush("#E7EEF7"), FontFamily = FontFamily, FontSize = 12,
                Resources = Resources
            };
            var layout = new DockPanel { Margin = new Thickness(23) };
            var heading = new TextBlock { Text = L("开源组件与许可"), FontSize = 21, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 16) };
            DockPanel.SetDock(heading, Dock.Top);
            layout.Children.Add(heading);
            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
            var export = new Button { Content = L("导出 PAR2 源码"), Margin = new Thickness(0, 0, 10, 0) };
            AutomationProperties.SetAutomationId(export, "ExportRecoverySource");
            export.Click += async (_, _) =>
            {
                var save = new SaveFileDialog { Title = L("导出内附的 PAR2 完整对应源代码"), Filter = L("源代码压缩包 (*.tar.xz)|*.tar.xz"), FileName = "par2cmdline-turbo-source.tar.xz", AddExtension = true, DefaultExt = ".tar.xz", OverwritePrompt = false };
                if (save.ShowDialog(dialog) != true) return;
                export.IsEnabled = false;
                try
                {
                    var saved = await RecoveryService.ExportSourceAsync(save.FileName);
                    MessageBox.Show(dialog, L("PAR2 对应源代码已导出：\n{0}", saved), "2Password", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception error) { MessageBox.Show(dialog, error.Message, L("导出未完成"), MessageBoxButton.OK, MessageBoxImage.Warning); }
                finally { export.IsEnabled = true; }
            };
            buttons.Children.Add(export);
            var close = new Button { Content = L("关闭"), MinWidth = 80 };
            close.Click += (_, _) => dialog.Close();
            buttons.Children.Add(close);
            DockPanel.SetDock(buttons, Dock.Bottom);
            layout.Children.Add(buttons);
            layout.Children.Add(new TextBox { Text = notices, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, FontFamily = new FontFamily("Consolas, Microsoft YaHei UI"), FontSize = 11 });
            dialog.Content = layout;
            dialog.ShowDialog();
        }
        catch (Exception error) { ShowError(error, L("无法查看开源许可")); }
    }

    private void ClearPasswords()
    {
        foreach (var entry in _passwordEntries) { entry.Password.Clear(); entry.Confirmation.Clear(); }
        ExtractPasswordBox.Clear();
    }

    private void UpdateProgress(PackageProgress progress)
    {
        if (!_busy) return;
        var stage = TranslateStage(progress.Stage);
        var percent = progress.TotalBytes > 0 ? Math.Clamp(progress.BytesProcessed * 100d / progress.TotalBytes, 0, 99.5) : 0;
        OperationProgress.Value = percent;
        var counts = progress.TotalBytes > 0 ? FormatSize(progress.BytesProcessed) + " / " + FormatSize(progress.TotalBytes) : L("正在处理");
        if (progress.TotalEntries > 0) counts += "  ·  " + L("{0}/{1} 项", progress.EntriesProcessed, progress.TotalEntries);
        if (_stopwatch.Elapsed.TotalSeconds > 1 && progress.BytesProcessed > 0)
            counts += "  ·  " + FormatSize((long)(progress.BytesProcessed / _stopwatch.Elapsed.TotalSeconds)) + "/s";
        if (!string.IsNullOrEmpty(progress.CurrentPath)) counts += "  ·  " + progress.CurrentPath;
        SetStatus(stage, counts);
    }

    private static string TranslateStage(string stage)
    {
        var value = stage.ToLowerInvariant();
        if (value.Contains("scan")) return L("正在扫描文件");
        if (value.Contains("deriv") || value.Contains("password") || value.Contains("key")) return L("正在处理独立密码");
        if (value.Contains("verif") || value.Contains("auth")) return L("正在验证完整性");
        if (value.Contains("extract") || value.Contains("decrypt") || value.Contains("restor")) return L("正在解密并还原");
        if (value.Contains("encrypt") || value.Contains("archiv") || value.Contains("pack")) return L("正在打包并加密");
        if (value.Contains("commit") || value.Contains("final")) return L("正在完成安全写入");
        return string.IsNullOrWhiteSpace(stage) ? L("正在处理") : stage;
    }

    private void SetStatus(string title, string detail, bool error = false)
    {
        StatusTitle.Text = title;
        StatusDetail.Text = detail;
        StatusDot.Fill = Brush(error ? "#EF9B9B" : "#6BE1C7");
        StatusTitle.Foreground = Brush(error ? "#F2B4B4" : "#E8F0F7");
    }

    private void ShowError(Exception error, string title)
    {
        var message = UiText.DescribeException(error);
        SetStatus(title, message, error: true);
        MessageBox.Show(this, message, "2Password · " + title, MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _operationCancellation?.Cancel();
        CancelButton.IsEnabled = false;
        _progressTimer.Stop();
        SetStatus(L("正在取消"), L("正在停止处理并清理临时输出，请稍候。"));
    }

    private void OpenResult_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResultPath is null) return;
        try
        {
            if (Directory.Exists(_lastResultPath)) Process.Start(new ProcessStartInfo("explorer.exe") { UseShellExecute = true, ArgumentList = { _lastResultPath } });
            else
            {
                var info = new ProcessStartInfo("explorer.exe") { UseShellExecute = true };
                info.Arguments = "/select,\"" + _lastResultPath + "\"";
                Process.Start(info);
            }
        }
        catch (Exception error) { ShowError(error, L("无法打开文件位置")); }
    }

    private async void ExtractPassword_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && !_busy && !_inspecting) { e.Handled = true; await ExtractAsync(); }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) { ToggleMaximize(); return; }
        try { DragMove(); } catch (InvalidOperationException) { }
    }
    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
    private void ToggleMaximize() => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_busy) { ClearPasswords(); return; }
        e.Cancel = true;
        if (MessageBox.Show(this, L("正在处理文件。要取消当前操作并关闭吗？"), "2Password", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        _closeWhenFinished = true;
        _operationCancellation?.Cancel();
        CancelButton.IsEnabled = false;
        _progressTimer.Stop();
        SetStatus(L("正在取消"), L("安全清理完成后将自动关闭。"));
    }

    private static string FormatSize(long bytes)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];
        var value = (double)Math.Max(0, bytes);
        var index = 0;
        while (value >= 1024 && index < units.Length - 1) { value /= 1024; index++; }
        return value.ToString(index == 0 ? "0" : "0.0") + " " + units[index];
    }

    private static SolidColorBrush Brush(string color)
    {
        var result = (SolidColorBrush)new BrushConverter().ConvertFromString(color)!;
        result.Freeze();
        return result;
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    private sealed class PasswordEntry
    {
        public TextBlock Label { get; set; } = null!;
        public TextBlock ConfirmationLabel { get; set; } = null!;
        public PasswordBox Password { get; set; } = null!;
        public PasswordBox Confirmation { get; set; } = null!;
        public Button Remove { get; set; } = null!;
    }

    private sealed class ForwardProgress(Action<PackageProgress> report) : IProgress<PackageProgress>
    {
        public void Report(PackageProgress value) => report(value);
    }

    private sealed class RecoveryForwardProgress(Action<RecoveryProgress> report) : IProgress<RecoveryProgress>
    {
        public void Report(RecoveryProgress value) => report(value);
    }
}

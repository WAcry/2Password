using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;
using TwoPassword.Core;
using TwoPassword.Recovery;
using static TwoPassword.App.UiText;
using Path = System.IO.Path;
using SharedText = TwoPassword.Localization.Text;

namespace TwoPassword.App;

public partial class MainWindow : Window
{
    private enum Screen { Home, Encrypt, Unlock, Repair, Working, Done }
    private enum Item { None, Several, Missing, Source, Package }
    private enum Work { Encrypt, Decrypt, Verify, Repair }
    private enum RepairNext { Verify, Repair, Open }

    private const int MaxPasswords = 16;

    private readonly string? _embeddedPackage;
    private readonly string? _stubOverride;
    private readonly string? _initialPath;
    private readonly bool _initialEncrypt;
    private readonly bool _initialRepair;
    private readonly string? _initialTarget;
    private bool _verifyFirstOnLoad;
    private readonly List<PasswordRow> _rows = [];
    private readonly DispatcherTimer _progressTimer;
    private readonly DispatcherTimer _revealTimer;
    private readonly Stopwatch _stopwatch = new();
    private Screen _screen = Screen.Home;
    private Screen _repairReturn = Screen.Home;
    private CancellationTokenSource? _operation;
    private CancellationTokenSource? _measure;
    private PackageProgress? _latestProgress;
    private RecoveryProgress? _latestRecoveryProgress;
    private Work _work;
    private bool _busy;
    private bool _damageSeen;
    private bool _closeWhenFinished;
    private Item _dragItem;
    private string? _dragPath;

    private string? _sourcePath;
    private (int Files, long Bytes)? _sourceSize;
    private string? _outputPath;

    private string? _packagePath;
    private PackageInfo? _packageInfo;
    private string? _packageError;
    private bool _packageHasRecovery;
    private bool _inspecting;
    private bool _wrongPassword;
    private string? _destinationPath;

    private string? _repairPath;
    private string? _repairMeta;
    private RecoveryResult? _repairResult;
    private bool _repairRan;
    private RepairNext _repairNext;

    private PackageResult? _doneResult;
    private string? _doneWarning;
    private bool _doneEncrypted;
    private bool _doneWithoutPassword;

    /// <param name="initialTarget">Save location for <paramref name="initialPath"/>, or the restore location when it is a package.</param>
    public MainWindow(string? embeddedPackage = null, string? stubOverride = null, string? initialPath = null, bool initialEncrypt = false,
        string? initialTarget = null, bool initialRepair = false)
    {
        _embeddedPackage = embeddedPackage;
        _stubOverride = stubOverride;
        _initialPath = initialPath;
        _initialEncrypt = initialEncrypt;
        _initialRepair = initialRepair;
        _initialTarget = initialTarget;
        InitializeComponent();
        var area = SystemParameters.WorkArea;
        Width = Math.Min(Width, area.Width - 24);
        Height = Math.Min(Height, area.Height - 24);
        MinWidth = Math.Min(MinWidth, Width);
        MinHeight = Math.Min(MinHeight, Height);
        _progressTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(120) };
        _progressTimer.Tick += (_, _) =>
        {
            UiText.Pin();
            if (Interlocked.Exchange(ref _latestProgress, null) is { } update) ShowProgress(update);
            if (Interlocked.Exchange(ref _latestRecoveryProgress, null) is { } recovery) ShowProgress(recovery);
        };
        // Short operations (most wrong passwords) finish before the progress screen would only flash.
        _revealTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(280) };
        _revealTimer.Tick += (_, _) =>
        {
            _revealTimer.Stop();
            if (_busy) Show(Screen.Working);
        };
        AddHandler(Keyboard.GotKeyboardFocusEvent, new KeyboardFocusChangedEventHandler((_, _) => UpdateCapsLock()), true);
        AddPasswordRow();
        UiText.Apply(Resources);
        Language = XmlLanguage.GetLanguage(UiText.Language);
        if (_embeddedPackage is not null)
        {
            AllowDrop = false;
            PrepareUnlock(_embeddedPackage);
            Show(Screen.Unlock, animate: false);
        }
        else Show(Screen.Home, animate: false);
    }

    private static string Version => typeof(App).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
    private static bool Motion => SystemParameters.ClientAreaAnimation;
    private FrameworkElement[] Views => [HomeView, EncryptView, UnlockView, RepairView, WorkingView, DoneView];

    private FrameworkElement ViewFor(Screen screen) => screen switch
    {
        Screen.Encrypt => EncryptView,
        Screen.Unlock => UnlockView,
        Screen.Repair => RepairView,
        Screen.Working => WorkingView,
        Screen.Done => DoneView,
        _ => HomeView,
    };

    internal void ApplyLaunchOptions(GuiLaunchOptions options)
    {
        if ((options.Compression switch { "zstd" => CompressionZstd, "brotli" => CompressionBrotli, "none" => CompressionNone, _ => null }) is { } compression)
            compression.IsChecked = true;
        if ((options.Layout switch { "auto" => LayoutAuto, "embedded" => LayoutEmbedded, "detached" => LayoutDetached, _ => null }) is { } layout)
            layout.IsChecked = true;
        if ((options.RecoveryPercent switch { 0 => Recovery0, 5 => Recovery5, 10 => Recovery10, 20 => Recovery20, _ => null }) is { } recovery)
            recovery.IsChecked = true;
        _verifyFirstOnLoad = options.VerifyFirst;
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        if (Elevation.IsElevated && _embeddedPackage is null) Elevation.AcceptShellDrops(this, ShellDrop);
        if (_embeddedPackage is not null)
        {
            if (_initialTarget is not null) UseTarget(_initialTarget);
            await InspectPackageAsync(_embeddedPackage);
        }
        else if (!string.IsNullOrWhiteSpace(_initialPath) && _initialRepair) OpenRepair(_initialPath, Screen.Home);
        else if (!string.IsNullOrWhiteSpace(_initialPath))
        {
            await RouteAsync(_initialPath, encrypt: _initialEncrypt);
            if (_initialTarget is not null) UseTarget(_initialTarget);
        }
        if (_verifyFirstOnLoad && _screen == Screen.Unlock) VerifyFirstCheck.IsChecked = true;
    }

    private void UseTarget(string target)
    {
        try
        {
            var full = Path.GetFullPath(target);
            if (_screen == Screen.Encrypt && _sourcePath is not null)
            {
                _outputPath = NextAvailablePackagePath(full);
                RenderOutput();
            }
            else if (_screen == Screen.Unlock && _packagePath is not null)
            {
                _destinationPath = NextAvailablePath(full, directory: true);
                RenderUnlock();
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
    }

    private void Window_SourceInitialized(object? sender, EventArgs e)
    {
        Theme.ApplyFrame(this);
    }

    private void ShellDrop(string[] paths)
    {
        if (!AcceptsDrops || paths.Length == 0) return;
        if (paths.Length > 1)
        {
            if (_screen == Screen.Home) ShowNotice(HomeNotice, L("一次只能放一项"));
            return;
        }
        var item = Classify(paths[0]);
        if (item is Item.Source or Item.Package) _ = OpenAsync(paths[0], item);
    }

    private void Window_StateChanged(object? sender, EventArgs e)
    {
        var maximized = WindowState == WindowState.Maximized;
        MaximizeButton.Content = maximized ? "\uE923" : "\uE922";
        AutomationProperties.SetName(MaximizeButton, maximized ? L("还原") : L("最大化"));
        // A maximized chrome-less window extends past the monitor by its resize frame.
        var frame = SystemParameters.WindowResizeBorderThickness;
        RootGrid.Margin = maximized ? new Thickness(frame.Left + 4, frame.Top + 4, frame.Right + 4, frame.Bottom + 4) : new Thickness(0);
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_busy) { ClearPasswords(); return; }
        e.Cancel = true;
        if (_closeWhenFinished) return;
        if (MessageBox.Show(this, L("正在处理文件。取消并关闭？"), "2Password", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        _closeWhenFinished = true;
        Cancel_Click(this, new RoutedEventArgs());
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape && ConcealPasswords()) { e.Handled = true; return; }
        // Between starting an operation and showing its progress screen, the form is frozen.
        if (_busy && _screen != Screen.Working && e.Key != Key.System) { e.Handled = true; return; }
        if (e.Key == Key.Escape && CanGoBack && !(_screen == Screen.Encrypt && HasTypedPasswords()))
        {
            e.Handled = true;
            GoBack();
        }
    }

    private void Window_PreviewKeyUp(object sender, KeyEventArgs e) => UpdateCapsLock();

    private void Window_PreviewTextInput(object sender, TextCompositionEventArgs e)
    {
        if (_busy && _screen != Screen.Working) e.Handled = true;
    }

    private void Window_Activated(object? sender, EventArgs e) => UpdateCapsLock();

    private bool CanGoBack => !_busy && _screen switch
    {
        Screen.Encrypt or Screen.Repair => true,
        Screen.Unlock or Screen.Done => _embeddedPackage is null,
        _ => false,
    };

    private void Show(Screen screen, bool animate = true)
    {
        ConcealPasswords();
        var changed = screen != _screen;
        _screen = screen;
        var current = ViewFor(screen);
        foreach (var view in Views) view.Visibility = view == current ? Visibility.Visible : Visibility.Collapsed;
        if (changed && current is ScrollViewer scroller) scroller.ScrollToTop();
        Render();
        UpdateCapsLock();
        if (animate && changed) Enter(current);
        if (changed && screen == Screen.Done) Pop(DoneMark);
        Dispatcher.BeginInvoke(DispatcherPriority.Input, FocusScreen);
    }

    private void Render()
    {
        BackButton.Visibility = CanGoBack ? Visibility.Visible : Visibility.Collapsed;
        WindowCaption.Margin = new Thickness(CanGoBack ? 6 : 16, 0, 0, 0);
        MenuButton.IsEnabled = !_busy;
        var caption = Elevation.IsElevated ? "2Password · " + L("管理员") : "2Password";
        WindowCaption.Text = caption;
        Title = _embeddedPackage is null ? caption : Path.GetFileName(_embeddedPackage) + " · " + caption;
        switch (_screen)
        {
            case Screen.Home: RenderDrop(); break;
            case Screen.Encrypt: RenderSource(); RenderOutput(); ValidatePasswords(); break;
            case Screen.Unlock: RenderUnlock(); break;
            case Screen.Repair: RenderRepair(); break;
            case Screen.Done: RenderDone(); break;
        }
    }

    private void FocusScreen()
    {
        if (_busy) return;
        switch (_screen)
        {
            case Screen.Encrypt:
                ((UIElement?)_rows.FirstOrDefault(row => IsEmpty(row.Password))?.Password ?? EncryptButton).Focus();
                break;
            case Screen.Unlock when UnlockPassword.IsEnabled:
                UnlockPassword.Focus();
                if (_wrongPassword) UnlockPassword.SelectAll();
                break;
            case Screen.Repair: RepairAction.Focus(); break;
            case Screen.Done: DonePrimary.Focus(); break;
        }
    }

    private void Back_Click(object sender, RoutedEventArgs e) => GoBack();

    private void GoBack()
    {
        if (!CanGoBack) return;
        if (_screen == Screen.Repair && _repairReturn == Screen.Unlock) Show(Screen.Unlock);
        else GoHome();
    }

    private void GoHome()
    {
        _measure?.Cancel();
        ClearPasswords();
        while (_rows.Count > 1) RemoveRow(_rows[^1], focus: false);
        foreach (var row in _rows) row.PasswordVisited = row.ConfirmationVisited = false;
        _sourcePath = null;
        _sourceSize = null;
        _outputPath = null;
        _packagePath = null;
        _packageInfo = null;
        _packageError = null;
        _inspecting = false;
        _wrongPassword = false;
        _repairPath = null;
        _repairResult = null;
        _doneResult = null;
        _doneWarning = null;
        _doneWithoutPassword = false;
        foreach (var notice in new[] { HomeNotice, EncryptNotice, UnlockNotice, RepairNotice }) Hide(notice);
        OptionsToggle.IsChecked = false;
        Show(Screen.Home);
    }

    private async Task RouteAsync(string path, bool packagesOnly = false, bool encrypt = false)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or IOException or SecurityException)
        {
            ShowNotice(HomeNotice, error);
            return;
        }
        var item = Classify(full);
        if (encrypt && item is Item.Package) item = Item.Source;
        if (packagesOnly && item == Item.Source) ShowNotice(HomeNotice, L("这个文件不是 2Password 加密包。"));
        else await OpenAsync(full, item);
    }

    private async Task OpenAsync(string path, Item item)
    {
        Hide(HomeNotice);
        switch (item)
        {
            case Item.Source: OpenSource(path); break;
            case Item.Package: PrepareUnlock(path); Show(Screen.Unlock); await InspectPackageAsync(path); break;
            case Item.Missing: ShowNotice(HomeNotice, L("找不到此文件或文件夹。")); break;
        }
    }

    private static Item Classify(string path)
    {
        try
        {
            if (Directory.Exists(path)) return Item.Source;
            if (!File.Exists(path)) return Item.Missing;
            if (path.EndsWith(".2pw", StringComparison.OrdinalIgnoreCase)) return Item.Package;
            if (path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && PackageService.HasPackage(path)) return Item.Package;
            return Item.Source;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) { return Item.Source; }
    }

    private void Menu_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var menu = new ContextMenu
        {
            PlacementTarget = MenuButton,
            Placement = PlacementMode.Custom,
            CustomPopupPlacementCallback = (popup, target, _) =>
                [new CustomPopupPlacement(new Point(target.Width - popup.Width, target.Height + 4), PopupPrimaryAxis.Horizontal)],
        };
        menu.Items.Add(LanguageItem("中文", "zh-CN"));
        menu.Items.Add(LanguageItem("English", "en"));
        menu.Items.Add(new Separator());
        menu.Items.Add(MenuEntry(L("修复加密包…"), "MenuRepair", ChooseRepair));
        menu.Items.Add(MenuEntry(L("开源许可"), "MenuLicenses", ShowNotices));
        var explorer = _embeddedPackage is null && Environment.ProcessPath is not null;
        if (explorer || !Elevation.IsElevated) menu.Items.Add(new Separator());
        if (explorer)
        {
            var item = MenuEntry(L("显示在右键菜单"), "MenuExplorer", ToggleExplorerMenu);
            item.IsChecked = ExplorerMenuEnabled();
            menu.Items.Add(item);
        }
        if (!Elevation.IsElevated)
        {
            var item = MenuEntry(L("以管理员身份运行"), "MenuElevate", RunElevated);
            if (Elevation.Shield is { } shield) item.Icon = new Image { Source = shield, Width = 16, Height = 16 };
            menu.Items.Add(item);
        }
        menu.Items.Add(new Separator());
        menu.Items.Add(new MenuItem { Header = L("版本 {0}", Version), IsEnabled = false });
        menu.IsOpen = true;
    }

    private void GitHub_Click(object sender, RoutedEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo("https://github.com/WAcry/2Password") { UseShellExecute = true }); }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException)
        {
            MessageBox.Show(this, DescribeException(error), "2Password", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static bool ExplorerMenuEnabled()
    {
        try { return Environment.ProcessPath is { } executable && ExplorerMenu.IsEnabled(executable); }
        catch (Exception error) when (error is SecurityException or UnauthorizedAccessException or IOException) { return false; }
    }

    private void ToggleExplorerMenu()
    {
        if (Environment.ProcessPath is not { } executable) return;
        try
        {
            if (ExplorerMenu.IsEnabled(executable)) ExplorerMenu.Disable(executable);
            else ExplorerMenu.Enable(executable);
        }
        catch (Exception error) when (error is SecurityException or UnauthorizedAccessException or IOException)
        {
            MessageBox.Show(this, DescribeException(error), "2Password", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Reopens elevated with the same item, locations and options. Passwords stay behind and are typed again.</summary>
    private void RunElevated()
    {
        if (_busy) return;
        var launch = new GuiLaunchOptions(StubPath: _stubOverride);
        switch (_screen)
        {
            case Screen.Encrypt when _sourcePath is not null:
                launch = launch with
                {
                    InitialPath = _sourcePath, Encrypt = true, Target = _outputPath,
                    Compression = SelectedCompression().ToString().ToLowerInvariant(),
                    Layout = SelectedLayout().ToString().ToLowerInvariant(),
                    RecoveryPercent = SelectedRecoveryPercent(),
                };
                break;
            case Screen.Unlock when _packagePath is not null:
                launch = launch with
                {
                    InitialPath = _embeddedPackage is null ? _packagePath : null,
                    Target = _destinationPath, VerifyFirst = VerifyFirstCheck.IsChecked == true,
                };
                break;
            case Screen.Repair when _repairPath is not null && _embeddedPackage is null:
                launch = launch with { InitialPath = _repairPath, Repair = true };
                break;
        }
        try
        {
            if (Elevation.Restart(launch.ElevationArguments(UiText.Language, Theme.Forced))) Close();
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException)
        {
            MessageBox.Show(this, DescribeException(error), "2Password", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private MenuItem LanguageItem(string label, string language)
    {
        var item = new MenuItem { Header = label, IsChecked = UiText.Language == language };
        AutomationProperties.SetAutomationId(item, "Language-" + language);
        item.Click += (_, _) => SwitchLanguage(language);
        return item;
    }

    private static MenuItem MenuEntry(string header, string id, Action action)
    {
        var item = new MenuItem { Header = header };
        AutomationProperties.SetAutomationId(item, id);
        item.Click += (_, _) => action();
        return item;
    }

    private void SwitchLanguage(string language)
    {
        if (_busy || language == UiText.Language) return;
        UiText.UseLanguage(language);
        UiText.Apply(Resources);
        Language = XmlLanguage.GetLanguage(UiText.Language);
        foreach (var notice in new[] { HomeNotice, EncryptNotice, UnlockNotice, RepairNotice }) Hide(notice);
        RefreshRows();
        Render();
        try { UiText.SaveLanguage(); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        try
        {
            if (_embeddedPackage is null && Environment.ProcessPath is { } executable && ExplorerMenu.IsEnabled(executable)) ExplorerMenu.Enable(executable);
        }
        catch (Exception error) when (error is SecurityException or UnauthorizedAccessException or IOException) { }
    }

    private bool AcceptsDrops => !_busy && _embeddedPackage is null;

    private void ChooseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = L("选择要加密的文件"), CheckFileExists = true, Multiselect = false, Filter = L("所有文件|*.*") };
        if (dialog.ShowDialog(this) == true) _ = RouteAsync(dialog.FileName);
    }

    private void ChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = L("选择要加密的文件夹"), Multiselect = false };
        if (dialog.ShowDialog(this) == true) OpenSource(dialog.FolderName);
    }

    private void OpenPackage_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = L("打开加密包"), CheckFileExists = true, Multiselect = false,
            Filter = L("2Password 加密包|*.exe;*.2pw|所有文件|*.*"),
        };
        if (dialog.ShowDialog(this) == true) _ = RouteAsync(dialog.FileName, packagesOnly: true);
    }

    private void Window_DragEnter(object sender, DragEventArgs e) => TrackDrag(e);
    private void Window_DragOver(object sender, DragEventArgs e) => TrackDrag(e);

    private void TrackDrag(DragEventArgs e)
    {
        var (item, _) = AcceptsDrops ? Inspect(e.Data) : (Item.None, null);
        e.Effects = item is Item.Source or Item.Package ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
        if (item == _dragItem) return;
        _dragItem = item;
        RenderDrop();
    }

    private void Window_DragLeave(object sender, DragEventArgs e)
    {
        var point = e.GetPosition(this);
        if (point.X > 0 && point.Y > 0 && point.X < ActualWidth && point.Y < ActualHeight) return;
        _dragItem = Item.None;
        _dragPath = null;
        RenderDrop();
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        e.Handled = true;
        var (item, path) = AcceptsDrops ? Inspect(e.Data) : (Item.None, null);
        _dragItem = Item.None;
        _dragPath = null;
        RenderDrop();
        if (path is not null && item is Item.Source or Item.Package) _ = OpenAsync(path, item);
    }

    private (Item Item, string? Path) Inspect(IDataObject data)
    {
        string[]? paths;
        try { paths = data.GetData(DataFormats.FileDrop) as string[]; }
        catch (Exception error) when (error is COMException or InvalidOperationException) { paths = null; }
        if (paths is null || paths.Length == 0) return (Item.None, null);
        if (paths.Length > 1) return (Item.Several, null);
        if (paths[0] == _dragPath && _dragItem != Item.None) return (_dragItem, _dragPath);
        _dragPath = paths[0];
        return (Classify(paths[0]), paths[0]);
    }

    private void RenderDrop()
    {
        var active = _screen == Screen.Home && _dragItem != Item.None;
        var accepted = active && _dragItem is Item.Source or Item.Package;
        DropTitle.Text = !active ? L("拖入文件或文件夹") : _dragItem switch
        {
            Item.Several => L("一次只能放一项"),
            Item.Package => L("松开，打开加密包"),
            Item.Source => L("松开，开始加密"),
            _ => L("拖入文件或文件夹"),
        };
        DropOutline.StrokeDashArray = accepted ? [] : [4, 3];
        DropOutline.SetResourceReference(Shape.StrokeProperty, accepted ? "Ink" : "LineStrong");
        if (accepted) DropFill.SetResourceReference(Shape.FillProperty, "Sunken");
        else DropFill.Fill = Brushes.Transparent;
        DropButtons.Opacity = active ? 0 : 1;
        DropButtons.IsHitTestVisible = !active;
        Lift(accepted && _dragItem == Item.Package);
    }

    private void Lift(bool up)
    {
        if (HomeLock.Template?.FindName("Shackle", HomeLock) is not Shape shackle) return;
        if (shackle.RenderTransform is not TranslateTransform { IsFrozen: false } shift) shackle.RenderTransform = shift = new TranslateTransform();
        var target = up ? -4d : 0d;
        if (!Motion) { shift.BeginAnimation(TranslateTransform.YProperty, null); shift.Y = target; return; }
        shift.BeginAnimation(TranslateTransform.YProperty,
            new DoubleAnimation(target, TimeSpan.FromMilliseconds(180)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
    }

    private void OpenSource(string path)
    {
        _sourcePath = path;
        _sourceSize = null;
        var trimmed = Path.TrimEndingDirectorySeparator(path);
        var parent = Path.GetDirectoryName(trimmed);
        if (string.IsNullOrEmpty(parent)) parent = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var name = Path.GetFileName(trimmed);
        Hide(EncryptNotice);
        try { _outputPath = NextAvailablePackagePath(Path.Combine(parent, (string.IsNullOrEmpty(name) ? L("加密文件") : name) + ".protected.exe")); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
        {
            _outputPath = null;
            ShowNotice(EncryptNotice, error);
        }
        Show(Screen.Encrypt);
        MeasureSource(path);
    }

    private async void MeasureSource(string path)
    {
        _measure?.Cancel();
        var measure = _measure = new CancellationTokenSource();
        try
        {
            var size = await Task.Run(() => Measure(path, measure.Token), measure.Token);
            if (!measure.IsCancellationRequested && _sourcePath == path)
            {
                _sourceSize = size;
                RenderSource();
            }
        }
        catch (Exception error) when (error is OperationCanceledException or IOException or UnauthorizedAccessException or SecurityException) { }
        finally
        {
            if (_measure == measure) _measure = null;
            measure.Dispose();
        }
    }

    private static (int Files, long Bytes) Measure(string path, CancellationToken token)
    {
        if (File.Exists(path)) return (1, new FileInfo(path).Length);
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        var files = 0;
        long bytes = 0;
        foreach (var file in new DirectoryInfo(path).EnumerateFiles("*", options))
        {
            if ((++files & 1023) == 0) token.ThrowIfCancellationRequested();
            bytes += file.Length;
        }
        return (files, bytes);
    }

    private void RenderSource()
    {
        if (_sourcePath is null) return;
        var folder = Directory.Exists(_sourcePath);
        SourceGlyph.Text = folder ? "\uE8B7" : "\uE7C3";
        SourceName.Text = DisplayName(_sourcePath);
        SourceName.ToolTip = _sourcePath;
        SourceMeta.Text = _sourceSize is not { } size ? " "
            : !folder ? FormatSize(size.Bytes)
            : size.Files == 0 ? L("空文件夹")
            : FileCount(size.Files, size.Bytes);
    }

    private void RenderOutput()
    {
        RenderPath(OutputPathText, _outputPath);
    }

    private static void RenderPath(TextBlock target, string? path)
    {
        target.Inlines.Clear();
        target.ToolTip = path;
        if (path is null) return;
        target.Inlines.Add(new Run(Path.GetFileName(path)));
        var folder = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(folder)) return;
        var location = new Run("   " + folder);
        location.SetResourceReference(TextElement.ForegroundProperty, "Ink3");
        target.Inlines.Add(location);
    }

    private void ChooseOutput_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = L("保存加密包"), Filter = L("加密包 (*.exe)|*.exe"), AddExtension = true, DefaultExt = ".exe", OverwritePrompt = false,
            FileName = SafeFileName(_outputPath, L("加密文件") + ".protected.exe"),
        };
        if (_outputPath is not null && Path.GetDirectoryName(_outputPath) is { } folder && Directory.Exists(folder)) dialog.InitialDirectory = folder;
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            _outputPath = NextAvailablePackagePath(dialog.FileName);
            Hide(EncryptNotice);
            RenderOutput();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) { ShowNotice(EncryptNotice, error); }
    }

    private void OptionsToggle_Changed(object sender, RoutedEventArgs e)
    {
        var open = OptionsToggle.IsChecked == true;
        OptionsPanel.Visibility = open ? Visibility.Visible : Visibility.Collapsed;
        if (open) Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () => OptionsPanel.BringIntoView());
    }

    private PackageCompression SelectedCompression() =>
        CompressionBrotli.IsChecked == true ? PackageCompression.Brotli : CompressionNone.IsChecked == true ? PackageCompression.None : PackageCompression.Zstd;

    private PackageLayout SelectedLayout() =>
        LayoutEmbedded.IsChecked == true ? PackageLayout.Embedded : LayoutDetached.IsChecked == true ? PackageLayout.Detached : PackageLayout.Auto;

    private int SelectedRecoveryPercent() =>
        Recovery0.IsChecked == true ? 0 : Recovery10.IsChecked == true ? 10 : Recovery20.IsChecked == true ? 20 : RecoveryService.DefaultPercent;

    private void Encrypt_Click(object sender, RoutedEventArgs e) => _ = EncryptAsync();

    private async Task EncryptAsync()
    {
        if (_busy || _sourcePath is null) return;
        Hide(EncryptNotice);
        if (!ValidatePasswords(reveal: true))
        {
            FocusFirstProblem();
            return;
        }
        var passwords = new List<string>();
        CreateOptions options;
        int redundancy;
        try
        {
            if (!File.Exists(_sourcePath) && !Directory.Exists(_sourcePath)) throw new IOException(L("找不到此文件或文件夹。"));
            var output = _outputPath ?? throw new IOException(L("先选择保存位置。"));
            if (PackageOutputCollision(output))
            {
                output = _outputPath = NextAvailablePackagePath(output);
                RenderOutput();
            }
            foreach (var row in _rows) passwords.Add(row.Password.Password);
            options = new CreateOptions(_sourcePath, output, passwords, SelectedCompression(), _stubOverride ?? CommandLine.StandaloneStub(), SelectedLayout());
            redundancy = SelectedRecoveryPercent();
        }
        catch (Exception error)
        {
            passwords.Clear();
            ShowNotice(EncryptNotice, error);
            return;
        }

        BeginWork(Work.Encrypt);
        var token = _operation!.Token;
        try
        {
            var (package, recoveryError) = await Task.Run(() => RecoveryService.CreateAsync(options, redundancy, PackageProgressSink(), RecoveryProgressSink(), token), token);
            _doneWithoutPassword = passwords.Any(password => password.Length == 0);
            ClearPasswords();
            var warning = recoveryError is null ? null : L("恢复记录没有生成：{0}", DescribeException(recoveryError));
            if (EndWork()) ShowDone(package, warning, encrypted: true);
        }
        catch (OperationCanceledException) { if (EndWork()) ReturnWithNotice(Screen.Encrypt, EncryptNotice, L("已取消"), neutral: true); }
        catch (Exception error) { if (EndWork()) ReturnWithNotice(Screen.Encrypt, EncryptNotice, error); }
        finally { passwords.Clear(); }
    }

    private sealed class PasswordRow
    {
        public required Grid Root { get; init; }
        public required PasswordBox Password { get; init; }
        public required PasswordBox Confirmation { get; init; }
        public required TextBlock Check { get; init; }
        public required Button Remove { get; init; }
        public required TextBlock Message { get; init; }
        public bool PasswordVisited { get; set; }
        public bool ConfirmationVisited { get; set; }
    }

    private void AddPassword_Click(object sender, RoutedEventArgs e)
    {
        AddPasswordRow();
        _rows[^1].Password.Focus();
    }

    private void AddPasswordRow()
    {
        if (_rows.Count >= MaxPasswords) return;
        var root = new Grid { Margin = new Thickness(0, 0, 0, 8) };
        root.ColumnDefinitions.Add(new ColumnDefinition());
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(8) });
        root.ColumnDefinitions.Add(new ColumnDefinition());
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(36) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var password = new PasswordBox();
        password.SetResourceReference(Field.PlaceholderProperty, "Ui.PasswordPlaceholder");
        var confirmation = new PasswordBox { Padding = new Thickness(12, 0, 66, 0) };
        confirmation.SetResourceReference(Field.PlaceholderProperty, "Ui.ConfirmPlaceholder");
        Grid.SetColumn(confirmation, 2);
        var check = new TextBlock
        {
            Text = "\uE73E", FontFamily = (FontFamily)FindResource("Icons"), FontSize = 12, IsHitTestVisible = false,
            HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 44, 0), Visibility = Visibility.Collapsed,
        };
        check.SetResourceReference(TextBlock.ForegroundProperty, "Success");
        Grid.SetColumn(check, 2);
        var remove = new Button
        {
            Content = "\uE711", Style = (Style)FindResource("IconButton"),
            HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center,
        };
        Grid.SetColumn(remove, 3);
        var message = new TextBlock { Style = (Style)FindResource("Meta"), Margin = new Thickness(2, 6, 0, 0), TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed };
        message.SetResourceReference(TextBlock.ForegroundProperty, "Danger");
        Grid.SetRow(message, 1);
        Grid.SetColumnSpan(message, 3);
        foreach (UIElement child in new UIElement[] { password, confirmation, check, remove, message }) root.Children.Add(child);

        var row = new PasswordRow { Root = root, Password = password, Confirmation = confirmation, Check = check, Remove = remove, Message = message };
        password.PasswordChanged += (_, _) => { Hide(EncryptNotice); ValidatePasswords(); };
        confirmation.PasswordChanged += (_, _) => ValidatePasswords();
        password.LostKeyboardFocus += (_, _) =>
        {
            if (!IsEmpty(password)) row.PasswordVisited = true;
            ValidatePasswords();
        };
        confirmation.LostKeyboardFocus += (_, _) =>
        {
            if (!IsEmpty(confirmation)) row.ConfirmationVisited = true;
            ValidatePasswords();
        };
        password.KeyDown += (_, e) =>
        {
            if (e.Key != Key.Enter) return;
            e.Handled = true;
            confirmation.Focus();
        };
        confirmation.KeyDown += (_, e) =>
        {
            if (e.Key != Key.Enter) return;
            e.Handled = true;
            var next = _rows.IndexOf(row) + 1;
            if (next < _rows.Count) _rows[next].Password.Focus();
            else _ = EncryptAsync();
        };
        remove.Click += (_, _) => RemoveRow(row, focus: true);
        _rows.Add(row);
        PasswordRows.Children.Add(root);
        RefreshRows();
        ValidatePasswords();
    }

    private void RemoveRow(PasswordRow row, bool focus)
    {
        if (_rows.Count <= 1) return;
        var index = _rows.IndexOf(row);
        row.Password.Clear();
        row.Confirmation.Clear();
        _rows.Remove(row);
        PasswordRows.Children.Remove(row.Root);
        RefreshRows();
        ValidatePasswords();
        if (focus) _rows[Math.Min(index, _rows.Count - 1)].Password.Focus();
    }

    private void RefreshRows()
    {
        for (var i = 0; i < _rows.Count; i++)
        {
            var row = _rows[i];
            row.Remove.Visibility = _rows.Count > 1 ? Visibility.Visible : Visibility.Hidden;
            row.Remove.ToolTip = L("移除");
            AutomationProperties.SetName(row.Remove, L("移除密码 {0}", i + 1));
            AutomationProperties.SetName(row.Password, L("密码 {0}", i + 1));
            AutomationProperties.SetAutomationId(row.Password, "Password" + (i + 1));
            AutomationProperties.SetName(row.Confirmation, L("确认密码 {0}", i + 1));
            AutomationProperties.SetAutomationId(row.Confirmation, "ConfirmPassword" + (i + 1));
        }
        AddPasswordButton.Visibility = _rows.Count < MaxPasswords ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Marks each row in place. Problems show once a field has been left, or for every row when <paramref name="reveal"/> is set.</summary>
    private bool ValidatePasswords(bool reveal = false)
    {
        var secrets = _rows.Select(row => (Password: row.Password.SecurePassword, Confirmation: row.Confirmation.SecurePassword)).ToArray();
        try
        {
            var valid = true;
            var withoutPassword = secrets.Any(secret => secret.Password.Length == 0 && secret.Confirmation.Length == 0);
            PasswordsHint.Text = withoutPassword ? L("无需密码，任何人都能解开") : L("任意一个都能解开");
            PasswordsHint.Visibility = withoutPassword || _rows.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
            for (var i = 0; i < _rows.Count; i++)
            {
                var row = _rows[i];
                var (password, confirmation) = secrets[i];
                string? message = null;
                bool passwordBad = false, confirmationBad = false, ok = false;
                var showPassword = reveal || row.PasswordVisited;
                var duplicateOf = Array.FindIndex(secrets, 0, i, other => SameSecret(other.Password, password));
                if (duplicateOf >= 0)
                {
                    if (showPassword) (message, passwordBad) = (L("和第 {0} 个密码相同", duplicateOf + 1), true);
                }
                else if (!SameSecret(password, confirmation))
                {
                    if (reveal || row.ConfirmationVisited || confirmation.Length >= password.Length)
                        (message, confirmationBad) = (confirmation.Length == 0 ? L("再输入一次") : L("两次输入不一致"), true);
                }
                else ok = true;
                valid &= ok;
                Field.SetIsInvalid(row.Password, passwordBad);
                Field.SetIsInvalid(row.Confirmation, confirmationBad);
                row.Check.Visibility = ok ? Visibility.Visible : Visibility.Collapsed;
                row.Message.Text = message ?? "";
                row.Message.Visibility = message is null ? Visibility.Collapsed : Visibility.Visible;
            }
            return valid;
        }
        finally
        {
            foreach (var (password, confirmation) in secrets)
            {
                password.Dispose();
                confirmation.Dispose();
            }
        }
    }

    private void FocusFirstProblem()
    {
        foreach (var row in _rows)
        {
            if (Field.GetIsInvalid(row.Password)) { row.Password.Focus(); Shake(row.Root); return; }
            if (Field.GetIsInvalid(row.Confirmation)) { row.Confirmation.Focus(); Shake(row.Root); return; }
        }
    }

    private bool HasTypedPasswords() => _rows.Any(row => !IsEmpty(row.Password) || !IsEmpty(row.Confirmation));

    private static bool IsEmpty(PasswordBox box)
    {
        using var secure = box.SecurePassword;
        return secure.Length == 0;
    }

    /// <summary>Ordinal comparison without copying either secret into a managed string.</summary>
    private static bool SameSecret(SecureString first, SecureString second)
    {
        if (first.Length != second.Length) return false;
        IntPtr a = IntPtr.Zero, b = IntPtr.Zero;
        try
        {
            a = Marshal.SecureStringToGlobalAllocUnicode(first);
            b = Marshal.SecureStringToGlobalAllocUnicode(second);
            var difference = 0;
            for (var offset = 0; offset < first.Length * 2; offset++) difference |= Marshal.ReadByte(a, offset) ^ Marshal.ReadByte(b, offset);
            return difference == 0;
        }
        finally
        {
            if (a != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(a);
            if (b != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(b);
        }
    }

    private void UpdateCapsLock()
    {
        var on = Keyboard.IsKeyToggled(Key.CapsLock) && Keyboard.FocusedElement is PasswordBox;
        EncryptCapsLock.Visibility = on && _screen == Screen.Encrypt ? Visibility.Visible : Visibility.Collapsed;
        UnlockCapsLock.Visibility = on && _screen == Screen.Unlock ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ClearPasswords()
    {
        ConcealPasswords();
        foreach (var row in _rows)
        {
            row.Password.Clear();
            row.Confirmation.Clear();
        }
        UnlockPassword.Clear();
    }

    private bool ConcealPasswords()
    {
        var concealed = PasswordRevealButton.Conceal(UnlockPassword);
        foreach (var row in _rows)
        {
            concealed |= PasswordRevealButton.Conceal(row.Password);
            concealed |= PasswordRevealButton.Conceal(row.Confirmation);
        }
        return concealed;
    }

    private void PrepareUnlock(string path)
    {
        _packagePath = path;
        _packageInfo = null;
        _packageError = null;
        _wrongPassword = false;
        _inspecting = true;
        _packageHasRecovery = false;
        _destinationPath = SuggestDestination(path);
        UnlockPassword.Clear();
        VerifyFirstCheck.IsChecked = false;
        Hide(UnlockNotice);
    }

    private async Task InspectPackageAsync(string path)
    {
        UiText.Pin();
        // A damaged trailer makes this scan the whole file, so it stays off the UI thread.
        var hasRecovery = await Task.Run(() => RecoveryService.HasRecovery(path));
        if (_packagePath == path) _packageHasRecovery = hasRecovery;
        try
        {
            var info = await Task.Run(() => PackageService.InspectAsync(path));
            if (_packagePath == path) _packageInfo = info;
        }
        catch (Exception error)
        {
            if (_packagePath == path) _packageError = DescribeException(error);
        }
        if (_packagePath != path) return;
        _inspecting = false;
        if (_screen != Screen.Unlock) return;
        RenderUnlock();
        FocusScreen();
    }

    private static string? SuggestDestination(string package)
    {
        var parent = Path.GetDirectoryName(package) ?? Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var stem = Path.GetFileNameWithoutExtension(package);
        if (stem.EndsWith(".protected", StringComparison.OrdinalIgnoreCase)) stem = stem[..^10];
        try { return NextAvailablePath(Path.Combine(parent, L("{0}_已还原", stem)), directory: true); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }

    private void RenderUnlock()
    {
        if (_packagePath is null) return;
        PackageName.Text = Path.GetFileName(_packagePath);
        PackageName.ToolTip = _packagePath;
        var tone = "Ink3";
        string meta;
        if (_inspecting) meta = L("正在读取…");
        else if (_packageInfo is { } info)
            meta = info.PasswordSlots == 1
                ? L("{0} · 1 个密码", FormatSize(info.EncryptedBytes))
                : L("{0} · {1} 个密码", FormatSize(info.EncryptedBytes), info.PasswordSlots);
        else if (_packageHasRecovery) (meta, tone) = (L("文件有损坏，解密时会用恢复记录修复"), "Warning");
        else (meta, tone) = (_packageError ?? "", "Danger");
        PackageMeta.Text = meta;
        PackageMeta.SetResourceReference(TextBlock.ForegroundProperty, tone);
        ReloadButton.Visibility = !_inspecting && _packageInfo is null && !_packageHasRecovery ? Visibility.Visible : Visibility.Collapsed;
        var ready = !_inspecting && (_packageInfo is not null || _packageHasRecovery);
        UnlockPassword.IsEnabled = ready;
        DecryptButton.IsEnabled = ready;
        UnlockError.Visibility = _wrongPassword ? Visibility.Visible : Visibility.Collapsed;
        Field.SetIsInvalid(UnlockPassword, _wrongPassword);
        RenderPath(DestinationText, _destinationPath);
        VerifyFirstCheck.Visibility = _packageHasRecovery ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void Reload_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _packagePath is null) return;
        var path = _packagePath;
        PrepareUnlock(path);
        RenderUnlock();
        await InspectPackageAsync(path);
    }

    private void UnlockPassword_PasswordChanged(object sender, RoutedEventArgs e)
    {
        Hide(UnlockNotice);
        if (!_wrongPassword) return;
        _wrongPassword = false;
        UnlockError.Visibility = Visibility.Collapsed;
        Field.SetIsInvalid(UnlockPassword, false);
    }

    private void UnlockPassword_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        e.Handled = true;
        _ = DecryptAsync();
    }

    private void ChooseDestination_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = L("选择还原位置"), Multiselect = false };
        if (_destinationPath is not null && Path.GetDirectoryName(_destinationPath) is { } parent && Directory.Exists(parent)) dialog.InitialDirectory = parent;
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var name = SafeFileName(_destinationPath, L("2Password_已还原"));
            _destinationPath = NextAvailablePath(Path.Combine(dialog.FolderName, name), directory: true);
            Hide(UnlockNotice);
            RenderUnlock();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) { ShowNotice(UnlockNotice, error); }
    }

    private void Decrypt_Click(object sender, RoutedEventArgs e) => _ = DecryptAsync();

    private async Task DecryptAsync()
    {
        if (_busy || _inspecting || _packagePath is null || !DecryptButton.IsEnabled) return;
        Hide(UnlockNotice);
        string destination;
        try
        {
            destination = _destinationPath ?? throw new IOException(L("先选择还原位置。"));
            if (File.Exists(destination) || Directory.Exists(destination))
            {
                destination = _destinationPath = NextAvailablePath(destination, directory: true);
                RenderUnlock();
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
        {
            ShowNotice(UnlockNotice, error);
            return;
        }
        var options = new ExtractOptions(_packagePath, destination, UnlockPassword.Password);
        var verifyFirst = _packageHasRecovery && VerifyFirstCheck.IsChecked == true;

        BeginWork(Work.Decrypt);
        var token = _operation!.Token;
        try
        {
            var result = await Task.Run(() => RecoveryService.ExtractAsync(options, PackageProgressSink(), RecoveryProgressSink(), token, verifyFirst), token);
            ClearPasswords();
            if (EndWork()) ShowDone(result, null, encrypted: false);
        }
        catch (PasswordNotRecognizedException)
        {
            if (!EndWork()) return;
            _wrongPassword = true;
            Show(Screen.Unlock);
            Shake(UnlockPassword);
        }
        catch (OperationCanceledException) { if (EndWork()) ReturnWithNotice(Screen.Unlock, UnlockNotice, L("已取消"), neutral: true); }
        catch (Exception error) { if (EndWork()) ReturnWithNotice(Screen.Unlock, UnlockNotice, error); }
    }

    private void ChooseRepair()
    {
        if (_busy) return;
        var dialog = new OpenFileDialog { Title = L("选择要修复的加密包"), Filter = L("2Password 加密包|*.exe;*.2pw|所有文件|*.*"), CheckFileExists = true, Multiselect = false };
        if (_packagePath is not null && Path.GetDirectoryName(_packagePath) is { } folder && Directory.Exists(folder)) dialog.InitialDirectory = folder;
        if (dialog.ShowDialog(this) != true) return;
        OpenRepair(dialog.FileName, _embeddedPackage is not null || _screen == Screen.Unlock ? Screen.Unlock : Screen.Home);
    }

    private async void OpenRepair(string path, Screen returnTo)
    {
        _repairPath = path;
        _repairResult = null;
        _repairReturn = returnTo;
        _repairMeta = L("正在读取…");
        Hide(RepairNotice);
        Show(Screen.Repair);
        UiText.Pin();
        string meta;
        try
        {
            // A damaged trailer makes this scan the whole file.
            var regions = await Task.Run(() => RecoveryService.LocateRegions(path));
            meta = regions.RecoveryLength > 0 ? L("恢复记录 {0}", FormatSize(regions.RecoveryLength)) : L("没有恢复记录");
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException) { meta = DescribeException(error); }
        if (_repairPath != path) return;
        _repairMeta = meta;
        if (_screen == Screen.Repair) RenderRepair();
    }

    private void RenderRepair()
    {
        if (_repairPath is null) return;
        RepairName.Text = Path.GetFileName(_repairPath);
        RepairName.ToolTip = _repairPath;
        RepairMeta.Text = _repairMeta ?? "";
        if (_repairResult is not { } result)
        {
            RepairResult.Visibility = Visibility.Collapsed;
            _repairNext = RepairNext.Verify;
            RepairAction.Content = L("检查");
            return;
        }
        var repairable = result.Repairable && !_repairRan;
        var (status, tone) = result.Success ? (_repairRan && result.Repaired ? L("已修复") : L("没有损坏"), "Success")
            : repairable ? (L("有损坏，可以修复"), "Warning")
            : (L("无法修复"), "Danger");
        RepairResult.Visibility = Visibility.Visible;
        RepairStatus.Text = status;
        RepairDot.SetResourceReference(Shape.FillProperty, tone);
        RepairSummary.Text = result.Summary;
        RepairSummary.Visibility = result.Success && !result.Repaired ? Visibility.Collapsed : Visibility.Visible;
        _repairNext = repairable ? RepairNext.Repair : result.Success ? RepairNext.Open : RepairNext.Verify;
        RepairAction.Content = _repairNext switch
        {
            RepairNext.Repair => L("修复"),
            RepairNext.Open => L("打开加密包"),
            _ => L("重新检查"),
        };
    }

    private async void RepairAction_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        if (_repairNext == RepairNext.Open && _repairPath is { } package)
        {
            PrepareUnlock(package);
            Show(Screen.Unlock);
            await InspectPackageAsync(package);
        }
        else await RunRecoveryAsync(repair: _repairNext == RepairNext.Repair);
    }

    private async Task RunRecoveryAsync(bool repair)
    {
        if (_busy || _repairPath is null) return;
        Hide(RepairNotice);
        var path = _repairPath;
        if (!File.Exists(path))
        {
            ShowNotice(RepairNotice, L("找不到此文件或文件夹。"));
            return;
        }
        BeginWork(repair ? Work.Repair : Work.Verify);
        var token = _operation!.Token;
        try
        {
            var result = await Task.Run(() => repair
                ? RecoveryService.RepairAsync(path, RecoveryProgressSink(), token)
                : RecoveryService.VerifyAsync(path, RecoveryProgressSink(), token), token);
            if (!EndWork()) return;
            _repairResult = result;
            _repairRan = repair;
            Show(Screen.Repair);
        }
        catch (OperationCanceledException) { if (EndWork()) ReturnWithNotice(Screen.Repair, RepairNotice, L("已取消"), neutral: true); }
        catch (Exception error) { if (EndWork()) ReturnWithNotice(Screen.Repair, RepairNotice, error); }
    }

    private void BeginWork(Work work)
    {
        ConcealPasswords();
        UiText.Pin();
        _busy = true;
        _work = work;
        _damageSeen = false;
        _operation = new CancellationTokenSource();
        ViewFor(_screen).IsHitTestVisible = false;
        WorkStage.Text = work switch
        {
            Work.Encrypt => L("正在加密"),
            Work.Decrypt => L("正在解密"),
            Work.Verify => L("正在检查"),
            _ => L("正在修复"),
        };
        SetPercent(null);
        WorkDetail.Text = WorkPath.Text = " ";
        CancelButton.IsEnabled = true;
        Render();
        _stopwatch.Restart();
        _progressTimer.Start();
        _revealTimer.Start();
    }

    /// <summary>Returns false when the window closes instead of returning to a screen.</summary>
    private bool EndWork()
    {
        _revealTimer.Stop();
        _progressTimer.Stop();
        _stopwatch.Stop();
        Interlocked.Exchange(ref _latestProgress, null);
        Interlocked.Exchange(ref _latestRecoveryProgress, null);
        _operation?.Dispose();
        _operation = null;
        _busy = false;
        foreach (var view in Views) view.IsHitTestVisible = true;
        if (!_closeWhenFinished) return true;
        Close();
        return false;
    }

    private void ReturnWithNotice(Screen screen, TextBlock notice, string message, bool neutral = false)
    {
        Show(screen);
        ShowNotice(notice, message, neutral);
    }

    private void ReturnWithNotice(Screen screen, TextBlock notice, Exception error)
    {
        Show(screen);
        ShowNotice(notice, error);
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        ConcealPasswords();
        _operation?.Cancel();
        CancelButton.IsEnabled = false;
        _progressTimer.Stop();
        WorkStage.Text = L("正在取消");
        SetPercent(null);
        WorkDetail.Text = WorkPath.Text = " ";
    }

    private IProgress<PackageProgress> PackageProgressSink() =>
        new ForwardProgress<PackageProgress>(value => Interlocked.Exchange(ref _latestProgress, value));

    private IProgress<RecoveryProgress> RecoveryProgressSink() =>
        new ForwardProgress<RecoveryProgress>(value => Interlocked.Exchange(ref _latestRecoveryProgress, value));

    private void ShowProgress(PackageProgress progress)
    {
        if (!_busy) return;
        var (title, measured) = StageOf(progress.Stage);
        if (title is not null) WorkStage.Text = title;
        if (!measured || progress.TotalBytes <= 0 || progress.BytesProcessed <= 0)
        {
            SetPercent(null);
            WorkDetail.Text = IsStage(progress.Stage, "检查文件") && progress.EntriesProcessed > 0
                ? L("{0} 项", progress.EntriesProcessed.ToString("N0", CultureInfo.CurrentCulture)) : " ";
        }
        else
        {
            SetPercent(Math.Clamp(progress.BytesProcessed * 100d / progress.TotalBytes, 0, 99));
            var detail = FormatSize(progress.BytesProcessed) + " / " + FormatSize(progress.TotalBytes);
            var seconds = _stopwatch.Elapsed.TotalSeconds;
            if (seconds > 1) detail += "  ·  " + FormatSize((long)(progress.BytesProcessed / seconds)) + "/s";
            WorkDetail.Text = detail;
        }
        var current = progress.CurrentPath.TrimEnd('/', '\\');
        WorkPath.Text = current.Length == 0 ? " " : Path.GetFileName(current);
    }

    private void ShowProgress(RecoveryProgress progress)
    {
        if (!_busy) return;
        if (IsStage(progress.Stage, "检测到损坏")) _damageSeen = true;
        var title = progress.Stage switch
        {
            _ when IsStage(progress.Stage, "生成恢复记录") => L("正在生成恢复记录"),
            _ when IsStage(progress.Stage, "检查加密数据") => _damageSeen ? L("发现损坏，正在检查") : L("正在检查"),
            _ when IsStage(progress.Stage, "准备修复") || IsStage(progress.Stage, "修复加密数据") || IsStage(progress.Stage, "检测到损坏") =>
                _damageSeen ? L("发现损坏，正在修复") : L("正在修复"),
            _ when IsStage(progress.Stage, "重新解密") => L("正在解密"),
            _ when IsStage(progress.Stage, "恢复记录已生成") || IsStage(progress.Stage, "修复完成") => null,
            _ => string.IsNullOrWhiteSpace(progress.Stage) ? null : progress.Stage,
        };
        if (title is not null) WorkStage.Text = title;
        SetPercent(progress.Percent is int percent ? Math.Clamp(percent, 0, 99) : null);
        WorkDetail.Text = WorkPath.Text = " ";
    }

    private void SetPercent(double? percent)
    {
        WorkProgress.IsIndeterminate = percent is null;
        WorkProgress.Value = percent ?? 0;
        WorkPercent.Text = percent is { } value ? ((int)value).ToString(CultureInfo.CurrentCulture) + "%" : "";
    }

    private static bool IsStage(string stage, string key) => string.Equals(stage, SharedText.Get(key), StringComparison.Ordinal);

    /// <summary>Maps Core progress stages to a short headline; <c>Measured</c> stages carry meaningful byte counts.</summary>
    private static (string? Title, bool Measured) StageOf(string stage)
    {
        if (IsStage(stage, "检查文件") || IsStage(stage, "核对源文件")) return (L("正在检查文件"), false);
        if (IsStage(stage, "保护独立密码")) return (L("正在设置密码"), false);
        if (IsStage(stage, "验证密码")) return (L("正在验证密码"), false);
        if (IsStage(stage, "加密打包")) return (L("正在加密"), true);
        if (IsStage(stage, "组装独立 EXE") || IsStage(stage, "生成配套解密程序")) return (L("正在生成 EXE"), true);
        if (IsStage(stage, "验证并解包")) return (L("正在解密"), true);
        if (IsStage(stage, "恢复文件属性")) return (L("即将完成"), false);
        if (IsStage(stage, "完成")) return (null, true);
        return (string.IsNullOrWhiteSpace(stage) ? null : stage, true);
    }

    private void ShowDone(PackageResult result, string? warning, bool encrypted)
    {
        _doneResult = result;
        _doneWarning = warning;
        _doneEncrypted = encrypted;
        Show(Screen.Done);
    }

    private void RenderDone()
    {
        if (_doneResult is not { } result) return;
        DoneFiles.Children.Clear();
        if (_doneEncrypted)
        {
            DoneTitle.Text = L("加密完成");
            AddDoneRow(Path.GetFileName(result.OutputPath), FormatSize(SizeOf(result.OutputPath)), result.OutputPath);
            if (result.DataPath is { } data) AddDoneRow(Path.GetFileName(data), FormatSize(SizeOf(data)), data);
            DoneHint.Text = DoneFiles.Children.Count > 1 ? L("两个文件要放在同一个文件夹里") : "";
            if (_doneWithoutPassword)
                DoneHint.Text = L("无需密码，任何人都能解开") + (DoneHint.Text.Length == 0 ? "" : "\n" + DoneHint.Text);
            DonePrimary.Content = L("在文件夹中显示");
            DoneSecondary.Content = L("完成");
        }
        else
        {
            DoneTitle.Text = L("解密完成");
            AddDoneRow(DisplayName(result.OutputPath), result.FileCount == 0 ? L("空文件夹") : FileCount(result.FileCount, result.TotalBytes), result.OutputPath);
            DoneHint.Text = Path.GetDirectoryName(result.OutputPath) ?? "";
            DonePrimary.Content = L("打开文件夹");
            DoneSecondary.Content = _embeddedPackage is null ? L("完成") : L("关闭");
        }
        DoneHint.Visibility = DoneHint.Text.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
        DoneWarning.Text = _doneWarning ?? "";
        DoneWarning.Visibility = _doneWarning is null ? Visibility.Collapsed : Visibility.Visible;
    }

    private void AddDoneRow(string name, string detail, string tooltip)
    {
        var row = new Grid { Margin = new Thickness(16, 11, 16, 11), ToolTip = tooltip };
        row.ColumnDefinitions.Add(new ColumnDefinition());
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.Children.Add(new TextBlock { Text = name, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center });
        var size = new TextBlock { Text = detail, Style = (Style)FindResource("Meta"), Margin = new Thickness(16, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(size, 1);
        row.Children.Add(size);
        var frame = new Border { Child = row, BorderThickness = new Thickness(0, DoneFiles.Children.Count == 0 ? 0 : 1, 0, 0) };
        frame.SetResourceReference(Border.BorderBrushProperty, "Line");
        DoneFiles.Children.Add(frame);
    }

    private void DonePrimary_Click(object sender, RoutedEventArgs e)
    {
        if (_doneResult is not { } result) return;
        try
        {
            if (_doneEncrypted) Process.Start(new ProcessStartInfo("explorer.exe") { UseShellExecute = true, Arguments = "/select,\"" + result.OutputPath + "\"" });
            else Process.Start(new ProcessStartInfo("explorer.exe") { UseShellExecute = true, ArgumentList = { result.OutputPath } });
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException or IOException)
        {
            DoneWarning.Text = DescribeException(error);
            DoneWarning.Visibility = Visibility.Visible;
        }
    }

    private void DoneSecondary_Click(object sender, RoutedEventArgs e)
    {
        if (_embeddedPackage is not null && !_doneEncrypted) Close();
        else GoHome();
    }

    private void ShowNotices()
    {
        string notices;
        try
        {
            using var stream = typeof(App).Assembly.GetManifestResourceStream("TwoPassword.ThirdPartyNotices.txt")
                ?? throw new IOException(L("未能读取此版本内的第三方许可文件。"));
            using var reader = new StreamReader(stream);
            notices = reader.ReadToEnd();
        }
        catch (IOException error)
        {
            MessageBox.Show(this, error.Message, "2Password", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var area = SystemParameters.WorkArea;
        var dialog = new Window
        {
            Title = L("开源许可"), Owner = this, ShowInTaskbar = false, Language = Language,
            Width = Math.Min(760, area.Width - 40), Height = Math.Min(620, area.Height - 40), MinWidth = 480, MinHeight = 360,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, FontFamily = FontFamily, FontSize = 13,
            UseLayoutRounding = true,
        };
        dialog.SetResourceReference(BackgroundProperty, "Bg");
        dialog.SetResourceReference(ForegroundProperty, "Ink");
        dialog.SourceInitialized += (_, _) => Theme.ApplyFrame(dialog);
        var layout = new DockPanel { Margin = new Thickness(20) };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        var export = new Button { Content = L("导出 PAR2 源码") };
        AutomationProperties.SetAutomationId(export, "ExportRecoverySource");
        export.Click += async (_, _) =>
        {
            var save = new SaveFileDialog
            {
                Title = L("导出 PAR2 源码"), Filter = L("源代码压缩包 (*.tar.xz)|*.tar.xz"), FileName = "par2cmdline-turbo-source.tar.xz",
                AddExtension = true, DefaultExt = ".tar.xz", OverwritePrompt = false,
            };
            if (save.ShowDialog(dialog) != true) return;
            export.IsEnabled = false;
            try
            {
                var saved = await RecoveryService.ExportSourceAsync(save.FileName);
                MessageBox.Show(dialog, L("已导出：{0}", saved), "2Password", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception error) { MessageBox.Show(dialog, DescribeException(error), "2Password", MessageBoxButton.OK, MessageBoxImage.Warning); }
            finally { export.IsEnabled = true; }
        };
        var close = new Button { Content = L("关闭"), MinWidth = 88, Margin = new Thickness(8, 0, 0, 0), IsCancel = true, Style = (Style)FindResource("PrimaryButton") };
        close.Click += (_, _) => dialog.Close();
        buttons.Children.Add(export);
        buttons.Children.Add(close);
        DockPanel.SetDock(buttons, Dock.Bottom);
        layout.Children.Add(buttons);
        var text = new TextBox
        {
            Text = notices, Style = (Style)FindResource("Readout"), FontFamily = new FontFamily("Cascadia Mono, Consolas, Microsoft YaHei UI"),
            Padding = new Thickness(14, 12, 4, 12), BorderThickness = new Thickness(1),
        };
        text.SetResourceReference(BackgroundProperty, "Surface");
        text.SetResourceReference(BorderBrushProperty, "Line");
        layout.Children.Add(text);
        dialog.Content = layout;
        dialog.ShowDialog();
    }

    private void ShowNotice(TextBlock target, Exception error)
    {
        ShowNotice(target, DescribeException(error));
        if (Elevation.IsElevated || !Elevation.IsAccessDenied(error)) return;
        var retry = new Hyperlink { TextDecorations = TextDecorations.Underline, Cursor = Cursors.Hand };
        retry.SetResourceReference(TextElement.ForegroundProperty, "Ink");
        if (Elevation.Shield is { } shield)
            retry.Inlines.Add(new InlineUIContainer(new Image { Source = shield, Width = 14, Height = 14, Margin = new Thickness(0, 0, 4, -2) }));
        retry.Inlines.Add(new Run(L("以管理员身份重试")));
        AutomationProperties.SetAutomationId(retry, "RetryElevated");
        retry.Click += (_, _) => RunElevated();
        target.Inlines.Add(new Run("  "));
        target.Inlines.Add(retry);
    }

    private static void ShowNotice(TextBlock target, string message, bool neutral = false)
    {
        target.Text = message;
        target.SetResourceReference(TextBlock.ForegroundProperty, neutral ? "Ink2" : "Danger");
        target.Visibility = Visibility.Visible;
    }

    private static void Hide(TextBlock target)
    {
        target.Visibility = Visibility.Collapsed;
        target.Text = "";
    }

    private static void Enter(FrameworkElement view)
    {
        if (!Motion) return;
        var shift = new TranslateTransform(0, 10);
        view.RenderTransform = shift;
        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        view.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)) { EasingFunction = ease });
        shift.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(10, 0, TimeSpan.FromMilliseconds(240)) { EasingFunction = ease });
    }

    private static void Pop(FrameworkElement element)
    {
        if (!Motion) return;
        var scale = new ScaleTransform();
        element.RenderTransform = scale;
        var grow = new DoubleAnimation(0.6, 1, TimeSpan.FromMilliseconds(360)) { EasingFunction = new BackEase { Amplitude = 0.45, EasingMode = EasingMode.EaseOut } };
        scale.BeginAnimation(ScaleTransform.ScaleXProperty, grow);
        scale.BeginAnimation(ScaleTransform.ScaleYProperty, grow);
    }

    private static void Shake(FrameworkElement element)
    {
        if (!Motion) return;
        var shift = new TranslateTransform();
        element.RenderTransform = shift;
        var animation = new DoubleAnimationUsingKeyFrames { Duration = TimeSpan.FromMilliseconds(380) };
        foreach (var (time, x) in new[] { (0, 0d), (60, -9d), (120, 8d), (180, -6d), (240, 4d), (300, -2d), (380, 0d) })
            animation.KeyFrames.Add(new EasingDoubleKeyFrame(x, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(time))));
        shift.BeginAnimation(TranslateTransform.XProperty, animation);
    }

    private static string DisplayName(string path)
    {
        var name = Path.GetFileName(Path.TrimEndingDirectorySeparator(path));
        return string.IsNullOrEmpty(name) ? path : name;
    }

    private static string FileCount(int files, long bytes) => files == 1
        ? L("1 个文件 · {0}", FormatSize(bytes))
        : L("{0} 个文件 · {1}", files.ToString("N0", CultureInfo.CurrentCulture), FormatSize(bytes));

    private static long SizeOf(string path)
    {
        try { return new FileInfo(path).Length; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { return 0; }
    }

    private static string FormatSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        var format = unit == 0 || value >= 100 ? "0" : "0.0";
        return value.ToString(format, CultureInfo.CurrentCulture) + " " + units[unit];
    }

    private static string SafeFileName(string? path, string fallback)
    {
        try
        {
            var name = Path.GetFileName(path);
            return string.IsNullOrEmpty(name) ? fallback : name;
        }
        catch (ArgumentException) { return fallback; }
    }

    private static string NextAvailablePath(string path, bool directory)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return path;
        var parent = Path.GetDirectoryName(path) ?? "";
        var stem = directory ? Path.GetFileName(path) : Path.GetFileNameWithoutExtension(path);
        var extension = directory ? "" : Path.GetExtension(path);
        for (var i = 2; i < 10000; i++)
        {
            var candidate = Path.Combine(parent, stem + " (" + i + ")" + extension);
            if (!File.Exists(candidate) && !Directory.Exists(candidate)) return candidate;
        }
        throw new IOException(L("没有可用的名称，请手动选择位置。"));
    }

    private static string NextAvailablePackagePath(string path)
    {
        if (!PackageOutputCollision(path)) return path;
        var parent = Path.GetDirectoryName(path) ?? "";
        var stem = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        for (var index = 2; index < 10000; index++)
        {
            var candidate = Path.Combine(parent, stem + " (" + index + ")" + extension);
            if (!PackageOutputCollision(candidate)) return candidate;
        }
        throw new IOException(L("没有可用的名称，请手动选择位置。"));
    }

    /// <summary>True when the EXE or its .2pw sidecar already exists.</summary>
    private static bool PackageOutputCollision(string path)
    {
        path = Path.GetFullPath(path);
        var dataPath = Path.ChangeExtension(path, ".2pw");
        return File.Exists(path) || Directory.Exists(path) || File.Exists(dataPath) || Directory.Exists(dataPath);
    }

    private sealed class ForwardProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }
}

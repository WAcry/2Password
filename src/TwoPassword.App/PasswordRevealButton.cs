using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace TwoPassword.App;

/// <summary>A press-and-hold preview. PasswordBox remains the only editable source of the secret.</summary>
public sealed class PasswordRevealButton : Button
{
    public static readonly DependencyProperty PasswordOwnerProperty = DependencyProperty.Register(
        nameof(PasswordOwner), typeof(PasswordBox), typeof(PasswordRevealButton),
        new PropertyMetadata(null, (element, _) => ((PasswordRevealButton)element).Attach()));
    private static readonly DependencyProperty HandlerProperty = DependencyProperty.RegisterAttached(
        "Handler", typeof(PasswordRevealButton), typeof(PasswordRevealButton), new PropertyMetadata(null));

    private PasswordBox? _owner;
    private TextBox? _preview;
    private Window? _window;
    private bool _cancelledPress;

    public PasswordBox? PasswordOwner
    {
        get => (PasswordBox?)GetValue(PasswordOwnerProperty);
        set => SetValue(PasswordOwnerProperty, value);
    }

    public PasswordRevealButton()
    {
        Loaded += (_, _) => Attach();
        Unloaded += (_, _) => Detach();
    }

    internal static bool Conceal(PasswordBox owner) =>
        (owner.GetValue(HandlerProperty) as PasswordRevealButton)?.CancelReveal() ?? false;

    private void Attach()
    {
        Detach();
        if (!IsLoaded || PasswordOwner is not { } owner) return;
        _owner = owner;
        owner.SetValue(HandlerProperty, this);
        owner.PasswordChanged += OwnerPasswordChanged;
        _window = Window.GetWindow(this);
        if (_window is not null) _window.Deactivated += WindowDeactivated;
    }

    private void Detach()
    {
        CancelReveal();
        if (_owner is { } owner)
        {
            owner.PasswordChanged -= OwnerPasswordChanged;
            if (ReferenceEquals(owner.GetValue(HandlerProperty), this)) owner.ClearValue(HandlerProperty);
        }
        if (_window is not null) _window.Deactivated -= WindowDeactivated;
        _owner = null;
        _window = null;
    }

    private void OwnerPasswordChanged(object sender, RoutedEventArgs e) => CancelReveal();
    private void WindowDeactivated(object? sender, EventArgs e) => CancelReveal();

    protected override void OnPropertyChanged(DependencyPropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.Property == IsPressedProperty)
        {
            if (IsPressed) Reveal();
            else HidePreview();
        }
        else if ((e.Property == IsEnabledProperty || e.Property == IsVisibleProperty || e.Property == IsHitTestVisibleProperty)
            && e.NewValue is false) CancelReveal();
    }

    protected override void OnPreviewMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        _cancelledPress = false;
        base.OnPreviewMouseLeftButtonDown(e);
    }

    protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
    {
        var restoreFocus = IsPressed && IsMouseOver;
        base.OnMouseLeftButtonUp(e);
        HidePreview();
        if (restoreFocus && _window?.IsActive == true) _owner?.Focus();
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Space && !e.IsRepeat) _cancelledPress = false;
        if (e.Key == Key.Escape && CancelReveal()) e.Handled = true;
        base.OnPreviewKeyDown(e);
    }

    protected override void OnLostKeyboardFocus(KeyboardFocusChangedEventArgs e)
    {
        CancelReveal();
        base.OnLostKeyboardFocus(e);
    }

    protected override void OnLostMouseCapture(MouseEventArgs e)
    {
        CancelReveal();
        base.OnLostMouseCapture(e);
    }

    private void Reveal()
    {
        if (_cancelledPress || !IsEnabled || !IsVisible || !IsHitTestVisible || _window?.IsActive != true
            || _owner is not { } owner || Field.GetIsEmpty(owner)) return;
        if (owner.Template.FindName("PART_RevealedPassword", owner) is not TextBox preview) return;
        _preview = preview;
        preview.Text = owner.Password;
        Field.SetIsRevealed(owner, true);
        preview.ScrollToHome();
    }

    private bool HidePreview()
    {
        var visible = _owner is not null && Field.GetIsRevealed(_owner);
        if (_owner is not null) Field.SetIsRevealed(_owner, false);
        // No binding, undo history, clipboard operation, or cached plaintext remains in the preview.
        _preview?.Clear();
        _preview = null;
        return visible;
    }

    private bool CancelReveal()
    {
        _cancelledPress = true;
        var visible = HidePreview();
        if (IsMouseCaptured) ReleaseMouseCapture();
        return visible;
    }
}

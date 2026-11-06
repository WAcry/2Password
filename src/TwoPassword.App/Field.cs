using System.Windows;
using System.Windows.Controls;

namespace TwoPassword.App;

/// <summary>Attached state for input templates. PasswordBox.Password is not a dependency property, so emptiness is mirrored here.</summary>
public static class Field
{
    public static readonly DependencyProperty PlaceholderProperty = DependencyProperty.RegisterAttached(
        "Placeholder", typeof(string), typeof(Field), new PropertyMetadata("", OnPlaceholderChanged));

    public static readonly DependencyProperty IsEmptyProperty = DependencyProperty.RegisterAttached(
        "IsEmpty", typeof(bool), typeof(Field), new PropertyMetadata(true));

    public static readonly DependencyProperty IsInvalidProperty = DependencyProperty.RegisterAttached(
        "IsInvalid", typeof(bool), typeof(Field), new PropertyMetadata(false));

    private static readonly DependencyPropertyKey IsRevealedPropertyKey = DependencyProperty.RegisterAttachedReadOnly(
        "IsRevealed", typeof(bool), typeof(Field), new PropertyMetadata(false));
    public static readonly DependencyProperty IsRevealedProperty = IsRevealedPropertyKey.DependencyProperty;

    public static string GetPlaceholder(DependencyObject element) => (string)element.GetValue(PlaceholderProperty);
    public static void SetPlaceholder(DependencyObject element, string value) => element.SetValue(PlaceholderProperty, value);
    public static bool GetIsEmpty(DependencyObject element) => (bool)element.GetValue(IsEmptyProperty);
    public static bool GetIsInvalid(DependencyObject element) => (bool)element.GetValue(IsInvalidProperty);
    public static void SetIsInvalid(DependencyObject element, bool value) => element.SetValue(IsInvalidProperty, value);
    public static bool GetIsRevealed(DependencyObject element) => (bool)element.GetValue(IsRevealedProperty);
    internal static void SetIsRevealed(DependencyObject element, bool value) => element.SetValue(IsRevealedPropertyKey, value);

    private static void OnPlaceholderChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not PasswordBox box) return;
        box.PasswordChanged -= OnPasswordChanged;
        box.PasswordChanged += OnPasswordChanged;
        Refresh(box);
    }

    private static void OnPasswordChanged(object sender, RoutedEventArgs e) => Refresh((PasswordBox)sender);

    private static void Refresh(PasswordBox box)
    {
        using var secure = box.SecurePassword;
        box.SetValue(IsEmptyProperty, secure.Length == 0);
    }
}

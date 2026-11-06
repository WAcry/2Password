namespace TwoPassword.App;

/// <summary>Strings referenced from XAML as DynamicResource, mapped to their catalog keys.</summary>
internal static class UiXamlKeys
{
    internal static readonly IReadOnlyDictionary<string, string> Values = new Dictionary<string, string>
    {
        ["Ui.Back"] = "返回",
        ["Ui.More"] = "更多",
        ["Ui.Minimize"] = "最小化",
        ["Ui.Maximize"] = "最大化",
        ["Ui.Close"] = "关闭",
        ["Ui.ChooseFile"] = "选择文件",
        ["Ui.ChooseFolder"] = "选择文件夹",
        ["Ui.OpenPackage"] = "打开加密包",
        ["Ui.Passwords"] = "密码",
        ["Ui.AnyOneOpens"] = "任意一个都能解开",
        ["Ui.AddPassword"] = "+ 添加密码",
        ["Ui.CapsLock"] = "大写锁定已打开",
        ["Ui.PasswordPlaceholder"] = "输入密码",
        ["Ui.UnlockPasswordPlaceholder"] = "密码（未设置可留空）",
        ["Ui.ConfirmPlaceholder"] = "再输一次",
        ["Ui.HoldToReveal"] = "按住显示密码",
        ["Ui.RevealHelp"] = "按住鼠标或空格键查看，松开即隐藏",
        ["Ui.SaveTo"] = "保存到",
        ["Ui.Change"] = "更改",
        ["Ui.Options"] = "选项",
        ["Ui.Compression"] = "压缩",
        ["Ui.NoCompression"] = "不压缩",
        ["Ui.NoCompressionTip"] = "视频、照片这类已经压缩过的文件，选这个更快",
        ["Ui.Output"] = "输出",
        ["Ui.Auto"] = "自动",
        ["Ui.AutoTip"] = "装得下就生成单个 EXE，太大时拆成 EXE 和 .2pw 两个文件",
        ["Ui.SingleExe"] = "单个 EXE",
        ["Ui.SingleExeTip"] = "单个 EXE 最大 4 GB",
        ["Ui.DetachedTip"] = "两个文件要放在同一个文件夹里",
        ["Ui.Recovery"] = "恢复记录",
        ["Ui.RecoveryTip"] = "PAR2 恢复数据存在加密包里，文件损坏时用来修复",
        ["Ui.Off"] = "无",
        ["Ui.Encrypt"] = "加密",
        ["Ui.Reload"] = "重新读取",
        ["Ui.WrongPassword"] = "密码不正确",
        ["Ui.Decrypt"] = "解密",
        ["Ui.RestoreTo"] = "还原到",
        ["Ui.VerifyFirst"] = "先检查并修复，再解密",
        ["Ui.Progress"] = "进度",
        ["Ui.Cancel"] = "取消",
    };
}

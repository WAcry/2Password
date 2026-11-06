# 2Password 1.0.0

[English](https://github.com/WAcry/2Password/blob/main/docs/RELEASE_NOTES.md) · [简体中文](https://github.com/WAcry/2Password/blob/main/docs/RELEASE_NOTES.zh.md)

把文件或文件夹加密成一个 EXE，设 1 到 16 个密码，任意一个都能打开。收到的人双击就能解密，不用装任何软件。

- 每个密码都能单独解开全部内容，知道一个推不出其他的。
- 支持无需密码的包：创建时留空，解密时直接打开；任意一组密码留空都会让整个包无需密码。
- 压缩可选 `Zstd (Lv.3)`（默认）、`Brotli (Lv.6)`，或不压缩。
- 创建和解密时，按住密码框右侧的眼睛按钮可以临时查看密码，松开后隐藏。
- 默认附带 5% 的 PAR2 恢复记录，存在加密包里，不另外生成文件。加密包损坏时，解密会自动修复；文件尾部损坏或被截断也能修。
- 加密后超过 4 GB 时，拆成 EXE 和同目录的 `.2pw` 两个文件。
- 文件名、空文件夹、时间和属性原样还原，已有文件不会被覆盖。
- 可以加到资源管理器右键菜单，右键文件或文件夹直接加密。
- 目标位置需要管理员权限时，界面里点一下就能以管理员身份重试。
- 中英文界面，跟随系统的浅色或深色主题。

下载 `-zh-CN.msi`（中文安装向导）或 `-en-US.msi`（英文安装向导），装在当前用户下，不需要管理员权限。也可以直接用便携版 EXE 或 ZIP。

发布版没有代码签名，Windows 可能提示“未知发布者”，可以用 `SHA256SUMS.txt` 核对文件。`par2cmdline-turbo-1.5.0.tar.xz` 是内置 PAR2 程序的源码。使用说明见 [README](https://github.com/WAcry/2Password/blob/main/README.zh.md)。

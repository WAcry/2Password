# 2Password 1.0.0

## 简体中文

把文件或文件夹加密成一个 EXE，设 1 到 16 个密码，任意一个都能打开。收到的人双击就能解密，不用装任何软件。

- 每个密码都能单独解开全部内容，知道一个推不出其他的。
- 默认附带 5% 的 PAR2 恢复记录，存在加密包里，不另外生成文件。加密包损坏时，解密会自动修复；文件尾部损坏或被截断也能修。
- 加密后超过 4 GB 时，拆成 EXE 和同目录的 `.2pw` 两个文件。
- 文件名、空文件夹、时间和属性原样还原，已有文件不会被覆盖。
- 可以加到资源管理器右键菜单，右键文件或文件夹直接加密。
- 目标位置需要管理员权限时，界面里点一下就能以管理员身份重试。
- 中英文界面，跟随系统的浅色或深色主题。

本轮修复了双文件包混用时的恢复校验、部分损坏分布导致的尾部定位失败、管理员重试丢失已选选项，以及大包重建尾部时的额外内存占用。保留现有包格式和默认设置。

下载 `-zh-CN.msi`（中文安装向导）或 `-en-US.msi`（英文安装向导），装在当前用户下，不需要管理员权限。也可以直接用便携版 EXE 或 ZIP。

发布版没有代码签名，Windows 可能提示“未知发布者”，可以用 `SHA256SUMS.txt` 核对文件。`par2cmdline-turbo-1.5.0.tar.xz` 是内置 PAR2 程序的源码。使用说明见 [README](https://github.com/WAcry/2Password#readme)。

## English

Encrypt a file or folder into a single EXE with 1 to 16 passwords. Any one of them opens it. The recipient double-clicks the EXE to decrypt, with nothing to install.

- Each password unlocks everything on its own, and knowing one doesn't reveal the others.
- 5% PAR2 recovery data is stored inside the package by default, with no extra file. Decryption repairs a damaged package automatically, including a damaged or truncated end of file.
- Encrypted results larger than 4 GB are split into an EXE and a `.2pw` file in the same folder.
- Filenames, empty folders, timestamps and attributes come back as they were. Existing files are never overwritten.
- Optional Explorer right-click menu: right-click a file or folder to encrypt it.
- When a destination needs administrator rights, one click retries as administrator.
- English and Chinese interface, following the system's light or dark theme.

This revision fixes recovery checks for mismatched companion files and lost-trailer detection when the initial samples are damaged. It also preserves selected options when retrying as administrator and bounds memory use while locating a lost trailer in large packages. The package format and defaults are unchanged.

Download the `-en-US.msi` (English setup wizard) or `-zh-CN.msi` (Chinese setup wizard). Both install for the current user without admin rights. The portable EXE and ZIP work too.

Releases aren't code-signed, so Windows may warn about an unknown publisher. Check downloads against `SHA256SUMS.txt`. `par2cmdline-turbo-1.5.0.tar.xz` is the source of the bundled PAR2 program. See the [README](https://github.com/WAcry/2Password/blob/main/README.en.md) for usage.

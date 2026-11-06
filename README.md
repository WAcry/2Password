# 2Password

[简体中文](README.md) · [English](README.en.md)

**一个加密包，多个独立密码。** 为 Windows 制作的本地文件加密、独立解包与 PAR2 修复工具。

> **任意一个有效密码都能解包全部文件，但知道其中一个密码，不会因此得到或推导出其他密码。** 每个密码使用独立随机盐和独立密钥槽；程序不保存密码明文。持有一个密码的人可以读取、复制或重新打包文件内容，因此多密码并不是分级访问控制。

[![Windows build](https://github.com/WAcry/2Password/actions/workflows/build-release.yml/badge.svg)](https://github.com/WAcry/2Password/actions/workflows/build-release.yml)

![2Password Windows interface](assets/screenshots/main.png)

## 下载与运行

从 [GitHub Releases](https://github.com/WAcry/2Password/releases/latest) 下载：

| 文件 | 用途 |
| --- | --- |
| `2Password-版本-win-x64-zh-CN.msi` | 简体中文安装向导；当前用户安装、开始菜单入口及卸载，不需要管理员权限 |
| `2Password-版本-win-x64-en-US.msi` | English 安装向导；应用内仍可切换中英文 |
| `2Password-版本-win-x64.exe` | 完整便携版，直接运行 |
| `2Password-版本-win-x64-portable.zip` | 便携程序、说明和第三方许可 |
| `SHA256SUMS.txt` | 发布资产的 SHA-256 校验值 |
| `par2cmdline-turbo-1.5.0.tar.xz` | 随附 PAR2 程序的完整对应源码 |

面向 **Windows 10 / 11 x64**。应用和生成的解包 EXE 均包含 .NET 运行时，不需要接收者安装 2Password、.NET、压缩软件或 PAR2。首次运行会在用户可写的运行时缓存目录释放内置运行组件。

当前发布未配置代码签名证书，Windows 可能显示“未知发布者”。校验发布页的哈希，确认程序来源。对于来源不明的 EXE，可在已信任的 2Password 中选择该文件解密，避免直接执行它。

## 使用

1. 选择或拖入一个文件、文件夹。
2. 设置 **1–16 个不同的密码**并分别确认。界面要求至少 8 个字符；建议使用更长、不可预测的口令。保留首尾空格，不进行 Unicode 归一化。
3. 选择 Zstd、Brotli 或不压缩；默认使用 Zstd。
4. 选择打包方式。界面默认生成 10% PAR2 恢复记录，也可调整为 5%、20% 或关闭。
5. 创建完成后，将程序列出的文件一起保存或发送。原始文件不会被删除。

接收者打开解包 EXE，输入其中任意一个密码，并指定一个**尚不存在的新文件夹**。程序在验证全部内容后提交还原目录，保留原始顶层文件或文件夹名称。

界面提供中文和 English，可随时切换并记住语言选择。界面以“加密打包”和“解密还原”为主要操作；恢复记录在相应流程内自动处理，手动校验与修复作为高级操作。创建或解包时发现目标同名项目，程序会建议一个新的名称，绝不覆盖或合并现有内容。

### 单 EXE 与大文件

| 方式 | 行为 |
| --- | --- |
| 自动（默认） | 成品能装入单个 Windows EXE 时生成单文件；超过限制时自动使用双文件 |
| 单个 EXE | 程序与加密数据放在同一个文件；超过 `4,294,967,295` 字节则明确失败 |
| EXE + 数据文件 | 始终生成独立启动器和同目录 `.2pw` 加密数据文件 |

双文件示例：

```text
资料.exe
资料.2pw
```

双文件包仍然无需安装程序或运行时。**保持两者在同一目录，并保留数据文件名**。启动器自身包含有校验的相对引用，不依赖创建机器的绝对路径。也可以在主程序中直接打开 `.2pw`。

Windows 对可执行文件大小存在加载限制。本项目在真实 Windows 上验证了 `4 GiB - 1` 字节能够启动、`4 GiB` 被系统拒绝，因此大包使用外部数据文件，避免生成打不开的 EXE。启动器包含完整运行时，体积约 64 MiB；这是它能够脱离安装环境工作的成本。

### 恢复记录

启用 PAR2 后，除加密包外，还会生成一个索引和若干恢复分卷，例如：

```text
资料.exe.par2
资料.exe.vol000+NNN.par2
资料.exe.volNNN+NNN.par2
...
```

恢复数据保护的是**密文、容器元数据和启动器本身**，生成、校验、修复都不需要密码。默认直接流式解密并做强制 AES-GCM 认证；健康包只读一遍加密数据，**不会因为存在 PAR2 文件就先做一次整包扫描**。遇到容器损坏、认证失败或数据文件丢失时，程序才检查对应恢复记录，修复能力足够时修复，再从头完整认证和解包。密码错误直接返回，不触发 PAR2。

对于已知损坏的介质，可勾选解包前完整检查，或使用高级操作手动校验/修复；命令行对应 `--verify-first`。完整预检查需要额外顺序读取整个包，实际修复还需要密文工作区和额外 I/O。即使关闭预检查，密码验证、每块认证和结束标记检查始终执行。

- 恢复过程先在私有工作区重建并独立检查结果，再替换损坏文件；损坏原件保留为 `.2pw-before-repair-*.bak`。
- 索引损坏或丢失时，可使用恢复分卷中的重复元数据。
- 无法完整修复时，停止操作并保留原文件。恢复记录不能替代离线备份。
- 10% 冗余按恢复块计算，**不等于任意分布的 10% 字节损坏都一定可修复**。损坏分布、丢失的恢复分卷和块粒度都会影响结果。
- PAR2 使用自身格式的 MD5/CRC 损坏检测；解包安全仍由 AES-GCM 认证提供。修复成功不会跳过密码验证或内容认证，也不会自动执行修复后的程序。

## 加密设计

没有自行实现密码学原语。使用 .NET 的 AES-GCM、成熟的 Argon2id 库和经过独立标准向量检查的实现。

每个包随机生成一个 256 位内容密钥；每个密码分别使用独立随机盐经过 **Argon2id（64 MiB，3 次迭代，4 条并行通道）**，派生自己的包装密钥，再用 AES-256-GCM 包装内容密钥。任意密码都能解开自己的密钥槽；包内不保存其他密码的明文，也不能从一个已知密码直接推导出其他密码。

数据按 **1 MiB 块**处理：PAX 归档流 → 每块独立 Zstd/Brotli 压缩 → AES-256-GCM。不压缩或压缩后变大的块直接保存为认证的原始块。每个块的顺序、编码、明文长度、密文长度和头部摘要都参与认证，且必须存在认证的结束记录。

关键头部、尾部和分离引用各有三份带校验的副本。完整有效但互相冲突的副本会被拒绝。目录和文件名位于加密的 PAX 数据中；没有需要整体载入内存的中央文件索引或块偏移表。PAR2 进一步覆盖完整包，包括这些元数据。

不知道有效密码时，只能尝试离线猜测密码或攻击实现/运行环境；项目不声称已获得外部安全审计。**整个包的抗猜测能力取决于最弱的有效密码。** 知道任一密码的人已经能够取得全部明文，可以复制、转发或重新加密内容；更换密码需要重新生成并分发新包，不能撤销旧副本。

外层的文件大小、压缩类型、密码槽数量和统计值可见；原始文件名、目录结构、文件内容不会以明文保存。EXE 程序前缀本身不受数据容器 AEAD 保护，因此程序来源与代码签名是独立的信任问题。详见 [安全设计与边界](docs/SECURITY.md) 和 [格式说明](src/TwoPassword.Core/CoreDesign.md)。

## 文件名、长路径与完整还原

- 路径使用严格 UTF-8 编码，保留原始 Unicode 码点；中文、日文、阿拉伯文、重音字母、emoji，以及看起来相同但编码不同的 NFC/NFD 文件名分别保存。
- 文件内容始终按字节读取。UTF-8、UTF-16、GBK、Shift-JIS 等文本编码不会被转换，二进制内容也不会被重新解释。
- 使用 Windows 扩展长度路径和 longPathAware 清单，不需要修改系统的长路径注册表开关。已测试超过 1,000 字符的路径；实际可用上限仍受 Windows、路径分量长度及目标文件系统限制。
- 保留空文件、空目录、隐藏/系统项目、创建/修改时间及常用文件属性；时间精度受目标文件系统限制。
- 普通下载文件的 `Zone.Identifier` 数据流可按原始字节保存和恢复（上限 64 KiB）。
- 严格拒绝路径穿越、设备名、大小写冲突、覆盖已有目标，以及无法无损处理的名称。
- 符号链接、目录联接、其他重解析点、EFS、离线占位文件及其他 NTFS 备用数据流会明确报错，**不会静默跳过**。请先将云端文件完整下载到本地。
- 尾随点/空格的特殊 Win32 名称不支持；硬链接按独立文件内容存档，不保留链接关系；不保留原始 ACL/所有者、稀疏布局和 NTFS 压缩状态。

打包前后检查文件清单和属性，并在读取文件时禁止其他进程写入或删除。它不是 VSS 快照；正在被应用持续修改的目录应先关闭写入程序再打包。

解包只写入当前用户和 SYSTEM 可访问的私有暂存目录，认证全部通过后才进行无覆盖重命名。发生错误或取消时清理未完成结果。没有明文中间 TAR 文件；组装包和 PAR2 修复使用的临时文件都是密文。请预留源数据、成品及解包/修复工作区所需空间。

## 开发与构建

需要 Windows x64、Git、**.NET SDK 10.0.114**（由 `global.json` 固定）。WiX 4.0.6 安装到项目的 `.tools` 下；图标和 PAR2 组件已固定在仓库中，正常构建不需要 Python。仅重新生成图标时需要 Pillow。

```powershell
git clone https://github.com/WAcry/2Password.git
cd 2Password
dotnet restore 2Password.slnx --locked-mode
dotnet build 2Password.slnx -c Release
dotnet run --project tests/TwoPassword.Tests -c Release
dotnet run --project tests/TwoPassword.Recovery.Tests -c Release
pwsh -File scripts/Build-Release.ps1
pwsh -File scripts/Test-Standalone.ps1
pwsh -File scripts/Test-Installer.ps1
```

安装包、便携 EXE、ZIP 和校验文件输出到 `artifacts/release/`。开发构建不含完整运行时，创建独立包时应使用发布版 EXE，或通过 `--stub` 明确指定已发布的模板。

大文件验证单独运行，建议预留约 30 GiB 可用空间：

```powershell
pwsh -File scripts/Test-LargeFiles.ps1
```

测试报告保存在被 Git 忽略的 `artifacts/`。覆盖独立密码、标准密码学向量、长路径、多语言、恶意归档/恢复元数据、重复与截断块、解压边界、取消与覆盖保护、真实 PAR2 损坏修复和真实独立 EXE。大文件测试包含超过 4 GiB 的未压缩数据和超过 8 GiB 的 PAX 文件，逐字节 SHA-256 核对。具体证据见 [验证记录](docs/VALIDATION.md)。

### 自动发布

[GitHub Actions](.github/workflows/build-release.yml) 在推送和 PR 时构建、测试、生成安装包，并上传构建产物。推送 `vMAJOR.MINOR.PATCH` 标签后，只有构建、安全回归、独立解包和安装/升级/卸载验证通过，才创建 GitHub Release 并附加中英文 Windows 安装包、便携版、校验值及 PAR2 对应源码。

### 命令行

```text
2Password.exe --help
2Password.exe --help --language en
2Password.exe --inspect package.exe --report new-report.json
2Password.exe --create SOURCE --output package.exe --passwords-stdin --compression zstd --layout auto --recovery-percent 10 --report new-report.json
2Password.exe --extract package.exe --output NEW_DIRECTORY --password-stdin --report new-report.json
2Password.exe --extract package.exe --output NEW_DIRECTORY --password-stdin --verify-first --language zh-CN --report new-report.json
package.exe --extract-self --output NEW_DIRECTORY --password-stdin --report new-report.json
2Password.exe --verify-recovery package.exe.par2 --report new-report.json
2Password.exe --repair-recovery package.exe.par2 --report new-report.json
2Password.exe --export-recovery-source new-source.tar.xz
```

创建操作从严格 UTF-8 标准输入读取 JSON 密码数组；解密操作读取一个密码，仅移除最后一处输入行结束符，不修剪空格、BOM 字符或进行 Unicode 归一化。密码不接受命令行参数，以免出现在进程列表中。`--language en` 或 `--language zh-CN` 指定本次运行语言。报告路径必须是新文件。所有测试使用明确的合成口令，不读取用户真实资料。

## 使用的成熟组件

| 组件 | 用途 |
| --- | --- |
| .NET 10 WPF | 原生 Windows GUI、DPI、输入及文件选择 |
| System.Security.Cryptography | AES-256-GCM、随机数、SHA-256 |
| Konscious.Security.Cryptography.Argon2 1.3.1 | Argon2id 密码派生 |
| System.Formats.Tar / PAX | 流式归档、长名称与 Unicode |
| ZstdSharp.Port 0.8.8 / Zstandard 1.5.7 | 独立块 Zstd 压缩 |
| System.IO.Compression | 独立块 Brotli 压缩 |
| par2cmdline-turbo 1.5.0 | PAR2 恢复记录、校验与修复 |
| WiX Toolset 4.0.6 | Windows MSI 安装包 |

依赖版本和 NuGet 内容哈希已锁定。PAR2 二进制和源码校验值记录在 [vendor/par2](vendor/par2/README.md)。完整第三方许可位于 [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt)；PAR2 程序、许可及完整对应源码内嵌在便携版和自解包 EXE 中，可离线导出。

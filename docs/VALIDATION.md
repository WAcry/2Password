# 验证记录 / Validation evidence

本文件记录 2026-11-06 在 Windows x64 上执行的可复现验证，以及发布流水线的检查范围。所有测试均使用生成的合成文件和测试专用密码。测试代码、独立格式解析器和构建脚本保存在仓库中；原始 JSON 报告位于本地 `artifacts/`，常规报告也由 GitHub Actions 保留为 `verification-reports` 构建产物。

密码学假设、文件系统限制和威胁模型见 [SECURITY.md](SECURITY.md) / [SECURITY.en.md](SECURITY.en.md)。

## 环境与重现

本地大文件验证环境：Windows `10.0.26300`、x64、.NET SDK `10.0.114`、运行时 `.NET 10.0.14`。发布流水线另在 GitHub 托管的 `windows-latest` 环境执行常规验证。

```powershell
dotnet restore 2Password.slnx --locked-mode
dotnet build 2Password.slnx -c Release --no-restore
dotnet run --project tests/TwoPassword.Tests -c Release --no-build
dotnet run --project tests/TwoPassword.Recovery.Tests -c Release --no-build
dotnet run --project tests/TwoPassword.Localization.Tests -c Release --no-build
pwsh -File scripts/Build-Release.ps1
pwsh -File scripts/Test-Standalone.ps1
pwsh -File scripts/Test-Installer.ps1
```

`Build-Release.ps1` 默认包含前三个测试项目。`-SkipTests` 仅用于已验证后的本地重新打包，发布流水线不使用它。测试程序在失败时返回非零退出码；流水线会阻止发布。

本地最终发布构建为 0 警告、0 错误。对应常规验证结果：

| 检查 | 通过 | 失败 |
| --- | ---: | ---: |
| 独立安全与文件往返 | 189 | 0 |
| 真实 PAR2 与按需恢复 | 25 | 0 |
| 共享语言资源与跨语言操作 | 15 | 0 |
| 真实自包含 EXE / CLI | 14 | 0 |
| 中文安装、英文替换与卸载 | 52 | 0 |

共享语言验证覆盖 192 对资源和 192 个实际 `Text.Get` 源代码键；App 自有界面另有 148 对资源。

## 常规安全与还原验证

主测试项目 `tests/TwoPassword.Tests` 共 **189 项，GitHub Actions 上全部通过**。本机以普通权限运行时，“Private directory blocks permissive parent ACLs and protects child files”一项因为无权修改测试父目录的权限而失败，其余 188 项通过。其重要覆盖包括：

| 范围 | 实际检查 |
| --- | --- |
| 密码学原语 | RFC 9106 Argon2id 标准向量；公开 AES-256-GCM 向量与错误标签拒绝 |
| 独立密码 | 多个密码分别还原同一完整文件树；第 16 个密码槽；1 个字符的密码；错误、空、超长及非法 Unicode 密码 |
| 独立格式检查 | 测试代码独立编写的容器编码器和解码器，与生产代码交叉验证 |
| 名称与内容 | 中文、日文、阿拉伯文、emoji、NFC/NFD 区分，超过 1,000 字符路径；逐文件 SHA-256、空目录和空文件 |
| 压缩 | Zstd、Brotli、不压缩；截断、尾随数据、串联帧、错误长度、过大窗口、异常帧和解压输出边界 |
| 认证结构 | 内容、标签、长度、顺序、结束标记篡改；截断、重复块和多余块；未使用密码槽损坏 |
| 元数据冗余 | 头部和尾部的各个单副本存活情形；有效但冲突的副本拒绝 |
| 内嵌恢复数据 | 恢复数据长度与文件长度对不上时拒绝；生产读取器和独立参考读取器都能跳过加密数据后的恢复数据 |
| 分离文件 | 丢失或替换数据文件、错误头部身份、绝对路径、穿越、递归引用及名称限制 |
| 恶意归档 | 穿越、设备名、重解析点、大小写冲突、重复条目、异常元数据与资源上限 |
| 操作完整性 | 取消、源文件改变、目标已存在、失败后清理和最终提交保护 |
| PAR2 元数据 | 20 个用例：默认块大小、损坏或截断后从下一个包继续、混用的恢复集、相互冲突的文件描述、6 种错误的源文件名、长度和块大小不符、FileID 校验、超大分配、未知包类型、重复的恢复块和取消 |
| 工作区权限 | 22 个用例，包含真实 NTFS 权限及子目录继承、宽松父目录、并发创建和原始 ACL 的恶意构造；不支持持久 ACL 的能力策略明确拒绝 |

权限测试读回真实 NTFS 安全描述符，并检查陌生主体、空或未保护 DACL、错误所有者、回调/对象 ACE、错误继承与权限范围。FAT/exFAT 的拒绝逻辑用模拟的能力标志验证，没有挂载真实的 FAT/exFAT 介质。

## 实际 PAR2 与按需修复

`tests/TwoPassword.Recovery.Tests` 调用内嵌的真实 `par2cmdline-turbo 1.5.0` 进程，覆盖以下行为：

- 对含中文、日文和 emoji 的文件名生成恢复记录，恢复记录存在加密包里，不另外生成文件。
- 健康包直接解包，恢复进度回调保持为空，未启动 PAR2 扫描。
- 错误密码直接退出；即使密文也有损坏，仍不会因错误密码运行 PAR2。
- 空、超长和非法 Unicode 密码在预检查之前被拒绝。
- 用户明确请求预检查时执行 PAR2；已有还原目标始终先拒绝。
- 恢复记录里的包损坏时，健康的加密包仍可正常认证解包和检查。
- 实际翻转密文字节：先确认 AES-GCM 拒绝，再在副本上修复并完整解包，原文件不改动；原地修复后与原始 SHA-256 一致。
- 三份头部副本全部清零时，解包仍能通过恢复记录完成。
- 冗余不足时，检查和修复都返回退出码 2，损坏的文件保持原样，也不产生解包输出。
- 验证只读源文件时，不改变源文件的只读属性。
- 单个 EXE 和双文件包的 `.2pw` 各自带恢复记录，损坏后能解包和原地修复。
- 尾部丢失：`.2pw` 截掉最后 1,192 字节；EXE 最后 4 KiB 清零，同时清掉第一份头部副本，程序部分还放了两处假的 `2PWHDR03`。两种情况都能扫描定位并解包，修复后写回新尾部，加密数据与原始一致。截到加密数据中间的文件报告失败，不做猜测。
- 取消后不留下工作区；离线导出完整 PAR2 对应源码并核对固定 SHA-256；拒绝覆盖已有导出文件。

这组测试直接验证了默认解包的性能策略：**健康文件不做额外整包 PAR2 读取，认证始终执行；只有检测到损坏并确实完成修复才重新解包一次。**

## 真正的独立 EXE

`scripts/Test-Standalone.ps1` 调用发布后的单文件 EXE，再调用由它创建的加密 EXE。测试将解包 EXE 单独复制到另一个目录，并为子进程设置：

- 空的 `DOTNET_ROOT` / `DOTNET_ROOT_X64`。
- 仅包含 Windows 系统目录的 `PATH`。
- 独立的本机运行组件缓存。
- .NET 主机跟踪，检查自包含模式及包内 `System.Private.CoreLib.dll`。

真实进程检查包括独立创建、独立解析、每个密码还原完整文件树、错误密码不产生目标、拒绝覆盖和无压缩包。恢复记录方面：双文件包的 `.2pw` 和单个 EXE 损坏后都能解密，原文件不改动；`--repair-recovery` 原地修复后与原始字节一致；EXE 最后 4 KiB 清零后，便携版能检查、解密并写回新尾部，修好的 EXE 又能自己解密。

中英文命令行帮助、报告中的中英文密码错误、复制后仍可使用中文卫星资源，也在该脚本中检查。第二个密码包含前导 U+FEFF、前导和尾随空格；输入末尾附加 CRLF，验证程序只移除输入行结束符，保留密码本身。

测试在本机的隔离进程中运行，通过实际启动和运行时跟踪确认 EXE 不依赖已安装的 .NET。

## 中英文资源

`tests/TwoPassword.Localization.Tests` 检查两套共享资源键和格式占位符、默认语言回退、显式语言切换、后台工作线程的语言继承、密码错误类型与语言，以及英文创建后中文解包的字节和文件名一致性。它还扫描 Core/Recovery 的资源引用，避免遗漏用户可见错误。

应用界面资源另由 UI 构建和实际窗口检查覆盖。语言切换只改变显示文本，不转换密码、用户路径或文件内容。

## 实际界面操作

已使用真实发布版程序完成文件夹选择、双密码创建、Zstd、分离文件布局、PAR2 恢复记录生成，以及使用第二个含日文和首尾空格的密码解包。全部文件 SHA-256 一致，空目录以及不同子目录中的同名文件均保留。创建目标和解包目录发生冲突时，现有哨兵文件保持原样，建议名称中的 `(2)` 后缀正确配对。

中英文界面在 125% DPI 下用 UI Automation 驱动实际检查，浅色和深色主题各一遍：按打开的文件类型进入加密、解密或修复，最小窗口 520×500 下的滚动，最大化边距，密码行内校验（重复、两次不一致），错误密码提示，以及加密、解密、修复的进度页与完成页。窗口截图保存在 `assets/screenshots/`，仅包含空字段。

恢复记录内嵌后的界面另外检查了：标题栏的 GitHub 图标；选项里恢复记录默认 5%，加密只产生一个 EXE；从修复页打开密文损坏的 EXE，检查后修复；尾部清零的 EXE 在修复页显示恢复记录大小，检查结果为“文件尾部损坏，加密数据完整，可以修复”；`.2pw` 尾部清零的双文件包在解密页提示损坏，输入密码后成功解密。1 个字符的密码在界面里通过校验并完成加密，再用命令行以同一密码解开。

提权和右键菜单同样实际操作过。加密或解密到 `C:\Program Files` 时，提示旁出现“以管理员身份重试”；点击并通过 UAC 后，新的管理员窗口保留源文件和目标位置，在 Program Files 中完成加密和解密，标题显示“管理员”，菜单不再提供“以管理员身份运行”。管理员窗口能接收从普通权限资源管理器拖入的文件。开启右键菜单后，在资源管理器中检查了普通文件、文件夹和 `.2pw` 各自显示的菜单项，关闭后注册表项全部移除。

## 安装、升级和卸载

WiX 构建使用 `-wx` 将警告视为错误。`scripts/Test-Installer.ps1` 对本项目的产品标识执行真实 MSI 安装，不调用 `Win32_Product`，不扫描或修复其他软件。

本地双语安装验证完成 **52 项检查**，中文安装、同版本英文替换、卸载三个过程退出码均为 `0`。检查包括：

- MSI 产品身份、当前用户安装范围、中英文向导标准文本和自定义文本。
- 含中文、日文和空格的自定义安装目录。
- 程序、两份 README 和第三方声明的安装后 SHA-256。
- 英文版本替换中文版本时记住安装目录，只留下一个已注册产品。
- 开始菜单快捷方式、HKCU 标记、卸载登记与移除。
- 用户在安装目录新增的文件卸载后仍然保留。
- 安装的程序用 `--explorer-menu on` 写入的资源管理器右键菜单指向安装目录，英文替换后仍然保留，卸载时被移除。
- 项目源文件哨兵哈希在测试前后保持一致。

快捷方式校验使用 Windows 卷标识及完整 128 位文件标识，确认实际指向安装的程序及工作目录，并要求无附加参数；原始路径、解析路径和标识都写入诊断报告。真实 NTFS 8.3 别名被正确识别为同一对象，不同文件或丢失目标仍被拒绝。

脚本发现已有用户安装或 2Password 右键菜单项时会拒绝覆盖，以免把真实安装当成临时测试环境。

## 大文件与资源使用

大文件测试单独执行，不在每次提交中重复写入数十 GiB：

```powershell
pwsh -File scripts/Test-LargeFiles.ps1
```

建议预留至少约 30 GiB 空间。测试构造稀疏源文件，在 2/4/8 GiB 边界及末尾放置非零随机标记，随后实际读取、加密和解包。未压缩测试实际写出了超过 4 GiB 的密文数据文件。

2026-11-06 本地实际记录：

| 测试 | 源文件字节数 | 输出 | 创建耗时 | 解包耗时 | 结果 |
| --- | ---: | --- | ---: | ---: | --- |
| 不压缩 + 自动布局 | 4,423,942,144 | 66,762,374 字节启动器 + 4,424,069,228 字节 `.2pw` | 5.38 秒 | 7.57 秒 | 源和还原长度、完整 SHA-256 相同 |
| Zstd + 自动布局 | 8,589,934,715 | 67,434,976 字节嵌入式 EXE | 6.43 秒 | 21.04 秒 | 超过 8 GiB 的 PAX 文件长度与完整 SHA-256 相同 |

整个测试进程观察到的峰值工作集为 **413,523,968 字节（约 394 MiB）**，峰值托管内存为 281,612,328 字节。计时受本机存储、缓存、稀疏文件和高压缩率数据影响，只反映这组数据在这台机器上的表现。

大文件用例调用生产 Core API，用本次 v3 格式发布版 EXE 的快照作模板，不生成恢复记录，也没有直接运行这些大包；独立 EXE 的实际启动见上一节。

### Windows 加载器边界

另用真实 Windows 可执行程序加稀疏附加数据验证加载行为：

| EXE 总字节数 | 本机结果 |
| ---: | --- |
| 2,147,483,649 | 启动成功，退出码 0 |
| 4,294,967,295 | 启动成功，退出码 0 |
| 4,294,967,296 | Windows 拒绝，提示不是有效的 Win32 应用程序 |

因此自动布局按**最终 EXE 大小**决定是否分离，不按未经压缩的源文件大小简单判断。超过该限制的密文可以保存在使用 64 位长度的 `.2pw` 文件中。

## 验证范围

以下情形没有测试，也不在设计目标内：任意分布的损坏都能恢复、保留全部 NTFS 元数据、防御同一用户下的恶意进程、VSS 一致快照、断电时多个文件的事务提交。管理员权限、恶意内核、崩溃转储和系统备份等边界见安全文档。

依赖版本、NuGet 内容哈希、PAR2 二进制及源码摘要固定在仓库中。NuGet 漏洞检查没有报告已知漏洞的包。发布文件用 SHA-256 校验，没有 Authenticode 签名。

---

**English overview.** The repository includes reproducible adversarial tests, real PAR2 recovery tests, localization checks, actual copied self-extractor execution, and install/upgrade/uninstall tests. The primary suite has 189 cases, including 22 workspace-permission regressions, and all of them pass on GitHub Actions; run locally without elevation, one ACL case fails because it can't change the test parent's permissions. The recovery tests cover packages whose trailer is zeroed or truncated. Local large-file cases processed 4,423,942,144-byte uncompressed data and an 8,589,934,715-byte PAX file, comparing full SHA-256 hashes after extraction. The approximately 394 MiB observed peak working set and timing figures describe these synthetic fixtures on one Windows host. Regular suites and installer/standalone checks gate GitHub Releases; large-file tests are available separately.

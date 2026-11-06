# 验证记录 / Validation evidence

本文件记录 2026-11-06 在 Windows x64 上执行的可复现验证，以及发布流水线的检查范围。所有测试均使用生成的合成文件和测试专用密码。测试代码、独立格式解析器和构建脚本保存在仓库中；原始 JSON 报告位于本地 `artifacts/`，常规报告也由 GitHub Actions 保留为 `verification-reports` 构建产物。

这些结果是实现与回归证据，不等同于外部密码学安全审计。密码学假设、文件系统限制和威胁模型见 [SECURITY.md](SECURITY.md) / [SECURITY.en.md](SECURITY.en.md)。

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
| 独立安全与文件往返 | 165 | 0 |
| 真实 PAR2 与按需恢复 | 24 | 0 |
| 共享语言资源与跨语言操作 | 15 | 0 |
| 真实自包含 EXE / CLI | 11 | 0 |
| 中文安装、英文替换与卸载 | 48 | 0 |

共享语言验证覆盖 235 对资源和 234 个实际 `Text.Get` 源代码键；App 自有界面另有 251 对资源。

## 常规安全与还原验证

主测试项目 `tests/TwoPassword.Tests` 的完整本地记录为 **165 项通过，0 项失败，0 项跳过**。其重要覆盖包括：

| 范围 | 实际检查 |
| --- | --- |
| 密码学原语 | RFC 9106 Argon2id 标准向量；公开 AES-256-GCM 向量与错误标签拒绝 |
| 独立密码 | 多个密码分别还原同一完整文件树；第 16 个密码槽；错误、空、超长及非法 Unicode 密码 |
| 独立格式检查 | 测试代码独立编写的容器编码器和解码器，不仅调用生产代码做往返 |
| 名称与内容 | 中文、日文、阿拉伯文、emoji、NFC/NFD 区分，超过 1,000 字符路径；逐文件 SHA-256、空目录和空文件 |
| 压缩 | Zstd、Brotli、不压缩；截断、尾随数据、串联帧、错误长度、过大窗口、异常帧和解压输出边界 |
| 认证结构 | 内容、标签、长度、顺序、结束标记篡改；截断、重复块和多余块；未使用密码槽损坏 |
| 元数据冗余 | 头部和尾部的各个单副本存活情形；有效但冲突的副本拒绝 |
| 分离文件 | 丢失或替换数据文件、错误头部身份、绝对路径、穿越、递归引用及名称限制 |
| 恶意归档 | 穿越、设备名、重解析点、大小写冲突、重复条目、异常元数据与资源上限 |
| 操作完整性 | 取消、源文件改变、目标已存在、失败后清理和最终提交保护 |
| PAR2 元数据 | 21 个独立恶意输入用例，检查路径、描述符、Unicode 扩展、不同恢复集混用、校验与块数量限制 |

## 实际 PAR2 与按需修复

`tests/TwoPassword.Recovery.Tests` 使用内嵌的真实 `par2cmdline-turbo 1.5.0` 进程，而非模拟修复器。当前测试包含以下行为：

- 对含中文、日文和 emoji 的文件名生成并校验真实恢复记录。
- 健康包直接解包，恢复进度回调保持为空，未启动 PAR2 扫描。
- 错误密码直接退出；即使密文也有损坏，仍不会因错误密码运行 PAR2。
- 空、超长和非法 Unicode 密码在预检查之前被拒绝。
- 用户明确请求预检查时执行 PAR2；已有还原目标始终先拒绝。
- 健康的加密包在可选恢复记录全部损坏时仍可正常认证解包。
- 实际翻转密文字节：先确认 AES-GCM 拒绝，再执行自动修复与完整认证重试；密文和还原文件均与原始 SHA-256 一致。
- 删除索引后，直接 `.2pw` 的预检查能够找到有效恢复分卷；损坏索引同样可用冗余元数据恢复。
- 冗余不足时，原始损坏文件保持原样；成功修复保留损坏原件备份。
- 验证只读源文件时，不改变源文件的只读属性。
- 对分离包重建完全缺失的小启动器；对恶意穿越描述符、取消和临时工作区清理进行检查。
- 离线导出完整 PAR2 对应源码，并核对固定 SHA-256；拒绝覆盖已有源码导出文件。

这组测试直接验证了默认解包的性能策略：**健康文件不做额外整包 PAR2 读取，认证始终执行；只有检测到损坏并确实完成修复才重新解包一次。**

## 真正的独立 EXE

`scripts/Test-Standalone.ps1` 调用发布后的单文件 EXE，再调用由它创建的加密 EXE。测试将解包 EXE 单独复制到另一个目录，并为子进程设置：

- 空的 `DOTNET_ROOT` / `DOTNET_ROOT_X64`。
- 仅包含 Windows 系统目录的 `PATH`。
- 独立的本机运行组件缓存。
- .NET 主机跟踪，检查自包含模式及包内 `System.Private.CoreLib.dll`。

真实进程检查包括独立创建、独立解析、每个密码还原完整文件树、错误密码不产生目标、拒绝覆盖、无压缩包、外部数据文件丢失后 PAR2 重建，以及**正在运行的嵌入式 EXE 修复自身损坏的数据区后继续解包**。

中英文命令行帮助、报告中的中英文密码错误、复制后仍可使用中文卫星资源，也在该脚本中检查。第二个密码包含前导 U+FEFF、前导和尾随空格；输入末尾附加 CRLF，验证程序只移除输入行结束符，保留密码本身。

测试运行在当前 Windows 主机的隔离进程中，未将其描述为全新 Windows 虚拟机测试。独立运行的证据包括实际启动和运行时跟踪，而不是仅检查发布参数。

## 中英文资源

`tests/TwoPassword.Localization.Tests` 检查两套共享资源键和格式占位符、默认语言回退、显式语言切换、后台工作线程的语言继承、密码错误类型与语言，以及英文创建后中文解包的字节和文件名一致性。它还扫描 Core/Recovery 的资源引用，避免遗漏用户可见错误。

应用界面资源另由 UI 构建和实际窗口检查覆盖。语言切换只改变显示文本，不转换密码、用户路径或文件内容。

## 安装、升级和卸载

WiX 构建使用 `-wx` 将警告视为错误。`scripts/Test-Installer.ps1` 对本项目的产品标识执行真实 MSI 安装，不调用 `Win32_Product`，不扫描或修复其他软件。

本地双语安装验证完成 **48 项检查**，中文安装、同版本英文替换、卸载三个过程退出码均为 `0`。检查包括：

- MSI 产品身份、当前用户安装范围、中英文向导标准文本和自定义文本。
- 含中文、日文和空格的自定义安装目录。
- 程序、两份 README 和第三方声明的安装后 SHA-256。
- 英文版本替换中文版本时记住安装目录，只留下一个已注册产品。
- 开始菜单快捷方式、HKCU 标记、卸载登记与移除。
- 用户在安装目录新增的文件卸载后仍然保留。
- 项目源文件哨兵哈希在测试前后保持一致。

脚本发现已有用户安装时会拒绝覆盖，以免把真实安装当成临时测试环境。

## 大文件与资源使用

大文件测试单独执行，不在每次提交中重复写入数十 GiB：

```powershell
pwsh -File scripts/Test-LargeFiles.ps1
```

建议预留至少约 30 GiB 空间。测试构造稀疏源文件，在 2/4/8 GiB 边界及末尾放置非零随机标记，随后实际读取、加密和解包。未压缩测试产生了真实超过 4 GiB 的密文数据文件，不只检查长度字段。

2026-11-06 本地实际记录：

| 测试 | 源文件字节数 | 输出 | 创建耗时 | 解包耗时 | 结果 |
| --- | ---: | --- | ---: | ---: | --- |
| 不压缩 + 自动布局 | 4,423,942,144 | 66,674,733 字节启动器 + 4,424,069,228 字节 `.2pw` | 4.78 秒 | 6.09 秒 | 源和还原长度、完整 SHA-256 相同 |
| Zstd + 自动布局 | 8,589,934,715 | 67,347,338 字节嵌入式 EXE | 6.48 秒 | 5.70 秒 | 超过 8 GiB 的 PAX 文件长度与完整 SHA-256 相同 |

整个测试进程观察到的峰值工作集为 **357,687,296 字节（约 341 MiB）**，峰值托管内存为 207,750,824 字节。这里的计时受本机存储、缓存、稀疏文件和高可压缩数据影响，不能当作任意文件或任意硬盘的吞吐承诺。

大文件用例调用生产 Core API，并使用当时发布版 EXE 的快照作为模板；它们没有直接运行这些大包。独立 EXE 的真实启动由上一节单独验证。后续界面语言改动不改变容器格式或加密的数据处理方式。

### Windows 加载器边界

另用真实 Windows 可执行程序加稀疏附加数据验证加载行为：

| EXE 总字节数 | 本机结果 |
| ---: | --- |
| 2,147,483,649 | 启动成功，退出码 0 |
| 4,294,967,295 | 启动成功，退出码 0 |
| 4,294,967,296 | Windows 拒绝，提示不是有效的 Win32 应用程序 |

因此自动布局按**最终 EXE 大小**决定是否分离，不按未经压缩的源文件大小简单判断。超过该限制的密文可以保存在使用 64 位长度的 `.2pw` 文件中。

## 验证范围

已验证的结果不能扩展为未测试的断言：没有声称恢复任何分布的全部损坏、支持全部 NTFS 元数据、抗同用户恶意进程、提供 VSS 一致快照，或在断电时实现跨多文件的事务。私有目录和认证保护正常操作中的中间结果；管理员权限、恶意内核、崩溃转储与系统备份等边界详见安全文档。

依赖版本、NuGet 内容哈希、PAR2 二进制及源码摘要固定在仓库中。NuGet 漏洞列表检查未报告已知易受攻击的包；该检查不是实现代码审计。发布文件使用 SHA-256 校验，当前未配置 Authenticode 签名证书。

---

**English overview.** The repository includes reproducible adversarial tests, real PAR2 recovery tests, localization checks, actual copied self-extractor execution, and install/upgrade/uninstall tests. The primary suite passed 165 cases with no failures or skips. Local large-file cases processed 4,423,942,144-byte uncompressed data and an 8,589,934,715-byte PAX file, comparing full SHA-256 hashes after extraction. The approximately 341 MiB observed peak working set and timing figures describe these specific synthetic fixtures on one Windows host. They are not general performance guarantees or a substitute for an external security audit. Regular suites and installer/standalone checks gate GitHub Releases; large-file tests are available separately.

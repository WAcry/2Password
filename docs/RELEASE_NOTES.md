# 2Password 1.0.0

## 简体中文

Windows 10 / 11 x64 本地加密工具，支持中英文界面和独立自解包。

- **多个独立密码**：1–16 个密码中的任意一个均可解包全部内容；知道其中一个密码，不会因此得到其他密码。密码不以明文保存在包内。
- **独立 EXE**：接收者无需安装 2Password、.NET 或压缩工具。超过 Windows 单 EXE 大小限制时，自动生成启动器与同目录 `.2pw` 数据文件。
- **文件还原**：流式 PAX 归档，严格 Unicode 和长路径处理，保留空目录、空文件及支持的 Windows 属性；遇到不支持的文件系统特性会明确报错。
- **加密与压缩**：Argon2id、AES-256-GCM，以及 1 MiB 独立认证块；可选 Zstd、Brotli 或不压缩。关键元数据保留三份带校验的副本。
- **集成恢复记录**：默认 10% PAR2，可调整或关闭。健康包直接流式解密并认证；检测到损坏后才尝试修复并重新解包。可选择完整预检查或手动修复。
- **安全处理同名目标**：建议新名称，绝不静默覆盖或合并。解包在私有暂存区完成，完整认证通过后才提交最终目录。
- **双语安装包**：按当前用户安装，无需管理员权限；支持中英文安装向导、语言版本替换、开始菜单入口和卸载。

下载 `-zh-CN.msi` 使用中文安装向导，下载 `-en-US.msi` 使用英文安装向导；应用内可独立切换语言。便携 EXE 和 ZIP 包含相同功能。`SHA256SUMS.txt` 提供各发布文件的校验值。

完整设计、功能边界和实际验证证据见仓库的 [README](https://github.com/WAcry/2Password#readme)、[安全说明](https://github.com/WAcry/2Password/blob/main/docs/SECURITY.md) 和 [验证记录](https://github.com/WAcry/2Password/blob/main/docs/VALIDATION.md)。此版本未配置 Authenticode 签名证书，Windows 可能显示未知发布者。项目未经过外部密码学安全审计；密码强度决定离线猜测的难度。

## English

A local Windows 10 / 11 x64 encryption application with English and Simplified Chinese interfaces.

- **Independent passwords:** any one of 1–16 passwords unlocks the contents without exposing the other passwords.
- **Self-contained extraction:** generated EXEs need no installed application or .NET runtime. Large packages automatically use a standalone launcher and a sibling `.2pw` data file.
- **Exact file handling:** streaming PAX archives, strict Unicode, long paths, empty files/directories, supported Windows metadata, and explicit failures for unsupported filesystem features.
- **Authenticated blocks:** Argon2id and AES-256-GCM, independent 1 MiB Zstd/Brotli/raw blocks, and three checksummed copies of critical metadata.
- **Integrated PAR2 recovery:** optional recovery data, defaulting to 10%. Healthy extraction avoids a separate PAR2 scan; detected corruption triggers repair followed by full authenticated extraction. Explicit prechecks and manual repair remain available.
- **No silent overwrite:** new destination names, private extraction staging, and publication only after complete validation.
- **Per-user installers:** Chinese and English setup packages, language-edition replacement, shortcuts, and clean uninstall while preserving user-created files.

Choose the `-en-US.msi` for an English setup wizard or use the portable EXE/ZIP. Both application languages are included in every distribution. Verify downloads using `SHA256SUMS.txt`. The complete corresponding source for the embedded PAR2 component is included as a release asset and can also be exported offline from the application.

See the [English README](https://github.com/WAcry/2Password/blob/main/README.en.md) and [security documentation](https://github.com/WAcry/2Password/blob/main/docs/SECURITY.en.md) for supported metadata and operational limits. This release is not Authenticode-signed and has not received an external cryptographic security audit.

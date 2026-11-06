# 固定版本的 PAR2 分发文件

[English](README.md) · [简体中文](README.zh.md)

本目录包含未经修改的 **par2cmdline-turbo 1.5.0** Windows x64 可执行文件、与之对应的完整源码分发包，以及 GPL-2.0-or-later 的 COPYING 许可文件。工具作为独立进程运行，不链接进托管应用程序。

官方上游：https://github.com/animetosho/par2cmdline-turbo/releases/tag/v1.5.0

| 文件 | SHA-256 |
| --- | --- |
| 官方 `par2cmdline-turbo-1.5.0-win-x64.zip` | `873a6f25822415f432224cc6f734407ca2732004184e002960fc68ed1e99c5d7` |
| 解压出的 `par2.exe` | `36ce11d92c895a552485ba8cb1ad4b92ca62a00333f1aa6308daafbc371e69e9` |
| `par2cmdline-turbo-1.5.0.tar.xz` | `035584144d3ac3b08fb5d7d4b844f60cf97404b6469f6aed7d9b9430a25bef0e` |

使用该可执行文件之前，已将 ZIP 和源码的哈希与官方 GitHub Release 资产摘要核对。运行时还会再次用固定的可执行文件哈希校验解压出的程序。

每个发布的 2Password 应用及其生成的自解密程序，都内嵌了该可执行文件、完整源码归档和许可。可以通过应用的第三方许可对话框，或 `2Password.exe --export-recovery-source <new-output.tar.xz>` 导出完整源码。公开发布的版本也会单独附带源码归档。源码归档包含上游构建说明和随附的计算模块源码。使用恢复功能或导出这些源码均不需要联网下载。

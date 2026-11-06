# 2Password 1.0.0

[English](https://github.com/WAcry/2Password/blob/main/docs/RELEASE_NOTES.md) · [简体中文](https://github.com/WAcry/2Password/blob/main/docs/RELEASE_NOTES.zh.md)

Encrypt a file or folder into a single EXE with 1 to 16 passwords. Any one of them opens it. The recipient double-clicks the EXE to decrypt, with nothing to install.

- Each password unlocks everything on its own, and knowing one doesn't reveal the others.
- Packages can open without a password: leave a password pair blank when creating and the input blank when decrypting. Any empty password opens the whole package.
- Choose `Zstd (Lv.3)` (default), `Brotli (Lv.6)`, or no compression.
- Hold the eye button beside a password field to view it temporarily when creating or decrypting a package; release to hide it.
- 5% PAR2 recovery data is stored inside the package by default, with no extra file. Decryption repairs a damaged package automatically, including a damaged or truncated end of file.
- Encrypted results larger than 4 GB are split into an EXE and a `.2pw` file in the same folder.
- Filenames, empty folders, timestamps and attributes come back as they were. Existing files are never overwritten.
- Optional Explorer right-click menu: right-click a file or folder to encrypt it.
- When a destination needs administrator rights, one click retries as administrator.
- English and Chinese interface, following the system's light or dark theme.

Download the `-en-US.msi` (English setup wizard) or `-zh-CN.msi` (Chinese setup wizard). Both install for the current user without admin rights. The portable EXE and ZIP work too.

Releases aren't code-signed, so Windows may warn about an unknown publisher. Check downloads against `SHA256SUMS.txt`. `par2cmdline-turbo-1.5.0.tar.xz` is the source of the bundled PAR2 program. See the [README](https://github.com/WAcry/2Password#readme) for usage.

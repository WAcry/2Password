# 2Password security design

[简体中文](SECURITY.md) · English

## Protection goals

The threat model permits an attacker to obtain an encrypted package, know the complete source code, modify any package bytes, and make unlimited offline password guesses. With sufficiently strong passwords, a trusted executable, and an uncompromised operating system, the attacker cannot read file contents or filenames. Damaged content, altered password slots, reordered records, truncation, and unauthorized trailing data make decryption fail.

Anyone holding **one valid password can read all contents**. Each password works on its own; none of them has to be combined with another.

## Established implementations

- `Konscious.Security.Cryptography.Argon2` implements Argon2id password derivation. The application does not implement Argon2 itself.
- .NET `System.Security.Cryptography.AesGcm` provides AES-256-GCM; randomness comes from `RandomNumberGenerator`.
- .NET `System.Formats.Tar` supplies standard PAX archive writing and reading. Names are represented losslessly as UTF-8.
- `ZstdSharp.Port` supplies the default Zstd (Lv.3) compression. Optional Brotli (Lv.6) uses .NET `BrotliEncoder` / `BrotliDecoder`. Blocks are compressed independently; no compression is also supported.
- The optional recovery component is bundled `par2cmdline-turbo 1.5.0`, checked against a pinned SHA-256. Its corresponding source and GPL license text are distributed with the application.

The multiple-password envelope, streaming authenticated records, filesystem handling, and user interface are this project's own code, and that is where review should focus.

## Independent passwords

Each package receives a random 256-bit content key. Each password has an independent random salt and derives its own wrapping key through Argon2id. AES-256-GCM wraps the same content key independently under each wrapping key. The package stores salts, nonces, ciphertext, and authentication tags, never plaintext passwords or a password list that can expose the other passwords.

Container format V1 uses the following fixed parameters:

| Parameter | Value |
| --- | --- |
| Argon2 variant | Argon2id, version 1.3 |
| Memory | 64 MiB |
| Iterations | 3 |
| Parallel lanes | 4 |
| Random salt per password | 16 bytes |
| Derived wrapping key and content key | 32 bytes |
| AES-GCM nonce | 12 bytes |
| AES-GCM authentication tag | 16 bytes |
| Password slots | 1–16 |

These Argon2id parameters follow the lower-memory recommended option in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html). The format version fixes the cost parameters; an untrusted package cannot request arbitrary KDF memory or iteration counts.

A valid password reveals the content key, but the content key does not reveal the other passwords. Those passwords can still be attacked with offline dictionary guessing. **The weakest valid password determines the package's practical confidentiality**, so adding a weak password weakens the whole package. Copies already sent cannot be revoked.

Passwords retain their exact Unicode character sequence. The application does not trim whitespace, change case, or normalize NFC/NFD. An empty string is allowed: if any password is empty, anyone can open the entire package with empty input, so its contents and filenames have no password confidentiality. Invalid Unicode, null, duplicates, and oversized input are rejected.

V1 uses `0x00 || StrictUTF8(password)` as the Argon2id input for every password. The fixed prefix lets the dependency process an empty string while preserving a one-to-one encoding of passwords; an empty string, a space, and the U+0000 character remain distinct.

## Content authentication and parsing

The archive stream is divided into raw blocks of at most 1 MiB. Each block is independently compressed and then authenticated through AES-GCM. Compression falls back to raw encoding when it does not save space. A block does not depend on a previous block's compression dictionary.

The nonce combines a random prefix with an increasing 64-bit record number; every package has a new content key. Each record's additional authenticated data includes the complete logical header's SHA-256, record number, raw length, encoded length, codec identifier, and reserved fields. Consequently, alteration of even an unused password slot is detected during content decryption.

Raw and encoded lengths are bounded before processing. Decompression writes into caller-allocated buffers rather than allocating memory according to attacker-controlled frame declarations. Zstd must contain exactly one standard frame, use no external dictionary, have a window no larger than 1 MiB, and declare exactly the authenticated raw size. Brotli must consume the entire encoded block and produce exactly the declared number of bytes. Additional compressed frames, trailing bytes, and size mismatches are rejected.

The logical key-slot/container header has three fixed-size physical replicas. The locating footer also has three replicas. Each copy has a SHA-256 checksum. Damaged copies are ignored, and valid copies must agree. The checksums only pick an intact replica; AES-GCM authentication decides whether the content is genuine. If every header replica is damaged, the recovery data or an original backup is needed. File-level directory information is inside the authenticated PAX stream and is additionally covered by the recovery data.

A dedicated authenticated zero-length final record is mandatory. Extraction validates this record, exact payload boundaries, and the actual end of the file before publishing output.

Each block is authenticated before its plaintext reaches decompression and archive parsing. The parser treats names, declared lengths, entry counts, and archive types as untrusted. Lengths and counts have limits, actual totals must match declarations, and unknown format versions are rejected.

The visible header reveals the format version, password-slot count, compression selection, file/directory counts, and declared aggregate byte count. Physical file size is also visible. Filenames, directory names, and file contents are encrypted. `Inspect` reads format information only; it checks neither the password nor the content.

The outer EXE and `.2pw` filenames are also visible. The GUI suggests an output name based on the source name, so encryption of names inside the archive does not conceal the chosen package filename. Choose a neutral output name when that label is sensitive.

## Paths, encoding, and source consistency

Windows treats filenames as Unicode character sequences. The application does not convert names through a local code page or normalize them. For example, `café.txt` and a name containing `e` followed by a combining accent remain distinct.

Filesystem access uses Unicode and extended-length paths, and the application manifest enables long-path awareness. Windows and the destination filesystem still impose total-path and component-length limits, and the destination needs enough free space. Explorer's support for very long paths differs from the underlying file APIs.

Extraction accepts only safe relative paths. It rejects absolute paths, drive letters, UNC paths, `..`, alternate-stream syntax, reserved device names, ambiguous names, collisions, and names ending in dots or spaces that are unsuitable for ordinary Windows directories. Such names cause an error; nothing is renamed to work around them.

Hidden and system entries are packaged too, and any scanning failure fails the whole operation. The following inputs cause an error:

- Symbolic links, directory junctions, and other reparse points, including placeholders that may require cloud hydration.
- NTFS alternate data streams other than the download marker `Zone.Identifier`. That marker is preserved as original bytes up to 64 KiB; larger markers are rejected.
- EFS encryption, device attributes, and offline file attributes.
- Entries that cannot be read, are exclusively locked, or are detected changing during packaging.
- Names that cannot be represented unambiguously in a normal Windows destination.

Restored: file bytes, file and directory names, empty directories, supported timestamps, and common attributes. Not preserved: NTFS ACLs and owners, hard-link relationships, sparse allocation layout, short names, file IDs, audit information, and other filesystem-specific metadata. Hard-linked content is restored as separate files, and sparse content can take more disk space.

The file inventory is compared before and after packaging, and ordinary concurrent changes cause an error. There is no VSS snapshot, so export a consistent backup of a live database with its own tools before packaging it.

## Publication, cancellation, and failures

During creation, the archive/compression stream goes directly into encryption without an intermediate plaintext archive. The encrypted result is first written to a temporary file in its destination directory, then published without overwriting an existing file.

Extraction creates a private staging directory whose ACL permits the current user and SYSTEM. Only after all authentication, path, and length checks pass is it renamed to a new destination without overwriting. A destination that already exists, or is created concurrently, causes failure and is preserved.

Staging directories and recovery workspaces require a filesystem with persistent ACL support. The application queries volume capabilities through an actual file handle, atomically supplies a protected DACL at creation, and reads it back to verify the current user owns the directory and only that user and SYSTEM receive inheritable full control. Existing paths are neither reused nor given new permissions. FAT/exFAT destinations without persistent ACLs, providers whose capabilities cannot be queried, and directories whose strict permissions cannot be verified cause an error. Use local NTFS for extraction destinations and recovery workspaces. If the recovery workspace can't be created during encryption (for example when the output is on exFAT), the package is still written, without recovery data, and the app says so.

Named-stream support is also checked against the actual volume capabilities. A provider's corresponding unsupported-enumeration error is treated as absence of alternate streams only when the volume explicitly lacks named-stream support. A failed capability query is treated as an error.

Ordinary exceptions and cancellation trigger cleanup. Power loss, forced termination, disk damage, or lost cleanup permissions can leave temporary files or staging directories. Temporary plaintext is deleted normally, so SSDs, backups, filesystem journals, and snapshots may retain copies.

## Trust boundary of a standalone EXE

The extraction EXE includes its runtime and does not require the recipient to install .NET or 2Password. Automatic layout uses the final encrypted size: a package is embedded when it fits within the Windows executable limit, otherwise the output is an extraction EXE plus a sibling `.2pw` data file. Detached layout can also be selected explicitly.

A single EXE must be smaller than 4 GiB. Larger source data can still be embedded if compression makes the final EXE fit. Detached data uses 64-bit lengths with a 16 TiB raw-content limit, subject to available space, entry counts, paths, and metadata resource limits. The reference permits only a safe sibling `.2pw` basename bound to the data container's logical-header SHA-256. It accepts no URLs, path components, or cross-directory references. The descriptor and locating footer also have three replicas.

Data authentication covers the encrypted content only. Whether the EXE itself can be trusted depends on where it came from.

A maliciously replaced EXE can steal passwords when they are entered. Run only trusted executables and obtain release files or checksums through trusted channels. Packages supplied by third parties can be opened as data using a trusted installed application, reducing the need to execute an unfamiliar EXE.

Outside the protection scope: malware controlling the current user session, keyloggers, administrator or kernel compromise, memory dumps, screen capture, weak passwords, and deliberate sharing of decrypted contents. The application clears the key and byte buffers it controls; managed strings and the KDF library's internal memory cannot be guaranteed to be cleared.

## Administrator rights and the right-click menu

The app runs with normal rights. Only "Retry as administrator" or "Run as administrator" starts a new elevated process through UAC, and the old window then closes. The new process gets the interface language, theme, source and destination on its command line. Passwords are never passed on the command line and have to be entered again.

Windows blocks drag and drop from normal-rights programs into elevated windows. The elevated window lets three drop messages through: `WM_DROPFILES`, `WM_COPYDATA` and `0x0049`. A dropped path only opens in the interface, as with a normal drop. Encrypting or decrypting still needs a password and a click.

The right-click menu writes only to the current user's `HKCU\Software\Classes`, and its commands point at the running executable. Turning it off removes only entries that point at this executable. Uninstalling the installed version does the same cleanup.

## PAR2 recovery data

par2cmdline-turbo generates the recovery data from the encrypted data. It never sees plaintext and needs no password. The recovery data lives in the same file as the encrypted data: a single EXE is `[program][encrypted data][recovery data][trailer]`, and the `.2pw` of a two-file package is `[encrypted data][recovery data][trailer]`. The three trailer copies record where the encrypted data starts, its length and the recovery data's length. The program part of the EXE is not covered; if it is damaged, open the EXE with another copy of 2Password.

The three trailer copies sit next to each other in the last 192 bytes, so one bad sector or a truncated file loses all of them. The app then scans the whole file instead. It finds a header copy that passes its checksum, then a FileDesc packet in the recovery data that records the length of the encrypted data. The three header copies are identical, which leaves three possible starting points; the block checksums in the recovery data pick the right one. Checking then reports a damaged trailer, and repair restores any damaged blocks and writes a new trailer. A truncated file can be repaired only if enough recovery blocks remain; a cut into the encrypted data can't be repaired. In a single EXE, if all three header copies are lost along with the trailer, the data can't be located either.

A single EXE with a destroyed trailer opens as a plain copy of 2Password when double-clicked, and dragging it into a window doesn't recognize it. Select it with "Repair a package…" in another copy of 2Password; once repaired it works normally again.

The parameters are par2cmdline-turbo's defaults: a block size of about 1/2000 of the encrypted data, rounded to a multiple of 4 bytes, with memory and thread count left to par2. Redundancy is 5% by default, with 10% and 20% as options. Capacity is counted in damaged blocks, so 5% redundancy repairs roughly 5% of the blocks. A few errors spread across many blocks can still use up the recovery blocks.

When reading the recovery data, the app checks each PAR2 packet's length and MD5. A damaged packet is skipped and scanning resumes at the next packet marker, so one damaged spot costs one packet. Only packets that describe this encrypted data reach the native tool: the file name must be `payload`, the length, block size and file ID must match, and there must be exactly one recovery set. Creator packets and other packet types are dropped. Conflicting metadata is an error.

Checking doesn't run the native tool. The app hashes the encrypted data block by block and compares the MD5 values with the checksum table in the recovery data to count damaged blocks.

To repair, the app copies the encrypted data and the filtered recovery data into a restricted workspace, and par2 rebuilds the copy. The rebuilt data is checked against every block checksum and the whole-file MD5, and then only the damaged blocks are written back into the original file. Other processes can only read the file while the repair runs.

Normal extraction uses one authenticated streaming pass. A password that matches no slot fails directly and never starts a repair. When container, data or archive validation finds damage and the package has recovery data, the app repairs a copy in a workspace next to the destination and runs a complete extraction from that copy. The original file is not changed, and plaintext staged by the first attempt is cleaned up. With "Check and repair before decrypting" selected, the whole package is checked before extraction. Every block is authenticated before decompression.

PAR2's MD5 only detects damage; protection against tampering comes from AES-GCM. Rebuilt data still has to pass AES-GCM authentication, and the app never runs a rebuilt EXE.

## Verification and review

The test project includes public cryptographic known-answer vectors, independent format decoding, per-file SHA-256 comparisons, malicious/corrupted inputs, and filesystem boundary cases:

```powershell
dotnet run --project tests/TwoPassword.Tests -c Release
```

The report is written to the Git-ignored `artifacts/test-results.json` and records the environment and every test result.

Public-vector checks validate how the dependencies and APIs are used. The project has not had a third-party cryptographic audit or penetration test. Review should focus on envelope composition, archive boundaries, filesystem races, resource limits, update and signing trust, and failure recovery.

## Primary references

- [RFC 9106: Argon2 parameters and test vectors](https://www.rfc-editor.org/rfc/rfc9106.html)
- [.NET AesGcm.Encrypt: nonce and additional authenticated data](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm.encrypt?view=net-10.0)
- [Official BoringSSL AES-GCM public test vectors](https://boringssl.googlesource.com/boringssl/+/ed22bbb42a36ba6878a2e68b34d43036c221e763/crypto/cipher_extra/test/cipher_tests.txt)
- [Microsoft: Windows path length and Unicode names](https://learn.microsoft.com/windows/win32/fileio/maximum-file-path-limitation)
- [Microsoft: Windows file path formats](https://learn.microsoft.com/dotnet/standard/io/file-path-formats)
- [Microsoft: single-file deployment and self-contained runtimes](https://learn.microsoft.com/dotnet/core/deploying/single-file/overview)
- [ZstdSharp official project](https://github.com/oleg-st/ZstdSharp)
- [PAR2 format specification](https://parchive.sourceforge.net/docs/specifications/parity-volume-spec/article-spec.html)
- [par2cmdline-turbo official project](https://github.com/animetosho/par2cmdline-turbo)

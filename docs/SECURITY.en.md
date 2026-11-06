# 2Password security design and limitations

[简体中文](SECURITY.md) · English

This document distinguishes design goals, implementation measures, and guarantees the project does not make. Passing automated tests is not an independent cryptographic audit.

## Protection goals

The threat model permits an attacker to obtain an encrypted package, know the complete source code, modify any package bytes, and make unlimited offline password guesses. With sufficiently strong passwords, a trusted executable, and an uncompromised operating system, the attacker should not be able to read file contents or filenames. Damaged content, altered password slots, reordered records, truncation, and unauthorized trailing data must fail rather than be reported as a successful restoration.

Anyone holding **one valid password is authorized to read all contents**. Multiple passwords are independent access keys, not secret shares, threshold decryption, or multiple factors that must be supplied together.

## Established implementations

- `Konscious.Security.Cryptography.Argon2` implements Argon2id password derivation. The application does not implement Argon2 itself.
- .NET `System.Security.Cryptography.AesGcm` provides AES-256-GCM; randomness comes from `RandomNumberGenerator`.
- .NET `System.Formats.Tar` supplies standard PAX archive writing and reading. Names are represented losslessly as UTF-8.
- `ZstdSharp.Port` supplies the default Zstandard compression. Optional Brotli uses .NET `BrotliEncoder` / `BrotliDecoder`. Blocks are compressed independently; no compression is also supported.
- The optional recovery component is bundled `par2cmdline-turbo 1.5.0`, checked against a pinned SHA-256. Its corresponding source and GPL license text are distributed with the application.

Project-specific code combines these components into a multiple-password envelope, streaming authenticated records, filesystem restrictions, and the user interface. These composition and parsing decisions still require review; established primitives do not automatically establish the security of a new protocol.

## Independent passwords

Each package receives a random 256-bit content key. Each password has an independent random salt and derives its own wrapping key through Argon2id. AES-256-GCM wraps the same content key independently under each wrapping key. The package stores salts, nonces, ciphertext, and authentication tags, never plaintext passwords or a password list that can expose the other passwords.

Container format version 2 fixes the following parameters:

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

A valid password reveals the content key, but the content key does not directly reveal the other passwords. Offline dictionary attacks against those passwords remain possible. **The weakest valid password determines the package's practical confidentiality.** Adding a weak password weakens protection for the whole package. Access to already distributed copies cannot be revoked by creating a new package or changing passwords elsewhere.

Passwords retain their exact Unicode character sequence. The application does not trim whitespace, change case, or normalize NFC/NFD. Invalid Unicode, empty passwords, duplicates, and oversized input are rejected.

## Content authentication and parsing

The archive stream is divided into raw blocks of at most 1 MiB. Each block is independently compressed and then authenticated through AES-GCM. Compression falls back to raw encoding when it does not save space. A block does not depend on a previous block's compression dictionary.

The nonce combines a random prefix with an increasing 64-bit record number; every package has a new content key. Each record's additional authenticated data includes the complete logical header's SHA-256, record number, raw length, encoded length, codec identifier, and reserved fields. Consequently, alteration of even an unused password slot is detected during content decryption.

Raw and encoded lengths are bounded before processing. Decompression writes into caller-allocated buffers rather than allocating memory according to attacker-controlled frame declarations. Zstd must contain exactly one standard frame, use no external dictionary, have a window no larger than 1 MiB, and declare exactly the authenticated raw size. Brotli must consume the entire encoded block and produce exactly the declared number of bytes. Additional compressed frames, trailing bytes, and size mismatches are rejected.

The logical key-slot/container header has three fixed-size physical replicas. The locating footer also has three replicas. Each copy has a SHA-256 checksum. Damaged copies can be ignored, but valid copies must agree. These checksums detect damage; they do not replace AES-GCM authentication. Losing every replica still requires PAR2 or an original backup. File-level directory information is inside the authenticated PAX stream and is additionally covered by optional PAR2.

A dedicated authenticated zero-length final record is mandatory. Extraction validates this record, exact payload boundaries, and the actual end of the file before publishing output. Opening a password slot alone does not establish the integrity of the package.

Each block is authenticated before its plaintext reaches decompression and archive parsing. The parser treats names, declared lengths, entry counts, and archive types as untrusted. Lengths and counts have limits, actual totals must match declarations, and unknown format versions are rejected.

The visible header reveals the format version, password-slot count, compression selection, file/directory counts, and declared aggregate byte count. Physical file size is also visible. Filenames, directory names, and file contents are encrypted. `Inspect` is a structural inspection, not password verification or complete authentication.

The outer EXE, `.2pw`, and PAR2 filenames are also visible. The GUI suggests an output name based on the source name, so encryption of names inside the archive does not conceal the chosen package filename. Choose a neutral output name when that label is sensitive.

## Paths, encoding, and source consistency

Windows treats filenames as Unicode character sequences. The application does not convert names through a local code page or normalize them. For example, `café.txt` and a name containing `e` followed by a combining accent remain distinct.

Filesystem access uses Unicode and extended-length paths, and the application manifest enables long-path awareness. Windows and the destination filesystem still impose total-path and component-length limits, and sufficient destination space is required. Explorer's support for very long paths differs from the underlying file APIs.

Extraction accepts only safe relative paths. It rejects absolute paths, drive letters, UNC paths, `..`, alternate-stream syntax, reserved device names, ambiguous names, collisions, and names ending in dots or spaces that are unsuitable for ordinary Windows directories. It does not silently rename, truncate, or replace invalid characters to continue.

Source scanning includes hidden and system entries and never silently skips failures. The following inputs fail explicitly:

- Symbolic links, directory junctions, and other reparse points, including placeholders that may require cloud hydration.
- NTFS alternate data streams other than the download marker `Zone.Identifier`. That marker is preserved as original bytes up to 64 KiB; larger markers are rejected.
- EFS encryption, device attributes, and offline file attributes.
- Entries that cannot be read, are exclusively locked, or are detected changing during packaging.
- Names that cannot be represented unambiguously in a normal Windows destination.

Ordinary file bytes, file/directory names, empty directories, supported timestamps, and common attributes are restored. The package is not a complete filesystem image: it does not preserve NTFS ACLs/owners, hard-link relationships, sparse allocation layout, short names, file IDs, audit information, or every filesystem-specific attribute. Hard-linked content can be restored as separate files, and sparse content can require additional disk space.

Preflight and final inventory checks detect ordinary concurrent changes. They are not a VSS snapshot and do not provide a transactional snapshot across a changing directory tree or live database. Package stable source data; export a consistent application-specific backup first when necessary.

## Publication, cancellation, and failures

During creation, the archive/compression stream goes directly into encryption without an intermediate plaintext archive. The encrypted result is first written to a temporary file in its destination directory, then published without overwriting an existing file.

Extraction creates a private staging directory whose ACL permits the current user and SYSTEM. Only after all authentication, path, and length checks pass is it renamed to a new destination without overwriting. A destination that already exists, or is created concurrently, causes failure and is preserved.

Staging directories and PAR2 workspaces require a filesystem with persistent ACL support. The application queries volume capabilities through an actual file handle, atomically supplies a protected DACL at creation, and reads it back to verify the current user owns the directory and only that user and SYSTEM receive inheritable full control. Existing paths are neither reused nor given new permissions. FAT/exFAT destinations without persistent ACLs, providers whose capabilities cannot be queried, and directories whose strict permissions cannot be verified fail explicitly. Use local NTFS for extraction destinations and recovery workspaces. A successful ACL-setting call alone is not accepted as evidence that private access is enforced.

Named-stream support is also checked against the actual volume capabilities. A provider's corresponding unsupported-enumeration error is treated as absence of alternate streams only when the volume explicitly lacks named-stream support. Failure to query capabilities never silently becomes a safe result.

Ordinary exceptions and cancellation trigger cleanup. Power loss, forced termination, disk damage, or lost cleanup permissions can leave temporary files or staging directories. Deleting temporary plaintext is not secure erasure; SSDs, backups, filesystem journals, and snapshots may retain copies.

## Trust boundary of a standalone EXE

The extraction EXE includes its runtime and does not require the recipient to install .NET or 2Password. Automatic layout uses the final encrypted size: a package is embedded when it fits within the Windows executable limit, otherwise the output is an extraction EXE plus a sibling `.2pw` data file. Detached layout can also be selected explicitly.

A single EXE must be smaller than 4 GiB. Larger source data can still be embedded if compression makes the final EXE fit. Detached data uses 64-bit lengths with a 16 TiB raw-content limit, subject to available space, entry counts, paths, and metadata resource limits. The reference permits only a safe sibling `.2pw` basename bound to the data container's logical-header SHA-256. It accepts no URLs, path components, or cross-directory references. The descriptor and locating footer also have three replicas.

Content authentication does not establish the identity of the executable's publisher.

A maliciously replaced EXE can steal passwords when they are entered. Run only trusted executables and obtain release files or checksums through trusted channels. Packages supplied by third parties can be opened as data using a trusted installed application, reducing the need to execute an unfamiliar EXE.

The program does not protect against malware controlling the current user session, keyloggers, administrator/kernel compromise, memory dumps, screen capture, weak passwords, or deliberate sharing of decrypted contents. Managed strings and internal KDF memory cannot receive an absolute erasure guarantee. The application clears key and byte buffers under its control where possible.

## PAR2 recovery and processing order

PAR2 recovery data is generated over already encrypted EXE/data files. It does not access original plaintext and needs no password. Index and recovery volumes repeat locating information, file descriptions, and slice checksums; intact volumes can supply this metadata if the index is missing or damaged.

Normal extraction uses one authenticated streaming pass without an additional full-file prescan. A password that matches no slot fails directly without launching PAR2. When container, data, or archive validation detects damage and recovery records exist, the application verifies and attempts repair on copies of the encrypted input. Successful repair is followed by a new complete authenticated extraction. Staging plaintext from the failed attempt is cleaned up, and a destination is published only after the retry succeeds. Every block is authenticated before decompression.

Users can explicitly request verification before extraction or use the separate verification/repair operation. Independent compression helps contain dependency between blocks; it does not reconstruct missing data. Reconstruction comes from additional PAR2 recovery blocks.

Recovery capacity is measured in affected slices. A 10% setting does not guarantee recovery from every distribution of damage affecting 10% of bytes. Small errors spread across many slices can exhaust the available recovery blocks. Missing or damaged recovery volumes also reduce capacity. Safety preflight excludes an entire volume unless all its packets validate; partially checked files are not passed to the native program.

Before recovery, the wrapper validates packet boundaries and MD5 values, recovery-set IDs, file IDs, filenames, and the protected file set. Only the selected EXE and its data companion, or one data file, are permitted. Traversal, alternate-stream names, reserved names, case aliases, conflicting descriptions, and Unicode filename-override extensions are rejected. Staged copies are validated again in a restricted workspace, and only validated copies may be discovered by the native tool. Repairs happen on copies; reconstructed output must pass independent length and digest checks before commit. Damaged originals are backed up.

PAR2's MD5 is format-defined damage detection, not publisher authentication or cryptographic protection against deliberate replacement. A repaired payload still requires AES-GCM authentication, and the application never automatically executes a reconstructed EXE. Current recovery bounds are two protected input files, 128 recovery files, 32,768 source slices, 64 MiB per slice, and 2 TiB of protected data. These differ from the encrypted-container size limits.

## Verification and remaining review

The test project includes public cryptographic known-answer vectors, independent format decoding, per-file SHA-256 comparisons, malicious/corrupted inputs, and filesystem boundary cases:

```powershell
dotnet run --project tests/TwoPassword.Tests -c Release
```

The report is written to the Git-ignored `artifacts/test-results.json`. Its recorded environment and pass/fail/skip outcomes are the evidence for that particular run.

Public-vector checks validate dependency/API usage and do not constitute NIST CAVP certification. The current version has not undergone an independent external cryptographic or penetration-test audit. Future review should focus on envelope composition, archive boundaries, filesystem races, resource limits, update/signing trust, and failure recovery.

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

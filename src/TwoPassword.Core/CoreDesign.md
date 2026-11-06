# 2Password core — format v2

This document describes the implementation in `TwoPassword.Core`. The application writes and reads **v2**. Earlier in-development v1 fixtures are intentionally unsupported; no released user containers use v1.

## Dependencies and data flow

- Key derivation: `Konscious.Security.Cryptography.Argon2` 1.3.1.
- AES-256-GCM and SHA-256: .NET `System.Security.Cryptography`.
- Archive serialization: .NET `System.Formats.Tar`, PAX format.
- Independent block compression: `ZstdSharp.Port` 0.8.8 (Zstandard 1.5.7 implementation) or .NET Brotli. Default: Zstd.
- Windows paths, streams, timestamps, ACLs: .NET filesystem APIs and documented Windows APIs for volume capabilities, atomic directory creation and stream enumeration.

Creation streams file data into PAX TAR, fills at most a 1 MiB plaintext block, optionally compresses that block, and encrypts it. No plaintext intermediate TAR file is written. A completed **encrypted** temporary payload is used to decide between an embedded EXE and a detached dataset.

Decoding reverses those operations one authenticated block at a time. The normal application path authenticates and extracts first, so intact data requires one read pass. On a damage-related failure, the recovery layer can verify and repair with PAR2, then retry authentication and extraction. An explicit verify-first option is available when a prior full PAR2 check is desired. Invalid password syntax is rejected before recovery work; a password unrecognized by every key slot is reported separately and does not automatically trigger an expensive scan. Incorrect passwords remain indistinguishable from damaged key data, so a user who suspects key-data damage can request an explicit recovery check. The core performs no opportunistic partial extraction: a destination is published only after the complete archive and authenticated terminal block validate.

## Independent passwords

A container has 1–16 distinct, nonempty passwords. Strings are encoded with strict UTF-8 and are never trimmed or normalized. The limit is 1024 UTF-16 code units; invalid surrogate sequences are rejected.

Every creation generates a fresh random 32-byte content key. Each password independently derives a 32-byte key-encryption key using Argon2id with a fresh 16-byte salt and fixed parameters:

- Memory: 65,536 KiB.
- Iterations: 3.
- Parallelism: 4.

Each key slot contains salt (16 bytes), random GCM nonce (12), wrapped content key (32), and authentication tag (16). Slot AAD is the fixed 48-byte logical header followed by the 32-bit little-endian slot index.

The password strings and their derived keys are never stored in the package. Knowing one password reveals the content key and the archive as intended; it does not mathematically derive another password. Other weak passwords can still be guessed offline. The security of access to the content is therefore limited by the weakest authorized password.

## Logical header

All integers below are little-endian unless explicitly specified otherwise.

| Offset | Bytes | Value |
|---:|---:|---|
| 0 | 8 | ASCII `2PWPKG02` |
| 8 | 4 | Version = 2 |
| 12 | 4 | Raw chunk size = 1,048,576 |
| 16 | 1 | Requested codec: 0 = none, 1 = Brotli, 2 = Zstd |
| 17 | 3 | Reserved, zero |
| 20 | 8 | Total source file bytes |
| 28 | 4 | File count |
| 32 | 4 | Directory count |
| 36 | 4 | Random nonce prefix |
| 40 | 4 | Password slot count |
| 44 | 4 | Reserved, zero |
| 48 | 76 × slots | Independent key slots |

File names and PAX metadata are inside encrypted blocks. File/directory counts, total data length, compression selection and password-slot count are public header metadata.

The logical header's SHA-256 is the header identity and is included in every data-block AAD. Untrusted files cannot select arbitrary KDF memory, iteration counts, algorithms or allocation sizes.

## Redundant header storage

The payload starts with three identical 2048-byte records: a fixed 6144-byte region. Each record contains:

| Offset | Bytes | Value |
|---:|---:|---|
| 0 | 8 | ASCII `2PWHDR02` |
| 8 | 4 | Logical header length |
| 12 | 4 | Reserved, zero |
| 16 | 32 | SHA-256 of the logical header |
| 48 | variable | Logical header |
| remainder | variable | Zero padding to 2048 bytes |

The reader needs at least one intact, checksummed record. If multiple checksum-valid records disagree, it rejects the package. A checksum selects an intact replica; it is not a substitute for authentication. The selected logical header must also authenticate against the encrypted content before any plaintext staging begins.

## Independent authenticated blocks

Each block is independently compressed. There is no compression dictionary spanning blocks. If compression would expand a block, that block uses codec 0.

| Field | Bytes | Meaning |
|---|---:|---|
| Raw length | 4 | 1–1,048,576 for data |
| Encoded length | 4 | 1–raw length for data |
| Codec | 1 | 0, or the global selected codec |
| Reserved | 3 | Zero |
| Ciphertext | encoded length | AES-256-GCM encrypted raw/compressed bytes |
| GCM tag | 16 | Authentication tag |

Codec 0 requires equal raw and encoded lengths. A compressed block must be smaller than its raw length. The terminal block has an all-zero 12-byte record header, no ciphertext, and a valid 16-byte tag.

The 12-byte nonce is the header's random 4-byte prefix followed by the 64-bit **big-endian** sequential block index. AAD is:

1. Logical-header SHA-256 (32 bytes).
2. The 64-bit big-endian block index (8 bytes).
3. The complete 12-byte block header.

The 52-byte AAD binds block lengths, codec, reserved bits, ordering and all logical header/key-slot bytes. A mandatory authenticated terminal block and exact payload-end check reject truncation, dropped/reordered/duplicated records and extra records.

### Codec limits

Brotli uses quality 1 and a 1 MiB window for writing. Each decode must finish with exactly the expected output size and consume exactly the authenticated encoded block; extra/truncated compressed data fails.

Zstd uses level 3, a maximum 1 MiB window and a frame checksum. Before decoding, the maintained Zstandard parser verifies a single standard frame, dictionary ID 0, exact declared content length, bounded window, and exact compressed-frame extent. Decode uses a caller-owned fixed-size span, never an allocation requested by a frame's claimed output size.

A small, isolated unsafe wrapper pins these bounded spans to call ZstdSharp's maintained frame-parser methods. It performs no pointer arithmetic or unmanaged allocation.

## Redundant footer

The physical file ends with three 64-byte footer records (192 bytes total):

| Offset | Bytes | Value |
|---:|---:|---|
| 0 | 8 | ASCII `2PWTAIL2` |
| 8 | 8 | Payload start offset |
| 16 | 8 | Payload length, excluding the footer region |
| 24 | 8 | Reserved, zero |
| 32 | 32 | SHA-256 of the preceding 32 bytes |

The common payload end must equal file length minus 192. At least one checksum-valid record must remain; conflicting valid records fail closed. The last authenticated block must end exactly at that payload end. Embedded EXEs use the stub length as the payload offset; raw `.2pw` datasets use offset zero.

Redundancy tolerates damage to up to two header copies and up to two footer copies. It does not reconstruct corrupted ciphertext. PAR2 supplies separate data-repair redundancy.

## Automatic and detached layouts

`CreateOptions.Layout` supports:

- `Auto`: embed the completed payload when stub + payload length is at most 4,294,967,295 bytes; otherwise create a small EXE and a sibling `.2pw` dataset.
- `Embedded`: require a single EXE within that limit.
- `Detached`: always create a small EXE and a sibling `.2pw` dataset.

Detached layouts require a caller-supplied self-contained decoder stub. No-stub `Auto` creation writes a raw container. The GUI uses its own published standalone executable as the stub.

A detached EXE contains only its decoder stub and a reference descriptor. The descriptor is stored as three 2048-byte replicas plus three 64-byte footer records, giving **6336 bytes** of reference overhead. The sibling dataset carries the complete normal v2 envelope at offset zero.

Logical reference descriptor:

| Offset | Bytes | Value |
|---:|---:|---|
| 0 | 8 | ASCII `2PWREF02` |
| 8 | 4 | Filename byte length |
| 12 | 4 | Reserved, zero |
| 16 | 32 | Expected dataset logical-header SHA-256 |
| 48 | variable | Strict UTF-8 sibling filename |

Reference-record magic is `2PWLHDR2`; reference-footer magic is `2PWLINK2`. Other record/checksum layouts are identical to those above. A reference footer points to the 6144-byte descriptor region.

The filename must be a single valid Windows filename ending in `.2pw`, at most 255 UTF-16 code units and 1024 UTF-8 bytes. Absolute paths, separators, traversal, device names, ADS syntax, invalid Unicode and reparse-point parents are rejected. The reader checks the expected header hash before attempting password derivation. References cannot chain recursively. A dataset can also be opened directly without its launcher.

Creation publishes a completed dataset first and its launcher last, with no overwrites. A failure removes only temporary/newly published files owned by that operation. A crash between the two renames can leave an orphaned encrypted dataset.

## Filesystem and archive invariants

PAX names use strict UTF-8. No NFC, NFD, NFKC, case or other normalization is applied. File contents remain opaque bytes, including files containing GBK, Shift-JIS or invalid text encodings.

The source root itself is an archive entry. Empty files/directories, hidden and system files, exact names, full contents, creation/write timestamps and supported basic Windows attributes are retained. `Zone.Identifier` is preserved as raw bytes, up to 64 KiB per entry. Other alternate streams, reparse points, junctions, symbolic links, EFS, device and offline entries are rejected explicitly instead of being silently lost.

PAX fields used by the application:

| Field | Encoding |
|---|---|
| `2Password.creationTicks` | Invariant decimal UTC `DateTime.Ticks` |
| `2Password.writeTicks` | Invariant decimal UTC `DateTime.Ticks` |
| `2Password.attributes` | Decimal allowed bitmask: ReadOnly, Hidden, System, Archive, NotContentIndexed |
| `2Password.zoneIdentifier` | Optional base64 of exact raw ADS bytes |

The framing guard limits each PAX metadata record to 256 KiB and 64 unique fields before the BCL archive reader can allocate from untrusted lengths. Only standard PAX regular-file/directory entries are accepted. The guard enforces the authenticated file-byte budget and exactly two TAR zero terminator blocks.

Source scanning includes all entries and fails on inaccessible entries. Files are opened with `FileShare.Read`, which excludes concurrent writes and deletes while being copied. A before/after inventory check detects changed names, sizes, timestamps, attributes and Zone.Identifier contents. There is no VSS snapshot, so a same-user process racing these checks can still produce an inconsistent multi-file archive.

Extraction rejects traversal, absolute paths, invalid/device names, duplicate paths, case-insensitive collisions, missing parents, unsupported types, oversized metadata and inconsistent authenticated totals. It creates only new files beneath a private random staging directory in the destination's parent, authenticates the whole stream, restores metadata, then performs a no-overwrite directory rename.

Before creating staging, the shared `WindowsPrivateDirectory` helper opens the existing parent and requires its actual volume to report `FILE_PERSISTENT_ACLS`. An unavailable capability query or a volume without persistent ACLs fails before any plaintext files are written. Native `CreateDirectoryW` supplies the protected DACL atomically and rejects an existing path. The helper reads back the raw security descriptor and requires the current user as owner, a protected present DACL, and exactly the distinct current-user/SYSTEM Allow FullControl ACEs with object/container inheritance and no additional ACEs. A validation failure attempts to remove only the newly created empty directory, never an unexpected tree. PAR2 workspaces use the same helper.

Local NTFS is the validated destination. FAT32 and exFAT cannot be extraction or recovery workspace destinations because they lack persistent ACLs. A network filesystem is accepted only if its provider can report the required capability and preserve the exact verified DACL. Source stream enumeration treats EOF normally, but errors 1/50/87 are considered absence of stream support only after a successful volume query confirms that `FILE_NAMED_STREAMS` is absent. A query failure or a provider claiming streams but refusing enumeration fails explicitly. These checks use the documented [volume capability flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew).

The staging/final directory retains that private ACL. Original ACLs, owners, EFS identity, hard-link relationships, NTFS compression/sparsity and non-Zone ADS are not reproduced. Sparse input bytes are retained exactly, but restored files may occupy their full logical size.

## Resource and operational boundaries

- Per-block raw/decompressed data: at most 1 MiB.
- Aggregate uncompressed primary file-content bytes: at most 16 TiB; this is not a ciphertext-output size limit.
- Entry count: at most 1,000,000, subject to the metadata budget below.
- Windows full/relative paths: fewer than 32,700 UTF-16 code units; components at most 255.
- Conservative retained metadata budget: 128 MiB per source inventory (before/after may coexist), and 256 MiB for extraction. Pending directory enumeration is charged before being retained. Exceeding the budget fails explicitly.
- Self-contained EXE maximum: 4,294,967,295 bytes. Large encrypted data uses detached layout.
- Encoding, encryption, decoding, copying and hashing are streamed. Temporary payloads are encrypted. Embedded assembly requires a second encrypted copy temporarily.
- Destination files/directories are never overwritten.
- Normal failure/cancellation cleans temporary output with ordinary deletion. Forced process termination or power loss can leave a private staging directory or encrypted temporary file.
- A compromised same-user process, malicious EXE stub, keylogger, memory dump or replaced executable is outside the data-encryption threat model. AEAD authenticates the encrypted dataset only; trust in the executable stub comes from signing and distribution.

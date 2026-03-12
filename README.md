# PsiRepacker

Repacking NT hash files from Troy Hunt's [Pwned Passwords](https://haveibeenpwned.com/Passwords) to compact binary format for the [Get-Badpasswords](https://github.com/yourlink) solution.

## Versions

### PyPsiRepacker (Python — recommended)

A streaming Python implementation that converts NTLM hash text files to binary with **near-zero memory usage**. Unlike the C++ version, it does not load all entries into RAM — it processes line-by-line, relying on the input already being sorted (as produced by [PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)).

**Requirements:** Python 3.6+ (no external dependencies)

**RAM usage:** ~0 (streams line by line)

```
python -m pypsirepacker <input filepath> <output filepath>
```

For example:

```
python -m pypsirepacker "C:\pwned-passwords-ntlm.txt" "C:\pwned-passwords-ntlm.bin"
```

Options:

| Flag | Description |
|------|-------------|
| `--no-verify` | Skip sort-order verification (not recommended) |

Sort-order verification is enabled by default. If a hash is found out of order, conversion aborts immediately — this means the input was not pre-sorted and a streaming approach cannot produce a valid binary file.

### PsiRepacker (C++ — original)

The original C++ implementation loads all hashes into memory, sorts them, and writes the binary output. This requires **~50 GB RAM** for a full Pwned Passwords NTLM file (~1.7 billion entries) and is Windows-only.

```
PsiRepacker <input filepath> <output filepath>
```

Use this version if your input file is **not pre-sorted** and you have sufficient RAM.

## Binary output format

The output `.bin` file has the following structure:

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 8 bytes | Entry count (uint64, little-endian) |
| 8 | 16 bytes each | NTLM hashes packed as raw binary, sorted |

Each 32-character hex NTLM hash (e.g. `A4F49C406510BDCAB6824EE7C30FD852`) is stored as 16 raw bytes — halving the size of the text representation and enabling fast binary search.

## Workflow

1. Download NTLM hashes using [PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader) with the `-n` (NTLM) flag
2. Run PsiRepacker (Python or C++) to convert to binary
3. Use the `.bin` file with Get-Badpasswords to audit Active Directory passwords

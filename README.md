# PsiRepacker

Repacking NT hash files from Troy Hunt's [Pwned Passwords](https://haveibeenpwned.com/Passwords) to compact binary format for the [Get-Badpasswords](https://github.com/yourlink) solution.

## Versions

### PyPsiRepacker (Python — recommended)

A streaming Python implementation that converts NTLM hash text files to binary with **near-zero memory usage**. Unlike the C++ version, it does not load all entries into RAM — it processes line-by-line, relying on the input already being sorted (as produced by [PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)).

**Requirements:** Python 3.6+ (no external dependencies)

**RAM usage:** ~0 (streams line by line)

#### Prerequisites (Windows)

1. **Install Python 3.6 or later** — download from [python.org](https://www.python.org/downloads/)
   - During installation, check **"Add Python to PATH"**
2. **Verify** by opening Command Prompt or PowerShell:
   ```
   python --version
   ```
3. **Clone or download** this repository:
   ```
   git clone https://github.com/improsec/PsiRepacker.git
   cd PsiRepacker
   ```

#### Usage

Run from the repository root:

```
python -m pypsirepacker <input filepath> <output filepath>
```

**Windows example (Command Prompt or PowerShell):**

```
python -m pypsirepacker "D:\output\hashes\pwnedpasswords_ntlm.txt" "D:\output\bin\pwnedpasswords_ntlm.bin"
```

**Linux / macOS example:**

```
python3 -m pypsirepacker /data/pwnedpasswords_ntlm.txt /data/pwnedpasswords_ntlm.bin
```

#### Options

| Flag | Description |
|------|-------------|
| `--no-verify` | Skip sort-order verification (not recommended) |

Sort-order verification is enabled by default. If a hash is found out of order, conversion aborts immediately — this means the input was not pre-sorted and a streaming approach cannot produce a valid binary file.

#### Example run (Pwned Passwords v10, ~2 billion NTLM hashes)

| | File | Size |
|---|---|---|
| **Input** | `pwnedpasswords_ntlm.txt` | ~70 GB |
| **Output** | `pwnedpasswords_ntlm.bin` | ~30.6 GB |

```
Counting entries in pwnedpasswords_ntlm.txt...
Found 2,052,742,897 entries.
Converting to binary: pwnedpasswords_ntlm.bin
   1,800,000,000 / 2,052,742,897 (87.7%)
   1,850,000,000 / 2,052,742,897 (90.1%)
   1,900,000,000 / 2,052,742,897 (92.6%)
   1,950,000,000 / 2,052,742,897 (95.0%)
   2,000,000,000 / 2,052,742,897 (97.4%)
   2,050,000,000 / 2,052,742,897 (99.9%)
Done. Wrote 2,052,742,897 entries (32,843,886,352 bytes + 8 byte header).
Completed in 870.2 seconds.
```

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

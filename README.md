# ZIP Divider (Rust)

Split a ZIP into **standalone ZIP archives**, each strictly smaller than a chosen limit. Each part contains whole files at their original relative paths and can be extracted independently. Merge the complete set back into one ZIP when needed.

## Build

Install a current stable Rust toolchain, then run:

```powershell
cargo build --release --locked
```

On Windows the executable is `target\release\zip-divider.exe`. On Linux/macOS it is `target/release/zip-divider`.

## Split a ZIP with a 1.9 GB limit

```powershell
.\target\release\zip-divider.exe split "D:\data\original.zip" --output "D:\data\parts" --max-size 1.9GB
```

`parts` must not already exist; its parent directory must exist. The result is:

```text
parts/
  manifest.json
  part-00001.zip
  part-00002.zip
  ...
```

`1.9GB` means **1,900,000,000 bytes**; every ZIP will be **strictly less** than that. `GiB` uses powers of 1024. Other units: `B`, `KB`, `MB`, `TB`, `KiB`, `MiB`, `TiB`; bare numbers mean bytes. ZIP headers and encryption overhead count toward the limit. A small conservative header allowance can leave some unused space in each part. Files are packed in input order; this does not try to minimize the number of parts.

For a 6 GB input, the number of parts depends on the sizes of its individual files and their compression. It will not necessarily be exactly four parts.

## Password protection

Add `--password` to prompt for a hidden password and encrypt file contents with AES-256:

```powershell
.\target\release\zip-divider.exe split "D:\data\original.zip" -o "D:\data\parts" -m 1.9GB --password
```

For an already password-protected input, add `--input-password` (the input and output passwords may differ):

```powershell
.\target\release\zip-divider.exe split "D:\data\original.zip" -o "D:\data\parts" -m 1.9GB --input-password --password
```

For unattended use, supply `ZIP_DIVIDER_PASSWORD` and/or `ZIP_DIVIDER_INPUT_PASSWORD` as environment variables instead of the prompt flags. Do not combine an environment variable with its corresponding prompt flag. Output is unencrypted unless an output password is supplied, even when the input is encrypted. Passwords are never stored in the manifest.

Use an extractor that supports WinZip AES, such as 7-Zip, for encrypted parts. ZIP encryption protects file contents; **file and folder names and the manifest remain visible**. Directory entries themselves are not encrypted.

## Extract independently

Open any `part-xxxxx.zip` in your ZIP extractor. All files inside it are complete and usable without the other parts. Extract all parts into the same directory to restore the whole folder tree. Explicit empty directories are retained. Keep all ZIP parts together with `manifest.json` if you want to use the merge command.

## Merge

```powershell
.\target\release\zip-divider.exe merge "D:\data\parts" --output "D:\data\restored.zip"
```

For password-protected parts:

```powershell
.\target\release\zip-divider.exe merge "D:\data\parts" -o "D:\data\restored.zip" --password
```

Merge checks each part's expected size, SHA-256 hash, entry count, and file data integrity, including password authentication, before publishing the merged archive. It preserves the parts' compression and encryption without recompressing. Missing or changed parts fail the operation. The manifest checks accidental damage; it is not a signed proof of authenticity.

## Important limits and behavior

- **One file must fit in one part.** If a file's standalone ZIP size is greater than or equal to the limit, splitting fails with its name and required size. Increase the limit in that case. Dividing that file into chunks would require joining it before use, which conflicts with independent extraction.
- Regular file contents, relative paths, explicit empty directories, basic ZIP timestamps, and permission bits are retained. Symlinks/special files, unsafe paths, Windows reserved names, duplicate names, case-colliding names, and file/directory conflicts are rejected.
- Split decompresses and recompresses entries using Deflate, verifying input integrity as it reads. It does not reproduce the source ZIP byte for byte. ZIP comments and arbitrary extra metadata are not retained.
- File data is streamed. Memory use includes compression buffers and ZIP directory metadata, rather than entire file contents. Temporary disk space is needed for the output set plus one staged compressed entry. Merge needs disk space for its complete output.
- Work is staged next to the output and published on success. Normal errors clean up temporary output. Existing destinations are refused. A forced process termination can leave a temporary staging directory or file.
- ZIP64 is supported for large archives. This is a collection of ordinary ZIPs, not a `.z01`/multi-volume archive.

## Verification

```powershell
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

Tests cover independent extraction and merging with/without AES, nested Unicode paths and empty folders, strict size boundaries, oversized files, corrupt input, missing/tampered parts, wrong passwords, and overwrite refusal.

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use zip::{AesMode, CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

#[derive(Parser)]
#[command(
    version,
    about = "Create complete, independently extractable ZIP parts with a strict size limit"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Recompress whole entries into ZIP parts. Output directory must not exist.
    Split {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Strict upper limit; decimal GB/MB or binary GiB/MiB, e.g. 1.9GB
        #[arg(short, long, value_parser = parse_size)]
        max_size: u64,
        /// Prompt for an AES-256 output password
        #[arg(long)]
        password: bool,
        /// Alternative to prompting (avoid putting secrets in command-line arguments)
        #[arg(
            long,
            env = "ZIP_DIVIDER_PASSWORD",
            hide_env_values = true,
            conflicts_with = "password"
        )]
        password_env: Option<String>,
        /// Prompt for the input ZIP's password
        #[arg(long)]
        input_password: bool,
        #[arg(
            long,
            env = "ZIP_DIVIDER_INPUT_PASSWORD",
            hide_env_values = true,
            conflicts_with = "input_password"
        )]
        input_password_env: Option<String>,
    },
    /// Verify the manifest and combine parts into one ZIP, preserving encryption
    Merge {
        /// Directory containing manifest.json and its ZIP parts
        parts: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Prompt for the parts' password to verify every entry
        #[arg(long)]
        password: bool,
        #[arg(
            long,
            env = "ZIP_DIVIDER_PASSWORD",
            hide_env_values = true,
            conflicts_with = "password"
        )]
        password_env: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    max_bytes: u64,
    entries: usize,
    encrypted: bool,
    parts: Vec<Part>,
}

#[derive(Serialize, Deserialize)]
struct Part {
    file: String,
    bytes: u64,
    sha256: String,
    entries: usize,
}

fn parse_size(input: &str) -> std::result::Result<u64, String> {
    let s = input.trim().to_ascii_uppercase();
    let end = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let number = &s[..end];
    let unit = s[end..].trim();
    let factor: u128 = match unit {
        "" | "B" => 1,
        "KB" => 1000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        "TB" => 1_000_000_000_000,
        "KIB" => 1024,
        "MIB" => 1 << 20,
        "GIB" => 1 << 30,
        "TIB" => 1 << 40,
        _ => return Err("use B, KB, MB, GB, TB, KiB, MiB, GiB, or TiB".into()),
    };
    let fields: Vec<_> = number.split('.').collect();
    if fields.len() > 2 || fields[0].is_empty() || fields.iter().any(|s| s.is_empty()) {
        return Err("invalid size".into());
    }
    let whole: u128 = fields[0].parse().map_err(|_| "invalid size")?;
    let mut bytes = whole.checked_mul(factor).ok_or("size too large")?;
    if fields.len() == 2 {
        let scale = 10u128
            .checked_pow(fields[1].len().try_into().map_err(|_| "size too precise")?)
            .ok_or("size too precise")?;
        let fraction: u128 = fields[1].parse().map_err(|_| "invalid size")?;
        bytes = bytes
            .checked_add(fraction.checked_mul(factor).ok_or("size too large")? / scale)
            .ok_or("size too large")?;
    }
    let bytes = u64::try_from(bytes).map_err(|_| "size too large")?;
    if bytes <= 22 {
        return Err("limit must exceed the 22-byte empty ZIP header".into());
    }
    Ok(bytes)
}

fn password(prompt: bool, supplied: Option<String>, label: &str) -> Result<Option<String>> {
    let value = if prompt {
        Some(rpassword::prompt_password(label)?)
    } else {
        supplied
    };
    ensure!(
        value.as_ref().is_none_or(|s| !s.is_empty()),
        "Password must not be empty"
    );
    Ok(value)
}

// Reject names that would escape or collide when extracted on Windows or Unix.
#[derive(Default)]
struct Names {
    entries: HashSet<String>,
    files: HashSet<String>,
    directories: HashSet<String>,
}

fn validate_name(name: &str, names: &mut Names) -> Result<()> {
    ensure!(
        !name.is_empty() && !name.starts_with('/'),
        "Unsafe ZIP path: {name:?}"
    );
    ensure!(
        !name.contains(['\\', ':', '\0']),
        "Unsafe ZIP path: {name:?}"
    );
    let path = name.trim_end_matches('/');
    ensure!(!path.is_empty(), "Empty ZIP path");
    for component in path.split('/') {
        ensure!(
            !component.is_empty() && component != "." && component != "..",
            "Unsafe ZIP path: {name:?}"
        );
        ensure!(
            !component.ends_with([' ', '.']),
            "Unsafe ZIP path: {name:?}"
        );
        ensure!(
            !component
                .chars()
                .any(|c| c.is_control() || "<>\"|?*".contains(c)),
            "Unsafe ZIP path: {name:?}"
        );
        let stem = component.split('.').next().unwrap().to_ascii_uppercase();
        ensure!(
            !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9')),
            "Reserved ZIP path: {name:?}"
        );
    }
    let key = path.to_lowercase();
    ensure!(
        names.entries.insert(key.clone()),
        "Duplicate/case-colliding ZIP path: {name:?}"
    );
    if name.ends_with('/') {
        ensure!(
            !names.files.contains(&key),
            "File/directory conflict: {name:?}"
        );
        names.directories.insert(key.clone());
    } else {
        ensure!(
            !names.directories.contains(&key),
            "File/directory conflict: {name:?}"
        );
        names.files.insert(key.clone());
    }
    for (index, _) in key.match_indices('/') {
        let ancestor = &key[..index];
        ensure!(
            !names.files.contains(ancestor),
            "File used as parent directory: {name:?}"
        );
        names.directories.insert(ancestor.to_owned());
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 128 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn finish_part(
    writer: ZipWriter<File>,
    dir: &Path,
    manifest: &mut Manifest,
    entries: usize,
) -> Result<()> {
    let file = writer.finish()?;
    file.sync_all()?;
    let bytes = file.metadata()?.len();
    ensure!(
        bytes < manifest.max_bytes,
        "ZIP overhead exceeded the limit; no output published"
    );
    drop(file);
    let name = format!("part-{:05}.zip", manifest.parts.len() + 1);
    let path = dir.join(&name);
    manifest.parts.push(Part {
        file: name,
        bytes,
        sha256: hash_file(&path)?,
        entries,
    });
    Ok(())
}

fn split(
    input: &Path,
    output: &Path,
    max_bytes: u64,
    output_password: Option<&str>,
    input_password: Option<&str>,
) -> Result<()> {
    ensure!(
        !output.exists(),
        "Output directory already exists: {}",
        output.display()
    );
    let mut source = ZipArchive::new(File::open(input).context("Cannot open input ZIP")?)?;
    // All work is staged next to the destination. An error leaves no partial output set.
    let staging = tempfile::tempdir_in(parent(output))?;
    let dir = staging.path();
    let mut manifest = Manifest {
        version: 1,
        max_bytes,
        entries: source.len(),
        encrypted: output_password.is_some(),
        parts: vec![],
    };
    let mut names = Names::default();
    let mut writer: Option<ZipWriter<File>> = None;
    let mut budget = 128u64; // End records, including possible ZIP64 end records.
    let mut count = 0;
    for index in 0..source.len() {
        let mut entry = match input_password {
            Some(p) => source.by_index_decrypt(index, p.as_bytes())?,
            None => source.by_index(index)?,
        };
        let name = entry.name().to_owned();
        validate_name(&name, &mut names)?;
        ensure!(
            entry
                .unix_mode()
                .is_none_or(|m| m & 0o170000 == 0 || matches!(m & 0o170000, 0o040000 | 0o100000)),
            "Special file/symlink unsupported: {name}"
        );
        let mut options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .large_file(entry.size() >= u32::MAX as u64);
        if let Some(time) = entry.last_modified() {
            options = options.last_modified_time(time);
        }
        if let Some(mode) = entry.unix_mode() {
            options = options.unix_permissions(mode);
        }
        let mut spool = tempfile::tempfile_in(dir)?;
        {
            let mut single = ZipWriter::new(&mut spool);
            if entry.is_dir() {
                ensure!(entry.size() == 0, "Directory has unexpected data: {name}");
                single.add_directory(&name, options)?;
            } else {
                if let Some(p) = output_password {
                    options = options.with_aes_encryption(AesMode::Aes256, p);
                }
                single.start_file(&name, options)?;
                let copied = io::copy(&mut entry, &mut single).with_context(|| {
                    format!("Reading {name}; input may be corrupt or password incorrect")
                })?;
                ensure!(
                    copied == entry.size(),
                    "Incorrect uncompressed length: {name}"
                );
            }
            single.finish()?;
        }
        let size = spool.metadata()?.len();
        ensure!(
            size < max_bytes,
            "Entry {name:?} needs {size} bytes as a complete ZIP, but limit is {max_bytes}. A whole file cannot be divided while remaining independently extractable."
        );
        // Sum complete single-entry ZIP sizes, plus 64 bytes per entry, is a
        // conservative bound for merged headers/ZIP64 offsets. Check actual size too.
        let cost = size.checked_add(64).context("Size overflow")?;
        if writer.is_some() && budget.checked_add(cost).is_none_or(|n| n >= max_bytes) {
            finish_part(writer.take().unwrap(), dir, &mut manifest, count)?;
            budget = 128;
            count = 0;
        }
        if writer.is_none() {
            let path = dir.join(format!("part-{:05}.zip", manifest.parts.len() + 1));
            writer = Some(ZipWriter::new(File::create(path)?));
        }
        spool.seek(SeekFrom::Start(0))?;
        let staged = ZipArchive::new(spool)?;
        writer.as_mut().unwrap().merge_archive(staged)?;
        budget = budget.checked_add(cost).context("Size overflow")?;
        count += 1;
        eprintln!("Packed {}/{}: {}", index + 1, manifest.entries, name);
    }
    if let Some(w) = writer {
        finish_part(w, dir, &mut manifest, count)?;
    } else {
        finish_part(
            ZipWriter::new(File::create(dir.join("part-00001.zip"))?),
            dir,
            &mut manifest,
            0,
        )?;
    }
    let mut json = File::create(dir.join("manifest.json"))?;
    serde_json::to_writer_pretty(&mut json, &manifest)?;
    json.sync_all()?;
    drop(json);
    // Destination must still be absent; never replace an existing result.
    ensure!(
        !output.exists(),
        "Output directory appeared during processing"
    );
    fs::rename(dir, output).context("Cannot publish output directory")?;
    println!(
        "Created {} ZIP parts in {}",
        manifest.parts.len(),
        output.display()
    );
    Ok(())
}

fn merge(parts: &Path, output: &Path, password: Option<&str>) -> Result<()> {
    ensure!(
        !output.exists(),
        "Output already exists: {}",
        output.display()
    );
    let manifest: Manifest = serde_json::from_reader(File::open(parts.join("manifest.json"))?)?;
    ensure!(
        manifest.version == 1 && !manifest.parts.is_empty(),
        "Unsupported or empty manifest"
    );
    ensure!(
        !manifest.encrypted || password.is_some(),
        "Encrypted parts require --password or ZIP_DIVIDER_PASSWORD"
    );
    let mut temporary = NamedTempFile::new_in(parent(output))?;
    let mut writer = ZipWriter::new(temporary.as_file_mut());
    let mut names = Names::default();
    let mut total = 0usize;
    for (index, part) in manifest.parts.iter().enumerate() {
        ensure!(
            part.file == format!("part-{:05}.zip", index + 1),
            "Invalid part filename/order"
        );
        let path = parts.join(&part.file);
        ensure!(
            fs::metadata(&path)?.len() == part.bytes && part.bytes < manifest.max_bytes,
            "Part size mismatch: {}",
            part.file
        );
        ensure!(
            hash_file(&path)? == part.sha256,
            "Part checksum mismatch: {}",
            part.file
        );
        let mut archive = ZipArchive::new(File::open(&path)?)?;
        ensure!(
            archive.len() == part.entries,
            "Entry count mismatch: {}",
            part.file
        );
        for i in 0..archive.len() {
            let mut entry = match password {
                Some(p) => archive.by_index_decrypt(i, p.as_bytes())?,
                None => archive.by_index(i)?,
            };
            validate_name(entry.name(), &mut names)?;
            let size = io::copy(&mut entry, &mut io::sink())
                .context("Part entry failed integrity/password verification")?;
            ensure!(size == entry.size(), "Entry length mismatch");
        }
        total = total
            .checked_add(archive.len())
            .context("Entry count overflow")?;
        writer.merge_archive(archive)?;
        eprintln!("Verified and merged {}", part.file);
    }
    ensure!(
        total == manifest.entries,
        "Manifest total entry count mismatch"
    );
    writer.finish()?.sync_all()?;
    temporary
        .persist_noclobber(output)
        .context("Cannot publish merged ZIP")?;
    println!("Merged {total} entries into {}", output.display());
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Split {
            input,
            output,
            max_size,
            password: ask,
            password_env,
            input_password,
            input_password_env,
        } => {
            let p = password(ask, password_env, "Output ZIP password: ")?;
            let ip = password(input_password, input_password_env, "Input ZIP password: ")?;
            split(&input, &output, max_size, p.as_deref(), ip.as_deref())
        }
        Command::Merge {
            parts,
            output,
            password: ask,
            password_env,
        } => {
            let p = password(ask, password_env, "Parts password: ")?;
            merge(&parts, &output, p.as_deref())
        }
    }
}

#[cfg(test)]
mod tests;

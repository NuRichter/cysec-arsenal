//! fcarve — File Signature Carver
//! NuRichter · CySec Arsenal
//!
//! Carves embedded files from binary blobs, disk images, memory dumps,
//! or stego containers. Standard CTF forensics workflow.
//!
//! Usage:
//!   fcarve -f challenge.jpg --out extracted/
//!   fcarve -f memory.bin --out carved/ --min-size 512
//!   fcarve -f data.bin --list-sigs

use std::path::PathBuf;
use anyhow::{Context, Result};
use arsenal_core::{banner::{print_banner, Module}, found, info, ok, warn};
use clap::Parser;
use colored::Colorize;

#[derive(Debug, Clone)]
struct Sig {
    name:     &'static str,
    ext:      &'static str,
    header:   &'static [u8],
    footer:   Option<&'static [u8]>,
    max_size: usize,
}

macro_rules! sig {
    ($name:expr, $ext:expr, $header:expr, $footer:expr, $max:expr) => {
        Sig { name: $name, ext: $ext, header: $header, footer: $footer, max_size: $max }
    };
}

const MB: usize = 1024 * 1024;

static SIGNATURES: &[Sig] = &[
    sig!("JPEG",    "jpg",  b"\xff\xd8\xff",       Some(b"\xff\xd9"),                   50 * MB),
    sig!("PNG",     "png",  b"\x89PNG\r\n\x1a\n",  Some(b"IEND\xaeB`\x82"),            50 * MB),
    sig!("GIF87",   "gif",  b"GIF87a",              Some(b"\x00;"),                      10 * MB),
    sig!("GIF89",   "gif",  b"GIF89a",              Some(b"\x00;"),                      10 * MB),
    sig!("PDF",     "pdf",  b"%PDF",                Some(b"%%EOF"),                     200 * MB),
    sig!("ZIP",     "zip",  b"PK\x03\x04",          Some(b"PK\x05\x06"),                200 * MB),
    sig!("GZIP",    "gz",   b"\x1f\x8b\x08",        None,                               500 * MB),
    sig!("BMP",     "bmp",  b"BM",                  None,                                50 * MB),
    sig!("ELF",     "elf",  b"\x7fELF",             None,                               100 * MB),
    sig!("PE",      "exe",  b"MZ",                  None,                               100 * MB),
    sig!("MP3",     "mp3",  b"ID3",                 None,                               100 * MB),
    sig!("7ZIP",    "7z",   b"7z\xbc\xaf'\x1c",     None,                               500 * MB),
    sig!("RAR4",    "rar",  b"Rar!\x1a\x07\x00",    None,                               500 * MB),
    sig!("RAR5",    "rar",  b"Rar!\x1a\x07\x01",    None,                               500 * MB),
    sig!("SQLITE",  "db",   b"SQLite format 3\x00", None,                               100 * MB),
    sig!("CLASS",   "class",b"\xca\xfe\xba\xbe",    None,                                10 * MB),
    sig!("MACH-O",  "macho",b"\xcf\xfa\xed\xfe",    None,                               100 * MB),
    sig!("PCAP",    "pcap", b"\xd4\xc3\xb2\xa1",    None,                               500 * MB),
    sig!("OGG",     "ogg",  b"OggS",                None,                               100 * MB),
    sig!("WAV",     "wav",  b"RIFF",                None,                                50 * MB),
];

#[derive(Parser)]
#[command(name = "fcarve", about = "🔬 File Carver — CySec Arsenal")]
struct Args {
    /// Input file to carve
    #[arg(short, long)]
    file: Option<PathBuf>,

    /// Output directory
    #[arg(long, default_value = "carved_output")]
    out: PathBuf,

    /// Minimum carved file size (bytes)
    #[arg(long, default_value_t = 128)]
    min_size: usize,

    /// List available signatures and exit
    #[arg(long)]
    list_sigs: bool,

    /// Output results as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Debug, serde::Serialize)]
struct CarveResult {
    sig:    String,
    offset: usize,
    size:   usize,
    path:   String,
}

fn find_all(data: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut start = 0;
    while start + needle.len() <= data.len() {
        if let Some(pos) = data[start..].windows(needle.len()).position(|w| w == needle) {
            positions.push(start + pos);
            start += pos + 1;
        } else {
            break;
        }
    }
    positions
}

fn carve(data: &[u8], sig: &Sig, min_size: usize) -> Vec<(usize, Vec<u8>)> {
    let mut results = Vec::new();
    for &offset in &find_all(data, sig.header) {
        let end = if let Some(footer) = sig.footer {
            find_all(&data[offset..], footer)
                .first()
                .map(|&rel| offset + rel + footer.len())
                .unwrap_or(0)
        } else {
            (offset + sig.max_size).min(data.len())
        };

        if end <= offset { continue; }
        let chunk = &data[offset..end];
        if chunk.len() >= min_size {
            results.push((offset, chunk.to_vec()));
        }
    }
    results
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_sigs {
        println!("\n  {:<10} {:<8} {}", "Name".bright_cyan(), "Ext".bright_cyan(), "Header".bright_cyan());
        println!("  {}", "─".repeat(45));
        for s in SIGNATURES {
            println!("  {:<10} {:<8} {}", s.name, s.ext, hex::encode(s.header));
        }
        return Ok(());
    }

    let src = args.file.context("Specify --file")?;
    if !args.json { print_banner(Module::FileCarver); }

    let data = std::fs::read(&src).context("reading input file")?;
    if !args.json {
        println!("  {}", info(&format!("Input  : {} ({} bytes)", src.display(), data.len())));
        println!("  {}", info(&format!("Output : {}/", args.out.display())));
        println!();
    }

    std::fs::create_dir_all(&args.out)?;

    let mut all_results: Vec<CarveResult> = Vec::new();
    let mut sig_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

    for sig in SIGNATURES {
        let chunks = carve(&data, sig, args.min_size);
        if chunks.is_empty() { continue; }

        for (offset, chunk) in chunks {
            let count = sig_counts.entry(sig.name).or_insert(0);
            *count += 1;
            let filename = format!("{}_0x{:08x}_{}.{}", sig.name, offset, count, sig.ext);
            let out_path = args.out.join(&filename);
            std::fs::write(&out_path, &chunk)?;

            if !args.json {
                println!(
                    "  {} [{:<7}] offset=0x{:08x}  size={:<10}  → {}",
                    "[>]".bright_magenta().bold(),
                    sig.name.bright_cyan(),
                    offset,
                    format!("{}B", chunk.len()).bright_yellow(),
                    filename.bright_white()
                );
            }
            all_results.push(CarveResult {
                sig:    sig.name.to_string(),
                offset,
                size:   chunk.len(),
                path:   out_path.to_string_lossy().to_string(),
            });
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&all_results)?);
    } else {
        println!();
        println!("  {}", ok(&format!("{} file(s) carved → {}/", all_results.len(), args.out.display())));
        for (sig, cnt) in &sig_counts {
            println!("    {:<10} : {}", sig.bright_cyan(), cnt);
        }
    }
    Ok(())
}

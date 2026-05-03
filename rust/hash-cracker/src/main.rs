//! hcrack — Hash Identifier & Dictionary Cracker
//! NuRichter · CySec Arsenal
//!
//! Identifies hash type by length/pattern, then attempts
//! parallel dictionary attack using rayon.
//!
//! Usage:
//!   hcrack -H "5f4dcc3b5aa765d61d8327deb882cf99"
//!   hcrack -H "..." -w /usr/share/wordlists/rockyou.txt
//!   hcrack --file hashes.txt -w wordlist.txt
//!   hcrack -H "..." --identify-only

use std::path::PathBuf;

use anyhow::{Context, Result};
use arsenal_core::{
    banner::{print_banner, Module},
    found, info, ok, warn,
};
use clap::Parser;
use colored::Colorize;
use md5::Md5;
use rayon::prelude::*;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

use md5::Digest as _;

fn md5_hex(data: &[u8])     -> String { hex::encode(Md5::digest(data)) }
fn sha1_hex(data: &[u8])    -> String { hex::encode(Sha1::digest(data)) }
fn sha256_hex(data: &[u8])  -> String { hex::encode(Sha256::digest(data)) }
fn sha512_hex(data: &[u8])  -> String { hex::encode(Sha512::digest(data)) }
fn sha3_256_hex(data: &[u8])-> String { hex::encode(Sha3_256::digest(data)) }
fn sha3_512_hex(data: &[u8])-> String { hex::encode(Sha3_512::digest(data)) }

type HashFn = fn(&[u8]) -> String;

static ALGORITHMS: &[(&str, HashFn)] = &[
    ("md5",      md5_hex),
    ("sha1",     sha1_hex),
    ("sha256",   sha256_hex),
    ("sha512",   sha512_hex),
    ("sha3-256", sha3_256_hex),
    ("sha3-512", sha3_512_hex),
];

// ─── Hash type identification ─────────────────────────────────────────────────

fn identify(hash: &str) -> Vec<&'static str> {
    let h = hash.trim().to_lowercase();
    let len = h.len();
    let all_hex = h.chars().all(|c| c.is_ascii_hexdigit());

    let mut candidates = Vec::new();

    if all_hex {
        match len {
            8   => candidates.extend_from_slice(&["CRC32", "Adler32"]),
            16  => candidates.extend_from_slice(&["MySQL323", "MD4-half"]),
            32  => candidates.extend_from_slice(&["MD5", "NTLM", "MD4"]),
            40  => candidates.extend_from_slice(&["SHA-1", "RIPEMD-160"]),
            56  => candidates.push("SHA-224"),
            64  => candidates.extend_from_slice(&["SHA-256", "SHA3-256", "BLAKE2s"]),
            96  => candidates.push("SHA-384"),
            128 => candidates.extend_from_slice(&["SHA-512", "SHA3-512", "Whirlpool", "BLAKE2b"]),
            _   => {}
        }
    }

    if h.starts_with("$2a$") || h.starts_with("$2b$") || h.starts_with("$2y$") {
        candidates.push("bcrypt");
    }
    if h.starts_with("$1$") { candidates.push("MD5-Unix"); }
    if h.starts_with("$5$") { candidates.push("SHA-256-Unix"); }
    if h.starts_with("$6$") { candidates.push("SHA-512-Unix"); }

    if candidates.is_empty() {
        candidates.push("Unknown");
    }
    candidates
}

// ─── Dictionary crack ─────────────────────────────────────────────────────────

fn crack(target_hash: &str, wordlist_path: &PathBuf) -> Option<String> {
    let target = target_hash.trim().to_lowercase();
    let raw = std::fs::read(wordlist_path).ok()?;

    // Parallel line iteration with rayon
    raw.par_split(|&b| b == b'\n')
        .find_map_any(|line| {
            let word = line.strip_suffix(b"\r").unwrap_or(line);
            if word.is_empty() { return None; }
            for (_, hash_fn) in ALGORITHMS {
                if hash_fn(word) == target {
                    return Some(String::from_utf8_lossy(word).to_string());
                }
            }
            None
        })
}

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "hcrack", about = "🔓 Hash Identifier & Cracker — CySec Arsenal")]
struct Args {
    /// Single hash string
    #[arg(short = 'H', long)]
    hash: Option<String>,

    /// File containing one hash per line
    #[arg(long)]
    file: Option<PathBuf>,

    /// Wordlist for dictionary attack
    #[arg(short, long)]
    wordlist: Option<PathBuf>,

    /// Only identify hash type, skip cracking
    #[arg(long)]
    identify_only: bool,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Debug, serde::Serialize)]
struct HashResult {
    hash:     String,
    types:    Vec<String>,
    cracked:  Option<String>,
}

fn process(hash: &str, wordlist: &Option<PathBuf>, identify_only: bool, json: bool) -> HashResult {
    let types: Vec<String> = identify(hash).iter().map(|s| s.to_string()).collect();

    if !json {
        println!("\n  {}", "─".repeat(55).dimmed());
        println!("  {} {}", "Hash:".bright_cyan(), hash);
        println!("  {} {}", "Type(s):".bright_cyan(), types.join(", ").bright_yellow());
    }

    let cracked = if !identify_only {
        if let Some(wl) = wordlist {
            if !json { print!("  {} cracking... ", info("")); }
            let result = crack(hash, wl);
            if !json {
                match &result {
                    Some(plain) => println!("{}", found(&format!("CRACKED → {:?}", plain))),
                    None        => println!("{}", warn("Not found in wordlist.")),
                }
            }
            result
        } else {
            if !json { println!("  {} No wordlist provided.", warn("")); }
            None
        }
    } else {
        None
    };

    HashResult { hash: hash.to_string(), types, cracked }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.json {
        print_banner(Module::HashCracker);
    }

    let hashes: Vec<String> = if let Some(h) = &args.hash {
        vec![h.clone()]
    } else if let Some(path) = &args.file {
        std::fs::read_to_string(path)
            .context("reading hash file")?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        eprintln!("{}", "Specify --hash or --file");
        std::process::exit(1);
    };

    let mut results = Vec::new();
    for hash in &hashes {
        results.push(process(hash, &args.wordlist, args.identify_only, args.json));
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        let cracked = results.iter().filter(|r| r.cracked.is_some()).count();
        println!("\n  {}", ok(&format!("{}/{} hash(es) cracked.", cracked, results.len())));
    }

    Ok(())
}

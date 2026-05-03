//! cipher — Classic cipher encode/decode for CTF crypto challenges
//! NuRichter · CySec Arsenal
//!
//! Usage:
//!   cipher caesar  --decode --text "Khoor" --shift 3
//!   cipher vigenere --decode --text "RIJVS" --key "KEY"
//!   cipher xor     --text "hello" --key "41" --hex
//!   cipher auto    --text "SGVsbG8h"
//!   cipher brute   --text "Khoor Zruog"

use anyhow::Result;
use arsenal_core::banner::{print_banner, Module};
use arsenal_core::{found, info, ok};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use colored::Colorize;

#[derive(Parser)]
#[command(name = "cipher", about = "🔐 Cipher Tools — CySec Arsenal")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Caesar cipher
    Caesar  { #[arg(long)] text: String, #[arg(long)] decode: bool, #[arg(long, default_value_t=3)] shift: i32 },
    /// ROT13 (Caesar shift 13)
    Rot13   { #[arg(long)] text: String },
    /// Atbash cipher
    Atbash  { #[arg(long)] text: String },
    /// Vigenère cipher
    Vigenere{ #[arg(long)] text: String, #[arg(long)] decode: bool, #[arg(long, default_value="KEY")] key: String },
    /// XOR cipher
    Xor     { #[arg(long)] text: String, #[arg(long, default_value="41")] key: String, #[arg(long)] hex: bool },
    /// Rail-fence transposition
    Rail    { #[arg(long)] text: String, #[arg(long)] decode: bool, #[arg(long, default_value_t=3)] rails: usize },
    /// Morse code
    Morse   { #[arg(long)] text: String, #[arg(long)] decode: bool },
    /// Base64
    B64     { #[arg(long)] text: String, #[arg(long)] decode: bool },
    /// Hex encode/decode
    Hex     { #[arg(long)] text: String, #[arg(long)] decode: bool },
    /// Binary encode/decode
    Binary  { #[arg(long)] text: String, #[arg(long)] decode: bool },
    /// Brute-force all 25 Caesar shifts
    Brute   { #[arg(long)] text: String, #[arg(long, default_value_t=5)] top: usize },
    /// Auto-detect encoding
    Auto    { #[arg(long)] text: String },
}

// ─── Implementations ──────────────────────────────────────────────────────────

fn caesar(text: &str, shift: i32, decode: bool) -> String {
    let s = if decode { (((-shift) % 26) + 26) % 26 } else { shift.rem_euclid(26) };
    text.chars().map(|c| {
        if c.is_ascii_alphabetic() {
            let base = if c.is_uppercase() { b'A' } else { b'a' };
            (((c as i32 - base as i32 + s) % 26) as u8 + base) as char
        } else { c }
    }).collect()
}

fn atbash(text: &str) -> String {
    text.chars().map(|c| {
        if c.is_ascii_alphabetic() {
            let base = if c.is_uppercase() { b'A' } else { b'a' };
            (base + 25 - (c as u8 - base)) as char
        } else { c }
    }).collect()
}

fn vigenere(text: &str, key: &str, decode: bool) -> String {
    let key: Vec<i32> = key.to_uppercase().bytes()
        .filter(|b| b.is_ascii_alphabetic())
        .map(|b| (b - b'A') as i32)
        .collect();
    let mut ki = 0;
    text.chars().map(|c| {
        if c.is_ascii_alphabetic() {
            let base = if c.is_uppercase() { b'A' } else { b'a' };
            let ks   = if decode { -key[ki % key.len()] } else { key[ki % key.len()] };
            ki += 1;
            ((((c as i32 - base as i32 + ks) % 26 + 26) % 26) as u8 + base) as char
        } else { c }
    }).collect()
}

fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect()
}

fn rail_fence(text: &str, rails: usize, decode: bool) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let pattern: Vec<usize> = {
        let mut p = Vec::with_capacity(n);
        let (mut rail, mut dir) = (0i32, 1i32);
        for _ in 0..n {
            p.push(rail as usize);
            if rail == 0 { dir = 1; } else if rail == rails as i32 - 1 { dir = -1; }
            rail += dir;
        }
        p
    };
    if !decode {
        let mut fence: Vec<Vec<char>> = vec![vec![]; rails];
        for (ch, r) in chars.iter().zip(pattern.iter()) { fence[*r].push(*ch); }
        fence.into_iter().flatten().collect()
    } else {
        let mut indices: Vec<usize> = (0..n).collect();
        indices.sort_by_key(|&i| pattern[i]);
        let mut result = vec![' '; n];
        for (idx, ch) in indices.iter().zip(chars.iter()) { result[*idx] = *ch; }
        result.into_iter().collect()
    }
}

const MORSE: &[(&str, &str)] = &[
    ("A",".-"),("B","-..."),("C","-.-."),("D","-.."),("E","."),
    ("F","..-."),("G","--."),("H","...."),("I",".."),("J",".---"),
    ("K","-.-"),("L",".-.."),("M","--"),("N","-."),("O","---"),
    ("P",".--."),("Q","--.-"),("R",".-."),("S","..."),("T","-"),
    ("U","..-"),("V","...-"),("W",".--"),("X","-..-"),("Y","-.--"),
    ("Z","--.."),("0","-----"),("1",".----"),("2","..---"),("3","...--"),
    ("4","....-"),("5","....."),("6","-...."),("7","--..."),("8","---.." ),
    ("9","----."),(" ","/"),
];

fn morse_encode(text: &str) -> String {
    text.to_uppercase().chars()
        .filter_map(|c| MORSE.iter().find(|(l, _)| *l == c.to_string()).map(|(_, m)| *m))
        .collect::<Vec<_>>().join(" ")
}

fn morse_decode(text: &str) -> String {
    text.split(' ')
        .map(|code| MORSE.iter().find(|(_, m)| *m == code).map(|(l, _)| *l).unwrap_or("?"))
        .collect()
}

fn english_score(text: &str) -> f64 {
    let common = "etaoinshrdlcumwfgypbvkjxqz";
    let lower = text.to_lowercase();
    let alpha_count = lower.chars().filter(|c| c.is_ascii_alphabetic()).count();
    if alpha_count == 0 { return 0.0; }
    let hits = lower.chars()
        .filter(|c| common[..6].contains(*c))
        .count();
    hits as f64 / alpha_count as f64
}

fn auto_detect(text: &str) {
    println!("{}", info("Auto-detecting encoding...\n"));

    // Base64
    if let Ok(decoded) = general_purpose::STANDARD.decode(text) {
        if let Ok(s) = std::str::from_utf8(&decoded) {
            println!("  {} [Base64] → {}", "[>]".bright_magenta().bold(), s.bright_white());
        }
    }
    // Hex
    if let Ok(bytes) = hex::decode(text.replace(' ', "")) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            println!("  {} [Hex]    → {}", "[>]".bright_magenta().bold(), s.bright_white());
        }
    }
    // ROT13
    let rot = caesar(text, 13, false);
    if english_score(&rot) > 0.4 {
        println!("  {} [ROT13]  → {}", "[>]".bright_magenta().bold(), rot.bright_white());
    }
    // Caesar brute
    let best = (0..26)
        .map(|s| (s, caesar(text, s, true)))
        .max_by(|a, b| english_score(&a.1).partial_cmp(&english_score(&b.1)).unwrap());
    if let Some((s, dec)) = best {
        if english_score(&dec) > 0.45 {
            println!("  {} [Caesar] shift={} → {}", "[>]".bright_magenta().bold(), s, dec.bright_white());
        }
    }
    // Atbash
    let ab = atbash(text);
    if english_score(&ab) > 0.4 {
        println!("  {} [Atbash] → {}", "[>]".bright_magenta().bold(), ab.bright_white());
    }
    // Morse
    let chars: std::collections::HashSet<char> = text.chars().collect();
    if chars.is_subset(&['.', '-', '/', ' ', '\t'].iter().cloned().collect()) {
        println!("  {} [Morse]  → {}", "[>]".bright_magenta().bold(), morse_decode(text).bright_white());
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    print_banner(Module::CipherTools);
    println!();

    match &cli.cmd {
        Cmd::Caesar { text, decode, shift } => {
            println!("{}", found(&caesar(text, *shift, *decode)));
        }
        Cmd::Rot13 { text } => {
            println!("{}", found(&caesar(text, 13, false)));
        }
        Cmd::Atbash { text } => {
            println!("{}", found(&atbash(text)));
        }
        Cmd::Vigenere { text, decode, key } => {
            println!("{}", found(&vigenere(text, key, *decode)));
        }
        Cmd::Xor { text, key, hex } => {
            let (data, key_bytes) = if *hex {
                (hex::decode(text.replace(' ', ""))?, hex::decode(key)?)
            } else {
                (text.as_bytes().to_vec(), key.as_bytes().to_vec())
            };
            let result = xor(&data, &key_bytes);
            println!("  hex   : {}", hex::encode(&result).bright_yellow());
            println!("  ascii : {}", String::from_utf8_lossy(&result).bright_white());
        }
        Cmd::Rail { text, decode, rails } => {
            println!("{}", found(&rail_fence(text, *rails, *decode)));
        }
        Cmd::Morse { text, decode } => {
            if *decode { println!("{}", found(&morse_decode(text))); }
            else       { println!("{}", found(&morse_encode(text))); }
        }
        Cmd::B64 { text, decode } => {
            if *decode {
                let b = general_purpose::STANDARD.decode(text)?;
                println!("{}", found(&String::from_utf8_lossy(&b)));
            } else {
                println!("{}", found(&general_purpose::STANDARD.encode(text)));
            }
        }
        Cmd::Hex { text, decode } => {
            if *decode {
                let b = hex::decode(text.replace(' ', ""))?;
                println!("{}", found(&String::from_utf8_lossy(&b)));
            } else {
                println!("{}", found(&hex::encode(text.as_bytes())));
            }
        }
        Cmd::Binary { text, decode } => {
            if *decode {
                let s: String = text.split_whitespace()
                    .map(|b| char::from(u8::from_str_radix(b, 2).unwrap_or(b'?')))
                    .collect();
                println!("{}", found(&s));
            } else {
                let s: String = text.bytes().map(|b| format!("{:08b}", b)).collect::<Vec<_>>().join(" ");
                println!("{}", found(&s));
            }
        }
        Cmd::Brute { text, top } => {
            let mut results: Vec<(i32, String, f64)> = (0..26)
                .map(|s| {
                    let d = caesar(text, s, true);
                    let sc = english_score(&d);
                    (s, d, sc)
                })
                .collect();
            results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
            for (shift, dec, score) in results.iter().take(*top) {
                println!("  shift={:>2}  score={:.2}  {}", shift, score, dec.bright_white());
            }
        }
        Cmd::Auto { text } => {
            auto_detect(text);
        }
    }

    println!();
    Ok(())
}

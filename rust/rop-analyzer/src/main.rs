//! ropx — ELF Binary Analyzer: checksec, section dump, ROP gadget search
//! NuRichter · CySec Arsenal
//!
//! Usage:
//!   ropx --checksec ./vuln
//!   ropx --sections ./vuln
//!   ropx --strings ./vuln --min-len 6
//!   ropx --gadgets ./vuln --pattern "pop rdi"

use std::path::PathBuf;
use anyhow::{Context, Result};
use arsenal_core::{banner::{print_banner, Module}, found, info, ok, warn};
use clap::{Parser, Subcommand};
use colored::Colorize;

#[derive(Parser)]
#[command(name = "ropx", about = "🔩 ROP Analyzer — CySec Arsenal")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check binary security mitigations
    Checksec { binary: PathBuf },
    /// List ELF sections with addresses and sizes
    Sections { binary: PathBuf },
    /// Extract printable strings
    Strings {
        binary: PathBuf,
        #[arg(long, default_value_t = 6)] min_len: usize,
        #[arg(long)] interesting_only: bool,
    },
    /// Search for ROP gadgets (simple pattern matching)
    Gadgets {
        binary: PathBuf,
        #[arg(long, default_value = "ret")] pattern: String,
    },
    /// Dump hex of a section
    Hexdump {
        binary: PathBuf,
        #[arg(long)] offset: Option<String>,
        #[arg(long, default_value_t = 256)] len: usize,
    },
    /// Show all info
    All { binary: PathBuf },
}

// ─── ELF parsing (manual, no deps) ───────────────────────────────────────────

fn read_le16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off+2].try_into().unwrap_or_default())
}
fn read_le32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off+4].try_into().unwrap_or_default())
}
fn read_le64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off+8].try_into().unwrap_or_default())
}

struct ElfInfo {
    data:     Vec<u8>,
    bits:     u8,        // 32 or 64
    arch:     String,
    sections: Vec<ElfSection>,
    entry:    u64,
}

#[derive(Debug, Clone)]
struct ElfSection {
    name:    String,
    sh_type: u32,
    addr:    u64,
    offset:  u64,
    size:    u64,
    flags:   u64,
}

impl ElfInfo {
    fn parse(data: Vec<u8>) -> Result<Self> {
        if data.len() < 16 || &data[0..4] != b"\x7fELF" {
            anyhow::bail!("Not a valid ELF file");
        }
        let bits = if data[4] == 1 { 32u8 } else { 64 };
        let arch = match read_le16(&data, 18) {
            0x03 => "x86",
            0x3e => "x86-64",
            0x28 => "ARM",
            0xb7 => "AArch64",
            0xf3 => "RISC-V",
            other => return Ok(ElfInfo {
                bits, arch: format!("0x{:04x}", other),
                sections: vec![], entry: 0, data,
            }),
        }.to_string();

        let (shoff, shentsize, shnum, shstrndx, entry): (u64, u16, u16, u16, u64) = if bits == 64 {
            (read_le64(&data, 40), read_le16(&data, 58), read_le16(&data, 60), read_le16(&data, 62), read_le64(&data, 24))
        } else {
            (read_le32(&data, 32) as u64, read_le16(&data, 46), read_le16(&data, 48), read_le16(&data, 50), read_le32(&data, 24) as u64)
        };

        // Section name string table
        let strtab_off = if bits == 64 {
            let sh = shoff as usize + shstrndx as usize * shentsize as usize;
            if sh + 24 > data.len() { 0usize } else { read_le64(&data, sh + 24) as usize }
        } else {
            let sh = shoff as usize + shstrndx as usize * shentsize as usize;
            if sh + 16 > data.len() { 0usize } else { read_le32(&data, sh + 16) as usize }
        };

        let mut sections = Vec::new();
        for i in 0..shnum as usize {
            let sh = shoff as usize + i * shentsize as usize;
            if sh + shentsize as usize > data.len() { break; }

            let (name_off, sh_type, flags, addr, offset, size) = if bits == 64 {
                (read_le32(&data, sh) as usize, read_le32(&data, sh+4),
                 read_le64(&data, sh+8), read_le64(&data, sh+16),
                 read_le64(&data, sh+24), read_le64(&data, sh+32))
            } else {
                (read_le32(&data, sh) as usize, read_le32(&data, sh+4),
                 read_le32(&data, sh+8) as u64, read_le32(&data, sh+12) as u64,
                 read_le32(&data, sh+16) as u64, read_le32(&data, sh+20) as u64)
            };

            let name = if strtab_off > 0 && strtab_off + name_off < data.len() {
                let start = strtab_off + name_off;
                let end = data[start..].iter().position(|&b| b == 0).map(|p| start + p).unwrap_or(start);
                String::from_utf8_lossy(&data[start..end]).to_string()
            } else {
                format!("<sect_{i}>")
            };

            sections.push(ElfSection { name, sh_type, flags, addr, offset, size });
        }

        Ok(ElfInfo { data, bits, arch, sections, entry })
    }

    fn has_section(&self, name: &str) -> bool {
        self.sections.iter().any(|s| s.name == name)
    }

    fn section_data(&self, name: &str) -> Option<&[u8]> {
        self.sections.iter().find(|s| s.name == name).map(|s| {
            let start = s.offset as usize;
            let end   = (s.offset + s.size) as usize;
            &self.data[start..end.min(self.data.len())]
        })
    }
}

// ─── Commands ─────────────────────────────────────────────────────────────────

fn do_checksec(elf: &ElfInfo) {
    println!("\n  {}", info("Binary Protections:"));
    println!("  {}", "─".repeat(45).dimmed());

    fn flag(label: &str, enabled: bool, good_if_enabled: bool) {
        let (sym, col) = match (enabled, good_if_enabled) {
            (true,  true)  => ("✓", colored::Color::Green),
            (true,  false) => ("✗", colored::Color::Red),
            (false, true)  => ("✗", colored::Color::Red),
            (false, false) => ("✓", colored::Color::Green),
        };
        let status = if enabled { "Enabled" } else { "Disabled" };
        println!(
            "  {:<22} {}",
            label.bright_cyan(),
            format!("{sym} {status}").color(col).bold()
        );
    }

    let has_relro  = elf.has_section(".got.plt");
    let has_stack  = elf.has_section(".note.ABI-tag");
    let nx         = elf.sections.iter().any(|s| s.name == ".gnu.stack" && s.flags & 0x1 == 0);
    let pie        = elf.entry < 0x400000;
    let has_rpath  = elf.has_section(".dynamic");

    println!("  {:<22} {} ({})", "Arch".bright_cyan(), elf.arch.bright_white().bold(), format!("{}-bit", elf.bits).dimmed());
    println!("  {:<22} {}", "Entry Point".bright_cyan(), format!("0x{:016x}", elf.entry).bright_yellow());
    flag("RELRO",        has_relro, true);
    flag("Stack Canary", has_stack, true);
    flag("NX",           nx,        true);
    flag("PIE",          pie,       true);

    println!();
    if !pie && !nx {
        println!("  {}", found("Classic BOF target — no PIE + no NX!"));
    }
}

fn do_sections(elf: &ElfInfo) {
    println!("\n  {}", info("ELF Sections:"));
    println!("  {:<20} {:<12} {:<12} {:<12} {}", 
        "Name".bright_cyan(), "Type".bright_cyan(), "Addr".bright_cyan(), 
        "Size".bright_cyan(), "Flags".bright_cyan());
    println!("  {}", "─".repeat(65).dimmed());
    for s in &elf.sections {
        if s.size == 0 { continue; }
        let flag_str = {
            let mut f = String::new();
            if s.flags & 0x1 != 0 { f.push('W'); }
            if s.flags & 0x2 != 0 { f.push('A'); }
            if s.flags & 0x4 != 0 { f.push('X'); }
            f
        };
        let name_col = if flag_str.contains('X') {
            s.name.bright_red().bold().to_string()
        } else if flag_str.contains('W') {
            s.name.bright_yellow().to_string()
        } else {
            s.name.normal().to_string()
        };
        println!(
            "  {:<28} {:<12} 0x{:<10x} {:<12} {}",
            name_col,
            s.sh_type,
            s.addr,
            s.size,
            flag_str.bright_green()
        );
    }
}

fn do_strings(elf: &ElfInfo, min_len: usize, interesting_only: bool) {
    let interesting_kw = ["flag", "ctf", "password", "secret", "key", "token",
                          "http", "ssh", "admin", "root", "/bin/sh", "/bin/bash"];
    println!("\n  {}", info(&format!("Strings (min-len={min_len}):")));
    let mut count = 0;

    let mut current: Vec<u8> = Vec::new();
    for &byte in &elf.data {
        if (0x20..0x7f).contains(&byte) {
            current.push(byte);
        } else {
            if current.len() >= min_len {
                let s = String::from_utf8_lossy(&current).to_string();
                let is_interesting = interesting_kw.iter().any(|kw| s.to_lowercase().contains(kw));
                if !interesting_only || is_interesting {
                    if is_interesting {
                        println!("  {} {}", "[>]".bright_magenta().bold(), s.bright_white().bold());
                    } else {
                        println!("  {}", s.dimmed());
                    }
                    count += 1;
                    if count > 500 && !interesting_only {
                        println!("  … truncated. Use --interesting-only to filter.");
                        break;
                    }
                }
            }
            current.clear();
        }
    }
    println!("\n  {}", ok(&format!("{count} string(s) shown.")));
}

fn do_gadgets(elf: &ElfInfo, pattern: &str) {
    println!("\n  {}", info(&format!("Gadget search: {:?}", pattern)));

    // Simple opcode patterns for common gadgets
    let gadget_opcodes: &[(&str, &[u8])] = &[
        ("ret",          &[0xc3]),
        ("ret far",      &[0xcb]),
        ("pop rdi; ret", &[0x5f, 0xc3]),
        ("pop rsi; ret", &[0x5e, 0xc3]),
        ("pop rdx; ret", &[0x5a, 0xc3]),
        ("pop rax; ret", &[0x58, 0xc3]),
        ("pop rsp; ret", &[0x5c, 0xc3]),
        ("pop rbp; ret", &[0x5d, 0xc3]),
        ("pop rbx; ret", &[0x5b, 0xc3]),
        ("syscall",      &[0x0f, 0x05]),
        ("int 0x80",     &[0xcd, 0x80]),
        ("jmp rsp",      &[0xff, 0xe4]),
        ("call rsp",     &[0xff, 0xd4]),
        ("xor eax,eax",  &[0x31, 0xc0]),
    ];

    let mut found_count = 0;

    // Get executable sections
    for section in elf.sections.iter().filter(|s| s.flags & 0x4 != 0 && s.size > 0) {
        let start = section.offset as usize;
        let end   = (section.offset + section.size) as usize;
        if end > elf.data.len() { continue; }
        let code = &elf.data[start..end];

        for (name, opcodes) in gadget_opcodes {
            if !pattern.is_empty() && !name.to_lowercase().contains(&pattern.to_lowercase()) {
                continue;
            }
            let mut off = 0;
            while off + opcodes.len() <= code.len() {
                if &code[off..off + opcodes.len()] == *opcodes {
                    let addr = section.addr + off as u64;
                    println!(
                        "  0x{:016x}  {}  [{}]",
                        addr,
                        name.bright_white().bold(),
                        section.name.dimmed()
                    );
                    found_count += 1;
                    if found_count > 200 {
                        println!("  {} (truncated at 200 results)", warn(""));
                        return;
                    }
                }
                off += 1;
            }
        }
    }

    if found_count == 0 {
        println!("  {}", warn("No gadgets found matching pattern."));
    } else {
        println!("\n  {}", ok(&format!("{found_count} gadget(s) found.")));
    }
}

fn do_hexdump(data: &[u8], offset: usize, len: usize) {
    let end = (offset + len).min(data.len());
    println!("\n  {}", info(&format!("Hexdump @ 0x{:08x} ({} bytes):", offset, end - offset)));
    println!("  {}", "─".repeat(72).dimmed());
    for chunk_start in (offset..end).step_by(16) {
        let chunk_end = (chunk_start + 16).min(end);
        let chunk = &data[chunk_start..chunk_end];
        let hex_part: String = chunk.iter()
            .map(|b| format!("{:02x} ", b))
            .collect();
        let ascii_part: String = chunk.iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        println!(
            "  {:08x}  {:<48}  {}",
            chunk_start,
            hex_part.bright_yellow(),
            ascii_part.bright_white()
        );
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let binary = match &cli.cmd {
        Cmd::Checksec { binary } | Cmd::Sections { binary } |
        Cmd::Strings  { binary, .. } | Cmd::Gadgets { binary, .. } |
        Cmd::Hexdump  { binary, .. } | Cmd::All { binary } => binary.clone(),
    };

    let data = std::fs::read(&binary)
        .with_context(|| format!("reading {}", binary.display()))?;

    let elf = match ElfInfo::parse(data.clone()) {
        Ok(e) => e,
        Err(e) => {
            println!("{}", warn(&format!("ELF parse warning: {e} — running strings/hexdump only")));
            ElfInfo { data, bits: 64, arch: "unknown".into(), sections: vec![], entry: 0 }
        }
    };

    print_banner(Module::RopAnalyzer);
    println!("  {}", info(&format!("Binary: {}", binary.display())));

    match &cli.cmd {
        Cmd::Checksec { .. } => do_checksec(&elf),
        Cmd::Sections { .. } => do_sections(&elf),
        Cmd::Strings { min_len, interesting_only, .. } => {
            do_strings(&elf, *min_len, *interesting_only);
        }
        Cmd::Gadgets { pattern, .. } => do_gadgets(&elf, pattern),
        Cmd::Hexdump { offset, len, .. } => {
            let off = offset.as_deref()
                .map(|s| usize::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
                .unwrap_or(0);
            do_hexdump(&elf.data, off, *len);
        }
        Cmd::All { .. } => {
            do_checksec(&elf);
            do_sections(&elf);
            do_strings(&elf, 8, true);
            do_gadgets(&elf, "");
        }
    }

    println!();
    Ok(())
}

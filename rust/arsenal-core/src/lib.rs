//! arsenal-core — Shared library for CySec Arsenal
//! NuRichter · CySec Arsenal
//!
//! Provides:
//! - Terminal color helpers
//! - ASCII banner rendering
//! - Structured logging setup
//! - Common types and utilities

pub mod banner;
pub mod colors;
pub mod logger;

pub use anyhow::{anyhow, bail, Context, Result};
pub use colors::*;

/// Target specification — IP, hostname, or CIDR
#[derive(Debug, Clone)]
pub struct Target {
    pub raw: String,
    pub kind: TargetKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TargetKind {
    Ip,
    Hostname,
    Cidr,
    Url,
}

impl Target {
    pub fn parse(raw: &str) -> Self {
        let kind = if raw.contains('/') && !raw.starts_with("http") {
            TargetKind::Cidr
        } else if raw.starts_with("http") {
            TargetKind::Url
        } else if raw.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            TargetKind::Ip
        } else {
            TargetKind::Hostname
        };
        Target { raw: raw.to_string(), kind }
    }
}

/// Common finding severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info     => write!(f, "INFO"),
            Self::Low      => write!(f, "LOW"),
            Self::Medium   => write!(f, "MEDIUM"),
            Self::High     => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Generic scan finding
#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub kind:     String,
    pub target:   String,
    pub detail:   String,
    pub severity: String,
}

impl Finding {
    pub fn new(kind: &str, target: &str, detail: &str, sev: Severity) -> Self {
        Finding {
            kind:     kind.to_string(),
            target:   target.to_string(),
            detail:   detail.to_string(),
            severity: sev.to_string(),
        }
    }
}

/// Print a table of findings to stdout
pub fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("{}", ok("No findings."));
        return;
    }
    println!("\n{}", "─".repeat(70));
    println!(" {:<12} {:<30} {:<20}", "SEVERITY", "TARGET", "KIND");
    println!("{}", "─".repeat(70));
    for f in findings {
        let sev_colored = match f.severity.as_str() {
            "CRITICAL" => f.severity.bright_red().bold().to_string(),
            "HIGH"     => f.severity.red().to_string(),
            "MEDIUM"   => f.severity.yellow().to_string(),
            "LOW"      => f.severity.cyan().to_string(),
            _          => f.severity.dimmed().to_string(),
        };
        println!(" {:<20} {:<30} {}", sev_colored, f.target, f.kind);
        println!("   └─ {}", f.detail.dimmed());
    }
    println!("{}", "─".repeat(70));
    println!(" {} finding(s) total.", findings.len());
}

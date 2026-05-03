//! banner.rs — ASCII art banner renderer
//! NuRichter · CySec Arsenal

use colored::Colorize;

const LOGO: &str = r"
  ██████╗██╗   ██╗███████╗███████╗ ██████╗
 ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔════╝
 ██║      ╚████╔╝ ███████╗█████╗  ██║
 ██║       ╚██╔╝  ╚════██║██╔══╝  ██║
 ╚██████╗   ██║   ███████║███████╗╚██████╗
  ╚═════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝";

const TAGLINE: &str = "  ░░ ARSENAL ░░  NuRichter Workspace  ░░ Rust Edition ░░";
const MOTTO:   &str = "  Richterize The Infinity ∞";

/// Module identifiers for sub-banners
#[derive(Debug, Clone, Copy)]
pub enum Module {
    PortScanner,
    SubdomainEnum,
    WebFuzzer,
    HashCracker,
    SqliProbe,
    LfiProbe,
    XssProbe,
    CipherTools,
    FileCarver,
    OsintHarvest,
    NetMonitor,
    RopAnalyzer,
    DirBuster,
}

impl Module {
    pub fn label(&self) -> &'static str {
        match self {
            Module::PortScanner   => "PORT-SCANNER",
            Module::SubdomainEnum => "SUBDOMAIN-ENUM",
            Module::WebFuzzer     => "WEB-FUZZER",
            Module::HashCracker   => "HASH-CRACKER",
            Module::SqliProbe     => "SQLI-PROBE",
            Module::LfiProbe      => "LFI-PROBE",
            Module::XssProbe      => "XSS-PROBE",
            Module::CipherTools   => "CIPHER-TOOLS",
            Module::FileCarver    => "FILE-CARVER",
            Module::OsintHarvest  => "OSINT-HARVEST",
            Module::NetMonitor    => "NET-MONITOR",
            Module::RopAnalyzer   => "ROP-ANALYZER",
            Module::DirBuster     => "DIR-BUSTER",
        }
    }

    pub fn color(&self) -> colored::Color {
        match self {
            Module::PortScanner | Module::NetMonitor  => colored::Color::Cyan,
            Module::SubdomainEnum | Module::DirBuster => colored::Color::BrightGreen,
            Module::WebFuzzer | Module::SqliProbe
            | Module::LfiProbe | Module::XssProbe     => colored::Color::Yellow,
            Module::HashCracker | Module::CipherTools  => colored::Color::BrightMagenta,
            Module::FileCarver                         => colored::Color::BrightBlue,
            Module::OsintHarvest                       => colored::Color::White,
            Module::RopAnalyzer                        => colored::Color::Red,
        }
    }
}

pub fn print_banner(module: Module) {
    println!("{}", LOGO.bright_red().bold());
    println!("{}", TAGLINE.purple());
    println!("{}", MOTTO.dimmed());
    println!(
        "\n  {} {}\n",
        format!("[{}]", module.label()).color(module.color()).bold(),
        "─".repeat(50 - module.label().len()).dimmed()
    );
}

pub fn print_main_banner() {
    println!("{}", LOGO.bright_red().bold());
    println!("{}", TAGLINE.purple());
    println!("{}", MOTTO.dimmed());
    println!();
}

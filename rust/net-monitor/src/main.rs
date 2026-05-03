//! netmon — Network Traffic Monitor / Connection Tracker
//! NuRichter · CySec Arsenal
//!
//! Reads /proc/net/{tcp,tcp6,udp,udp6} to display active connections.
//! Tracks established connections and flags suspicious activity.
//!
//! Usage:
//!   netmon
//!   netmon --watch --interval 3
//!   netmon --suspicious

use std::collections::HashMap;
use std::time::Duration;
use anyhow::Result;
use arsenal_core::{banner::{print_banner, Module}, found, info, ok, warn};
use clap::Parser;
use colored::Colorize;
use chrono::Local;

#[derive(Parser)]
#[command(name = "netmon", about = "📡 Network Monitor — CySec Arsenal")]
struct Args {
    /// Continuously refresh
    #[arg(long)] watch: bool,
    /// Refresh interval (seconds)
    #[arg(long, default_value_t = 3)] interval: u64,
    /// Show only suspicious/unusual connections
    #[arg(long)] suspicious: bool,
    /// Filter by port
    #[arg(long)] port: Option<u16>,
    /// JSON output
    #[arg(long)] json: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Connection {
    proto:     String,
    local_ip:  String,
    local_port: u16,
    remote_ip:  String,
    remote_port: u16,
    state:     String,
    pid:       u32,
}

const SUSPICIOUS_PORTS: &[u16] = &[
    1234, 4444, 5555, 6666, 7777, 8888, 9999, 31337, 1337, 12345,
    65535, 54321, 44444, 55555,
];

const KNOWN_SERVICES: &[(u16, &str)] = &[
    (22, "SSH"), (80, "HTTP"), (443, "HTTPS"), (3306, "MySQL"),
    (5432, "PostgreSQL"), (6379, "Redis"), (27017, "MongoDB"),
    (8080, "HTTP-Alt"), (53, "DNS"), (25, "SMTP"), (110, "POP3"),
    (143, "IMAP"), (21, "FTP"), (445, "SMB"), (3389, "RDP"),
];

fn hex_to_ip(hex: &str) -> String {
    if hex.len() == 8 {
        // IPv4
        if let Ok(n) = u32::from_str_radix(hex, 16) {
            let b = n.to_le_bytes();
            return format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
        }
    } else if hex.len() == 32 {
        // IPv6
        let parts: Vec<String> = hex.as_bytes().chunks(4)
            .rev()
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect();
        return parts.chunks(2).map(|p| p.join("")).collect::<Vec<_>>().join(":");
    }
    hex.to_string()
}

fn hex_to_port(hex: &str) -> u16 {
    u16::from_str_radix(hex, 16).unwrap_or(0)
}

fn tcp_state(n: &str) -> &'static str {
    match n {
        "01" => "ESTABLISHED", "02" => "SYN_SENT",  "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",   "05" => "FIN_WAIT2",  "06" => "TIME_WAIT",
        "07" => "CLOSE",       "08" => "CLOSE_WAIT", "09" => "LAST_ACK",
        "0A" => "LISTEN",      "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn service_name(port: u16) -> Option<&'static str> {
    KNOWN_SERVICES.iter().find(|(p, _)| *p == port).map(|(_, s)| *s)
}

fn parse_proc_net(proto: &str) -> Vec<Connection> {
    let path = format!("/proc/net/{proto}");
    let Ok(content) = std::fs::read_to_string(&path) else { return vec![] };

    content.lines().skip(1).filter_map(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 { return None; }

        let (local_hex_addr, local_hex_port) = parts[1].split_once(':')?;
        let (remote_hex_addr, remote_hex_port) = parts[2].split_once(':')?;

        let local_ip    = hex_to_ip(local_hex_addr);
        let local_port  = hex_to_port(local_hex_port);
        let remote_ip   = hex_to_ip(remote_hex_addr);
        let remote_port = hex_to_port(remote_hex_port);

        let state = if proto.starts_with("tcp") {
            tcp_state(parts[3]).to_string()
        } else {
            "STATELESS".to_string()
        };

        let pid: u32 = parts.get(7).and_then(|s| s.parse().ok()).unwrap_or(0);

        Some(Connection {
            proto: proto.to_uppercase(),
            local_ip, local_port,
            remote_ip, remote_port,
            state, pid,
        })
    }).collect()
}

fn is_suspicious(conn: &Connection) -> bool {
    SUSPICIOUS_PORTS.contains(&conn.remote_port)
    || SUSPICIOUS_PORTS.contains(&conn.local_port)
    || (!conn.remote_ip.is_empty() && conn.remote_ip != "0.0.0.0" && conn.remote_ip != "127.0.0.1"
        && conn.state == "ESTABLISHED" && conn.remote_port > 1024
        && service_name(conn.remote_port).is_none())
}

fn display_connections(conns: &[Connection], suspicious_only: bool, port_filter: Option<u16>) {
    println!(
        "\n  {:<6} {:<22} {:<22} {:<15} {}",
        "Proto".bright_cyan(), "Local".bright_cyan(),
        "Remote".bright_cyan(), "State".bright_cyan(), "Service".bright_cyan()
    );
    println!("  {}", "─".repeat(80).dimmed());

    let mut shown = 0;
    for conn in conns {
        if suspicious_only && !is_suspicious(conn) { continue; }
        if let Some(p) = port_filter {
            if conn.local_port != p && conn.remote_port != p { continue; }
        }

        let local  = format!("{}:{}", conn.local_ip,  conn.local_port);
        let remote = format!("{}:{}", conn.remote_ip, conn.remote_port);
        let svc    = service_name(conn.remote_port)
            .or_else(|| service_name(conn.local_port))
            .unwrap_or("-");

        let state_col = match conn.state.as_str() {
            "ESTABLISHED" => conn.state.bright_green().to_string(),
            "LISTEN"      => conn.state.bright_cyan().to_string(),
            "TIME_WAIT"   => conn.state.yellow().to_string(),
            "CLOSE_WAIT"  => conn.state.red().to_string(),
            _             => conn.state.dimmed().to_string(),
        };

        if is_suspicious(conn) {
            println!(
                "  {:<6} {:<22} {:<22} {:<22} {} {}",
                conn.proto.bright_red().bold(),
                local, remote, state_col, svc,
                "⚠ SUSPICIOUS".bright_red().bold()
            );
        } else {
            println!(
                "  {:<6} {:<22} {:<22} {:<22} {}",
                conn.proto.dimmed(),
                local, remote, state_col, svc.dimmed()
            );
        }
        shown += 1;
    }
    if shown == 0 {
        println!("  {}", info("No connections to display."));
    }
}

fn collect_all() -> Vec<Connection> {
    let mut all = Vec::new();
    for proto in &["tcp", "tcp6", "udp", "udp6"] {
        all.extend(parse_proc_net(proto));
    }
    all
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if !args.watch {
        let conns = collect_all();

        if args.json {
            println!("{}", serde_json::to_string_pretty(&conns)?);
            return Ok(());
        }

        print_banner(Module::NetMonitor);
        println!("  {}", info(&format!("Timestamp : {}", Local::now().format("%Y-%m-%d %H:%M:%S"))));
        println!("  {}", info(&format!("Total     : {} connections", conns.len())));
        let suspicious = conns.iter().filter(|c| is_suspicious(c)).count();
        if suspicious > 0 {
            println!("  {}", found(&format!("⚠ Suspicious: {suspicious} connection(s)")));
        }
        display_connections(&conns, args.suspicious, args.port);
        return Ok(());
    }

    // Watch mode
    loop {
        // Clear terminal
        print!("\x1b[2J\x1b[H");
        let conns = collect_all();
        print_banner(Module::NetMonitor);
        println!("  {} [watch mode — Ctrl+C to stop]",
                 info(&Local::now().format("%H:%M:%S").to_string()));
        display_connections(&conns, args.suspicious, args.port);
        tokio::time::sleep(Duration::from_secs(args.interval)).await;
    }
}

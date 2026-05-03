//! pscan — Async TCP port scanner
//! NuRichter · CySec Arsenal
//!
//! Usage:
//!   pscan -t 192.168.1.1
//!   pscan -t 10.0.0.0/24 -p 1-1000 --banner
//!   pscan -t target.com --top100 --timeout 500

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use arsenal_core::{banner::{print_banner, Module}, found, info, ok, warn};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    time::timeout,
};

/// Top 100 most common TCP ports
const TOP_100: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
    587, 631, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 5985,
    6379, 8080, 8443, 8888, 9090, 9200, 9300, 10000, 27017, 49152,
    20, 26, 69, 79, 88, 106, 179, 199, 389, 427, 444, 543, 544, 548,
    554, 646, 873, 990, 1025, 1028, 1029, 1110, 1720, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5666, 5800, 6000, 6001, 6646, 7070,
    8000, 8008, 9100, 9999, 32768, 49153, 49154, 49155, 49156,
    137, 138, 161, 162, 500, 514, 520,
];

static SERVICE_MAP: &[(u16, &str)] = &[
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (443, "HTTPS"), (445, "SMB"), (1433, "MSSQL"), (3306, "MySQL"),
    (3389, "RDP"), (5432, "PostgreSQL"), (5900, "VNC"),
    (6379, "Redis"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"),
    (9200, "Elasticsearch"), (27017, "MongoDB"),
];

#[derive(Parser, Debug)]
#[command(
    name = "pscan",
    about = "⚡ Async TCP Port Scanner — CySec Arsenal",
    long_about = None
)]
struct Args {
    /// Target IP, hostname, or CIDR (e.g. 10.0.0.0/24)
    #[arg(short, long)]
    target: String,

    /// Port range: "80", "1-1024", "80,443,8080" (default: 1-1024)
    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    /// Scan top 100 common ports
    #[arg(long)]
    top100: bool,

    /// Attempt banner grabbing on open ports
    #[arg(long)]
    banner: bool,

    /// Connection timeout in milliseconds
    #[arg(long, default_value_t = 800)]
    timeout: u64,

    /// Max concurrent connections
    #[arg(long, default_value_t = 500)]
    concurrency: usize,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Debug, serde::Serialize)]
struct OpenPort {
    host:    String,
    port:    u16,
    service: &'static str,
    banner:  Option<String>,
}

fn service_for(port: u16) -> &'static str {
    SERVICE_MAP
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, s)| *s)
        .unwrap_or("unknown")
}

fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = std::collections::BTreeSet::new();
    for part in spec.split(',') {
        let part = part.trim();
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a.parse().context("invalid port range start")?;
            let end:   u16 = b.parse().context("invalid port range end")?;
            ports.extend(start..=end);
        } else {
            ports.insert(part.parse::<u16>().context("invalid port")?);
        }
    }
    Ok(ports.into_iter().collect())
}

async fn grab_banner(addr: &str, port: u16, ms: u64) -> Option<String> {
    let stream = timeout(
        Duration::from_millis(ms + 1500),
        TcpStream::connect(format!("{addr}:{port}")),
    )
    .await
    .ok()??
    .ok()?;

    let (mut r, mut w) = stream.into_split();
    // Send HTTP probe
    let _ = w.write_all(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n").await;
    let mut buf = vec![0u8; 512];
    let n = timeout(Duration::from_millis(1500), r.read(&mut buf))
        .await
        .ok()??
        .ok()?;

    let raw = String::from_utf8_lossy(&buf[..n]);
    let first_line = raw.lines().next()?.trim().to_string();
    if first_line.is_empty() { None } else { Some(first_line) }
}

async fn scan_port(
    host: Arc<String>,
    port: u16,
    ms: u64,
    do_banner: bool,
    sem: Arc<Semaphore>,
) -> Option<OpenPort> {
    let _permit = sem.acquire().await.ok()?;
    let addr = format!("{}:{}", host, port);

    let connected = timeout(
        Duration::from_millis(ms),
        TcpStream::connect(&addr),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .is_some();

    if !connected {
        return None;
    }

    let banner = if do_banner {
        grab_banner(&host, port, ms).await
    } else {
        None
    };

    Some(OpenPort {
        host:    host.to_string(),
        port,
        service: service_for(port),
        banner,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    arsenal_core::logger::init();

    if !args.json {
        print_banner(Module::PortScanner);
        println!("  {}", info(&format!("Target  : {}", args.target)));
        println!("  {}", info(&format!("Timeout : {}ms", args.timeout)));
        println!("  {}", info(&format!("Threads : {}", args.concurrency)));
        println!();
    }

    let ports: Vec<u16> = if args.top100 {
        TOP_100.to_vec()
    } else {
        parse_ports(&args.ports)?
    };

    let sem  = Arc::new(Semaphore::new(args.concurrency));
    let host = Arc::new(args.target.clone());

    let pb = ProgressBar::new(ports.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  [{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ports")
            .unwrap(),
    );

    let mut tasks = Vec::with_capacity(ports.len());
    for port in &ports {
        let host = Arc::clone(&host);
        let sem  = Arc::clone(&sem);
        let port = *port;
        let ms   = args.timeout;
        let banner = args.banner;
        tasks.push(tokio::spawn(async move {
            scan_port(host, port, ms, banner, sem).await
        }));
    }

    let mut results: Vec<OpenPort> = Vec::new();
    for task in tasks {
        pb.inc(1);
        if let Ok(Some(open)) = task.await {
            if !args.json {
                let banner_str = open.banner.as_deref()
                    .map(|b| format!("  [{}]", b.dimmed()))
                    .unwrap_or_default();
                println!(
                    "\n  {} {}:{}/tcp  {}{}",
                    "[>]".bright_magenta().bold(),
                    open.host.bright_white(),
                    open.port.to_string().bright_yellow(),
                    open.service.bright_cyan(),
                    banner_str
                );
            }
            results.push(open);
        }
    }
    pb.finish_and_clear();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!(
            "\n  {}",
            ok(&format!("{} open port(s) found.", results.len()))
        );
    }

    Ok(())
}

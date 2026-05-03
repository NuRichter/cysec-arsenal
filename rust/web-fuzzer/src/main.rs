//! wfuzz — Async HTTP Fuzzer
//! NuRichter · CySec Arsenal
//!
//! Supports FUZZ placeholder substitution in URL path, params, or headers.
//!
//! Usage:
//!   wfuzz -u "http://target.ctf/FUZZ" -w wordlist.txt
//!   wfuzz -u "http://target.ctf/page?id=FUZZ" -w nums.txt --filter-code 200
//!   wfuzz -u "http://target.ctf/api/FUZZ" -w dirs.txt -t 100 --show-headers

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use arsenal_core::banner::{print_banner, Module};
use arsenal_core::{found, info, ok, warn};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;
use url::Url;

const FUZZ_MARKER: &str = "FUZZ";

#[derive(Parser, Debug)]
#[command(name = "wfuzz", about = "💥 HTTP Fuzzer — CySec Arsenal")]
struct Args {
    /// Target URL with FUZZ placeholder (e.g. http://target/FUZZ)
    #[arg(short = 'u', long)]
    url: String,

    /// Wordlist file
    #[arg(short, long)]
    wordlist: PathBuf,

    /// Number of concurrent requests
    #[arg(short = 't', long, default_value_t = 50)]
    threads: usize,

    /// Request timeout in milliseconds
    #[arg(long, default_value_t = 5000)]
    timeout: u64,

    /// Only show responses with these HTTP status codes (comma-separated)
    #[arg(long, default_value = "200,201,301,302,403")]
    filter_code: String,

    /// Hide responses with these codes (overrides filter-code)
    #[arg(long, default_value = "404")]
    hide_code: String,

    /// Minimum response size to show (bytes)
    #[arg(long, default_value_t = 0)]
    min_size: usize,

    /// HTTP method (GET, POST, HEAD)
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,

    /// Custom header (can be repeated): "X-Header: value"
    #[arg(long = "header", short = 'H')]
    headers: Vec<String>,

    /// POST body (FUZZ placeholder supported)
    #[arg(long)]
    data: Option<String>,

    /// Follow redirects
    #[arg(long)]
    follow: bool,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Debug, serde::Serialize)]
struct FuzzResult {
    payload:  String,
    url:      String,
    status:   u16,
    size:     usize,
    lines:    usize,
    words:    usize,
    redirect: Option<String>,
}

fn parse_codes(s: &str) -> Vec<u16> {
    s.split(',')
        .filter_map(|c| c.trim().parse().ok())
        .collect()
}

async fn fuzz_one(
    client:      Arc<reqwest::Client>,
    url_tmpl:    Arc<String>,
    body_tmpl:   Arc<Option<String>>,
    method:      Arc<String>,
    payload:     String,
    show_codes:  Arc<Vec<u16>>,
    hide_codes:  Arc<Vec<u16>>,
    min_size:    usize,
) -> Option<FuzzResult> {
    let url_str  = url_tmpl.replace(FUZZ_MARKER, &payload);
    let body_str = body_tmpl.as_ref().as_ref().map(|b| b.replace(FUZZ_MARKER, &payload));

    let req = match method.to_uppercase().as_str() {
        "POST" => {
            let b = body_str.unwrap_or_default();
            client.post(&url_str).body(b)
        }
        "HEAD" => client.head(&url_str),
        _      => client.get(&url_str),
    };

    let resp = req.send().await.ok()?;
    let status  = resp.status().as_u16();
    let redirect = resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if hide_codes.contains(&status) {
        return None;
    }
    if !show_codes.is_empty() && !show_codes.contains(&status) {
        return None;
    }

    let body  = resp.text().await.ok()?;
    let size  = body.len();
    if size < min_size { return None; }

    let lines = body.lines().count();
    let words = body.split_whitespace().count();

    Some(FuzzResult {
        payload,
        url: url_str,
        status,
        size,
        lines,
        words,
        redirect,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    arsenal_core::logger::init();

    if !args.json {
        print_banner(Module::WebFuzzer);
        println!("  {}", info(&format!("URL      : {}", args.url)));
        println!("  {}", info(&format!("Method   : {}", args.method)));
        println!("  {}", info(&format!("Threads  : {}", args.threads)));
        println!();
    }

    let wordlist = std::fs::read_to_string(&args.wordlist)
        .context("reading wordlist")?;
    let words: Vec<String> = wordlist
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let show_codes = Arc::new(parse_codes(&args.filter_code));
    let hide_codes = Arc::new(parse_codes(&args.hide_code));

    let mut headers = reqwest::header::HeaderMap::new();
    for h in &args.headers {
        if let Some((k, v)) = h.split_once(':') {
            if let (Ok(name), Ok(val)) = (
                k.trim().parse::<reqwest::header::HeaderName>(),
                v.trim().parse::<reqwest::header::HeaderValue>(),
            ) {
                headers.insert(name, val);
            }
        }
    }
    headers.insert("User-Agent", "Mozilla/5.0 (wfuzz/1.0 CTF)".parse().unwrap());

    let client = Arc::new(
        reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_millis(args.timeout))
            .redirect(if args.follow {
                reqwest::redirect::Policy::limited(5)
            } else {
                reqwest::redirect::Policy::none()
            })
            .danger_accept_invalid_certs(true)
            .build()?,
    );

    let url_tmpl  = Arc::new(args.url.clone());
    let body_tmpl = Arc::new(args.data.clone());
    let method    = Arc::new(args.method.clone());
    let sem       = Arc::new(Semaphore::new(args.threads));
    let min_size  = args.min_size;

    let pb = ProgressBar::new(words.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  [{elapsed}] {bar:40.yellow/black} {pos}/{len} reqs")
            .unwrap(),
    );

    if !args.json {
        println!(
            "  {:>6}  {:<8} {:<8} {:<8}  {}",
            "Status".bright_cyan(),
            "Size".bright_cyan(),
            "Lines".bright_cyan(),
            "Words".bright_cyan(),
            "Payload".bright_cyan()
        );
        println!("  {}", "─".repeat(60).dimmed());
    }

    let mut tasks = Vec::with_capacity(words.len());
    for payload in words {
        let client     = Arc::clone(&client);
        let url_tmpl   = Arc::clone(&url_tmpl);
        let body_tmpl  = Arc::clone(&body_tmpl);
        let method     = Arc::clone(&method);
        let show       = Arc::clone(&show_codes);
        let hide       = Arc::clone(&hide_codes);
        let sem        = Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            let _p = sem.acquire().await.ok()?;
            fuzz_one(client, url_tmpl, body_tmpl, method, payload, show, hide, min_size).await
        }));
    }

    let mut results = Vec::new();
    for task in tasks {
        pb.inc(1);
        if let Ok(Some(r)) = task.await {
            if !args.json {
                let status_colored = match r.status {
                    200..=299 => r.status.to_string().green().bold().to_string(),
                    300..=399 => r.status.to_string().yellow().to_string(),
                    400..=499 => r.status.to_string().red().to_string(),
                    _         => r.status.to_string().dimmed().to_string(),
                };
                print!("\r");
                println!(
                    "  {}  {:<8} {:<8} {:<8}  {}",
                    format!("{:>6}", status_colored),
                    r.size,
                    r.lines,
                    r.words,
                    r.payload.bright_white().bold()
                );
                if let Some(ref loc) = r.redirect {
                    println!("    └─ → {}", loc.dimmed());
                }
            }
            results.push(r);
        }
    }
    pb.finish_and_clear();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!(
            "\n  {}",
            ok(&format!("{} result(s) found.", results.len()))
        );
    }

    Ok(())
}

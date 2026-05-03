//! dbust — Async HTTP Directory & File Brute-Forcer
//! NuRichter · CySec Arsenal
//!
//! Usage:
//!   dbust -u http://target.ctf -w /usr/share/seclists/Discovery/Web-Content/common.txt
//!   dbust -u http://target.ctf -w wordlist.txt --ext php,html,txt -t 100
//!   dbust -u http://target.ctf -w wordlist.txt --recursive --depth 3

use std::{path::PathBuf, sync::Arc, time::Duration};
use anyhow::{Context, Result};
use arsenal_core::{banner::{print_banner, Module}, found, info, ok, warn};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;
use url::Url;

#[derive(Parser)]
#[command(name = "dbust", about = "💣 Dir Buster — CySec Arsenal")]
struct Args {
    #[arg(short = 'u', long)]             url:        String,
    #[arg(short, long)]                   wordlist:   PathBuf,
    /// Comma-separated extensions to append (e.g. php,html,txt)
    #[arg(long, default_value = "")]      ext:        String,
    /// Max concurrent requests
    #[arg(short = 't', long, default_value_t = 50)] threads: usize,
    /// Timeout (ms)
    #[arg(long, default_value_t = 5000)]  timeout:    u64,
    /// HTTP status codes to show (comma-separated)
    #[arg(long, default_value = "200,201,204,301,302,307,401,403")]
    show_codes: String,
    /// Follow redirects
    #[arg(long)]                          follow:     bool,
    /// Recursive scan (only on 301/302 redirects pointing to subdirs)
    #[arg(long)]                          recursive:  bool,
    /// Max recursion depth
    #[arg(long, default_value_t = 3)]     depth:      u32,
    /// JSON output
    #[arg(long)]                          json:       bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct DirResult {
    url:      String,
    status:   u16,
    size:     usize,
    redirect: Option<String>,
}

fn parse_codes(s: &str) -> Vec<u16> {
    s.split(',').filter_map(|c| c.trim().parse().ok()).collect()
}

async fn probe(
    client:     Arc<reqwest::Client>,
    url:        String,
    show_codes: Arc<Vec<u16>>,
) -> Option<DirResult> {
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    if !show_codes.contains(&status) { return None; }
    let redirect = resp.headers().get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = resp.text().await.ok()?;
    Some(DirResult { url, status, size: body.len(), redirect })
}

fn build_urls(base: &str, word: &str, exts: &[String]) -> Vec<String> {
    let base = base.trim_end_matches('/');
    let mut urls = vec![format!("{base}/{word}")];
    if !word.contains('.') {
        // also try with slash (directory)
        urls.push(format!("{base}/{word}/"));
        for ext in exts {
            urls.push(format!("{base}/{word}.{ext}"));
        }
    }
    urls
}

async fn bust(
    client:     Arc<reqwest::Client>,
    base_url:   String,
    words:      Arc<Vec<String>>,
    exts:       Arc<Vec<String>>,
    show_codes: Arc<Vec<u16>>,
    threads:    usize,
    json:       bool,
) -> Vec<DirResult> {
    let sem = Arc::new(Semaphore::new(threads));
    let total_urls = words.len() * (1 + exts.len() + 1); // rough estimate

    let pb = if !json {
        let pb = ProgressBar::new(words.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  [{elapsed}] {bar:40.blue/black} {pos}/{len}")
                .unwrap(),
        );
        Some(pb)
    } else {
        None
    };

    let mut tasks = Vec::with_capacity(total_urls);

    for word in words.iter() {
        for url in build_urls(&base_url, word, &exts) {
            let client = Arc::clone(&client);
            let show   = Arc::clone(&show_codes);
            let sem    = Arc::clone(&sem);
            tasks.push(tokio::spawn(async move {
                let _p = sem.acquire().await.ok()?;
                probe(client, url, show).await
            }));
        }
        if let Some(ref p) = pb { p.inc(1); }
    }

    let mut results = Vec::new();
    for task in tasks {
        if let Ok(Some(r)) = task.await {
            if !json {
                let status_col = match r.status {
                    200..=299 => r.status.to_string().bright_green().bold().to_string(),
                    301 | 302 | 307 => r.status.to_string().yellow().to_string(),
                    401 | 403 => r.status.to_string().red().to_string(),
                    _ => r.status.to_string().dimmed().to_string(),
                };
                print!("\r");
                println!(
                    "  {}  {:>8}B  {}{}",
                    format!("[{status_col}]"),
                    r.size,
                    r.url.bright_white().bold(),
                    r.redirect.as_deref().map(|l| format!("  → {}", l.dimmed())).unwrap_or_default()
                );
            }
            results.push(r);
        }
    }

    if let Some(pb) = pb { pb.finish_and_clear(); }
    results
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !args.json { print_banner(Module::DirBuster); }

    // Validate URL
    let base_url = args.url.trim_end_matches('/').to_string();
    let _ = Url::parse(&base_url).context("invalid URL")?;

    // Load wordlist
    let words = Arc::new(
        std::fs::read_to_string(&args.wordlist)
            .context("reading wordlist")?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect::<Vec<_>>()
    );

    let exts: Vec<String> = args.ext.split(',')
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect();
    let exts = Arc::new(exts);

    if !args.json {
        println!("  {}", info(&format!("Target  : {base_url}")));
        println!("  {}", info(&format!("Words   : {}", words.len())));
        println!("  {}", info(&format!("Ext     : {}", if exts.is_empty() { "(none)".into() } else { exts.join(",") })));
        println!("  {}", info(&format!("Threads : {}", args.threads)));
        println!();
    }

    let show_codes = Arc::new(parse_codes(&args.show_codes));

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_millis(args.timeout))
            .user_agent("Mozilla/5.0 (dbust/1.0 CTF)")
            .danger_accept_invalid_certs(true)
            .redirect(if args.follow {
                reqwest::redirect::Policy::limited(5)
            } else {
                reqwest::redirect::Policy::none()
            })
            .build()?,
    );

    let mut all_results = bust(
        Arc::clone(&client),
        base_url.clone(),
        Arc::clone(&words),
        Arc::clone(&exts),
        Arc::clone(&show_codes),
        args.threads,
        args.json,
    ).await;

    // Recursive busting on discovered directories
    if args.recursive && args.depth > 1 {
        let subdirs: Vec<String> = all_results.iter()
            .filter(|r| (r.status == 301 || r.status == 302 || r.url.ends_with('/'))
                && r.url != base_url)
            .map(|r| r.url.trim_end_matches('/').to_string())
            .collect();

        for subdir in subdirs.iter().take(10) { // cap at 10 subdirs
            if !args.json {
                println!("\n  {}", info(&format!("Recursing into: {subdir}")));
            }
            let sub_results = bust(
                Arc::clone(&client),
                subdir.clone(),
                Arc::clone(&words),
                Arc::clone(&exts),
                Arc::clone(&show_codes),
                args.threads,
                args.json,
            ).await;
            all_results.extend(sub_results);
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&all_results)?);
    } else {
        println!(
            "\n  {}",
            ok(&format!("{} path(s) found on {base_url}", all_results.len()))
        );
    }

    Ok(())
}

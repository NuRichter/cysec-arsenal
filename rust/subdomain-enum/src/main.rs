//! subenum — Subdomain enumeration tool
//! NuRichter · CySec Arsenal
//!
//! Sources:
//!   - crt.sh (certificate transparency — passive, no DNS)
//!   - DNS brute force (active, concurrent async resolves)
//!
//! Usage:
//!   subenum -d example.com
//!   subenum -d example.com -w wordlists/subdomains.txt --passive
//!   subenum -d example.com --json > results.json

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use arsenal_core::{
    banner::{print_banner, Module},
    found, info, ok, warn,
};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

const BUILTIN_WORDLIST: &[&str] = &[
    "www","mail","ftp","admin","api","dev","staging","test","beta","cdn",
    "static","assets","media","auth","login","portal","app","dashboard",
    "vpn","remote","ns1","ns2","smtp","pop","imap","webmail","shop",
    "store","blog","wiki","docs","support","help","status","monitor",
    "grafana","jenkins","git","gitlab","jira","confluence","internal",
    "intranet","corp","prod","uat","qa","ci","crm","erp","cloud",
    "backup","secure","server","mx","dns","ldap","sso","oauth","api2",
    "v1","v2","old","new","legacy","demo","test2","lab","research",
];

#[derive(Parser, Debug)]
#[command(name = "subenum", about = "🌐 Subdomain Enumerator — CySec Arsenal")]
struct Args {
    /// Target domain (e.g. example.com)
    #[arg(short, long)]
    domain: String,

    /// Custom wordlist file (one subdomain per line)
    #[arg(short, long)]
    wordlist: Option<PathBuf>,

    /// Passive only — crt.sh query, no DNS brute force
    #[arg(long)]
    passive: bool,

    /// Max concurrent DNS resolvers
    #[arg(long, default_value_t = 200)]
    concurrency: usize,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SubdomainResult {
    fqdn:   String,
    ips:    Vec<String>,
    source: String,
}

// ─── crt.sh ──────────────────────────────────────────────────────────────────

async fn crtsh_query(domain: &str) -> Result<Vec<String>> {
    let client = reqwest::Client::builder()
        .user_agent("cysec-arsenal/1.0")
        .timeout(std::time::Duration::from_secs(20))
        .build()?;

    let url = format!("https://crt.sh/?q=%.{domain}&output=json");
    let resp = client.get(&url).send().await?;
    let body: serde_json::Value = resp.json().await?;

    let mut names = std::collections::BTreeSet::new();
    if let Some(arr) = body.as_array() {
        for entry in arr {
            if let Some(name_val) = entry.get("name_value").and_then(|v| v.as_str()) {
                for line in name_val.lines() {
                    let clean = line.trim().trim_start_matches("*.");
                    if clean.ends_with(domain) && !clean.is_empty() {
                        names.insert(clean.to_lowercase());
                    }
                }
            }
        }
    }
    Ok(names.into_iter().collect())
}

// ─── DNS resolve ─────────────────────────────────────────────────────────────

async fn resolve(
    fqdn: String,
    resolver: Arc<TokioAsyncResolver>,
) -> Option<SubdomainResult> {
    match resolver.lookup_ip(fqdn.as_str()).await {
        Ok(lookup) => {
            let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
            Some(SubdomainResult { fqdn, ips, source: "dns-brute".to_string() })
        }
        Err(_) => None,
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    arsenal_core::logger::init();

    if !args.json {
        print_banner(Module::SubdomainEnum);
        println!("  {}", info(&format!("Domain : {}", args.domain)));
        println!("  {}", info(&format!("Mode   : {}", if args.passive { "passive" } else { "passive + active" })));
        println!();
    }

    let mut all: Vec<SubdomainResult> = Vec::new();

    // ── Passive: crt.sh ──────────────────────────────────────────────────────
    if !args.json { println!("{}", info("Querying crt.sh...")); }

    match crtsh_query(&args.domain).await {
        Ok(names) => {
            for name in &names {
                if !args.json {
                    println!("  {} [crt.sh] {}", "[>]".bright_magenta().bold(), name.bright_white());
                }
                all.push(SubdomainResult {
                    fqdn:   name.clone(),
                    ips:    vec![],
                    source: "crt.sh".to_string(),
                });
            }
            if !args.json {
                println!("{}", ok(&format!("{} names from crt.sh", names.len())));
            }
        }
        Err(e) => {
            if !args.json { println!("{}", warn(&format!("crt.sh failed: {e}"))); }
        }
    }

    // ── Active: DNS brute force ───────────────────────────────────────────────
    if !args.passive {
        let wordlist: Vec<String> = if let Some(path) = &args.wordlist {
            std::fs::read_to_string(path)
                .context("reading wordlist")?
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        } else {
            BUILTIN_WORDLIST.iter().map(|s| s.to_string()).collect()
        };

        if !args.json {
            println!("\n{}", info(&format!("DNS brute force: {} subdomains...", wordlist.len())));
        }

        let resolver = Arc::new(
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default())
        );
        let sem = Arc::new(Semaphore::new(args.concurrency));

        let pb = ProgressBar::new(wordlist.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  [{elapsed}] {bar:40.green/black} {pos}/{len}")
                .unwrap(),
        );

        let mut tasks = Vec::with_capacity(wordlist.len());
        for word in &wordlist {
            let fqdn = format!("{}.{}", word, args.domain);
            let res  = Arc::clone(&resolver);
            let sem  = Arc::clone(&sem);
            tasks.push(tokio::spawn(async move {
                let _p = sem.acquire().await.ok()?;
                resolve(fqdn, res).await
            }));
        }

        for task in tasks {
            pb.inc(1);
            if let Ok(Some(result)) = task.await {
                if !args.json {
                    println!(
                        "\n  {} {} → {}",
                        "[>]".bright_magenta().bold(),
                        result.fqdn.bright_white().bold(),
                        result.ips.join(", ").bright_yellow()
                    );
                }
                all.push(result);
            }
        }
        pb.finish_and_clear();
    }

    // ── Output ───────────────────────────────────────────────────────────────
    if args.json {
        println!("{}", serde_json::to_string_pretty(&all)?);
    } else {
        println!(
            "\n  {}",
            ok(&format!("{} subdomain(s) found.", all.len()))
        );
    }

    Ok(())
}

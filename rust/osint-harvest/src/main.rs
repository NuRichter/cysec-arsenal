//! osint — OSINT Harvester (passive APIs)
//! NuRichter · CySec Arsenal
//!
//! Sources: crt.sh · ip-api · Shodan InternetDB · HackerTarget DNS/WHOIS
//!
//! Usage:
//!   osint -d example.com
//!   osint -i 93.184.216.34
//!   osint -d example.com --no-whois --json

use std::time::Duration;
use anyhow::Result;
use arsenal_core::{banner::{print_banner, Module}, found, info, ok, warn};
use clap::Parser;
use colored::Colorize;
use serde_json::Value;

#[derive(Parser)]
#[command(name = "osint", about = "🔍 OSINT Harvester — CySec Arsenal")]
struct Args {
    #[arg(short, long)]  domain:   Option<String>,
    #[arg(short, long)]  ip:       Option<String>,
    #[arg(long)]         no_whois: bool,
    #[arg(long)]         json:     bool,
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("cysec-arsenal/1.0 (educational)")
        .build()
        .unwrap()
}

async fn get_text(url: &str) -> Option<String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("cysec-arsenal/1.0")
        .build()
        .ok()?
        .get(url)
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()
}

async fn get_json(url: &str) -> Option<Value> {
    let text = get_text(url).await?;
    serde_json::from_str(&text).ok()
}

// ─── Sources ──────────────────────────────────────────────────────────────────

async fn crtsh(domain: &str) -> Vec<String> {
    let url = format!("https://crt.sh/?q=%.{domain}&output=json");
    let Some(data) = get_json(&url).await else { return vec![] };
    let mut names = std::collections::BTreeSet::new();
    if let Some(arr) = data.as_array() {
        for entry in arr {
            if let Some(nv) = entry.get("name_value").and_then(|v| v.as_str()) {
                for line in nv.lines() {
                    let clean = line.trim().trim_start_matches("*.");
                    if clean.ends_with(domain) { names.insert(clean.to_lowercase()); }
                }
            }
        }
    }
    names.into_iter().collect()
}

async fn ip_api(ip: &str) -> Option<Value> {
    get_json(&format!("http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,reverse,lat,lon")).await
}

async fn shodan_internetdb(ip: &str) -> Option<Value> {
    get_json(&format!("https://internetdb.shodan.io/{ip}")).await
}

async fn hackertarget_dns(domain: &str) -> Option<String> {
    get_text(&format!("https://api.hackertarget.com/dnslookup/?q={domain}")).await
}

async fn hackertarget_whois(domain: &str) -> Option<String> {
    get_text(&format!("https://api.hackertarget.com/whois/?q={domain}")).await
}

async fn hackertarget_reverse(ip: &str) -> Option<String> {
    get_text(&format!("https://api.hackertarget.com/reversedns/?q={ip}")).await
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !args.json { print_banner(Module::OsintHarvest); }

    let mut output = serde_json::Map::new();

    // Resolve domain → IP
    let target_ip: Option<String> = args.ip.clone().or_else(|| {
        args.domain.as_ref().and_then(|d| {
            std::net::ToSocketAddrs::to_socket_addrs(&format!("{d}:80"))
                .ok()
                .and_then(|mut a| a.next())
                .map(|s| s.ip().to_string())
        })
    });

    // ── Domain intel ────────────────────────────────────────────────────────
    if let Some(ref domain) = args.domain {
        if !args.json {
            println!("{}", info(&format!("Domain: {domain}")));
            if let Some(ref ip) = target_ip {
                println!("{}", info(&format!("Resolved: {ip}")));
            }
            println!();
        }

        // crt.sh
        println!("{}", info("crt.sh certificate transparency..."));
        let crt_names = crtsh(domain).await;
        if !args.json {
            for n in &crt_names {
                println!("  {} {}", "[>]".bright_magenta().bold(), n.bright_white());
            }
            println!("{}", ok(&format!("{} cert entries", crt_names.len())));
            println!();
        }
        output.insert("crtsh".into(), serde_json::json!(crt_names));

        // DNS
        println!("{}", info("DNS records (HackerTarget)..."));
        if let Some(dns) = hackertarget_dns(domain).await {
            if !args.json { println!("{dns}"); }
            output.insert("dns".into(), dns.into());
        }

        // WHOIS
        if !args.no_whois {
            println!("{}", info("WHOIS..."));
            if let Some(whois) = hackertarget_whois(domain).await {
                if !args.json { println!("{}", &whois[..whois.len().min(1500)]); }
                output.insert("whois".into(), whois.into());
            }
        }
    }

    // ── IP intel ────────────────────────────────────────────────────────────
    if let Some(ref ip) = target_ip {
        if !args.json { println!("\n{}", info(&format!("IP: {ip}"))); }

        // GeoIP
        if let Some(geo) = ip_api(ip).await {
            if !args.json {
                println!("{}", info("GeoIP (ip-api.com):"));
                for (k, v) in geo.as_object().unwrap_or(&serde_json::Map::new()) {
                    if k != "status" {
                        println!("  {:<12} : {}", k.bright_cyan(), v.to_string().trim_matches('"').bright_white());
                    }
                }
            }
            output.insert("geoip".into(), geo);
        }

        // Reverse DNS
        if let Some(rdns) = hackertarget_reverse(ip).await {
            if !args.json { println!("\n{}\n{rdns}", info("Reverse DNS:")); }
            output.insert("reverse_dns".into(), rdns.into());
        }

        // Shodan InternetDB
        if let Some(shodan) = shodan_internetdb(ip).await {
            if !args.json {
                println!("{}", info("Shodan InternetDB:"));
                if let Some(ports) = shodan.get("ports") {
                    println!("  Ports : {ports}");
                }
                if let Some(vulns) = shodan.get("vulns") {
                    if !vulns.as_array().map(|a| a.is_empty()).unwrap_or(true) {
                        println!("  {}", found(&format!("Vulns : {vulns}")));
                    }
                }
                if let Some(tags) = shodan.get("tags") {
                    println!("  Tags  : {tags}");
                }
            }
            output.insert("shodan".into(), shodan);
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("\n{}", ok("OSINT harvest complete."));
    }

    Ok(())
}

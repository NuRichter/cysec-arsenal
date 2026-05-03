//! colors.rs — Terminal output helpers using `colored`
//! NuRichter · CySec Arsenal

use colored::Colorize;

/// `[+]` green — success
pub fn ok(msg: &str) -> String {
    format!("{} {}", "[+]".green().bold(), msg)
}

/// `[-]` red — error / not found
pub fn err(msg: &str) -> String {
    format!("{} {}", "[-]".red().bold(), msg)
}

/// `[!]` yellow — warning
pub fn warn(msg: &str) -> String {
    format!("{} {}", "[!]".yellow().bold(), msg)
}

/// `[*]` cyan — informational
pub fn info(msg: &str) -> String {
    format!("{} {}", "[*]".cyan().bold(), msg)
}

/// `[>]` orange/magenta — found something interesting
pub fn found(msg: &str) -> String {
    format!("{} {}", "[>]".bright_magenta().bold(), msg.bright_white().bold())
}

/// Separator line
pub fn sep(width: usize) -> String {
    "─".repeat(width).dimmed().to_string()
}

/// Print a labelled key-value row
pub fn kv(key: &str, val: &str) {
    println!("  {:<18} {}", key.bright_cyan(), val);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_contains_plus() {
        assert!(ok("test").contains("[+]"));
    }

    #[test]
    fn err_contains_minus() {
        assert!(err("test").contains("[-]"));
    }

    #[test]
    fn found_contains_arrow() {
        assert!(found("test").contains("[>]"));
    }
}

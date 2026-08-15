use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use frog_token_usage_core::{scan, ScanConfig, TokenUsage, UsageReport};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "frog-token-usage",
    version,
    about = "Offline usage insights from local agent session logs",
    after_help = "This reports local recorded usage, not provider billing or quota. It never reads credentials or uploads session data."
)]
struct Args {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format: Format,

    /// Override the Codex configuration root (sessions/ and archived_sessions/).
    #[arg(long)]
    codex_home: Option<PathBuf>,

    /// Override the Claude Code configuration root (projects/).
    #[arg(long)]
    claude_config_dir: Option<PathBuf>,

    /// Do not scan Codex logs.
    #[arg(long)]
    no_codex: bool,

    /// Do not scan Claude Code logs.
    #[arg(long)]
    no_claude: bool,

    /// Maximum number of JSONL files scanned across all sources.
    #[arg(long)]
    max_files: Option<usize>,

    /// Maximum accepted size of one session file in bytes.
    #[arg(long)]
    max_file_bytes: Option<u64>,

    /// Maximum accepted size of one JSONL record in bytes.
    #[arg(long)]
    max_line_bytes: Option<usize>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Json,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.no_codex && args.no_claude {
        bail!("both data sources are disabled");
    }

    let mut config = ScanConfig::from_environment();
    if let Some(root) = args.codex_home {
        config.codex_roots = vec![root.join("sessions"), root.join("archived_sessions")];
    }
    if let Some(root) = args.claude_config_dir {
        config.claude_roots = vec![root.join("projects")];
    }
    if args.no_codex {
        config.codex_roots.clear();
    }
    if args.no_claude {
        config.claude_roots.clear();
    }
    if let Some(value) = args.max_files {
        config.max_files = value;
    }
    if let Some(value) = args.max_file_bytes {
        config.max_file_bytes = value;
    }
    if let Some(value) = args.max_line_bytes {
        config.max_line_bytes = value;
    }

    let report = scan(&config).context("usage scan failed")?;
    match args.format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        Format::Table => print_table(&report),
    }
    Ok(())
}

fn print_table(report: &UsageReport) {
    println!("Local recorded usage — not billing or quota truth");
    println!();
    println!("{:<14} {:<28} {:>14}", "SOURCE", "MODEL", "TOKENS");
    for group in &report.by_source_and_model {
        println!(
            "{:<14} {:<28} {:>14}",
            group.source,
            truncate(&group.model, 28),
            grouped_number(group.total_tokens)
        );
    }
    if report.by_source_and_model.is_empty() {
        println!("{:<14} {:<28} {:>14}", "—", "No supported records", "0");
    }
    println!();
    println!("Total {}", grouped_number(report.total_tokens));
    print_breakdown(report.totals);
    println!(
        "Measurement: reported={} · derived={} · estimated={}",
        report.measurement.reported, report.measurement.derived, report.measurement.estimated
    );
    println!(
        "Scanned {} files; skipped {} symlinks, {} oversized files, {} partial tails.",
        report.scan.scanned_files,
        report.scan.skipped_symlinks,
        report.scan.skipped_oversized_files,
        report.scan.partial_tail_lines
    );
}

fn print_breakdown(usage: TokenUsage) {
    println!(
        "Input {} · output {} · cache read {} · cache write {} · reasoning {}",
        grouped_number(usage.input),
        grouped_number(usage.output),
        grouped_number(usage.cache_read),
        grouped_number(usage.cache_write),
        grouped_number(usage.reasoning)
    );
}

fn grouped_number(value: u64) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            output.push(',');
        }
        output.push(character);
    }
    output
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    value
        .chars()
        .take(width.saturating_sub(1))
        .chain(['…'])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_grouped_numbers() {
        assert_eq!(grouped_number(0), "0");
        assert_eq!(grouped_number(999), "999");
        assert_eq!(grouped_number(12_345_678), "12,345,678");
    }

    #[test]
    fn truncates_by_character_not_byte() {
        assert_eq!(truncate("abcdefgh", 5), "abcd…");
        assert_eq!(truncate("令牌用量", 4), "令牌用量");
    }
}

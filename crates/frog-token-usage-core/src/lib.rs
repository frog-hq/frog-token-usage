//! Auditable, offline token-usage summaries from local agent session logs.
//!
//! This crate never reads credentials and never emits prompts, responses, or
//! workspace paths. Its output is local recorded usage, not billing truth.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use thiserror::Error;
use walkdir::WalkDir;

const DEFAULT_MAX_FILES: usize = 20_000;
const DEFAULT_MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_LINE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub codex_roots: Vec<PathBuf>,
    pub claude_roots: Vec<PathBuf>,
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_line_bytes: usize,
}

impl ScanConfig {
    pub fn from_environment() -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let codex_home = std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|path| path.join(".codex")));
        let claude_home = std::env::var_os("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|path| path.join(".claude")));

        Self {
            codex_roots: codex_home
                .map(|root| vec![root.join("sessions"), root.join("archived_sessions")])
                .unwrap_or_default(),
            claude_roots: claude_home
                .map(|root| vec![root.join("projects")])
                .unwrap_or_default(),
            max_files: DEFAULT_MAX_FILES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self::from_environment()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub reasoning: u64,
}

impl TokenUsage {
    pub fn total(self) -> u64 {
        self.input
            .saturating_add(self.output)
            .saturating_add(self.cache_read)
            .saturating_add(self.cache_write)
            .saturating_add(self.reasoning)
    }

    fn saturating_add(self, rhs: Self) -> Self {
        Self {
            input: self.input.saturating_add(rhs.input),
            output: self.output.saturating_add(rhs.output),
            cache_read: self.cache_read.saturating_add(rhs.cache_read),
            cache_write: self.cache_write.saturating_add(rhs.cache_write),
            reasoning: self.reasoning.saturating_add(rhs.reasoning),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageGroup {
    pub source: String,
    pub model: String,
    pub measurement: MeasurementProvenance,
    pub usage: TokenUsage,
    pub total_tokens: u64,
}

/// Describes how aggregate values were obtained without implying billing truth.
/// `estimated` is reserved for a future, separately labelled cost model and is
/// always false for the local-log scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementProvenance {
    pub reported: bool,
    pub derived: bool,
    pub estimated: bool,
}

impl MeasurementProvenance {
    const fn reported() -> Self {
        Self {
            reported: true,
            derived: false,
            estimated: false,
        }
    }

    const fn derived() -> Self {
        Self {
            reported: false,
            derived: true,
            estimated: false,
        }
    }

    const fn merge(self, rhs: Self) -> Self {
        Self {
            reported: self.reported || rhs.reported,
            derived: self.derived || rhs.derived,
            estimated: self.estimated || rhs.estimated,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scanned_files: usize,
    pub skipped_symlinks: usize,
    pub skipped_oversized_files: usize,
    pub skipped_over_limit_files: usize,
    pub malformed_lines: usize,
    pub oversized_lines: usize,
    pub partial_tail_lines: usize,
    pub duplicate_events: usize,
    pub duplicate_sessions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageReport {
    pub schema_version: u32,
    pub scope: String,
    pub billing_authoritative: bool,
    pub calculation: String,
    pub measurement: MeasurementProvenance,
    pub totals: TokenUsage,
    pub total_tokens: u64,
    pub by_source_and_model: Vec<UsageGroup>,
    pub scan: ScanSummary,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("invalid scan limit: {0}")]
    InvalidLimit(&'static str),
    #[error("could not read {kind} session data: {source}")]
    Io {
        kind: &'static str,
        #[source]
        source: io::Error,
    },
}

pub fn scan(config: &ScanConfig) -> Result<UsageReport, ScanError> {
    validate_limits(config)?;
    let mut summary = ScanSummary::default();
    let mut sessions: HashMap<(Source, String), ParsedFile> = HashMap::new();
    let mut candidates = Vec::new();
    collect_candidates(
        Source::Codex,
        &config.codex_roots,
        &mut summary,
        &mut candidates,
    );
    collect_candidates(
        Source::ClaudeCode,
        &config.claude_roots,
        &mut summary,
        &mut candidates,
    );
    candidates.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.path.cmp(&right.path))
    });

    for (index, candidate) in candidates.into_iter().enumerate() {
        if index >= config.max_files {
            summary.skipped_over_limit_files = summary.skipped_over_limit_files.saturating_add(1);
            continue;
        }
        scan_candidate(candidate, config, &mut summary, &mut sessions)?;
    }

    let mut grouped: BTreeMap<(Source, String), MeasuredUsage> = BTreeMap::new();
    for parsed in sessions.into_values() {
        for (model, measured) in parsed.by_model {
            let slot = grouped.entry((parsed.source, model)).or_default();
            *slot = slot.saturating_add(measured);
        }
    }

    let mut totals = TokenUsage::default();
    let mut measurement = MeasurementProvenance::default();
    let by_source_and_model = grouped
        .into_iter()
        .map(|((source, model), measured)| {
            totals = totals.saturating_add(measured.usage);
            measurement = measurement.merge(measured.measurement);
            UsageGroup {
                source: source.as_str().to_owned(),
                model,
                measurement: measured.measurement,
                total_tokens: measured.usage.total(),
                usage: measured.usage,
            }
        })
        .collect();

    Ok(UsageReport {
        schema_version: 1,
        scope: "local_session_logs".to_owned(),
        billing_authoritative: false,
        calculation: "reported_or_derived_from_reported_local_events".to_owned(),
        measurement,
        total_tokens: totals.total(),
        totals,
        by_source_and_model,
        scan: summary,
    })
}

fn validate_limits(config: &ScanConfig) -> Result<(), ScanError> {
    if config.max_files == 0 {
        return Err(ScanError::InvalidLimit(
            "max_files must be greater than zero",
        ));
    }
    if config.max_file_bytes == 0 {
        return Err(ScanError::InvalidLimit(
            "max_file_bytes must be greater than zero",
        ));
    }
    if config.max_line_bytes < 2 {
        return Err(ScanError::InvalidLimit(
            "max_line_bytes must be at least two bytes",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Source {
    Codex,
    ClaudeCode,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude_code",
        }
    }
}

#[derive(Debug)]
struct ParsedFile {
    source: Source,
    session_id: String,
    modified: SystemTime,
    by_model: BTreeMap<String, MeasuredUsage>,
}

#[derive(Debug)]
struct FileCandidate {
    source: Source,
    path: PathBuf,
    modified: SystemTime,
}

fn collect_candidates(
    source: Source,
    roots: &[PathBuf],
    summary: &mut ScanSummary,
    candidates: &mut Vec<FileCandidate>,
) {
    for root in roots {
        if !root.exists() {
            continue;
        }
        for entry in WalkDir::new(root).follow_links(false).into_iter() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    if error.io_error().is_some() {
                        continue;
                    }
                    continue;
                }
            };
            if entry.file_type().is_symlink() {
                summary.skipped_symlinks = summary.skipped_symlinks.saturating_add(1);
                continue;
            }
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|value| value.to_str()) == Some("jsonl")
            {
                let path = entry.into_path();
                let Ok(metadata) = fs::symlink_metadata(&path) else {
                    continue;
                };
                if metadata.file_type().is_symlink() {
                    summary.skipped_symlinks = summary.skipped_symlinks.saturating_add(1);
                    continue;
                }
                candidates.push(FileCandidate {
                    source,
                    path,
                    modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                });
            }
        }
    }
}

fn scan_candidate(
    candidate: FileCandidate,
    config: &ScanConfig,
    summary: &mut ScanSummary,
    sessions: &mut HashMap<(Source, String), ParsedFile>,
) -> Result<(), ScanError> {
    let metadata = match fs::symlink_metadata(&candidate.path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(()),
    };
    if metadata.file_type().is_symlink() {
        summary.skipped_symlinks = summary.skipped_symlinks.saturating_add(1);
        return Ok(());
    }
    if metadata.len() > config.max_file_bytes {
        summary.skipped_oversized_files = summary.skipped_oversized_files.saturating_add(1);
        return Ok(());
    }

    let parsed = parse_file(
        candidate.source,
        &candidate.path,
        metadata.modified().unwrap_or(candidate.modified),
        config,
        summary,
    )?;
    summary.scanned_files = summary.scanned_files.saturating_add(1);
    let key = (candidate.source, parsed.session_id.clone());
    match sessions.entry(key) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(parsed);
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            summary.duplicate_sessions = summary.duplicate_sessions.saturating_add(1);
            if parsed.modified > entry.get().modified {
                entry.insert(parsed);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
struct MeasuredUsage {
    usage: TokenUsage,
    measurement: MeasurementProvenance,
}

impl MeasuredUsage {
    fn saturating_add(self, rhs: Self) -> Self {
        Self {
            usage: self.usage.saturating_add(rhs.usage),
            measurement: self.measurement.merge(rhs.measurement),
        }
    }
}

fn parse_file(
    source: Source,
    path: &Path,
    modified: SystemTime,
    config: &ScanConfig,
    summary: &mut ScanSummary,
) -> Result<ParsedFile, ScanError> {
    let file = open_session_file(path).map_err(|source_error| ScanError::Io {
        kind: source.as_str(),
        source: source_error,
    })?;
    let mut reader = BufReader::new(file);
    let mut parser = FileParser::new(source, fallback_session_id(path));

    loop {
        match read_bounded_line(&mut reader, config.max_line_bytes).map_err(|source_error| {
            ScanError::Io {
                kind: source.as_str(),
                source: source_error,
            }
        })? {
            BoundedLine::Complete(line) => {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                match serde_json::from_slice::<Value>(&line) {
                    Ok(value) => parser.observe(&value, summary),
                    Err(_) => summary.malformed_lines = summary.malformed_lines.saturating_add(1),
                }
            }
            BoundedLine::Oversized => {
                summary.oversized_lines = summary.oversized_lines.saturating_add(1)
            }
            BoundedLine::PartialTail => {
                summary.partial_tail_lines = summary.partial_tail_lines.saturating_add(1);
                break;
            }
            BoundedLine::Eof => break,
        }
    }

    Ok(parser.finish(modified))
}

fn open_session_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

enum BoundedLine {
    Complete(Vec<u8>),
    Oversized,
    PartialTail,
    Eof,
}

fn read_bounded_line<R: BufRead>(reader: &mut R, max_bytes: usize) -> io::Result<BoundedLine> {
    let mut line = Vec::with_capacity(4096.min(max_bytes));
    let mut oversized = false;
    let mut saw_bytes = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(if !saw_bytes {
                BoundedLine::Eof
            } else if oversized {
                BoundedLine::Oversized
            } else {
                BoundedLine::PartialTail
            });
        }
        saw_bytes = true;
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        let payload_len = newline.unwrap_or(buffer.len());
        if !oversized {
            if line.len().saturating_add(payload_len) > max_bytes {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(&buffer[..payload_len]);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(if oversized {
                BoundedLine::Oversized
            } else {
                BoundedLine::Complete(line)
            });
        }
    }
}

struct FileParser {
    source: Source,
    session_id: String,
    model: String,
    by_model: BTreeMap<String, MeasuredUsage>,
    codex_counter: CodexCounter,
    codex_token_events: usize,
    codex_completed: BTreeMap<String, MeasuredUsage>,
    seen_claude_events: HashSet<String>,
}

impl FileParser {
    fn new(source: Source, session_id: String) -> Self {
        Self {
            source,
            session_id,
            model: "unknown".to_owned(),
            by_model: BTreeMap::new(),
            codex_counter: CodexCounter::default(),
            codex_token_events: 0,
            codex_completed: BTreeMap::new(),
            seen_claude_events: HashSet::new(),
        }
    }

    fn observe(&mut self, value: &Value, summary: &mut ScanSummary) {
        match self.source {
            Source::Codex => self.observe_codex(value),
            Source::ClaudeCode => self.observe_claude(value, summary),
        }
    }

    fn observe_codex(&mut self, value: &Value) {
        let entry_type = string_at(value, &["type"]);
        let payload = value.get("payload").unwrap_or(value);

        if entry_type == Some("session_meta") {
            if let Some(id) = string_at(payload, &["id"]).filter(|id| !id.is_empty()) {
                self.session_id = id.to_owned();
            }
        }
        if let Some(model) = first_string(
            payload,
            &[&["model"], &["model_name"], &["model_info", "slug"]],
        ) {
            self.model = normalise_model(model);
        }

        let payload_type = string_at(payload, &["type"]);
        if entry_type == Some("event_msg") && payload_type == Some("token_count") {
            let Some(info) = payload.get("info") else {
                return;
            };
            if let Some(model) = first_string(info, &[&["model"], &["model_name"]]) {
                self.model = normalise_model(model);
            }
            let last = info.get("last_token_usage").and_then(RawUsage::from_value);
            let total = info.get("total_token_usage").and_then(RawUsage::from_value);
            if let Some(observed) = self.codex_counter.observe(last, total) {
                self.add_usage(observed.usage.normalised_codex(), observed.measurement);
                self.codex_token_events = self.codex_token_events.saturating_add(1);
            }
            return;
        }

        if entry_type == Some("turn.completed") || payload_type == Some("turn.completed") {
            if let Some(usage) = value
                .get("usage")
                .or_else(|| payload.get("usage"))
                .and_then(RawUsage::from_value)
            {
                let model = self.model.clone();
                let slot = self.codex_completed.entry(model).or_default();
                *slot = slot.saturating_add(MeasuredUsage {
                    usage: usage.normalised_codex(),
                    measurement: MeasurementProvenance::reported(),
                });
            }
        }
    }

    fn observe_claude(&mut self, value: &Value, summary: &mut ScanSummary) {
        if string_at(value, &["type"]) != Some("assistant") {
            return;
        }
        let Some(message) = value.get("message") else {
            return;
        };
        let Some(raw) = message.get("usage").and_then(RawUsage::from_value) else {
            return;
        };
        let model = string_at(message, &["model"])
            .map(normalise_model)
            .unwrap_or_else(|| "unknown".to_owned());
        let request_id = string_at(value, &["requestId"]);
        let message_id = string_at(message, &["id"]);
        if let (Some(request_id), Some(message_id)) = (request_id, message_id) {
            let key = format!("{request_id}\u{1f}{message_id}");
            if !self.seen_claude_events.insert(key) {
                summary.duplicate_events = summary.duplicate_events.saturating_add(1);
                return;
            }
        }
        let slot = self.by_model.entry(model).or_default();
        *slot = slot.saturating_add(MeasuredUsage {
            usage: raw.normalised_claude(),
            measurement: MeasurementProvenance::reported(),
        });
    }

    fn add_usage(&mut self, usage: TokenUsage, measurement: MeasurementProvenance) {
        let slot = self.by_model.entry(self.model.clone()).or_default();
        *slot = slot.saturating_add(MeasuredUsage { usage, measurement });
    }

    fn finish(mut self, modified: SystemTime) -> ParsedFile {
        if self.source == Source::Codex && self.codex_token_events == 0 {
            self.by_model = self.codex_completed;
        }
        ParsedFile {
            source: self.source,
            session_id: self.session_id,
            modified,
            by_model: self.by_model,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RawUsage {
    input: u64,
    output: u64,
    cached: u64,
    cache_write: u64,
    reasoning: u64,
}

impl RawUsage {
    fn from_value(value: &Value) -> Option<Self> {
        let usage = Self {
            input: nonnegative_u64(value.get("input_tokens")),
            output: nonnegative_u64(value.get("output_tokens")),
            cached: nonnegative_u64(value.get("cached_input_tokens"))
                .max(nonnegative_u64(value.get("cache_read_input_tokens"))),
            cache_write: nonnegative_u64(value.get("cache_creation_input_tokens")),
            reasoning: nonnegative_u64(value.get("reasoning_output_tokens")),
        };
        (usage.total() > 0).then_some(usage)
    }

    fn total(self) -> u64 {
        self.input
            .saturating_add(self.output)
            .saturating_add(self.cached)
            .saturating_add(self.cache_write)
            .saturating_add(self.reasoning)
    }

    fn componentwise_delta(self, previous: Self) -> Option<Self> {
        Some(Self {
            input: self.input.checked_sub(previous.input)?,
            output: self.output.checked_sub(previous.output)?,
            cached: self.cached.checked_sub(previous.cached)?,
            cache_write: self.cache_write.checked_sub(previous.cache_write)?,
            reasoning: self.reasoning.checked_sub(previous.reasoning)?,
        })
    }

    fn normalised_codex(self) -> TokenUsage {
        let cached = self.cached.min(self.input);
        TokenUsage {
            input: self.input.saturating_sub(cached),
            output: self.output,
            cache_read: cached,
            cache_write: 0,
            reasoning: self.reasoning,
        }
    }

    fn normalised_claude(self) -> TokenUsage {
        TokenUsage {
            input: self.input,
            output: self.output,
            cache_read: self.cached,
            cache_write: self.cache_write,
            reasoning: self.reasoning,
        }
    }

    fn looks_like_stale_regression(self, previous: Self, last: Self) -> bool {
        let current_total = self.total();
        let previous_total = previous.total();
        let last_total = last.total();
        previous_total > 0
            && current_total > 0
            && last_total > 0
            && (current_total.saturating_mul(100) >= previous_total.saturating_mul(98)
                || current_total.saturating_add(last_total.saturating_mul(2)) >= previous_total)
    }
}

#[derive(Default)]
struct CodexCounter {
    previous_total: Option<RawUsage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservedUsage {
    usage: RawUsage,
    measurement: MeasurementProvenance,
}

impl CodexCounter {
    fn observe(
        &mut self,
        last: Option<RawUsage>,
        total: Option<RawUsage>,
    ) -> Option<ObservedUsage> {
        let accepted = match (self.previous_total, last, total) {
            (None, Some(last), Some(total)) => {
                self.previous_total = Some(total);
                Some((last, MeasurementProvenance::reported()))
            }
            (None, Some(last), None) => Some((last, MeasurementProvenance::reported())),
            (None, None, Some(total)) => {
                self.previous_total = Some(total);
                Some((total, MeasurementProvenance::reported()))
            }
            (None, None, None) => None,
            (Some(previous), last, Some(total)) => match total.componentwise_delta(previous) {
                Some(delta) => {
                    self.previous_total = Some(total);
                    (delta.total() > 0).then_some((delta, MeasurementProvenance::derived()))
                }
                None if last
                    .is_some_and(|last| total.looks_like_stale_regression(previous, last)) =>
                {
                    None
                }
                None => {
                    self.previous_total = Some(total);
                    last.map(|usage| (usage, MeasurementProvenance::reported()))
                }
            },
            (Some(_), Some(last), None) => Some((last, MeasurementProvenance::reported())),
            (Some(_), None, None) => None,
        };
        accepted
            .filter(|(usage, _)| usage.total() > 0)
            .map(|(usage, measurement)| ObservedUsage { usage, measurement })
    }
}

fn nonnegative_u64(value: Option<&Value>) -> u64 {
    value
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().map(|v| v.max(0) as u64))
        })
        .unwrap_or(0)
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_str()
}

fn first_string<'a>(value: &'a Value, paths: &[&[&str]]) -> Option<&'a str> {
    paths.iter().find_map(|path| string_at(value, path))
}

fn normalise_model(model: &str) -> String {
    let trimmed = model.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) || trimmed.len() > 128 {
        "unknown".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn fallback_session_id(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_reader_rejects_large_and_partial_lines() {
        let mut reader = Cursor::new(b"123456\nok\npartial".to_vec());
        assert!(matches!(
            read_bounded_line(&mut reader, 4).unwrap(),
            BoundedLine::Oversized
        ));
        assert!(
            matches!(read_bounded_line(&mut reader, 4).unwrap(), BoundedLine::Complete(line) if line == b"ok")
        );
        assert!(matches!(
            read_bounded_line(&mut reader, 8).unwrap(),
            BoundedLine::PartialTail
        ));
    }

    #[test]
    fn codex_counter_uses_deltas_and_ignores_duplicate_totals() {
        let a = RawUsage {
            input: 100,
            output: 10,
            cached: 20,
            ..RawUsage::default()
        };
        let b = RawUsage {
            input: 150,
            output: 15,
            cached: 30,
            ..RawUsage::default()
        };
        let last = RawUsage {
            input: 50,
            output: 5,
            cached: 10,
            ..RawUsage::default()
        };
        let mut counter = CodexCounter::default();
        let first = counter.observe(Some(a), Some(a)).unwrap();
        assert_eq!(first.usage, a);
        assert_eq!(first.measurement, MeasurementProvenance::reported());
        let second = counter.observe(Some(last), Some(b)).unwrap();
        assert_eq!(second.usage, last);
        assert_eq!(second.measurement, MeasurementProvenance::derived());
        assert_eq!(counter.observe(Some(last), Some(b)), None);
    }
}

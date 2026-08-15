use frog_token_usage_core::{scan, MeasurementProvenance, ScanConfig, TokenUsage};
use std::fs::{self, File, FileTimes};
use std::time::{Duration, SystemTime};
use tempfile::tempdir;

fn config(codex: &std::path::Path, claude: &std::path::Path) -> ScanConfig {
    ScanConfig {
        codex_roots: vec![codex.to_owned()],
        claude_roots: vec![claude.to_owned()],
        max_files: 100,
        max_file_bytes: 1024 * 1024,
        max_line_bytes: 4096,
    }
}

#[test]
fn scans_supported_logs_without_exposing_content() {
    let root = tempdir().unwrap();
    let codex = root.path().join("codex");
    let claude = root.path().join("claude");
    fs::create_dir_all(&codex).unwrap();
    fs::create_dir_all(&claude).unwrap();
    fs::write(
        codex.join("session.jsonl"),
        concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"codex-1\",\"model\":\"gpt-test\",\"cwd\":\"/private/secret\"}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"message\":\"do not expose me\",\"info\":{\"last_token_usage\":{\"input_tokens\":100,\"cached_input_tokens\":40,\"output_tokens\":10},\"total_token_usage\":{\"input_tokens\":100,\"cached_input_tokens\":40,\"output_tokens\":10}}}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"last_token_usage\":{\"input_tokens\":50,\"cached_input_tokens\":10,\"output_tokens\":5},\"total_token_usage\":{\"input_tokens\":150,\"cached_input_tokens\":50,\"output_tokens\":15}}}}\n",
        ),
    )
    .unwrap();
    fs::write(
        claude.join("session.jsonl"),
        concat!(
            "{\"type\":\"assistant\",\"requestId\":\"req-1\",\"message\":{\"id\":\"msg-1\",\"model\":\"claude-test\",\"usage\":{\"input_tokens\":20,\"output_tokens\":4,\"cache_read_input_tokens\":3,\"cache_creation_input_tokens\":2},\"content\":\"private\"}}\n",
            "{\"type\":\"assistant\",\"requestId\":\"req-1\",\"message\":{\"id\":\"msg-1\",\"model\":\"claude-test\",\"usage\":{\"input_tokens\":20,\"output_tokens\":4}}}\n",
            "{\"type\":\"assistant\",\"message\":{\"model\":\"claude-test\",\"usage\":{\"input_tokens\":1",
        ),
    )
    .unwrap();

    let report = scan(&config(&codex, &claude)).unwrap();
    assert_eq!(
        report.totals,
        TokenUsage {
            input: 120,
            output: 19,
            cache_read: 53,
            cache_write: 2,
            reasoning: 0
        }
    );
    assert_eq!(report.scan.duplicate_events, 1);
    assert_eq!(report.scan.partial_tail_lines, 1);
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("private"));
    assert!(!json.contains("secret"));
    assert!(!report.billing_authoritative);
    assert_eq!(
        report.measurement,
        MeasurementProvenance {
            reported: true,
            derived: true,
            estimated: false,
        }
    );
    let codex_group = report
        .by_source_and_model
        .iter()
        .find(|group| group.source == "codex")
        .unwrap();
    assert!(codex_group.measurement.reported);
    assert!(codex_group.measurement.derived);
    assert!(!codex_group.measurement.estimated);
    let claude_group = report
        .by_source_and_model
        .iter()
        .find(|group| group.source == "claude_code")
        .unwrap();
    assert_eq!(
        claude_group.measurement,
        MeasurementProvenance {
            reported: true,
            derived: false,
            estimated: false,
        }
    );
}

#[test]
fn deduplicates_archived_and_active_codex_sessions() {
    let root = tempdir().unwrap();
    let active = root.path().join("active");
    let archived = root.path().join("archived");
    fs::create_dir_all(&active).unwrap();
    fs::create_dir_all(&archived).unwrap();
    let row = "{\"type\":\"session_meta\",\"payload\":{\"id\":\"same\",\"model\":\"gpt\"}}\n{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"last_token_usage\":{\"input_tokens\":7},\"total_token_usage\":{\"input_tokens\":7}}}}\n";
    fs::write(active.join("a.jsonl"), row).unwrap();
    fs::write(archived.join("b.jsonl"), row).unwrap();
    let report = scan(&ScanConfig {
        codex_roots: vec![active, archived],
        claude_roots: vec![],
        max_files: 10,
        max_file_bytes: 10000,
        max_line_bytes: 1000,
    })
    .unwrap();
    assert_eq!(report.total_tokens, 7);
    assert_eq!(report.scan.duplicate_sessions, 1);
}

#[test]
fn bounds_untrusted_input_and_skips_symlinks() {
    let root = tempdir().unwrap();
    let codex = root.path().join("codex");
    let claude = root.path().join("claude");
    fs::create_dir_all(&codex).unwrap();
    fs::create_dir_all(&claude).unwrap();
    fs::write(codex.join("large-file.jsonl"), vec![b'x'; 101]).unwrap();
    fs::write(
        codex.join("large-line.jsonl"),
        format!("{{\"padding\":\"{}\"}}\n", "x".repeat(80)),
    )
    .unwrap();
    fs::write(codex.join("malformed.jsonl"), b"not-json\n").unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(codex.join("malformed.jsonl"), codex.join("link.jsonl")).unwrap();

    let report = scan(&ScanConfig {
        codex_roots: vec![codex],
        claude_roots: vec![claude],
        max_files: 10,
        max_file_bytes: 100,
        max_line_bytes: 32,
    })
    .unwrap();
    assert_eq!(report.scan.skipped_oversized_files, 1);
    assert_eq!(report.scan.oversized_lines, 1);
    assert_eq!(report.scan.malformed_lines, 1);
    #[cfg(unix)]
    assert_eq!(report.scan.skipped_symlinks, 1);
}

#[test]
fn handles_codex_counter_reset_without_counting_stale_regression() {
    let root = tempdir().unwrap();
    let codex = root.path().join("codex");
    fs::create_dir_all(&codex).unwrap();
    fs::write(
        codex.join("session.jsonl"),
        concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"reset\",\"model\":\"gpt\"}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"last_token_usage\":{\"input_tokens\":100},\"total_token_usage\":{\"input_tokens\":1000}}}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"last_token_usage\":{\"input_tokens\":10},\"total_token_usage\":{\"input_tokens\":995}}}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"last_token_usage\":{\"input_tokens\":5},\"total_token_usage\":{\"input_tokens\":5}}}}\n",
        ),
    )
    .unwrap();
    let report = scan(&ScanConfig {
        codex_roots: vec![codex],
        claude_roots: vec![],
        max_files: 10,
        max_file_bytes: 10000,
        max_line_bytes: 1000,
    })
    .unwrap();
    assert_eq!(report.total_tokens, 105);
}

#[test]
fn file_cap_selects_newest_sessions_across_sources() {
    let root = tempdir().unwrap();
    let codex = root.path().join("codex");
    let claude = root.path().join("claude");
    fs::create_dir_all(&codex).unwrap();
    fs::create_dir_all(&claude).unwrap();
    let old_path = codex.join("old.jsonl");
    let new_path = claude.join("new.jsonl");
    fs::write(
        &old_path,
        "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"last_token_usage\":{\"input_tokens\":7}}}}\n",
    )
    .unwrap();
    fs::write(
        &new_path,
        "{\"type\":\"assistant\",\"message\":{\"model\":\"newest\",\"usage\":{\"input_tokens\":11}}}\n",
    )
    .unwrap();
    set_modified(&old_path, 10);
    set_modified(&new_path, 20);

    let mut capped = config(&codex, &claude);
    capped.max_files = 1;
    let report = scan(&capped).unwrap();
    assert_eq!(report.total_tokens, 11);
    assert_eq!(report.scan.scanned_files, 1);
    assert_eq!(report.scan.skipped_over_limit_files, 1);
    assert_eq!(report.by_source_and_model[0].source, "claude_code");
}

#[test]
fn equal_modification_times_use_stable_path_order() {
    let root = tempdir().unwrap();
    let codex = root.path().join("codex");
    fs::create_dir_all(&codex).unwrap();
    let first_path = codex.join("a.jsonl");
    let second_path = codex.join("b.jsonl");
    fs::write(
        &first_path,
        "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"model\":\"first\",\"info\":{\"last_token_usage\":{\"input_tokens\":3}}}}\n",
    )
    .unwrap();
    fs::write(
        &second_path,
        "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"model\":\"second\",\"info\":{\"last_token_usage\":{\"input_tokens\":5}}}}\n",
    )
    .unwrap();
    set_modified(&first_path, 30);
    set_modified(&second_path, 30);

    let mut capped = config(&codex, root.path());
    capped.max_files = 1;
    let report = scan(&capped).unwrap();
    assert_eq!(report.total_tokens, 3);
    assert_eq!(report.by_source_and_model[0].model, "first");
}

fn set_modified(path: &std::path::Path, seconds: u64) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(
            FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)),
        )
        .unwrap();
}

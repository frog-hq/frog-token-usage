# frog-token-usage

`frog-token-usage` provides auditable, offline Usage Insights from local Codex
and Claude Code JSONL session logs. It is the open-source usage component used
by Frog.

It deliberately does **not** read Keychain/Keystore entries, provider tokens,
cookies, prompts, responses, or workspace paths. It performs no network calls
and uploads nothing. Results are local usage reported by or derived from agent
session events; they are not authoritative billing, quota, or invoice data.

## Usage

```sh
cargo run -p frog-token-usage -- --format table
cargo run -p frog-token-usage -- --format json
```

The machine-readable contract is versioned with `schema_version: 1`. Report and
per-model aggregates contain explicit `reported`, `derived`, and `estimated`
measurement flags, token categories, scan counters, and
`billing_authoritative: false`. The local scanner never estimates usage, so
`estimated` remains false. Raw event content and file paths are never part of
the contract.

Environment discovery follows the tools' normal local data locations:

- Codex: `$CODEX_HOME`, otherwise `~/.codex`; scans `sessions/` and
  `archived_sessions/`.
- Claude Code: `$CLAUDE_CONFIG_DIR`, otherwise `~/.claude`; scans `projects/`.

The scanner does not follow symlinks. File count, file size, and record size are
bounded. An unterminated active JSONL tail is reported and ignored until it is
complete. Duplicate Codex session IDs and Claude request/message pairs are not
double-counted. If a file-count cap is reached, the newest sessions across all
enabled sources are selected first with a deterministic path tie-breaker.

Release binaries cover Linux x86_64/arm64 as static musl executables and macOS
x86_64/arm64. Each archive is checksummed and covered by GitHub build-provenance
attestation.

## Trust and scope

- No network dependency exists in the core or CLI.
- No credential store or provider account API is accessed.
- Cost estimates and public rankings are intentionally outside the v1 contract.
  A future estimate must pin a dated pricing source and remain clearly labeled
  as estimated. Any future ranking requires separate, explicit opt-in.
- Frog consumes signed/checksummed, version-pinned releases and the versioned
  JSON contract. The private app does not carry a hidden parser fork.

This implementation was written for Frog after studying tokScale's documented
local-log approach. Its Codex cumulative-counter edge-case handling is adapted
from that MIT-licensed reference; see `NOTICE` for attribution.

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

This project is dual-licensed under Apache-2.0 or MIT, at your option.

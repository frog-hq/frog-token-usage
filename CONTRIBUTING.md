# Contributing

Parser changes require synthetic tests for malformed input, duplicate events,
active partial tails, size limits, symlinks, cumulative counter resets, and
schema variants where relevant. Fixtures must not contain real user prompts,
responses, paths, identifiers, or credentials.

Run formatting, Clippy with warnings denied, and the full workspace test suite.
Do not add Keychain/Keystore access, provider credentials, implicit networking,
telemetry, cost claims without a dated pricing source, or ranking uploads.

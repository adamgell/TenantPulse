# Changelog for TenantPulse

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Repository scaffold: Sampler build pipeline, module manifest, QA gates, and CI workflow.
- Snapshot store: `New-PulseSnapshotStore`, `Write-PulseDataset`, `Read-PulseDataset`,
  `Get-PulseSnapshotManifest`, `Set-PulseManifestEntry`, and the canonical serialization
  primitive `ConvertTo-PulseCanonicalJson`, with a hashed, reason-carrying manifest that
  every later collector/evaluator/renderer component builds on.
- Operator key + pseudonymization: `Get-PulseOperatorKey` auto-creates a 32-byte key
  (0600-equivalent permissions on non-Windows) at `~/.tenantpulse/operator.key` on first
  call and refuses to create or read one inside a snapshot root; `Get-PulsePseudonym`
  turns any value into a stable `tp-`-prefixed HMAC-SHA256 pseudonym under that key, so
  raw tenant IDs never need to appear in snapshots or reports.

### Changed

- For changes in existing functionality.

### Deprecated

- For soon-to-be removed features.

### Removed

- For now removed features.

### Fixed

- `ConvertTo-PulseCanonicalJson` now sorts object/dictionary keys ordinally instead of via
  case-insensitive culture collation, which previously let case-distinct keys (`apple` vs
  `Apple`) keep their insertion order and produce non-deterministic bytes; it also now
  formats `DateTimeOffset` values with an explicit invariant offset instead of falling
  through to a lossy generic-string branch, and throws on non-finite `NaN`/`Infinity`
  doubles instead of silently emitting invalid JSON tokens.
- `Set-PulseManifestEntry` now guards its read-modify-write cycle with a per-store named
  Mutex and publishes `manifest.json` via a temp-file-then-atomic-rename, so a crash
  mid-write can no longer truncate the manifest and concurrent writers no longer silently
  drop one another's updates.
- `Write-PulseDataset`, `Read-PulseDataset` and `Set-PulseManifestEntry` now validate
  dataset `-Name` against a safe-character pattern before using it to build a file path,
  closing a path-traversal gap that could overwrite arbitrary files (including
  `manifest.json` itself) via a name like `..\manifest`.

### Security

- In case of vulnerabilities.

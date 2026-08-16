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
- Check descriptor schema + loader: `Import-PulseCheckCatalog` reads and validates every
  `.psd1` check descriptor under a directory (default `source/Data/Checks`) with
  `Import-PowerShellDataFile`, returning an ordinally-sorted-by-`Id` array of
  `TenantPulse.CheckDescriptor` objects; an empty/missing catalog returns an empty array
  rather than throwing. `Test-PulseCheckDescriptor` validates one descriptor's schema
  with explicit per-field type enforcement (scalar `[string]` vs. required/allowed-empty
  `[string[]]`, reported as `must be a <type>, got <actual type>` rather than silently
  coercing), Id/Severity/Effort/Impact/Rule.Type patterns and enums, Rule.Function
  resolving via `Get-Command` at import time, required Consulting fields,
  References.Research/Authorities and, once Task 1.5 lands `DatasetMap.psd1`,
  cross-checks Data.Datasets membership against a map parsed exactly once per catalog
  load. All validation errors across a catalog are aggregated into a single thrown
  error, each line prefixed with its source filename and naming the offending
  descriptor and property, rather than failing on the first bad file. Schema documented
  verbatim in `source/Data/Checks/README.md`.
- Evaluator: `Invoke-PulseEvaluation` runs a check catalog against a snapshot store and
  produces the canonical findings document (`source/Private/Evaluate/FindingsSchema.md`),
  plus an in-memory-only `RedactionMap` covering every evidence identity seen (built at
  evaluate, applied at render). `New-PulseFinding` is the rule-result contract every
  Function rule (`Test-Pulse* -Datasets <hashtable>`) returns to produce `Pass`/`Warn`/
  `Fail` with evidence; Expression rules resolve straight to `[bool]` with no evidence.
  `NotApplicable` and `Error` are engine-assigned only: a missing/`Failed`/`Skipped`
  dataset degrades a check to `NotApplicable` quoting the manifest's own (already
  redacted) reason verbatim, and a throwing or malformed-output rule becomes `Error`
  without aborting the rest of the run. `Get-PulseGateStatus` is a Phase 1 gate stub -
  every gate resolves `Unknown`, which never degrades a check. Findings are sorted
  ordinally by check Id, each finding's evidence ordinally by sortKey then identity, and
  `generatedUtc` is pinned to the snapshot manifest's own `createdUtc` (never wall
  clock), so re-evaluating the same snapshot is byte-identical through
  `ConvertTo-PulseCanonicalJson`.

### Changed

- Check descriptor loader hardening (post-review): closed PowerShell-coercion type holes
  that let array-typed `Id`/`Severity`/`Rule.Type`/etc. silently pass their
  pattern/enum checks and land wrong-typed in the loaded descriptor (also closing the
  matching duplicate-Id-detection bypass); prefixed every aggregated error line with its
  source filename so two files sharing a bad Id are distinguishable; hoisted
  `DatasetMap.psd1` parsing to once per catalog load with its own aggregated-error
  handling for a malformed map instead of a raw exception, and excluded a
  `DatasetMap.psd1` living inside the catalog directory from descriptor scanning;
  switched catalog ordering from culture-aware `Sort-Object` to an ordinal
  `[string]::CompareOrdinal` index-sort, matching `ConvertTo-PulseCanonicalJson`'s
  established pattern for deterministic ordering.

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
- `Get-PulseOperatorKey` now creates its key file exclusively (`FileMode.CreateNew`), so
  two concurrent first callers on a machine with no key yet can no longer each write and
  silently diverge on their own key - the loser now reads the winner's key instead. On
  non-Windows the file is chmod'd to owner-only before any key bytes are written (not
  after), and the parent directory it creates is chmod'd `0700`. Reading a key file now
  requires it to be exactly 32 bytes, throwing a clear "corrupt key file" error naming the
  actual byte count and the path to delete, instead of silently returning a truncated key
  or an opaque `$null`-related error.

### Security

- In case of vulnerabilities.

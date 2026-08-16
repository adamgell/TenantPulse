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

### Changed

- For changes in existing functionality.

### Deprecated

- For soon-to-be removed features.

### Removed

- For now removed features.

### Fixed

- For any bug fix.

### Security

- In case of vulnerabilities.

# Phase gate artifacts

Committed, redacted output from a real live-tenant gate run, kept so a reviewer can check a
phase's STATUS.md summary table against the raw artifact it was transcribed from, rather than
trusting the transcription alone.

## `phase4-ivy24-findings.redacted.json`

The Task 4.5 full-catalog live gate: `Invoke-PulseAssessment -ProfileId ivy24 -Redact` run
against the Ivy24 lab tenant from `phase4/t4.1-normalization`.

**Incident note (fix round, honest disclosure - deliberately NOT reproducing any of the actual
leaked values here, including in this note, since the entire point is that they must not
persist anywhere in this repository):** the first committed cut of this file leaked real
live-tenant PII in `evidence[].detail.displayName` (and `deviceName`/`servicePrincipalName`/
`roleDisplayName`/etc.) fields - real device names, several person-derived (personal-device
naming patterns like "\<Name\>'s \<device type\>"), roughly 80 real hostnames/asset-tag/
serial-shaped device names, and real Conditional Access policy display names - because that
cut's scrub only targeted dash-formatted GUIDs, not every free-text value a live Graph read can
carry. Caught by a downstream reviewer, not by this repo's own test suite
(`tests/QA/SecretScan.tests.ps1` did not scan `docs/` at all at the time). The leaking commit
was rewritten (not left in history and "fixed forward") because this branch has never been
pushed - see the fix-round commit for the rewrite and its own verification method
(`git log -p --all -- docs/gates/` checked for the actual leaked values, plus a reflog
expire + gc to remove the pre-rewrite objects from the local repository too).

**Current sanitization, on top of TenantPulse's own built-in `-Redact`** (which pseudonymizes
the top-level `tenant` field and every evidence `identity`/`sortKey`):

- `scripts/Protect-PulseGateArtifact.ps1` walks every finding's `evidence[].detail` object and
  replaces **every `[string]` leaf value, with no per-field-name exceptions**, with a stable
  `tp-<HMAC-SHA256 hex>` pseudonym (same value in -> same pseudonym out **within one run of
  the script**, so the artifact stays diffable - the same device still recurs under the same
  token everywhere it appears in this one file). Numbers/booleans/`$null` (`lifetimeDays: 365`,
  `severity: 'High'`) pass through unchanged. Deliberately exhaustive rather than a
  `displayName`-shaped allowlist: an allowlist of "the field names that look identity-bearing"
  is exactly the class of gap that let the original leak through unnoticed.
  **Keying (merge-review fix - a plain unsalted SHA-256 was the ORIGINAL construction here,
  and it was wrong):** low-entropy, identity-shaped inputs like device names are offline-
  dictionary-reversible against a plain hash, and the hash construction is public in this same
  repo - so this now reuses `Get-PulsePseudonym` (the same HMAC-SHA256 primitive
  `Invoke-PulseAssessment -Redact` itself uses) keyed with a **cryptographically random key
  generated fresh at script start and never written to disk, logged, or embedded in the
  artifact** - it is discarded the moment the script's process exits. This is a *different* key
  than `-Redact`'s own persistent operator key
  (`~/.tenantpulse/operator.key`); this artifact's pseudonyms are intentionally NOT
  correlatable with that or with any other run of this same script. **Consequence, not a
  defect: re-running this script (on a fresh live pull, or on this same file again) produces a
  DIFFERENT set of pseudonym tokens for the same underlying values** - cross-run linkability is
  exactly what an offline dictionary attack against this low-entropy input space would need,
  and losing it is the whole point of an ephemeral key. Diffability/consistency is preserved
  only *within* a single run's output, which is all this artifact's own purpose (a
  point-in-time transcription source) requires.
- **Manual-review carve-out removed (merge-review fix):** an earlier version of this README
  said `reason` strings were "checked by hand across all 28 findings... and carry only
  counts/booleans/template text" - true, but a one-time human assurance, not a mechanical
  guarantee, for the exact leak class this whole remediation exists to close. The script now
  also WALKS every field of the document - `id`/`title`/`category`/`severity`/`status`/
  `effort`/`impact`/`reason`/`coverage`/`scores`/`notices`/`producer`/`schemaVersion`/`tenant`,
  every one of them, mechanically, every run - and **asserts**, refusing to write the file if
  it fires, that none of them match a leak-shaped pattern (possessive-name-shaped text, a bare
  GUID, an email address). `consulting`/`references`/`origin` are the one exclusion, and it is
  a *structural* one, not a manual-review one: that content is sourced from the check-
  descriptor `.psd1` catalog files at catalog-load time, never from a live Graph read, so it
  cannot vary by tenant or run - proven, not assumed, by an earlier unscoped version of this
  check throwing on real catalog prose ("Security Defaults is Microsoft's free, all-or-nothing
  baseline identity policy") that is legitimate authored text, not a leak. `title`/`consulting`/
  `references`/`origin` are all still left as-authored either way (pseudonymizing TenantPulse's
  own check-descriptor content would destroy the artifact's purpose), but everything that
  genuinely could vary by run is now backed by a check that runs every time this script does,
  not by a memory of having looked once.
  **`approximateLastSignInDateTime`-style ISO-8601 timestamps inside `detail` are pseudonymized
  too - there is no timestamp exception.** An earlier draft of this README described them as a
  deliberate exception; that was actually a bug, not a decision - `ConvertFrom-Json`'s default
  behavior silently parsed those strings into `[datetime]` objects before the scrub ever saw
  them, so they survived untouched despite the "every string leaf" claim above. Fixed by adding
  `-DateKind String` to the script's read step (same fix `Export-PulseReport.ps1` already uses,
  for a different byte-identity reason - see that file's own docstring), which keeps every JSON
  string a `[string]` through the read, so the existing `-is [string]` scrub branch now sees
  (and pseudonymizes) a timestamp exactly like every other string leaf, with no special-casing.
- `tests/QA/SecretScan.tests.ps1` now scans `docs/` (this directory included) as part of its
  normal repo sweep, and carries a dedicated pattern (item 8) for a possessive-name-shaped
  `displayName`/`deviceName` JSON value (the personal-device-naming shape this incident's leak
  took - see `docs/gates/_qa-fixtures/planted-pii-sample.json`'s entirely synthetic
  `"Taylor's Test-Device"` example) and its dedicated regression test for proof the gate
  actually fires on that shape. Running `./build.ps1 -Tasks test` re-verifies this file (and
  everything else under `docs/`) against that gate on every build - this is now an enforced
  property of the repo's own test suite, not merely a claim in this README.

To re-run the scrub after regenerating this artifact from a fresh live run:

```powershell
pwsh -File scripts/Protect-PulseGateArtifact.ps1 -Path docs/gates/phase4-ivy24-findings.redacted.json
```

The docs/STATUS.md "Phase 4" section's live-gate table is a hand-curated transcription of
this file's `findings[].status`/`.reason` - this file is the raw source for anyone who wants
to check the transcription (or compute their own category-score arithmetic) directly.

## `_qa-fixtures/`

QA-only fixtures for `tests/QA/SecretScan.tests.ps1`. Excluded from that gate's normal sweep of
this directory (the same way `tests/QA/` excludes itself) because they deliberately contain a
planted, entirely synthetic violation - each is instead scanned directly by its own dedicated
regression test. Not part of the live-gate artifact story above.

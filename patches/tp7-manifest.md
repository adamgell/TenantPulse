# TP7 HTML renderer - proposed shared-file additions

Do not apply from this lane. Controller-only files stay untouched here.

## `source/TenantPulse.psd1`

No `FunctionsToExport` change. `Export-PulseHtmlReport` is private. Public surface remains the existing five commands; `-Format Html` is an additive parameter value on `Export-PulseReport` and `Invoke-PulseAssessment`.

## `README.md`

Document `-Format Html` on `Export-PulseReport` and `Invoke-PulseAssessment`:

- Writes `tenantpulse-report.html` next to canonical `tenantpulse-findings.json`.
- Self-contained single file: inline CSS, no scripts, no network-loading URLs.
- Consumes findings JSON only; does not call Graph or read a snapshot.

## `CHANGELOG.md`

Unreleased 0.3.0 Added:

- Self-contained HTML reports via `Export-PulseReport -Format Html` and `Invoke-PulseAssessment -Format Html`.

## `docs/STATUS.md`

Record HTML as the second findings renderer. JSON remains canonical. Excel and ReportBundle stay out of this lane.

## `source/en-US/about_TenantPulse.help.txt`

Mention HTML as a render format alongside JSON.

## `Invoke-PulseCheck`

Still `ValidateSet('Json')` only. Add `Html` in a later additive pass if the public check command should match assessment/export.

## CI / ratchet / `build.yaml`

No required change for this lane. Focused unit tests cover Html format, injection/escaping, notices, and all five outcomes.

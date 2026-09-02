# TP9A proposed controller patches

Do not apply from this lane. Shared files stay with the integration controller.

C0 D6 remains Proposed. This lane does not invent owner approval for safe-share UX
or a public rotate cmdlet.

## README.md

Replace the residual that `-Redact` is not a complete de-identification contract with:

- 1.0 classified construction uses Identity, SecretSensitive, SafeTechnical,
  SafeOperatorLabel, and BoundedReviewedText.
- `ConvertTo-PulseSafeShareDocument` / `Export-PulseJsonReport -RequireClassification`
  is the fail-closed classified JSON path.
- Optional `RedactDetailKeys` and `Protect-PulseReason` remain a local-only
  compatibility layer (`privacy.boundary = local-only`).
- Operator-key backup / replacement / join-break (no public rotate cmdlet).
- Snapshot stores remain never-shareable.

## docs/STATUS.md

Record R5/AC-25 progress: classified constructors and QA canaries exist;
catalog checks are not fully migrated; C0 D6 is still Proposed; live sanitized
sweep and ReportBundle/XLSX (TP9B) remain open.

## CHANGELOG.md

Unreleased: enforce TenantPulse 1.0 privacy classification constructors, reason
codes, and fail-closed safe-share conversion. Compatibility layer labeled
local-only.

## source/Public/Invoke-PulseAssessment.ps1

Document that `-Redact` is the compatibility identity substitution path.
Classified fail-closed sharing is `-RequireClassification` on the private JSON
exporter until C0 locks D6. Do not add a public rotate cmdlet.

## build.yaml / ci.yml / TenantPulse.psd1 / RequiredModules.psd1 / DatasetMap.psd1

No change required for this lane. New private Identity helpers are picked up by
ModuleBuilder wildcards. QA tests land under tests/QA which CI already runs.

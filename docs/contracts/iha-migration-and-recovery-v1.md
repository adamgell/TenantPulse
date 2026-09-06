# IHA migration and recovery contract v1

## Decision

TenantPulse replaces IntuneHealthAutomation's process-local cache, device checkpoint, consolidated
JSON importer, and console workflow. It does not embed or call IHA. There are no deployed IHA
consumers to migrate, so this release does not add a permissive importer for arbitrary legacy JSON.
The supported handoff is a fresh `-ReportData All` collection followed by offline re-evaluation of
the resulting TenantPulse snapshot.

This is a deliberate replacement, not an assertion that the two storage formats are byte-compatible.
IHA wrote one mutable `ConsolidatedData.json` object with `{ GeneratedDateTime, TenantID, Data }` and
loaded its properties into global module state. TenantPulse schema 2.0.0 uses a manifest plus
content-addressed datasets, references, and expansions. Every usable payload has a recorded hash,
count, provider, API version, operation set, and explicit collection outcome.

## Collection and transformation mapping

The authoritative 28-endpoint and 14-active-report register is
`iha-port-coverage-v1.json`. The following previously incomplete transformations are resolved as
documented replacements:

- `ConfigurationProfiles`: `deviceConfigurations` is a deterministic TenantPulse-owned composite
  of the policy root and its authoritative per-policy assignments. It preserves each assignment's
  id, intent, source, and structured target. The `groups` inventory supplies exact group ids, names,
  descriptions, types, and membership rules for an id join. IHA's opportunistic member-count and
  `"Group not found"` strings are presentation/cache state, not policy evidence, and are not stored
  as facts.
- `Applications`: `application-assignments` replaces IHA's enhanced app objects with one normalized
  row per assignment (and one explicit no-assignment row), exact target types, filters, settings,
  group metadata, bounded member counts, and independent resolution states.
- `AppProtectionPolicies`: IHA performed only the endpoint list and had no active report definition.
  `appProtectionPolicies` preserves the raw service rows in the 25-source inventory contract.
- `AutomaticEnrollment`: IHA performed only the shared device-enrollment-configuration list and had
  no dedicated transformation or active report. `deviceEnrollmentConfigurations` is the direct
  successor dataset; platform restrictions consume the same evidence without a second request.
- `ConfigurationConflicts`: TenantPulse replaces IHA's opaque conflict summary with normalized
  setting instances and deterministic conflict detection. Unsupported or partial policy families
  remain gaps, so a zero-conflict result is never inferred from incomplete input.
- `DeviceInventory`: Windows rows receive the dedicated beta `ManagedDevice.GetBeta` detail read.
  Hardware and device-health objects, including an authoritative TPM version when returned, remain
  structured. Non-Windows rows are explicitly `NotApplicable`; failed or suppressed detail reads
  make the artifact `Partial`. The activation-lock bypass code collected by IHA is deliberately not
  requested or persisted because it is a credential-like recovery secret, not audit evidence.

## Recovery instead of opaque checkpoint replay

IHA checkpoints existed primarily so an operator could paste a replacement bearer token and resume
from saved page/device state. GraphKit contexts reacquire tokens from their source credential and own
paging/retry, so that token-expiration workflow no longer applies. TenantPulse does not persist
access tokens or opaque `@odata.nextLink` values.

Recovery follows these rules:

1. A complete Graph operation becomes `Collected`; truncation, indeterminate completion, page caps,
   or usable child failures become `Partial` with structured gaps.
2. A dataset or expansion is published only through atomic staging and manifest replacement. Readers
   verify its recorded SHA-256 before returning rows.
3. Reusing an output path starts a clean store-owned `datasets`, `reference`, and `expanded` tree, so
   stale files cannot be mistaken for resumed evidence.
4. An interrupted or partial run remains evidence of that incomplete run. Recovery is a fresh
   collection. Equivalent complete input produces the same canonical artifact bytes regardless of
   source order.
5. Authentication failure sets the snapshot-wide abort state. No later network child is attempted;
   already collected sibling rows remain visible with `Failed` or `NotEvaluated` resolution states.

The deterministic proof lives in `tests/Unit/Snapshot/CollectionOutcomeSnapshot.Tests.ps1`,
`tests/Unit/Snapshot/ScaleStreaming.Tests.ps1`, `tests/Unit/PublicSurface.Tests.ps1`, and the report
data test files. These cover schema 2.0.0 partial outcomes, hash verification, large canonical
streaming, clear-on-reuse/offline evaluation, authentication abort, and order-independent output.

## Offline reuse and export

`Invoke-PulseAssessment -FromSnapshot <path>` is the supported equivalent of IHA's offline import.
It opens a known snapshot schema, performs no Graph call, verifies datasets as they are read, and
re-evaluates checks from the stored evidence. The snapshot directory itself is the consolidated
machine export; splitting it into a manifest and content-addressed payloads prevents one malformed
or truncated JSON object from silently becoming global state.

The external Office delivery layer consumes the versioned dataset and expansion schemas. DOCX/XLSX
rendering, customer branding, approval fields, and preservation of customer-authored document regions
remain outside GraphKit and TenantPulse.

## Release and live-evidence gates

The Apple enrollment-profile and managed-device-detail implementations require exact GraphKit
`0.3.1`. That maintenance source is merged on GraphKit's `release/0.3.x` line, its package is sealed
to the passing all-file proof, and this TenantPulse source selects it exactly. The earlier dependency
block is therefore closed for deterministic source/package verification. Distribution still requires
the verified local package or an internal channel until a separately authorized PSGallery publish;
TenantPulse never falls back to an unowned HTTP call. Microsoft Graph live permission and
response-shape verification is separate evidence and must not be inferred from these deterministic
contracts.

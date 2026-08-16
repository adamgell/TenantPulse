# TenantPulse Phase 1 - internal status

This is internal development/task narrative, moved out of README.md (post-review fix -
README.md is meant to read as a PSGallery landing page, not an implementation log). Nothing
here is required to install or use TenantPulse; see README.md for that.

## Phase 1 engine: complete

Collection, evaluation, scoring, and the deterministic pseudonymized JSON report all work
end to end through `Invoke-PulseAssessment`, and the whole pipeline has been
**live-smoke verified against a real tenant** (the Ivy24 lab tenant, Task 1.11): a fresh
`Invoke-PulseAssessment -ProfileId ivy24` run collected real Intune data
(`deviceCompliancePolicies`, `deviceConfigurations`, `deviceManagementSettings`,
`managedDevices`), degraded a permission gap honestly (`conditionalAccessPolicies` Skipped
with reason `permission-denied: Policy.Read.All`, its dependent checks NotApplicable rather
than silently wrong), left every not-yet-released GraphKit descriptor Skipped with
`descriptor-pending`, produced real Pass findings from the data that did collect, and
re-evaluating the same snapshot via `-FromSnapshot` reproduced a byte-identical findings
JSON. The tenant identifier appeared nowhere in the output tree except as its `tp-...`
pseudonym.

The live run also surfaced a real GraphKit 0.1.0 error-shape gap (its `Get-GraphObject`
throw carries no structured status code or `403`/`forbidden` text on failure) that made a
genuine permission denial misclassify as a generic failure instead of the honest-degradation
path above; that gap was fixed in the collector (a supplemental, read-only
`Invoke-GraphOperation` call recovers the real status code) with a regression test pinning
the fix against the real shape.

## Final fix wave (this pass)

A merged fix list from two independent reviews was implemented in full - contract fixes
(pseudonym-input source moved from `-ProfileId` to the resolved tenant id; `-Path`
parameters renamed to explicit `-OutputPath`/`-CatalogPath` with a deprecated alias),
snapshot-store boundary hardening (clear-on-reuse, manifest type validation, atomic
writes extracted into a shared helper), determinism/redaction fixes (a datetime
round-trip byte-drift bug, a culture-sensitive sort reaching document bytes, an
under-redacted evidence field, a DateTime-Kind-Unspecified handling bug in the canonical
serializer), check-logic fixes (a break-glass exemption that could wrongly exempt a
group/role-reachable account, an admin-MFA check that did not count `includeUsers: 'All'`
coverage, a dataset-status gate that enumerated bad statuses instead of failing closed on
any non-`Collected` status, a stale-device check that could silently fall back to
wall-clock time on a malformed manifest timestamp, an auth-abort loop that could overwrite
a Pending dataset's real reason), publish-tooling hardening (a shipped-file digest manifest
recorded at test time and verified at publish time, a `[SecureString]`/environment-variable
-only API key parameter, enum-typed HTTP status code handling, a silent supplemental-recovery
failure upgraded to a visible warning plus an artifact-level marker), and the public-facing
skin (this README, THIRD-PARTY-NOTICES.md, the `about_TenantPulse` help topic, pinned build
tool versions, an extended offline secret scan, and this file).

See the repository's git history and commit messages for the itemized, per-fix detail.

## GraphKit 0.1.1 migration (Task 1.11, complete)

GraphKit 0.1.1 is published to PSGallery and both pins (`source/TenantPulse.psd1`,
`RequiredModules.psd1`) are bumped. The migration:

- Deleted the `Get-PulseGraphFailureStatusCode` supplemental-probe workaround entirely -
  GraphKit 0.1.1's `Get-GraphObject` now throws an `ErrorRecord` with structured signal
  (`CategoryInfo.Category`, `TargetObject.Telemetry[-1].StatusCode`) directly, so no
  extra read-only Graph call is needed to recover a status code. `Get-PulseFailureClass`
  was rewritten to consume that ErrorRecord's structured data first, falling back to the
  rendered message only when neither signal is present.
- Dropped `Pending = $true` from all six DatasetMap.psd1 entries that had it
  (`securityDefaultsPolicy`, `directoryRoleAssignments`, `directoryRoleDefinitions`,
  `organization`, `organizationMdmAuthority`, `entraDevices`) - the static read-only QA
  gate (`tests/QA/ReadOnly.tests.ps1`) auto-upgraded all six to live catalog verification
  against installed GraphKit 0.1.1 and they pass the real Read/Safe predicate. The
  Pending mechanism itself stays covered by a synthetic fixture for the next descriptor
  that ships Pending.
- `./build.ps1 -Tasks pack` now produces `output/TenantPulse.0.1.0.nupkg` cleanly
  (GraphKit's `ExternalModuleDependencies` fix resolved the prior pack-time blocker).
  `scripts/Publish-TenantPulsePackage.ps1`'s dry run passes end-to-end (digest-manifest
  verification, no key, no publish).

**Two live-gate surprises, both fixed with regression tests** (first real run of the six
newly-live descriptors against a real tenant):

1. Two of the six datasets (`organization`, `directoryRoleAssignments`) carry the raw
   tenant GUID as a genuine Graph response FIELD (`Organization.id`,
   `DirectoryRoleAssignment.principalOrganizationId`), not merely a GraphKit provenance
   stamp. Fixed with a new `Protect-PulseGraphRowTenantId` helper, wired into
   `Write-PulseDataset`, that walks every row's value tree and redacts an exact match of
   the raw tenant id to its pseudonym before the dataset file is written. +5 regression
   tests in `Snapshot.Tests.ps1`.
2. `Protect-PulseGraphRowTenantId`'s first cut walked Hashtable-valued properties (e.g. a
   real `ConditionalAccessPolicy`'s `conditions`/`grantControls`, which GraphKit returns
   as `OrderedHashtable`, not `PSCustomObject`) via `.PSObject.Properties` - which
   surfaces a Hashtable's own adapter members (`Keys`, `Values`, `SyncRoot`, ...) rather
   than its dictionary entries. A non-synchronized Hashtable's `SyncRoot` IS the same
   hashtable, so the walk recursed into itself and blew PowerShell's call depth on every
   policy row (reproduced live: ~4s burned per row before falling back to the unredacted
   original - TOTAL-by-construction meant it never crashed the run, but it silently
   defeated the redaction on any Hashtable-nested tenant id and made collection
   pathologically slow). Fixed by walking `IDictionary` via its own `Keys`/`this[key]`
   entries, checked before the generic PSObject branch. +1 regression test pinning a
   Hashtable-nested tenant GUID redacts correctly and fast (<2s).

**Live gate re-run against Ivy24 after both fixes, clean**: all 11 datasets Collected
(including `securityDefaultsPolicy` - no 403; the tenant's granted `Policy.Read.All`
covers it), all 10 seed checks resolved with real statuses (5 Pass, 3 Fail, 1
NotApplicable, 0 Error), coverage 9/10 (90%), `-FromSnapshot` reproduced a byte-identical
findings JSON, and the raw tenant GUID appears nowhere in the output tree (datasets,
manifest, or findings) - only its `tp-...` pseudonym.

## Phase 2 (Settings expansion, core slice T2.1-T2.7): complete, live-gated

Every Phase 2 core-slice task (T2.1 snapshot schema extension, T2.2 Settings Catalog
fan-out/walk, T2.3 compliance/legacy typed-policy expansion, T2.5 baseline flagging, T2.6
conflict detection, T2.7 this task) is implemented, unit-tested (1091/1091), and now
**live-gated against Ivy24 end to end** with `-ExpandSettings`: real Settings Catalog
(781 policies), compliance (40) and deviceConfiguration (15) typed-policy expansion, and
conflict detection, all in one run.

**Live gate results (verbatim), Ivy24, sequential Settings Catalog fan-out** (see
"Live-gate surprises" below for why sequential, not the default `-MaxParallel 4`):

- `configurationPolicies` enumerated 781; `settingsCatalog` expansion status `Partial`,
  `policyCount` 781, `rowCount` 4302, every one of the 781 enumerated policies present in
  the row set (781 unique `policyId`s), 64 gaps (per-instance walk gaps within otherwise-
  successful policies, not whole-policy failures), `unresolvedNameCount` 0,
  `redactedSecretCount` 131.
- `deviceCompliancePolicies` enumerated 40; `compliance` expansion `Partial`, 34 policies
  contributed rows + 6 gapped (unmapped `@odata.type`, the documented "collected, not
  setting-expanded" outcome), `unresolvedNameCount` 0, `redactedSecretCount` 0.
- `deviceConfigurations` enumerated 15; `deviceConfiguration` expansion `Expanded`
  (zero gaps), 15/15 policies, `unresolvedNameCount` 0, `redactedSecretCount` 8.
- **Unresolved-name rate: 0% across all three families** - well inside the plan's <1%
  exit criterion.
- **Conflicts: real conflicts surfaced, not a zero-conflicts-by-luck outcome** - 165
  conflict entries from all 3 families; `assignmentOverlap` breakdown `none`=8,
  `possible`=34, `unknown`=123 (the 123 all involve at least one `settingsCatalog` row,
  whose assignments are deferred per the G-gate - the 8/34 non-`unknown` verdicts come
  from compliance/deviceConfiguration rows, which DO carry real assignment data today).
- `groupPolicyConfigurations` (the plan's own "9 gpConfigs" reconciliation note) is
  correctly ABSENT from this manifest - admin templates (T2.4) are Phase 2b, deferred by
  the G-gate; this dataset is not collected under the core-slice `-ExpandSettings` at all.
- **`-FromSnapshot` byte-identity**: re-derived all four expansion artifacts
  (`settingsCatalog`/`compliance`/`deviceConfiguration`/`conflicts`) from the same
  snapshot - all four byte-identical to the original run.
- **4-worker parallel vs sequential, real captured Ivy24 payloads**: byte-identical
  (`-MaxParallel 4` vs `-Sequential` over the real 781-policy raw-payload corpus).
- **TypedPolicyMaps deeper-nesting check (deferred F3)**: CONFIRMED live - 8 real
  `windows10CustomConfiguration` policies carry an `omaSettings.value` whose raw value is
  itself an object/dict, one level past what `TypedPolicyMaps.psd1`'s `Nested` schema
  supports. Recorded here as an explicit gap, not silently absorbed: the secret contract
  is NOT at risk (that exact property is flagged `Sensitive`, so the whole value redacts
  regardless of its internal shape - confirmed by `redactedSecretCount` 8 for
  `deviceConfiguration`, exactly matching the 8 affected policies), but the module cannot
  currently decompose that nested object into individual settings. Flagged for Phase 3.

**Live-gate surprises, fixed with regression tests (first full-expansion live run, as
expected)**:

1. **Raw tenant id in an ordinary (non-secret) Settings Catalog policy VALUE**: a real
   Ivy24 policy's own OneDrive Known-Folder-Move opt-in setting legitimately carries the
   tenant's own GUID as admin-entered configuration data (a standard, documented Intune
   configuration pattern, not a bug in the tenant's config) - and that raw GUID reached
   `expanded/settingsCatalog.<hash>.jsonl` unredacted, because `Protect-PulseGraphRowTenantId`
   (T1.11's raw-dataset tenant-id redaction walk) was never wired into the T2.2/T2.3
   expansion-row publish path, only into `Write-PulseDataset`'s raw writes. Fixed:
   `Invoke-PulseSettingsCatalogExpansion.ps1` and `Invoke-PulseTypedPolicyExpansion.ps1`
   both now redact their final row set through `Protect-PulseGraphRowTenantId`
   immediately before publication. +2 regression tests (one per pipeline). Re-run against
   Ivy24 after the fix: clean (848 files scanned, zero raw-tenant-id or literal-ProfileId
   hits).
2. **`-MaxParallel 4` (the default) is pathologically slow against a REAL tenant**: did
   not complete even a 20-policy real slice within 9m35s (killed); the identical slice
   completed `-Sequential` in 2.30s (0.12s/policy - even better than the T2.0 spike's own
   300ms mean). Root cause not fully established (see
   `docs/spike/2026-08-16-t27-perf-container.md`'s own section 4), but plausibly the
   RunspacePool's per-worker GraphKit re-import means each worker's token cache and
   `GraphThrottleCoordinator` state are NOT shared, so four workers independently unaware
   of each other's throttle state hammer the tenant with no shared backoff. Fixed
   pragmatically: `Invoke-PulseSettingsCatalogExpansionPipeline.ps1` (the one caller that
   ever runs against a real, live tenant) now forces `-Sequential` unconditionally,
   documented as a deliberate safe default pending the real root-cause fix.
   `Invoke-PulseSettingsCatalogExpansion`'s own `-MaxParallel 4` default is UNCHANGED and
   still fast/byte-identical against `-FromCapturedPayloads` data (no live Graph calls to
   starve of shared state).

**`-ExpandSettings` default-on flip, evaluated and deliberately deferred**: the parameter's
own pre-T2.7 docstring said this would flip on by default in T2.7 once the live gate
passed. The live gate DID pass clean. Trying the flip anyway surfaced two real,
wider-blast-radius costs not appropriate to absorb inside this same task: `[switch] $X =
$true` trips this repo's own PSScriptAnalyzer QA gate
(`PSAvoidDefaultValueSwitchParameter`), and at least two existing
`Get-PulseTenantSnapshot` unit tests assert on manifest shapes the flip changes for every
caller, not just ones that opt in - a genuine breaking change to the function's existing
contract. Reverted; `-ExpandSettings` stays opt-in. Flipping the default is real,
scoped, doable follow-up work - not done here under this task's own time budget.

**Performance/scale (Task 2.7)**: a dedicated, serial perf container
(`tests/Perf/ScaleAndMemory.Tests.ps1`, run via `./build.ps1 -Tasks build,perftest`, never
part of the default test workflow) measures and budgets ([measured] x1.5): a 5,000-policy
synthetic Settings Catalog expansion + conflict-detection compute pass (mocked Graph,
~202s/4300 rows), a 50,000-row `managedDevices` write+read memory ceiling, and raw
per-policy dataset write scaling. Two genuine, documented scale gaps surfaced (not fixed
in this task, flagged for follow-up): `Write-PulseDataset`/`Read-PulseDataset` do not
stream (materialize the full object graph - measured ~5.6-16x the serialized file size in
memory, not the plan's informal <=2x target), and `Set-PulseManifestEntry` re-reads and
re-serializes the WHOLE manifest on every single dataset write (O(n) per write / O(n^2)
total as a snapshot's own manifest grows - a real cost a live 781-policy run pays on every
policy). See `docs/spike/2026-08-16-t27-perf-container.md` for the full recorded numbers,
hardware, and method.

## Not yet done - one thing, an operator action, not code

1. **First publish to PSGallery**, which needs a PSGallery API key. Publish tooling is
   ready (`scripts/Publish-TenantPulsePackage.ps1`) but defaults to a dry run and refuses
   to publish without a resolved API key and `-Confirm`; Adam runs it.

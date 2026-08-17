# TenantPulse - internal status (Phase 1 through Phase 4)

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
  **RESOLVED T3.4 (Part C)**: root-caused first - the "deeper nesting" is this module's OWN
  collection-time redaction marker (`{redacted:true}`, `Protect-PulseTypedPolicySensitivePayload`)
  replacing `value` before the typed-policy expansion ever reads it back, not a Graph-native
  shape variance; `scratch/live-27/snapshot/datasets/deviceConfigurations.json` (still
  in-repo) is the exact evidentiary artifact, all 8 `windows10CustomConfiguration` policies
  present at that capture, 8/8. `TypedPolicyMaps.psd1`'s `Nested` schema is no longer capped
  at one level (`ConvertTo-PulseTypedPolicyRows.ps1`'s walk is now genuinely recursive,
  arbitrary depth); `omaSettings.value` now carries a `Nested` description of that real
  2-level shape - and `value` keeps `Sensitive = $true`, completely unchanged, so the
  existing unconditional wholesale-redaction behavior for a real, live secret is untouched.
  "Sensitive always wins, at every depth" is the closing invariant, proven (not merely
  asserted) by dedicated regression tests in `TypedPolicyWalk.Tests.ps1` (a golden fixture
  sanitized from the exact live-27 evidence, plus two synthetic mechanism-proof tests) and
  `ProtectTypedPolicySensitivePayload.Tests.ps1` (the raw-dataset redaction pass, unchanged
  code, proven still correct against an object-shaped raw `value`).

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
~202s/5000 rows), a 50,000-row `managedDevices` write+read memory ceiling, and raw
per-policy dataset write scaling. Two genuine, documented scale gaps surfaced (not fixed
in this task, flagged for follow-up): `Write-PulseDataset`/`Read-PulseDataset` do not
stream (materialize the full object graph - measured ~5.6-16x the serialized file size in
memory, not the plan's informal <=2x target), and `Set-PulseManifestEntry` re-reads and
re-serializes the WHOLE manifest on every single dataset write (O(n) per write / O(n^2)
total as a snapshot's own manifest grows - a real cost a live 781-policy run pays on every
policy). See `docs/spike/2026-08-16-t27-perf-container.md` for the full recorded numbers,
hardware, and method.

**Ledger: deferred/not-yet-populated Phase 2 data, explicit not silent**:

- An **expansion-summary dataset** (an aggregate-counts view across the settingsCatalog/
  compliance/deviceConfiguration expansion families, for a consuming report/check) is
  scoped but explicitly **deferred to Phase 3** - its consumer moved there, so there is
  nothing in this phase that reads or emits it. Not present anywhere in a Phase 2 snapshot;
  do not expect it before Phase 3.
- Every typed-assignment record `Invoke-PulseTypedPolicyExpansion` normalizes
  (`targetType`/`groupId`/`filterId`/`filterType`/`intent`) already carries an `intent`
  field, structurally, but it is hard-coded `$null` on every row today - unpopulated until
  Phase 2b, which is where the real intent value (include/exclude) gets threaded through.
  Present in the shape now so 2b is a pure data-population change, not a schema change.

## Phase 3 (T3.1-T3.6): engine and catalog work complete; T3.6 live gate honestly incomplete

Task 3.1 shipped the Maester attribution shim and TP.INT.0006 (Intune device cleanup rule
conflict check). Task 3.2 ported nine further Intune checks (TP.INT.0007-0009/0011-0015) and
formally evaluated (and **BLOCKED**, not shipped) `TP.INT.0010` - Maester's "Intune diagnostic
settings -> Audit Logs" check is an ARM call (`GET providers/microsoft.intune/diagnosticSettings`),
not a Graph call, so GraphKit's Graph-only transport can never surface it via the ordinary
descriptor-Pending mechanism. This is a genuine architecture gap needing a product decision
(a dedicated ARM auth path, or permanent descope), not a missing-descriptor case, and it
remains unresolved as of this task - see
`docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md`'s TP.INT.0010 numbering-gap
note. Task 3.3 added twelve more Intune checks (TP.INT.0019-0030) and imported research entries
for TP.INT.0016/0017/0018 for record-completeness without implementing them yet.

Phase 4 (T4.1-T4.5, its own section below) developed in parallel on a separate branch and
merged into `main` at `99126f6` ("Phase 4 core Entra catalog into main (28->49 checks)"),
after which Phase 3 work continued on the merged tree:

- **Task 3.4** shipped `TP.INT.0031` (BitLocker CSP settings present and correct) and
  `TP.INT.0016` (ASR Standard Protection rules configured), both settings-catalog-expansion-
  powered checks (the first checks in this catalog to consume `Resolve-PulseSettingsCatalog
  SnapshotExpansion`/the settings-presence-index rather than a typed dataset directly). A
  dual-review fix round corrected `TP.INT.0016`'s `settingDefinitionId` strings against the
  real corpus (`948150c`) and `TP.INT.0014`/`TP.INT.0031`'s BitLocker adjudication logic
  (`5f2ee17`), plus added a permanent QA gate
  (`tests/QA/SettingDefinitionCorpusCrossCheck.tests.ps1`, `b862e5f`) so a hard-coded
  `settingDefinitionId` can never again drift from the corpus it's meant to match without the
  suite catching it.
  **Still BLOCKED, not shipped**: `TP.INT.0017` (App Control policy enforced) and
  `TP.INT.0018` (Managed Installer rules paired with an enforcing App Control policy). Two
  independent blockers, both confirmed (not merely suspected) as of the T3.5 dual-review fix
  round: (1) `tests/Fixtures/SettingsCatalogCorpus/checked-definitions.json` has zero entries
  matching App Control or Managed Installer, even though this repo's own live capture
  (`scratch/live-27/snapshot/reference/settingDefinitions.json`) has 34 raw matching
  `settingDefinitions` - so a `TP.INT.0016`-style settings-presence-index port has nothing to
  key against in the corpus yet; and (2) App Control's `visibility:"template"` field, while
  real and confirmed present in that same live capture, is undocumented anywhere in
  Microsoft's published Graph API schema docs (re-confirmed live against the beta
  `deviceManagementConfigurationPolicyTemplate` resource for this fix round) - a genuine
  docs-vs-live-schema gap that a from-docs-only implementation can't safely paper over.
- **Task 3.5** wired `Get-PulseCaExclusionContext` into `TP.ENT.0004`/`TP.ENT.0005` so both
  checks surface honored Conditional Access group/user exclusions as evidence instead of
  silently ignoring them (`36bf53e`), then a dual-review fix round hardened both checks
  further: malformed-exclusion and group-exclusion-note evidence surfaced, and a
  report-only-only exclusion (an exclusion that exists but grants no real enforcement gap)
  now warns instead of passing silently (`ae5cc1d`). A final documentation-only fix round
  corrected `TP.INT.0017`'s BLOCKED note (the App Control `visibility` fact was live-confirmed
  in-repo all along, not "unconfirmed" as a prior pass claimed) and added the `TP.INT.0010`
  numbering-gap note referenced above (`bbef1d1`, current `main` HEAD).

**Catalog state at `bbef1d1`, verified against the live-built module
(`Get-PulseCheckCatalog`)**: **51 checks total - 28 `TP.INT` + 23 `TP.ENT`.** Three checks
remain genuinely BLOCKED and unshipped for the reasons above: `TP.INT.0010` (ARM-vs-Graph
architecture gap), `TP.INT.0017`/`TP.INT.0018` (corpus + docs-schema gaps). Suite:
1929/1929 tests, 0 failed, 0 errors (`./build.ps1 -Tasks build,test`, re-verified for this
task).

### Task 3.6 - Phase 3 live gate: NOT completed live-tenant-side

This task's brief called for a full live assessment of all 51 checks against the Ivy24 lab
tenant (fresh snapshot, full evaluation, reconciliation, `-FromSnapshot` byte-identity, a
secret/PII sweep, and a scripted license/attribution audit), mirroring the T4.5 Phase 4 gate
pattern (`docs/gates/phase4-ivy24-findings.redacted.json`, 28 checks). **The live-tenant
portion did not run in this pass.** While preparing the run, the environment's own permission
system denied a read of `~/.graphkit/profiles.json` (checking the `ivy24` profile's shape
before invoking it) with an explicit "let the user decide" instruction; the agent stopped
there rather than working around the denial, per this project's own operating rules. This is
recorded here as an honest, explicit pending item rather than a run that didn't happen being
implied to have happened - see the task's own report for the full timeline. What a live Task
3.6 gate still needs, whenever it runs: all 51 checks producing a real status or an honest
`NotApplicable` (with `TP.INT.0006` expected to `Fail` with real conflict evidence per the
Phase 2 baseline), reconciliation against the 781-policy Phase 2 baseline (tenant may have
drifted), the byte-identity check, the secret/PII sweep, and the scripted license/attribution
audit (item 5 of the brief - see below for what could be done without live data).

## Phase 4: core Entra catalog (complete, Task 4.5 phase gate)

Phase 4 took the catalog from 20 checks (Phase 1 seed + Phase 3's EIDSCA wave-1 clusters) to
**28** across five tasks: T4.1 (CA-policy and auth-method normalization views + a real
BreakGlassAccounts/ServiceAccounts exclusion context), T4.2 (EIDSCA wave-1, verified clusters),
T4.3 (EIDSCA wave-2, resolving every UNVERIFIED research flag before its check shipped), T4.4
(the ScuBA/CISA-cited Conditional Access, privileged-role, and credential-hygiene checks,
`TP.ENT.0017`-`0024`), and T4.5 (this task: cite-only CIS cross-reference support, the phase
gate, README/STATUS).

### T4.5 - CIS cross-references

Added an optional, cite-only `References.Cis` field to the check-descriptor schema (validated
only when present) and wired it through `Invoke-PulseEvaluation` into a document-level
`notices.cisDisclaimer` that fires only when at least one rendered finding carries a CIS
reference. Both directions (silent when none, firing when >=1, firing regardless of finding
order, Hashtable- and PSCustomObject-shaped `References` both read correctly) are covered by
new tests in `Evaluator.Tests.ps1`. **Zero of the 28 shipped checks carry a `References.Cis`
entry** - the Phase 4 research entries (`docs/research/iha-v2/2026-08-16-phase4-entra-check-
entries.md`) cite ScuBA/CISA, Maester/EIDSCA, and Microsoft Learn exclusively, with no verified
CIS mapping for any check in this catalog. The wiring is real and tested against synthetic
fixture data; it has nothing to cite yet on the live catalog. See README.md's "CIS compliance
disclaimer" section for the full picture.

### T4.5 - full-catalog live gate vs Ivy24

`Invoke-PulseAssessment -ProfileId ivy24 -OutputPath ./output/live-ivy24-t45 -Redact`, run from
this branch (`phase4/t4.1-normalization`) against the already-registered `ivy24` GraphKit
profile (certificate auth, `~/.graphkit/profiles.json`).

**Coverage: 21/28 assessed (75%)**. The 7 not-assessed checks are all honest `NotApplicable`,
not errors: `TP.ENT.0012` (the `authorizationPolicy`-backed cluster), `TP.ENT.0013`/`0015`/`0016`
(the three `directorySettings`-backed clusters), and `TP.ENT.0022`/`0023` (PIM posture,
cross-tenant access) are `descriptor-pending: awaiting
GraphKit release` - written, tested, cited, just waiting on GraphKit descriptors this catalog's
research already scoped. `TP.ENT.0001` (Security Defaults) is a genuine, correct
`NotApplicable`: this tenant runs Conditional Access, not Security Defaults, so the check
declines to evaluate a control the tenant deliberately superseded.

**Scores: overall 65.0/127.0 (51.2%)**. Hand-verified against the weight table (Critical=10,
High=6, Medium=3, Low=1, Info=0; Pass=full weight, Warn=half, Fail=0-but-counts-toward-possible,
NotApplicable excluded from the denominator entirely - `Add-PulseScores.ps1`) for two
categories, arithmetic below matching the findings JSON exactly:

- **Entra.ConditionalAccess** (assessed 6/6): `TP.ENT.0003` Critical(10) Fail=0,
  `TP.ENT.0004` High(6) Pass=6, `TP.ENT.0005` High(6) Pass=6, `TP.ENT.0017` Critical(10)
  Pass=10, `TP.ENT.0018` Critical(10) Fail=0, `TP.ENT.0024` Info(0) Pass=0.
  Possible = 10+6+6+10+10+0 = **42**. Earned = 0+6+6+10+0+0 = **22**. 22/42 = **52.4%** -
  matches the reported `earned:22.0, possible:42.0, percent:52.4`.
- **Entra.PrivilegedRoles** (assessed 3/4, `TP.ENT.0022` excluded as `NotApplicable`):
  `TP.ENT.0002` High(6) Fail=0, `TP.ENT.0020` High(6) Pass=6, `TP.ENT.0021` High(6) Fail=0.
  Possible = 6+6+6 = **18**. Earned = 0+6+0 = **6**. 6/18 = **33.3%** - matches the reported
  `earned:6.0, possible:18.0, percent:33.3`.

**Per-check status, all 28** (`status` / `reason`, `-Redact`ed evidence, tenant field
`tp-5de2c5ec...` pseudonym, never the raw GUID):

| Id | Status | Reason (verbatim, truncated where long) |
|---|---|---|
| TP.ENT.0001 | NotApplicable | Conditional Access is in use (4 enabled policies); Security Defaults is not evaluated as a standalone control here. |
| TP.ENT.0002 | Fail | (no reason string; evidence-only) |
| TP.ENT.0003 | Fail | No break-glass accounts are declared in the assessment profile (BreakGlassAccounts). |
| TP.ENT.0004 | Pass | 2 enabled CA policies block legacy authentication. |
| TP.ENT.0005 | Pass | All 9 of Microsoft's minimum admin roles are covered by MFA-requiring, enabled CA policies. |
| TP.ENT.0006 | Fail | FIDO2 attestation (AF03) and key restrictions (AF04) are not enforced. |
| TP.ENT.0007 | Fail | Suspicious sign-in reporting is not enabled (AG02, `state='default'`). |
| TP.ENT.0008 | Pass | Authenticator enabled, OTP fallback off, number matching + app-name display required tenant-wide. |
| TP.ENT.0009 | Fail | SMS still usable as a sign-in factor for 1 target group (`all_users`, AS04). |
| TP.ENT.0010 | Fail | Temporary Access Pass is disabled (AT01). |
| TP.ENT.0011 | Pass | Voice call is disabled (AV01). |
| TP.ENT.0012/0013/0015/0016 | NotApplicable | `descriptor-pending: awaiting GraphKit release` |
| TP.ENT.0017 | Pass | An enabled, enforced CA policy requires MFA for all users. |
| TP.ENT.0018 | Fail | 9 of 9 minimum admin roles lack an enforced phishing-resistant-strength CA policy. |
| TP.ENT.0019 | Fail | 1 of 12 evaluated SP credentials exceed ScuBA's lifetime guidance. |
| TP.ENT.0020 | Pass | (no reason string; evidence-only) |
| TP.ENT.0021 | Fail | 11 active privileged-role assignments across 36 privileged roles (direct-assignment count; see the check's documented group-expansion gap). |
| TP.ENT.0022/0023 | NotApplicable | `descriptor-pending: awaiting GraphKit release` |
| TP.ENT.0024 | Pass | 0 workload-identity-scoped CA policies found (Info, awareness-only, non-scored). |
| TP.INT.0001 | Pass | (no reason string; evidence-only) |
| TP.INT.0002 | Pass | Every enrolled platform (Windows) has a compliance policy. |
| TP.INT.0003 | Pass | (no reason string; evidence-only) |
| TP.INT.0004 | Pass | 4 Windows Update rings have deadlines configured. |
| TP.INT.0005 | Fail | 0/13 Intune-managed devices and 67/95 Entra-registered devices inactive >90d; 82 Entra-registered devices are not Intune-managed at all (population gap noted in evidence). |

`notices.cisDisclaimer` is `null` on this run (no finding carries a CIS reference, as expected -
see the T4.5 CIS section above), and `Import-PulseCheckCatalog`'s own count still pins at
exactly 28 (`CheckCatalog.Tests.ps1`).

### Suite

`./build.ps1 -Tasks build,test`: **1375 tests, 0 failed, 0 errors** (was 1366 before this task's
+9 net new Its). All four `MinimumTests` ratchet locations (`.build/AssertGateResult.tasks.ps1`,
`.github/workflows/ci.yml`, `scripts/Publish-TenantPulsePackage.ps1`,
`tests/QA/PublishTenantPulsePackage.tests.ps1`) bumped together in the same commit.

### Retrospective - what review rounds caught this phase

- **T4.1 (normalization layer):** the shape-neutrality fix round - CA-policy and auth-method
  views both needed to accept Hashtable- and PSObject-shaped input identically, a recurring
  theme every later task's fixtures had to keep honoring.
- **T4.2 (ci.yml ratchet miss):** the MinimumTests ratchet was bumped in
  `.build/AssertGateResult.tasks.ps1` but missed in `.github/workflows/ci.yml`, letting CI
  silently enforce a stale floor - the exact failure mode the "four locations, same commit"
  rule now exists to prevent, and this task re-verified all four before committing.
  **Lesson:** a ratchet with N tracking locations needs an explicit checklist step, not
  memory, every time the count changes - this task grepped for all occurrences of the old
  value before editing, specifically because of this history.
- **T4.3 (UNVERIFIED-flag resolution):** a genuine zero-fix review round - every flagged
  EIDSCA setting name had already been correctly re-verified against the live config source
  before review, nothing to fix. **Lesson:** the "five stages or defer with a ledger note"
  discipline from the task's own Definition of Done paid for itself here; nothing shipped on
  inference.
- **T4.4 (ScuBA/CISA checks):** the most consequential round - a fabricated authentication-
  strength GUID had been invented rather than sourced from a real Graph read (fixed by
  dropping the fabricated ID and reading the tenant's actual built-in strength), and
  `excludeRoles` exclusions were not being subtracted from `TP.ENT.0018`'s privileged-role
  coverage count, silently understating a real gap as smaller than it was (fixed to subtract
  documented exclusions and note them in evidence). **Lesson, carried into T4.5:** never
  invent an identifier a live Graph read can supply - this task's live-gate run was executed
  for real, against the real Ivy24 tenant, specifically because fabricating "what a live run
  would show" is the same failure class as T4.4's fabricated GUID, just at the report layer
  instead of the check-logic layer. Every number in the live-gate section above came out of
  the real `tenantpulse-findings.json` this run produced, not estimation.
- **T4.5 (this task):** the CIS cross-reference research entries turned out to carry zero
  actual CIS mappings - initially read as a possible gap in scope, confirmed correct by
  re-reading both the per-check research file and the licensing methodology doc: the research
  was written cite-only and deliberately conservative, and "add mappings where the research
  carries them" is correctly zero for this catalog. **Lesson:** a plan step reading as "should
  produce something" does not obligate inventing that something when the honest answer,
  checked directly against source, is "there is nothing here yet" - the same anti-fabrication
  discipline T4.4's fix round established.

## Not yet done - one thing, an operator action, not code

1. **First publish to PSGallery**, which needs a PSGallery API key. Publish tooling is
   ready (`scripts/Publish-TenantPulsePackage.ps1`) but defaults to a dry run and refuses
   to publish without a resolved API key and `-Confirm`; Adam runs it.

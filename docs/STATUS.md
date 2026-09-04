# TenantPulse - internal status (Phase 1 through Phase 4)

This is internal development/task narrative, moved out of README.md (post-review fix -
README.md is meant to read as a PSGallery landing page, not an implementation log). Nothing
here is required to install or use TenantPulse; see README.md for that.

## Released-package evidence (2026-08-30)

GraphKit `0.3.0` and TenantPulse `0.2.0` are the coordinated immutable PSGallery releases.
TenantPulse was greenfield and pre-adoption when this release was built: there was no installed
user base, customer estate, prior runtime, or migration/repoint/cutover task. Current source is
the separate unreleased TenantPulse `0.3.0` product-program line; it is not the public `0.2.0`
archive. Historical GraphKit `0.2.2` and TenantPulse `0.1.3` package identities remain recorded
below.

Current-source 0.3.0 program work records Endpoint Security composite provenance as the stable
qualified set `ConfigurationPolicy.ListBeta` and `ConfigurationPolicySetting.ListBeta`, with
setting failures attributed to the latter primitive. The finding-14 request to accept `Partial`
in released schema 1.0.0/1.1.0 manifests remains rejected: those writers emitted only `Collected`,
`Failed`, and `Skipped`; migration fails closed without modifying the manifest. Schema 2.0.0 is
the first writer contract that introduced `Partial`.

The current unreleased source also implements the R1a outcome-fidelity tranche. One canonical
mapper preserves Graph failure outcomes across direct, composite, and expansion collection. A
request-time `403` is persisted as `Failed` / `PermissionDenied`; only `AuthenticationFailed`
aborts later network-backed collection. Deadline expiration, cancellation, indeterminate
certainty, permission denial, and provider failure remain explicit and isolated, and a `Partial`
provider outcome never satisfies a later collection dependency.

`Data.PartialDatasets` is a strict Function-only opt-in requiring a `DatasetOutcomes` parameter.
Exactly four checks opt in. Universal checks `TP.INT.0013` and `TP.INT.0029` may Fail when a known
row proves an offender but cannot Pass while gaps remain. Existential checks `TP.INT.0014` and
`TP.INT.0015` may Pass on a known witness but cannot Fail while gaps remain; their BitLocker/LAPS
criteria require native Boolean values. The other 49 checks remain `NotApplicable` on Partial. For
the four opt-ins, structurally valid non-decisive Partial evidence is also `NotApplicable`; without
decisive proof, zero rows or malformed outcome, gap, or row data is `Error`. Findings schema `1.0`,
snapshot schema `2.0.0`, and scoring model `1.0` remain unchanged.

This tranche's evidence is deterministic source/package testing only. It adds no new live-service
or publication proof. Independent review after the earlier 2,510-test candidate found four
applicable correctness gaps: message-only provider failures could lose canonical authentication or
permission classification; authentication-aborted expansion pipelines could omit unattempted
policies or the top-level `collectionFailure`; and a relevant Endpoint Security policy without a
usable identifier could be treated as authoritative absence. All four are closed at exact tested
commit `21f6a1025331aa6d14bfb47b32bec403d2ff994d`, tree
`b6732cf8734a8020b3470f1c431a848ef81e21c0`. The synchronized minimum is 2,517, the active NotRun
allowance is zero, and the package-first full gate passed 2,517/2,517 with zero failures, errors,
skips, NotRun, or failed containers.

Proof run `9ef9712e-bddc-4dc9-82f0-f085ab874656` binds all 59 shipped files and the exact result pair.
The 418,518-byte local candidate archive SHA-256 is
`386d79effd65afbf1deaca17d57ab3c08a6b63111144ff6a59fc3ed4726a994f`; the tested-release-proof
SHA-256 is `54ab272f55b2321f81ff8b793e2612aa13581cdb3be501fb935fca8d73513b9e`. The built manifest
SHA-256 is `62e746a73e616acf14421ddf2355fb258a4af2fa3cf51d4ee015028c8a0432b3`; the built module SHA-256 is
`1f65e7a1b98c18207aca01c90d33acf3878e957359c460f7a6bf34468ce204a7`.

Source, built, packaged, and clean child-process import gates all preserve exact GraphKit `0.3.0`.
The publisher revalidated this exact proof in no-key/no-`-Publish` mode and reported that nothing
was published. A read-only controller-local freeze records `local-package-first` scope,
`externalTransferApproved = false`, and that the serialized test object contains synthetic
credential fixtures. Independent code and proof reviews found no P0-P3 issue in the corrected
candidate. Push/PR/CodeRabbit, exact-head six-job CI plus gitleaks, merge, and merged-main CI remain
pending. Local `gitleaks` is not installed, so only the repo-local Secret/PII/control-byte gate is
locally proven. The immutable TenantPulse `0.2.0` evidence table and exact-package live record below
are historical release proof, not proof for the unreleased `0.3.0` source.

| Evidence state | Proof |
|---|---|
| Deterministic | Reviewed tree `24b3d4ebe522d9bf94d9a75c8625be438fa9b768`; 2,277 tests; zero failures/errors/skips/NotRun; bound archive hash `a0d5ff793b92753ab3efb4db20cf5bcf8b953e3cf81bf1a776c96a3d992417bd`. |
| CI | PR-head run `33295409637` and merged-main run `33295648250` at `b2eb7a882cc1fcb7994c39a606c7b9ac22f5a114`; six OS/PowerShell matrix jobs plus gitleaks green. |
| Live | The exact-package Ivy24 rows and expansion counts are retained below. |
| Published | TenantPulse 0.2.0 on PSGallery at `2026-08-30T14:07:39.587Z`; the downloaded 411284-byte archive matches `a0d5ff793b92753ab3efb4db20cf5bcf8b953e3cf81bf1a776c96a3d992417bd`. |

The source implementation is wired through TenantPulse's public snapshot path. Synthetic
`Pending` map entries for composite datasets are implementation placeholders, not the runtime
outcome: the built-in provider registry intercepts each one before the ordinary descriptor
fallback. Evidence levels are kept separate below.

| Dataset/check | Exact-package evidence |
|---|---|
| `managedDeviceCleanupRules` / `TP.INT.0007` | Live: the exact package collected 1 row and the check passed. |
| `dataProcessorServiceForWindowsFeaturesOnboarding` / `TP.INT.0009` | Built-in no-network plan returns `PlatformUnavailable`. Microsoft publishes the resource shape but no official GET/application-permission contract, so neither project guesses a descriptor. Recheck only when that service contract changes. |
| `intuneRbacGroupProtection` / `TP.INT.0013` | Live: the exact package collected 3 rows. The check failed on tenant posture, not collection or execution. |
| `endpointSecurityDiskEncryptionPolicies` / `TP.INT.0014` | Live (partial): the exact package returned 1 usable row and 2 explicit `missing-setting` gaps. The check failed closed as `NotApplicable`. |
| `endpointSecurityLapsPolicies` / `TP.INT.0015` | Live: the exact package collected an authoritative empty set. The check failed because no qualifying policy exists, not because collection failed. |
| `securityBaselinesAssignedAndCurrent` / `TP.INT.0029` | Live: the exact package collected 3 rows. The check failed on tenant posture, not collection or execution. |

The read-only live gate installed that exact archive into an isolated root and loaded
TenantPulse `0.2.0`, GraphKit `0.3.0`, and Microsoft.Graph.Authentication `2.38.1` from that
root. All seven selected checks completed: 3 Pass, 3 posture Fail, and 1 fail-closed
NotApplicable from partial BitLocker evidence. The large expansion paths also completed:
Settings Catalog 781 policies / 4302 rows / 64 gaps; compliance 40 / 606 / 6; device
configuration 15 / 244 / 0; conflicts 3 / 165 / 70; and the setting-presence index 3 / 2320 /
70. Across 1629 generated artifacts, the raw tenant id was absent, profile provenance metadata
was absent, and the profile label was absent from the manifest and redacted report.

**Package identity and evidence boundary.** GraphKit `0.2.2` is the stable producer released
before R1. On 2026-08-29, the PSGallery archive downloaded for GraphKit `0.2.2` was 201750
bytes with SHA-256 `8993BFD6C78F6143069208F79F82D7EC9C72F87AB876DF6769C8733AAAB46385`.
Its `GraphKit.psm1` was 416488 bytes with SHA-256
`C20E30F8944EBDB38D9EFAAC7C538A4400DC5B91206E3510749FCF7E0F4091DC`, and its manifest
was 7487 bytes with SHA-256
`CAFFB3C39029310F9E562EBD6D90091BA329AD264A6E6728AB241C4E584A1111`. The locally
restored `output/RequiredModules/GraphKit/0.2.2` module and manifest match those public
payloads byte-for-byte. Earlier GraphKit hashes and the claim that the public module differed
only by one trailing newline did not identify this public package and are not release evidence.

TenantPulse `0.1.2` is published to PSGallery and its immutable embedded release notes still
describe it as a candidate. The pre-publication local `0.1.2` archive was 401634 bytes with
SHA-256 `91FF3860B6257257BBE827255FFF5E975B7521920411D31EFB3CE1496697B319`; it is not the
PSGallery archive, which is 401753 bytes with SHA-256
`51C90EA4CE8C428D7C87564715FB2EC19BDF0DA27D035131576EF341584E40E6`. TenantPulse `0.1.3`
is also published to PSGallery as the metadata-only correction with the same exact GraphKit
`0.2.2` dependency. Its public archive is 400377 bytes with SHA-256
`CA1A47BDC8FD9CD8D0885F61622B29DB23CA56F95042C6D789CEFAAA593F24B3`; its
`TenantPulse.psm1` is 1148725 bytes with SHA-256
`C4FAD4565747E150B21CF857C77C5F83122A7B9DC54771B05786A928D3AA8AD9`, and its manifest is
4980 bytes with SHA-256 `785B370BE4C8B70576654F0873B456476C884C05BAA8CEECED1EAAF9374ECCF7`.
All 61 files in the current local built module match the public `0.1.3` payloads. The local
and public `.nupkg` archives are not byte-identical because the archive entry metadata differs
(including two public `.gitkeep` entries), so an archive SHA-256 must not be used as a local
reproducibility claim. No CI result exists for source revision `771124b`.

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

## GraphKit 0.2.2 consume (TenantPulse 0.1.1)

GraphKit 0.2.2 is published and both pins (`source/TenantPulse.psd1`,
`RequiredModules.psd1`) are bumped. Official GET/List descriptors shipped for twelve
DatasetMap datasets that were Pending on 0.1.1: `authorizationPolicy`,
`directorySettings`, `roleAssignmentScheduleInstances`,
`roleEligibilityScheduleInstances`, `crossTenantAccessPolicyDefault`,
`operationApprovalPolicies`, `intuneBrandingProfiles`,
`windowsFeatureUpdateProfiles`, `applePushNotificationCertificate`,
`androidManagedStoreAccountEnterpriseSettings`, `mobileThreatDefenseConnectors`,
`windowsAutopilotDeploymentProfiles`. ApiVersion corrections to match GraphKit:
`authorizationPolicy`, `applePushNotificationCertificate`, and
`mobileThreatDefenseConnectors` are v1.0 (were beta). Still Pending (no official GET
/ no Walk in GraphKit): `dataProcessorServiceForWindowsFeaturesOnboarding`,
`intuneRbacGroupProtection`, `endpointSecurityDiskEncryptionPolicies`,
`endpointSecurityLapsPolicies`, `securityBaselinesAssignedAndCurrent`. Walks were
not invented. TenantPulse 0.1.0 is already published; this is the 0.1.1 consume.

**Task 7 evidence (2026-08-19):** the controlled Ivy24 probe did execute a read-only
`GET /beta/deviceManagement/dataProcessorServiceForWindowsFeaturesOnboarding` through
GraphKit 0.2.2's raw operation path and returned `Succeeded` with one singleton object
whose `hasValidWindowsLicense` and `areDataProcessorServiceForWindowsFeaturesEnabled`
fields were native Booleans. This proves the tenant endpoint and response shape, but it
does not prove a releasable GraphKit contract: the Microsoft Learn resource page has no
official GET method or application-permission section, and the read-only permission
analysis did not resolve a named application permission for the certificate app. The
DatasetMap entry therefore remains `Pending` rather than gaining a guessed descriptor or
claiming a false platform-unavailable endpoint. Recheck when Microsoft publishes the
method/permission contract or GraphKit ships the exact `Singleton.Default` descriptor,
then repeat the read-only Ivy24 probe before removing `Pending`.

The T4.5 Ivy24 live-gate table later in this file is the historical 0.1.1-era result.
Those twelve GET/List datasets are no longer awaiting GraphKit.

**R0 package-identity correction (2026-08-19):** published TenantPulse `0.1.1` remains the historical consumer artifact and is not overwritten. The `0.1.2` source first used the exact GraphKit `0.2.2` runtime requirement because changing `RequiredModules` changes shipped bytes; its build dependency file retains the separate `0.2.2` restore pin. `0.1.2` was then published with candidate-only embedded release notes. Published `0.1.3` corrects that metadata without changing runtime behavior or the GraphKit dependency.

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
- **Conflicts: real conflicts surfaced, not a zero-conflicts-by-luck outcome** - this
  historical pre-assignment-collection gate produced 165 conflict entries from all 3
  families; `assignmentOverlap` breakdown `none`=8, `possible`=34, `unknown`=123. Those
  counts are retained as evidence for that run, not as proof of the current assignment-aware
  runtime; Settings Catalog assignment collection now requires a fresh live-service gate.
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
2. **The former `-MaxParallel 4` path was pathologically slow against a REAL tenant**: it did
   not complete even a 20-policy real slice within 9m35s (killed); the identical slice
   completed `-Sequential` in 2.30s (0.12s/policy - even better than the T2.0 spike's own
   300ms mean). Root cause not fully established (see
   `docs/spike/2026-08-16-t27-perf-container.md`'s own section 4), but plausibly the
   RunspacePool's per-worker GraphKit re-import means each worker's token cache and
   `GraphThrottleCoordinator` state are NOT shared, so four workers independently unaware
   of each other's throttle state hammer the tenant with no shared backoff. Fixed
   first by forcing the production caller to `-Sequential`. The later R1a implementation
   deleted both `-MaxParallel` and `-Sequential`; current production is sequential-only.
   That is the safe current posture, not proof that the RunspacePool identity/throttle
   problem was root-caused. Parallel live fan-out remains unavailable until the producer
   and consumer share and prove one identity/throttle coordination model.

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

**Phase 2 task ledger, reconciled with the later governing product program**:

- The Phase 2 task explicitly **descoped** the orphaned expansion-summary dataset because no report
  or check consumed it and per-family counts/statuses already existed in the manifest. That was the
  accurate local-task disposition at the time. The later 2026-08-19 governing product-program R1b
  contract explicitly requires the deferred expansion-summary dataset, so the current program
  disposition is **open**; the later requirement supersedes the earlier task-local decision without
  rewriting its historical rationale.
- Typed compliance and device-configuration assignment records now populate include/exclude
  `intent` from the assignment target, preserve filter metadata, sort deterministically, and
  gap a policy rather than publishing a false unassigned row when a target is malformed.

## Phase 3 (T3.1-T3.6): engine and catalog complete; T3.6 live gate executed

Task 3.1 shipped the Maester attribution shim and TP.INT.0006 (Intune device cleanup rule
conflict check). Task 3.2 ported nine further Intune checks (TP.INT.0007-0009/0011-0015) and
formally evaluated (and **BLOCKED** at T3.2, not shipped; **DESCOPED** 2026-08-18)
`TP.INT.0010` - Maester's "Intune diagnostic settings -> Audit Logs" check is an ARM
call (`GET providers/microsoft.intune/diagnosticSettings`),
not a Graph call, so GraphKit's Graph-only transport can never surface it via the ordinary
descriptor-Pending mechanism. Product decision 2026-08-18: DESCOPED until GraphKit ARM
exists. The id is reserved (0009 then 0011). No `.psd1`, no Pending dataset, and no ARM
auth path in TenantPulse now. This is a genuine architecture gap, not a missing-descriptor
case. See
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
  **Shipped (2026-08-18):** `TP.INT.0017` (App Control policy enforced) and
  `TP.INT.0018` (Managed Installer rules paired with an enforcing App Control
  policy). Implemented against the live `applicationcontrolv2` schema in
  `scratch/live-27/snapshot/reference/settingDefinitions.json`; compact corpus
  fixture extended with those four definitionIds. `visibility:"template"` is
  still unpublished in Microsoft's Graph schema docs - the checks key the live
  ids, not that field. Same-policy AND via presence-index `policyIds` (not a
  tenant-wide union). Matching Maester, these two checks intentionally evaluate policy
  existence even though the expansion now also collects Settings Catalog assignments.
- **Task 3.5** wired `Get-PulseCaExclusionContext` into `TP.ENT.0004`/`TP.ENT.0005` so both
  checks surface honored Conditional Access group/user exclusions as evidence instead of
  silently ignoring them (`36bf53e`), then a dual-review fix round hardened both checks
  further: malformed-exclusion and group-exclusion-note evidence surfaced, and a
  report-only-only exclusion (an exclusion that exists but grants no real enforcement gap)
  now warns instead of passing silently (`ae5cc1d`). A final documentation-only fix round
  corrected `TP.INT.0017`'s BLOCKED note (the App Control `visibility` fact was live-confirmed
  in-repo all along, not "unconfirmed" as a prior pass claimed) and added the `TP.INT.0010`
  numbering-gap note referenced above (`bbef1d1`, current `main` HEAD).

**Catalog state after TP.INT.0017/0018:** **53 checks total - 30 `TP.INT` + 23 `TP.ENT`.**
`TP.INT.0010` is DESCOPED until GraphKit ARM exists (id reserved; no `.psd1`).
`TP.INT.0017`/`0018` shipped against the live App Control schema.

### Task 3.6 - Phase 3 live gate: EXECUTED

This task's brief called for a full live assessment of all 51 checks against the Ivy24 lab
tenant (fresh snapshot, full evaluation, reconciliation, `-FromSnapshot` byte-identity, a
secret/PII sweep, and a scripted license/attribution audit), mirroring the T4.5 Phase 4 gate
pattern (`docs/gates/phase4-ivy24-findings.redacted.json`, 28 checks). The permission-boundary
block recorded in an earlier draft of this section (a denied read of
`~/.graphkit/profiles.json`) was cleared by the operator; the live-tenant portion then ran to
completion, attended, on 2026-08-17.

**Round A (10 commits, whole-phase review fix round, `4aa3db9`..`5836106`):** the review pass
immediately preceding the live gate, closing every finding the review turned up before the
gate ran against real tenant data:

- `4aa3db9` - the permanent license/attribution audit itself (`tests/QA/LicenseAttributionAudit.tests.ps1`,
  6 standing tests: Origin<->THIRD-PARTY-NOTICES reconciliation both directions, Maester MIT
  notice verbatim check, CIS cite-only prose sweep, authority-quote attribution) plus this same
  Phase 3 STATUS catch-up in its earlier form; fixed the TP.INT.0016 notices gap the audit
  itself caught.
- `4450995` (I1) - TP.INT.0016 unconditional redaction-Warn honesty, matching TP.INT.0031's
  existing behavior.
- `806f78d` (I2) - ordinal evidence-identity fallback for TP.INT.0020/0021/0023/0026/0028 (an
  id-less row's fallback identity is now a per-row ordinal, not a field that can collide across
  rows sharing the same value).
- `d8045e1` (I3) - TP.INT.0020 severity demoted Critical -> High, Impact High -> Medium.
- `0e17965` (I4) - honest per-row evidence on every status path for TP.INT.0016/0031.
- `906b50f` (M1) - corroborating Pass-path evidence for TP.INT.0020/0021/0028 (never leave a
  Pass evidence-empty when real per-row data already exists to corroborate it with).
- `65673f7` (M2/M3/M4) - three documentation-only review notes for TP.INT.0013/0014/0029.
- `d3cee3c` (finding 7) - structural fail-closed fallback in the collector for unmapped
  `@odata.type` rows.
- `1ed6e80` (finding 8) - SecretScan's own explicit file list widened to cover missing root
  files.
- `5836106` (finding 9) - README artifact-sharing statement.

License/attribution audit: **shipped** (`4aa3db9`, `tests/QA/LicenseAttributionAudit.tests.ps1`,
6 permanent suite tests, part of the standing gate from that commit onward).

**LIVE GATE: EXECUTED, 2026-08-17, attended, against the Ivy24 lab tenant.** Results across all
51 checks: **13 Pass / 16 Fail / 21 NotApplicable / 1 Error.** Highlights:

- **TP.INT.0006** (settings-catalog conflict detection) reproduced the Phase 2 conflict
  baseline **exactly**: 165 conflicts (0 proven / 34 possible / 123 unknown / 8 none) -
  byte-for-byte the same distribution Phase 2's own gate recorded, confirming the conflict-
  detection pipeline is stable across everything Phase 3 built on top of it.
- **Policy count**: 781 policies collected, an exact match against the Phase 2 baseline - no
  tenant drift between the two gate runs.
- **`-FromSnapshot` byte-identity replay**: exact - re-evaluating the same snapshot reproduced
  byte-identical `tenantpulse-findings.json` output, confirming
  `ConvertTo-PulseCanonicalJson`'s determinism guarantee holds against a real, full-size
  51-check live document, not just fixture-scale test data.
- **Two live surprises**, both closed by this repo's own Phase 3 closing fix series (see that
  series' own commits, immediately following this gate on `main`):
  1. **TP.INT.0028** (Enrollment Status Page blocking) - the live
     `DeviceEnrollmentConfiguration`/List v1.0 endpoint returns TRIMMED
     `windows10EnrollmentCompletionPageConfiguration` rows (9 properties, no
     `allowDeviceUseOnInstallFailure`/`showInstallationProgress`), which the pre-fix check
     treated as an unconditional `Error` rather than the benign List-endpoint projection
     limitation it actually is - fixed to `NotApplicable` when the property is absent from
     every ESP row, still `Error` for a genuine mixed-absence anomaly.
  2. **Evidence-Detail redaction gap (Critical-class)** - a real Apple ID UPN surfaced raw in
     rendered findings evidence Detail under `-Redact`, via TP.INT.0020/0021's
     `appleIdentifier`/`organizationName` detail keys - `-Redact` only ever substituted
     `evidence.identity`/`evidence.sortKey`, never anything inside `Detail`. Fixed via a
     minimal contract extension (`RedactDetailKeys` on an evidence entry) and an audit of
     every check's evidence construction, which found one further unmarked Apple-ID instance
     (TP.INT.0019's `appleIdentifier`) beyond the two the live run surfaced directly. That
     audit was not the end of the Detail-key class: the later `docs/gates/README.md`
     live-gate incident (person-derived device names in `evidence[].detail.deviceName`/
     `displayName`) showed `TP.INT.0005` (`Test-PulseStaleDevices`) still shipped those
     hostnames unmarked. Closing-series leftover, now marked: `deviceName` on managed /
     newly-enrolled rows, `displayName` on entra + gap rows. Residual, not full
     de-identification: Reason text is still only capped; unmarked person-identifying
     Detail keys on other checks stay unredacted.

The secret/PII sweep against this gate's own run found no other raw identifying value under
`-Redact` beyond the two surprises above. The TP.INT.0005 device-name leftover above is a
later closing-series follow-up, not something that sweep claimed to close.

**Live `-FromSnapshot` re-check, EXECUTED 2026-08-18** against a fresh Ivy24 collection
(`output/live-gate-p3-full`, GraphKit 0.2.2, TenantPulse 0.1.1, `-Redact -ExpandSettings`):
51 findings (16 Pass / 1 Warn / 24 Fail / 9 NotApplicable / 1 Error). The five remaining
Pending Walk/data-processor checks are honest `descriptor-pending` NA
(`TP.INT.0009`/`0013`/`0014`/`0015`/`0029`). `-FromSnapshot` replay of that snapshot was
byte-identical (664563 bytes). Redacted findings sweep: 0 email-shaped leaves, 0
possessive `displayName`/`deviceName` leaves. Tenant-resource GUIDs in Detail stay
unredacted by design. **Live surprise, closed:** `TP.ENT.0012` Error on absent
`permissionGrantPolicyIdsAssignedToDefaultUserRole` remapped to NotApplicable (v1.0
AuthorizationPolicy/Get projection; same class as TP.INT.0028's ESP List trim).

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
not errors. **Historical (GraphKit 0.1.1 pin, T4.5 gate):** `TP.ENT.0012` (the
`authorizationPolicy`-backed cluster), `TP.ENT.0013`/`0015`/`0016` (the three
`directorySettings`-backed clusters), and `TP.ENT.0022`/`0023` (PIM posture,
cross-tenant access) were `descriptor-pending: awaiting GraphKit release` - written,
tested, cited, waiting on GraphKit descriptors this catalog's research already scoped.
GraphKit 0.2.2 later shipped official GET/List descriptors for those six Entra datasets
(and six more Intune GET/List datasets). They are no longer Pending. At that GraphKit 0.2.2
point, five Walk/data-processor datasets remained Pending; see the historical GraphKit 0.2.2
consume section above.
`TP.ENT.0001` (Security Defaults) is a genuine, correct `NotApplicable`: this tenant
runs Conditional Access, not Security Defaults, so the check declines to evaluate a
control the tenant deliberately superseded.

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

## Not yet done

1. **R1a outcome contract and remote integration — partial.** The implemented foundation is
   package-first proven only in the isolated local worktree. Structured dataset outcomes reach
   partial-aware evaluation, but they are not serialized through a versioned findings/renderer
   contract as the governing R1a criterion requires; that product decision remains open. No current
   verified evidence establishes the candidate's reviewed exact remote head, remote matrix/gitleaks
   result, merge, or merged-main CI. The docs-only reconciliation after that runtime tree does not
   alter the frozen candidate's package-producing bytes.
2. **R1b assignment and expansion completion — partial.** Settings Catalog assignments and typed
   include/exclude intent exist. Administrative Template expansion, the now-governing
   expansion-summary dataset, a protected live shape/count proof with populated assignment targets,
   and stale pre-implementation map/reason text remain open. Existing end-to-end fixtures use
   authoritative empty assignments and therefore do not prove overlap behavior with populated targets.
3. **R2 composite-provider representation and certainty — partial.** Four production provider plans
   already compose official GraphKit Read/Safe primitives, so no generic GraphKit `Walk` operation is
   required. The dataset map nevertheless publishes invented `Pending` / `Walk` tuples, QA currently
   blesses them, and outcome provenance is incomplete. Endpoint Security can skip malformed template
   metadata and publish authoritative empty; unknown BitLocker/LAPS values can become false decisions;
   and a legacy-baseline read failure suppresses the independent current baseline surface. The
   protected-live proof of the raw BitLocker value mapping and LAPS template identity remains
   mandatory before those Pending representations can close; the historical `0.2.0` table does not
   prove that mapping.
4. **R3 platform-unavailable representation — partial.** The Windows data-processor runtime correctly
   performs no network work and evaluates as `Skipped` / `PlatformUnavailable` / `NotApplicable`.
   Its static map and structured outcome still falsely name GraphKit and `Get`; closure requires a
   strict disposition, `Provider = TenantPulse`, empty operations, and no descriptor fallback.
5. **R4 coverage, relationships, and presentation — open.** Required work includes bounded,
   policy/root-scoped Conditional Access and role group closure; unique effective role counting;
   GraphKit `Application.List` plus combined app/service-principal credential hygiene; authoritative
   assignment handling for `TP.INT.0002`, `0004`, `0011`, `0012`, `0014`, `0015`, `0017`, `0018`,
   and producer-complete `0028`; exclusion-only semantics; deterministic evidence caps with omitted
   counts; and one supported non-JSON renderer. The all-unparseable `TP.ENT.0019` population must
   become `NotApplicable`, not Pass. `TP.ENT.0022` keeps one group assignment as one violation;
   expansion there is blast-radius evidence only.
6. **R5 privacy contract — open (0 of 53 checks migrated to an enforced field-classification
   schema).** Current protections are useful precursors, not the R5 contract:
   `RedactDetailKeys` is optional, tenant-derived reason/error text can remain free-form,
   render-only cannot reconstruct the in-memory redaction map, and the external gate-artifact
   scrub intentionally destroys safe values. Manifest-recorded expansion paths are hash-checked
   after joining but are not yet constrained to the snapshot root. R5 still requires one
   versioned classification contract across all checks, engine/snapshot projections, and every
   renderer; path-containment plus mutation tests; and a fresh protected-live artifact review.
7. **R6 scale/default contract — open (0 of 9 end-to-end criteria closed).** Current perf
   fixtures are useful baselines but are excluded from normal CI, measure endpoint heap deltas
   rather than observed process peaks, and do not span collection through rendering. GraphKit
   currently materializes all paged rows before TenantPulse receives them; TenantPulse then
   materializes dataset writes/reads, evaluator clones, renderer input, manifest rewrites, and
   expansion families. R6 requires a cross-repository bounded producer/consumer train before
   expansion can become the default. Sequential-only remains the safe live posture until shared
   identity and throttle coordination is root-caused and proven.
8. **R9 provisioning and adoption — split disposition.** Reusable GraphKit app-registration
   provisioning and actual-grant verification remain applicable producer work. With no installed
   users, legacy consumers, customer-tenant consumers, or repoint targets, adopter migration,
   customer repointing, rollback-window operation, legacy-authentication retirement, and destructive
   directory cleanup are `NotApplicable` and must not be executed for closeout. Reopen those gates
   only if an adopter is later identified.
9. **`TP.INT.0010`**, reserved until a separate GraphKit ARM provider exists and a protected
   diagnostic-settings read proves its service contract. ARM must not enter the Microsoft Graph
   descriptor catalog.

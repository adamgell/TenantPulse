<#
    Custom Invoke-Build tasks (post-review fix, Task: final fix wave items 15 & 27),
    loaded from .build/ per build.ps1's own convention (see its "Loading Build Tasks
    defined in the .build/ folder" step).

    Record_Tested_Module_Digest: records a manifest of SHA-256 hashes for every file the
    built module ships (psm1, psd1, Data/**, en-US/**) IMMEDIATELY after the Pester suite
    passes, to output/testResults/tested-module-digest.txt. Publish-TenantPulsePackage.ps1
    compares the packaged .nupkg's own files against THIS recorded manifest, not against
    whatever happens to be sitting in output/module/ at publish time - closing the gap
    where a built-module file could be silently edited (not rebuilt, just edited) between
    a passing test run and a later publish, with nothing catching the drift because the
    old check only ever re-hashed "whatever is on disk right now" and compared that
    against itself.

    Assert_Gate_Result: runs tests/QA/Assert-GateResult.ps1's whole-result gate (the same
    -MinimumTests/-AllowedSkips/-AllowNotRun ratchet ci.yml already enforces) against the
    NUnit result this same local `./build.ps1 -Tasks test` run just produced, so a
    developer running tests locally gets the same "did discovery silently drop tests"
    protection CI has always had - previously this gate only ever ran in CI, so a local
    green `test` run could still hide a discovery regression until CI caught it.
#>

# 814 -> 905 (Task 2.2 review-fix round): +91 tests - shape-neutrality coverage
# (PSObject/IDictionary parity across all 15 golden fixtures), the fan-out driver's
# prevalidation/worker-drain/depth-alignment/all-failed-NotExpanded regressions, the
# -FromSnapshot re-derivation wiring (Resolve-PulseSettingsCatalogSnapshotExpansion), and
# the shared value-classification helper's own dedicated suite - see task-2.2-report.md's
# review-fix addendum for the full accounting. Matches .github/workflows/ci.yml's own
# -MinimumTests, which must be bumped together with this value - see this file's own
# docstring for why the same ratchet exists in both places.
# 905 -> 912 (Task 2.2 re-review fix): +7 - IsNullOrWhiteSpace policy-id prevalidation
# (a whitespace-only id previously passed IsNullOrEmpty and reached Get-GraphObject) plus
# its own WHITESPACE-ID regression test.
# 912 -> 916 (Task 2.2 re-review round 2): +4 - the known-safe-value-shape suffix-match
# secret-leak bypass fix (exact fully-qualified string match, mirroring P1-9's instance-type
# fix) plus its own regression suite (suffix-bypass for both known-safe shapes, the
# real-type-still-matches control, and an end-to-end walker-level plaintext-never-leaks
# assertion). Set to the REAL total, not a headroom-padded number - the gate IS the count.
# 916 -> 947 (Task 2.3): +31 - the compliance/legacy typed-policy walk (shape-neutrality,
# Sensitive nested-property redaction, Nested object vs array-element walking, unpopulated-
# shell shape), the per-family fan-out driver (real assignment fetch, unmapped-type gap
# wording, exact-match dispatch, assignment-fetch-failure whole-policy gap, planted-secret-
# never-leaks, empty-policy-list Expanded), and the two-family pipeline (both datasets
# unavailable, one family independent of the other).
# 947 -> 949 (Task 2.3 follow-up): +2 - Invoke-PulseTypedPolicyExpansion.ps1's own
# -FromCapturedPayloads/raw-assignment-persistence addition (see that file's own docstring)
# picked up by the QA suites that enumerate shipped source files structurally (module.tests.ps1/
# SecretScan.tests.ps1), not a new Describe block.
# 949 -> 959 (Task 2.3 follow-up): +10 - own regression coverage for
# -FromCapturedPayloads/raw-assignment-persistence (3 new It cases, which also caught and
# fixed a real ARRAY-RETURN UNROLLING TRAP bug: Read-PulseDataset's result was being
# double-wrapped by a redundant caller-side @(), corrupting every re-expanded assignment's
# shape - see that file's own docstring) plus discovery picking up the remainder via the
# structural QA suites. Set to the REAL total.
# 959 -> 963 (Task 2.5): +4 - isBaseline now reflects the 'baseline' template family
# specifically (case-insensitive prefix match), not "any template-bearing policy" - the
# prior predicate marked every endpoint security policy (antivirus, disk encryption,
# firewall, ...) isBaseline:true right alongside real Security Baselines. New dedicated
# Describe block: a real baseline family, a non-baseline-but-template-bearing endpoint
# security family, an ordinary non-template policy, and a future 'baseline*' variant
# family (prefix match, not exact).
# 963 -> 965 (GUID hygiene fix): +2 - the SecretScan QA gate's new item-7 exact-match
# banned-identifier check (the Ivy24 lab tenant GUID leaked into
# tests/Unit/Snapshot.Tests.ps1 and tests/Unit/Get-PulseTenantSnapshot.Tests.ps1, now
# scrubbed to a synthetic placeholder) plus its own regression suite (fires with no
# domain nearby; does not fire for an ordinary synthetic placeholder GUID).
# 965 -> 991 (post-review follow-ups, T2.2/T2.3 publish-path unification + T2.3/T2.5
# real fixtures): +26 - unifying Invoke-PulseSettingsCatalogExpansion's own staging/hash/
# publish onto the shared Publish-PulseExpansionRows implementation (no new tests of its
# own - proven by T2.2's EXISTING fault-injection/determinism/real-worker-pool suite
# passing unchanged against the unified path); 7 new GOLDEN sanitized-real
# TypedPolicyWalk fixture tests (deviceCompliancePolicies' four real types + the three
# present-on-Ivy24 legacy deviceConfigurations types, sourced from scratch/live-011,
# scripted exhaustive value walk, PROVENANCE'd); 2 new GOLDEN real-fixture
# SettingsCatalogExpansion tests swapping the synthetic endpoint-security policy for the
# REAL Ivy24 endpointSecurityAccountProtection/endpointSecurityAttackSurfaceReduction
# fixtures (choicecollection-01/-02); plus the SecretScan QA gate's own new allowlist-
# entry regression coverage for the 7 new fixture GUIDs. Set to the REAL total for this
# task's own tree.
# 991 -> 996 (task-2.3-review C1/capstone fix round): +5 - C1's raw-dataset Sensitive-
# redaction pass (Protect-PulseTypedPolicySensitivePayload.ps1, wired into
# Invoke-PulseCollection.ps1 before the FIRST Write-PulseDataset call for
# deviceCompliancePolicies/deviceConfigurations) plus its own capstone end-to-end
# regression (TypedPolicySecretContract.Tests.ps1 - plants a WiFi-PSK-class secret through
# the real collect+expand pipeline, then walks EVERY file under the resulting snapshot
# root and asserts the planted marker appears in none of them; verified to actually fail
# red against a deliberately-disabled redaction pass before being restored green).
# 996 -> 1011 (task-2.3-review C1 round 2, findings 1/3): +15 - the fail-closed fix for
# Protect-PulseTypedPolicyNestedElement's own wrong-shaped-nested-value fail-open
# (unknown/scalar shape under a Sensitive-nested rule now redacts wholesale rather than
# passing through) plus its dedicated regression coverage
# (tests/Unit/Collect/ProtectTypedPolicySensitivePayload.Tests.ps1 - 13 new It cases
# pinning IDictionary/PSObject shape neutrality, unmapped-dataset/unmapped-type pass-
# through, a compliance-family lossless round-trip, a multi-property row, and both
# fail-open regression shapes: a bare scalar and a bare array planted where an object was
# expected, at both the direct-helper level and end-to-end through
# Protect-PulseTypedPolicySensitivePayload itself).
# 1011 -> 1063 (Task 2.6, conflict detection - artifact only): +52 - the pure
# ConvertTo-PulseConflictRecords builder (no-conflict/conflict/same-policy-repeats-itself/
# zero-conflicts-is-valid, redaction-never-un-redacts incl. two independently-redacted
# policies not conflicting with each other, the four assignmentOverlap states plus the
# core-slice assignments-deferred 'unknown' path and its cross-family case, determinism
# under reordered input, ordinal sort), Get-PulseExpansionRows' own verified-read gate
# (missing entry/NotExpanded status/hash-mismatch tamper detection/happy path),
# Publish-PulseConflictArtifact's own crash-consistent single-document publish (zero
# families NotExpanded, zero-conflicts-Expanded, Partial-with-gaps, sha256 determinism
# across two independent stores, the redaction-sentinel-never-reaches-disk regression),
# and Invoke-PulseConflictDetection/Resolve-PulseConflictSnapshotExpansion's own
# per-family-availability-vs-corruption-gap and -FromSnapshot verify-or-rederive coverage.
# 1063 -> 1079 (Task 74 fix wave): +16 - CI BLOCKER fix's own dual-branch byte-identity
# coverage for ConvertFrom-PulseJsonPreservingStrings (native -DateKind branch forced,
# JsonDocument fallback branch forced regardless of local PS version, both-branches-
# byte-identical, Export-PulseReport's own round-trip through the forced fallback: +4);
# the windowsUpdateForBusinessConfiguration installationSchedule POPULATED-with-all-4-
# sub-properties golden-adjacent test (+1); the new Publish-PulseExpansionRows dual-owned
# ALL-POLICIES-FAILED unit suite, settingsCatalog + compliance + deviceConfiguration caller
# idioms (+3); and the -FromSnapshot re-derivation rider fixes - NEVER-EXPANDED/NO-
# CAPTURED-PAYLOADS skip-cleanly and STALE-ENTRY-FAILURE-sets-Failed, for both the
# settingsCatalog resolver (+2) and the typed-policy compliance family resolver (+2,
# plus +1 for the mixed-captured-state control that proves the skip does not over-fire) -
# see task-74fix-report.md for the full accounting. Matches .github/workflows/ci.yml's own
# -MinimumTests, reconciled separately by the peer session already owning that file.
# 1079 -> 1087 (Task 2.6 review round 2): +8, NOT +34-in-a-vacuum - see task-2.6-report.md's
# addendum for why the first-round 1011->1063 (+52) accounting only ever had 34 explicit
# It blocks: the other 18 were SecretScan.tests.ps1's own auto-generated 2-cases-per-file
# (secret/PII scan + control-byte scan) firing for the 9 new source+test files that round
# added. This round adds ONE new file (ConflictDetectionEndToEnd.Tests.ps1, +2 SecretScan
# cases) plus 6 explicit It blocks: the settingName determinism fix's own two regressions
# (ordinal-minimum pick + nameVariants-null-when-no-disagreement) in
# ConvertTo-PulseConflictRecords.ps1/ConflictDetection.Tests.ps1, the three-or-more-policy
# assignmentOverlap precedence suite (proven-wins/possible-when-no-proven/none-only-when-
# every-pair-is-disjoint, 3 cases), and the single end-to-end golden pipeline test that
# threads a planted secret through the REAL T2.2 Settings Catalog + T2.3 typed-policy
# expansion pipelines into a REAL Invoke-PulseConflictDetection run.
# 1087 -> 1091 (Task 2.7, live-gate tenant-id-redaction fix): +4 - the live gate against
# Ivy24 found a real, previously-uncaught secret-contract-adjacent gap: a raw Settings
# Catalog policy VALUE (a OneDrive Known-Folder-Move opt-in setting) legitimately carries
# the tenant's own GUID as admin-entered configuration data, and Protect-
# PulseGraphRowTenantId (T1.11's raw-dataset tenant-id redaction walk) was never wired
# into the T2.2/T2.3 expansion-row publish path - only into Write-PulseDataset's raw
# writes - so the raw tenant id reached expanded/settingsCatalog.<hash>.jsonl unredacted.
# Fixed in Invoke-PulseSettingsCatalogExpansion.ps1 and Invoke-PulseTypedPolicyExpansion.ps1
# (both now redact the final row set through Protect-PulseGraphRowTenantId immediately
# before Publish-PulseExpansionRows) plus 2 new regression tests pinning the fix for each
# pipeline (see task-2.7-report.md for the full live-gate accounting). Set to the REAL
# total (1091), matching the module's own post-fix Pester run, not a headroom-padded
# number - the gate IS the count.
# 1091 -> 1092 (Task 2.7 review round): +1 - a dedicated driver-level regression test
# guarding -MaxParallel 4's real RunspacePool machinery directly (bypasses
# Invoke-PulseSettingsCatalogExpansionPipeline.ps1's own forced -Sequential, added the
# same review round, per the live-gate parallel-slowness finding - see that file's own
# docstring), asserting byte-identity vs -Sequential over 24 captured-payload policies.
# Set to the REAL total (1092), matching the module's own post-fix Pester run.
# 1092 -> 1131 (Task 3.1): +39 - the Maester shim's own suite (Convert-PulseMaesterAdapter.ps1,
# 10 tests), Get-PulseConflictArtifact's own suite (6 tests), TP.INT.0006's own
# fixture-driven suite (9 tests: catalog self-check, Pass/Warn/Fail/NotApplicable, evidence
# shape, determinism), plus discovery picking up the remainder via the structural QA suites
# that enumerate every shipped source file (module.tests.ps1/SecretScan.tests.ps1) and the
# CheckCatalog.Tests.ps1 self-check bump from 10 to 11 seed+T3.1 checks. Set to the REAL
# total (1131), matching the module's own post-fix Pester run.
# 1131 -> 1142 (Task 3.1 review-fix round, both reviews' Critical/High items): +11 -
# New-PulseArtifactReader's own dedicated suite (4 tests: no data properties, matches
# Get-PulseConflictArtifact, resolves correctly when called outside the module's own
# scope, reflects live artifact state not a construction-time snapshot) plus the
# Context-boundary regression coverage in Evaluator.Tests.ps1 (4 tests: an Expression
# rule never sees $Context.ArtifactReader or the prior $Context.Store, a Function rule's
# in-place $Context mutation never corrupts a later check's own view) plus discovery
# picking up the remainder via the structural QA suites. Set to the REAL total (1259,
# Task 3.2's TP.INT.0015 port round, closing the batch), matching the module's own
# post-fix Pester run.
# 1259 -> 1300 (Task 3.2 fix-round, two merged reviews): +41 across field-absence-lens
# hostile fixtures (TP.INT.0013 RBAC/0011 branding/0014 BitLocker/0015 LAPS), TP.INT.0006
# Partial-artifact-gap fixtures, Get-PulseCollectionManifest @($null)-guard regression
# coverage, and SecretScan's docs/.build roots extension plus its new person-name
# device-name heuristic (including a real-file planted-pattern self-test). Set to the
# REAL total, matching the module's own post-fix Pester run.
# 1300 -> 1465 (Task 3.3, TP.INT.0019-0030 + its own dual-review fix round): the
# Intune-side catalog's closing batch - 12 new checks plus their fix-round
# regressions. 1465 was the real, measured `./build.ps1 -Tasks test` total on
# main immediately before this Phase 4 merge.
#
# Phase 4 (phase4/t4.1-normalization) ran the same counter forward on its own
# line, in parallel, starting from the same 1063 base:
# 1063 -> 1092 (Phase 4 Task 4.1, Entra normalization layer + shared exclusion context):
# +29 - the two new normalization-layer views (ConvertTo-PulseCaPolicyView: state-mapping
# incl. absent/unrecognized-state throw, conditions/grants/session flattening, dual
# hashtable/PSObject shape neutrality, -Context authenticationStrength displayName
# fallback, pipeline array input - 14 It cases; ConvertTo-PulseAuthMethodView: methodId/
# state normalization incl. absent/unrecognized-state throw, generic -settings fold,
# includeTargets/excludeTargets normalization, dual shape neutrality, pipeline array input
# - 8 It cases) plus the Get-PulseCaExclusionContext rework's own additive fields
# (MalformedDeclaredAccounts GUID-contract classification, GroupExclusionsResolved/
# ResolvedGroupExclusions/GroupExclusionNote forward-compatible group-exclusion shape - 7
# It cases). TP.ENT.0003/0004/0005's own existing tests were left green, unmodified.
# 1092 -> 1112 (Task 4.1 post-review fixes, four findings): +20 - Finding 1/Critical
# (ARRAY-RETURN UNROLLING TRAP fix in both views' array-building helpers, comma-protecting
# every return; 4 new dedicated sparse-fixture It cases in ConvertTo-PulseCaPolicyView.Tests.ps1
# plus 2 in ConvertTo-PulseAuthMethodView.Tests.ps1 pinning the fix and its self-caught
# sibling defect), Finding 2/High (Get-PulseCaExclusionContext's new ReportOnlyExclusions
# field, kept separate from the enforced-only ExcludedIdentifiers union - 3 new It cases),
# Finding 3/Important (one consolidated SHAPE NEUTRALITY It per view test file, looping
# every named fixture through both hashtable and PSObject materializations - 2 new It
# cases, one per file), Finding 4/Low (ConvertTo-PulseAuthMethodView's -settings bag sorted
# ordinally before insertion, independent of raw response property order - 1 new It case).
# TP.ENT.0003 source+tests remain byte-identical (verified via `git diff` against the
# reviewed commit) - merge-order condition still satisfied.
# 1112 (declared floor) -> 1126 (Task 4.2, TP.ENT.0006 - EIDSCA AF01-AF06 FIDO2 method
# configuration cluster, first of Phase 4's wave-1 EIDSCA port): 8 new It cases in
# tests/Unit/Checks/TP.ENT.0006.Tests.ps1 (catalog self-check + Pass x2 shapes + Fail x4 +
# gate-degraded). This cluster adds no new dataset (reuses the already-released
# authenticationMethodsPolicy dataset), so ReadOnly.tests.ps1/SecretScan.tests.ps1's own
# -ForEach-driven case counts do not grow here. 1126 is the real, measured
# ./build.ps1 -Tasks test total at this commit, not merely 1112+8 - the declared floor was
# already below the suite's actual size before this change.
# 1126 -> 1140 (Task 4.2, TP.ENT.0008 - EIDSCA AM01-AM04/AM06/AM07/AM09/AM10 Microsoft
# Authenticator method configuration cluster): +14, matching
# tests/Unit/Checks/TP.ENT.0008.Tests.ps1's 8 new It cases plus real suite growth already
# present before this commit's own measurement (same "1126 is measured, not merely
# additive" note as above).
# 1140 -> 1154 (Task 4.2, TP.ENT.0012 - EIDSCA AP01/AP04-AP10/AP14 default authorization
# policy settings cluster): +14 - 7 new It cases in tests/Unit/Checks/TP.ENT.0012.Tests.ps1
# (catalog self-check, Pass x2 shapes, Fail-default, Fail-single-property, Error/field-
# absence, descriptor-pending NotApplicable), +1 new tests/QA/ReadOnly.tests.ps1 Pending-
# dataset -ForEach case (source/Data/DatasetMap.psd1's new authorizationPolicy entry, first
# Pending entry since GraphKit 0.1.1 dropped the previous six), and per-file
# tests/QA/SecretScan.tests.ps1 -ForEach growth for the new/changed source+test files this
# commit touched (TP.ENT.0012.psd1, Test-PulseAuthorizationPolicyDefaults.ps1,
# TP.ENT.0012.Tests.ps1).
# 1154 -> 1169 (Task 4.2, TP.ENT.0013 - EIDSCA CP01 group/team owner consent restriction):
# +15 - 6 new It cases in tests/Unit/Checks/TP.ENT.0013.Tests.ps1, +1 new
# ReadOnly.tests.ps1 Pending-dataset -ForEach case (directorySettings, this commit's new
# DatasetMap.psd1 entry), the new shared Get-PulseDirectorySettingValue.ps1 helper's own
# SecretScan.tests.ps1 per-file case, and per-file SecretScan growth for the remaining
# new/changed files this commit touched.
# 1169 -> 1181 (Task 4.2, TP.ENT.0015 - EIDSCA PR01 Password Protection mode): +12 - 6 new
# It cases in tests/Unit/Checks/TP.ENT.0015.Tests.ps1 (reuses the directorySettings dataset
# added with TP.ENT.0013, so no new ReadOnly.tests.ps1 -ForEach case here) plus per-file
# SecretScan.tests.ps1 growth for the new/changed files this commit touched.
# 1181 -> 1193 (Task 4.2, TP.ENT.0016 - EIDSCA ST08 guest group ownership restriction,
# completes wave 1): +12 - 6 new It cases in tests/Unit/Checks/TP.ENT.0016.Tests.ps1 (also
# reuses directorySettings, no new ReadOnly.tests.ps1 case) plus per-file
# SecretScan.tests.ps1 growth for the new/changed files this commit touched. 1193 is the
# real, measured ./build.ps1 -Tasks test total for the full T4.2 wave-1 diff, matching
# .github/workflows/ci.yml's own -MinimumTests (POST-REVIEW FIX: ci.yml was missed across
# all six of this wave's commits and still read 1112 - see the T4.2 report's corrected
# test-summary section - it is bumped together with this value from this commit onward,
# alongside scripts/Publish-TenantPulsePackage.ps1 and
# tests/QA/PublishTenantPulsePackage.tests.ps1's fabricated-fixture total: FOUR tracking
# locations total, not two, whenever this value moves).
# 1193 -> 1195 (Task 4.3 wave 2, TP.ENT.0013 - EIDSCA CP03/CP04 UNVERIFIED-flag
# resolution): net +3 It cases in tests/Unit/Checks/TP.ENT.0013.Tests.ps1 (2 new Fail
# cases, 1 new Pass-shape assertion folded into the existing two Pass tests rather than
# duplicated) plus per-file SecretScan.tests.ps1 growth for this commit's changed files.
# 1195 -> 1199 (Task 4.3 wave 2, TP.ENT.0015 - EIDSCA PR02/PR03/PR05/PR06
# UNVERIFIED-flag resolution): +4 net new It cases in tests/Unit/Checks/TP.ENT.0015.Tests.ps1
# (4 new Fail cases covering PR02/PR03/PR05/PR06 independently) plus per-file
# SecretScan.tests.ps1 growth for this commit's changed files.
# 1199 -> 1201 (Task 4.3 wave 2, TP.ENT.0016 - EIDSCA ST09 UNVERIFIED-flag resolution,
# with a corrected Claim polarity - see the research entry's own updated Notes): +2 net
# new It cases in tests/Unit/Checks/TP.ENT.0016.Tests.ps1 (1 new Pass, 1 new Fail for
# ST09) plus per-file SecretScan.tests.ps1 growth for this commit's changed files. 1201
# is the real, measured ./build.ps1 -Tasks test total; all four tracking locations
# bumped together in this commit per the standing RATCHET rule.
# 1201 -> 1215 (Task 4.3 wave 2, TP.ENT.0007 - new check, EIDSCA AG01-AG03 general
# settings, not part of T4.2's wave-1 port): +14 - 8 new It cases in
# tests/Unit/Checks/TP.ENT.0007.Tests.ps1, +1 CheckCatalog.Tests.ps1 count-pin bump
# (16 -> 17 catalog descriptors) plus per-file SecretScan.tests.ps1 growth for the new
# TP.ENT.0007.psd1/Test-PulseAuthMethodsPolicyGeneralSettings.ps1/
# TP.ENT.0007.Tests.ps1 files. 1215 is the real, measured ./build.ps1 -Tasks test
# total; all four tracking locations bumped together in this commit.
# 1215 -> 1227 (Task 4.3 wave 2, TP.ENT.0009 - new check, EIDSCA AS04 SMS sign-in
# disabled): +12 - 6 new It cases in tests/Unit/Checks/TP.ENT.0009.Tests.ps1, +1
# CheckCatalog.Tests.ps1 count-pin bump (17 -> 18) plus per-file SecretScan.tests.ps1
# growth for the new TP.ENT.0009.psd1/Test-PulseSmsSignInMethodDisabled.ps1/
# TP.ENT.0009.Tests.ps1 files. 1227 is the real, measured ./build.ps1 -Tasks test
# total; all four tracking locations bumped together in this commit.
# 1227 -> 1240 (Task 4.3 wave 2, TP.ENT.0010 - new check, EIDSCA AT01-AT02 Temporary
# Access Pass): +13 - 7 new It cases in tests/Unit/Checks/TP.ENT.0010.Tests.ps1, +1
# CheckCatalog.Tests.ps1 count-pin bump (18 -> 19) plus per-file SecretScan.tests.ps1
# growth for the new TP.ENT.0010.psd1/Test-PulseTemporaryAccessPassConfigured.ps1/
# TP.ENT.0010.Tests.ps1 files. 1240 is the real, measured ./build.ps1 -Tasks test
# total; all four tracking locations bumped together in this commit.
# 1240 -> 1252 (Task 4.3 wave 2, TP.ENT.0011 - new check, EIDSCA AV01 Voice call
# disabled, completes wave 2): +12 - 6 new It cases in
# tests/Unit/Checks/TP.ENT.0011.Tests.ps1, +1 CheckCatalog.Tests.ps1 count-pin bump
# (19 -> 20) plus per-file SecretScan.tests.ps1 growth for the new
# TP.ENT.0011.psd1/Test-PulseVoiceCallMethodDisabled.ps1/TP.ENT.0011.Tests.ps1 files.
# 1252 is the real, measured ./build.ps1 -Tasks test total; all four tracking
# locations bumped together in this commit.
# 1252 -> 1355 (Task 4.4, TP.ENT.0017-0024 - 8 new ScuBA/CISA CA + role +
# credential checks): new It cases across tests/Unit/Checks/TP.ENT.001[7-9].
# Tests.ps1, TP.ENT.002[0-4].Tests.ps1, +2 new It cases in
# tests/Unit/Checks/ConvertTo-PulseCaPolicyView.Tests.ps1 (clientApplications
# field, TP.ENT.0024's own dataset), +1 CheckCatalog.Tests.ps1 count-pin bump
# (20 -> 28) plus per-file SecretScan.tests.ps1 growth for the 8 new
# TP.ENT.00[17-24].psd1/Test-Pulse*.ps1/TP.ENT.00[17-24].Tests.ps1 files.
# POST-REVIEW CORRECTION: the commit that introduced this cluster recorded
# 1325 here, measured via an ad hoc FILTERED Invoke-Pester run rather than
# the sanctioned `./build.ps1 -Tasks build,test` path - that ad hoc run both
# undercounted (missed tests only the Sampler-bootstrapped module context
# collects) and reported 4 false "failures" that do not occur under the real
# pipeline. 1355 is the real, measured `./build.ps1 -Tasks test` total for
# that same Task 4.4 commit set - the number this value should always have
# been.
# 1355 -> 1366 (Task 4.4 fix round - dual review F1-F5): F1/F2 red-then-green
# tests added to tests/Unit/Checks/TP.ENT.0018.Tests.ps1 (custom-strength
# evidence, excludeRoles subtraction, undocumented-exclusion note), F4
# descriptor-pending NotApplicable cases added to TP.ENT.0022.Tests.ps1 (x2)
# and TP.ENT.0023.Tests.ps1 (x1), F5 red-then-green unclassifiable-accessType
# tests added to TP.ENT.0023.Tests.ps1 (x2). F3's relabeling of the cosmetic
# "(PSObject shape)" It titles across TP.ENT.0017/0019/0021/0023.Tests.ps1
# does not change the count; its genuine shape-neutrality case folded into
# ConvertTo-PulseCaPolicyView.Tests.ps1's existing populated-clientApplications
# It (loop, not a new It) likewise does not change the count. 1366 is the
# real, measured `./build.ps1 -Tasks test` total for the fix-round commit;
# all four tracking locations bumped together in the SAME commit as these
# test changes, per the ratchet's own rule.
# 1366 -> 1375 (Task 4.5, CIS cross-references + phase gate): +9 net new Its -
# References.Cis (optional, cite-only) descriptor validation coverage
# (CheckCatalog.Tests.ps1: valid-fixture pass-through assertion folded into an
# existing It, one new scalar-type-rejection It) and the CIS disclaimer
# footer's both-directions wiring in Evaluator.Tests.ps1 (silent when no
# finding cites CIS, fires when at least one does, fires regardless of finding
# order, verbatim References.Cis pass-through, and the Hashtable/PSCustomObject
# shape-neutral read of References.Cis). 1375 is the real, measured
# `./build.ps1 -Tasks test` total for this commit; all four tracking locations
# bumped together in the SAME commit as these test changes, per the ratchet's
# own rule.
# 1375 -> 1396 (Task 4.5 fix-round-of-the-fix-round, NEW-1/NEW-2/NEW-3 - a
# leaked-PII CRITICAL and two Majors from re-review of the prior fix round):
# +21 net new Its - SecretScan.tests.ps1's new item-8 possessive-name-shaped
# displayName/deviceName check (6 unit Its: straight apostrophe, curly
# apostrophe, deviceName variant, an already-pseudonymized value does NOT
# fire, a false-positive guard for ordinary possessive prose outside a
# displayName/deviceName key, plus the dedicated planted-PII regression proof
# against docs/gates/_qa-fixtures/planted-pii-sample.json), docs/ added to
# the repo-scan roots (its own new per-file Its, discovered dynamically - see
# that Describe block's own -ForEach), and CheckCatalog.Tests.ps1's new
# empty-References.Cis rejection It (NEW-3). 1396 is the real, measured
# `./build.ps1 -Tasks test` total for this commit; all four tracking
# locations bumped together in the SAME commit as these test changes, per
# the ratchet's own rule.
# 1396 -> 1399 (Task 4.5 merge-review fix round - HMAC-keyed pseudonym,
# whole-document leak assertion, References.Cis ID-only format enforcement):
# +3 net new Its - CheckCatalog.Tests.ps1's new prose-References.Cis
# rejection It (the new ID-only regex enforcement) plus the discovery-time
# per-file test cases the new tests/Fixtures/Checks/invalid/prose-cis/
# bad.psd1 fixture and PROVENANCE.md entry add. 1399 was the real, measured
# `./build.ps1 -Tasks test` total for that commit; all four tracking
# locations bumped together in the SAME commit as these test changes, per
# the ratchet's own rule.
# 1399 -> 1402 (merge-review Minor - CIS format check made case-sensitive):
# the -notmatch at Test-PulseCheckDescriptor.ps1's References.Cis format
# check was case-INsensitive, so a fully-lowercase CIS-shaped string passed;
# now -cnotmatch. +3: CheckCatalog.Tests.ps1's lowercase-bypass rejection It
# plus the discovery-time per-file cases the new invalid/lowercase-cis/
# bad.psd1 fixture and PROVENANCE.md entry add. 1402 is the real, measured
# `./build.ps1 -Tasks test` total for this commit. 1402 was the real, measured
# `./build.ps1 -Tasks test` total on phase4/t4.1-normalization immediately
# before this Phase 4 merge.
#
# This merge (Phase 4 into main) reconciles both lineages: the value below (1800) is
# the REAL measured ./build.ps1 -Tasks build,test total for the merged tree,
# set once post-merge per the merge review's ratchet step - not the sum of the
# two branch totals (1465 + 1402), which would double-count the shared pre-1063
# history and does not match this real post-merge count.
# 1814 -> 1818 (Task 3.4 Part E, manifest createdUtc culture-coercion fix): +4 - three new
# Snapshot.Tests.ps1 Its (Get-PulseSnapshotStore opens a 7-digit-fraction manifest cleanly;
# Get-PulseSnapshotManifest returns createdUtc byte-identical to source text; the read
# round-trips identically under a forced day-first thread culture) plus one new
# Evaluator.Tests.ps1 It (generatedUtc/EvaluationCutoffBase preserve the same 7-digit
# fraction end-to-end through Invoke-PulseEvaluation, under a forced day-first culture).
# 1818 is the real, measured `./build.ps1 -Tasks build,test` total for this commit; both
# tracking locations (here and .github/workflows/ci.yml) bumped together in the same
# commit as these test changes, per the ratchet's own rule.
#
# 1818 -> 1816 (Task 3.4 Part D, RunspacePool parallel path DELETED from
# Invoke-PulseSettingsCatalogExpansion - a DROP, not a raise): -MaxParallel and -Sequential
# are gone; sequential is the only path left. Two multi-worker byte-identity Its retired
# outright (SettingsCatalogExpansion.Tests.ps1's 'a real -MaxParallel 4 run over captured
# payloads is byte-identical to -Sequential' and its T2.7 24-policy sibling) - both asserted
# a RunspacePool run matched a sequential run's bytes, and there is no second code path left
# for either assertion to compare against; a third It in the same Describe (WORKER-FAILURE
# CLASSIFICATION, real behavior beyond byte-identity) was KEPT, converted off -MaxParallel
# onto the same sequential call every sibling test in the file already uses. Net: -2 tests,
# 0 coverage lost beyond the now-meaningless byte-identity comparisons themselves. 1816 is
# the real, measured `./build.ps1 -Tasks build,test` total for this commit; both tracking
# locations bumped together in the same commit as these test changes, per the ratchet's own
# rule. A DROPPING total is expected and correct here, not a regression - see this task's
# own report for the full retired-test inventory.
#
# 1816 -> 1822 (Task 3.4 Part C, TypedPolicyMaps deeper-nesting gap resolved): +6 -
# TypedPolicyWalk.Tests.ps1's 3 new Its (GOLDEN fixture sanitized from the real live-27
# deeper-nesting evidence; a synthetic "Sensitive always wins over its own Nested
# description" proof; a synthetic 3-level recursion mechanism proof), 1 new It in
# ProtectTypedPolicySensitivePayload.Tests.ps1 (the raw-redaction pass still correctly
# wholesale-redacts an object-shaped `value`, unchanged code, proven against the new map
# shape), plus 2 discovery-time SecretScan.tests.ps1 per-file cases (secret-scan +
# control-byte check) the new
# tests/Fixtures/TypedPolicy/deviceConfiguration-windows10Custom-deeperNesting.json fixture
# adds automatically. 1822 is the real, measured `./build.ps1 -Tasks build,test` total for
# this commit; both tracking locations bumped together in the same commit as these test
# changes, per the ratchet's own rule.
# 1822 -> 1861 (Task 3.4 Part A, per-family setting-presence index): +39 - 26 new Its in
# tests/Unit/Expand/SettingPresenceIndex.Tests.ps1 (the pure transform's grouping/
# redaction/assignment-classification/determinism behavior, the driver's per-family
# availability rules, the reader's four-way outcome, the ArtifactReader accessor, the
# -FromSnapshot re-derivation wiring, and the Get-PulseTenantSnapshot -ExpandSettings
# end-to-end call-site wiring), 1 new CheckCatalog.Tests.ps1 It (Data.Expansions accepts
# 'settingPresenceIndex', the known-artifact registry's second entry), plus 12
# discovery-time SecretScan.tests.ps1 per-file cases (secret-scan + control-byte check,
# x6 new files: the 5 new source/Private/Expand/*.ps1 producer/reader/driver/publisher
# files plus the new test file itself). 1861 is the real, measured
# `./build.ps1 -Tasks build,test` total for this commit; both tracking locations bumped
# together in the same commit as these test changes, per the ratchet's own rule.
# 1861 -> 1900 (Task 3.4 Part B, expansion-powered checks TP.INT.0016/0031): +39 - 14 new
# TP.INT.0016.Tests.ps1 Its (ASR Standard Protection union-across-policies logic,
# redaction/unknown-assignment honesty, Settings-Catalog-choice-suffix tolerance,
# determinism) + 11 new TP.INT.0031.Tests.ps1 Its (BitLocker CSP presence+value,
# assignment-awareness, redaction honesty, PARTIAL SCAN disclosure, determinism), 1 new
# CheckCatalog.Tests.ps1 catalog-count bump (49 -> 51 across two commits), plus 14
# discovery-time SecretScan.tests.ps1 per-file cases (secret-scan + control-byte check,
# x7 new files: Resolve-PulseSettingPresenceCriterion.ps1 (shared honesty-state helper),
# Test-PulseBitlockerCspSettingsPresentAndCorrect.ps1, Test-PulseAsrStandardProtectionRulesConfigured.ps1,
# TP.INT.0031.psd1, TP.INT.0016.psd1, and the two new test files). 1900 is the real,
# measured `./build.ps1 -Tasks build,test` total for this commit; both tracking locations
# bumped together in the same commit as these test changes, per the ratchet's own rule.
# 1900 -> 1912 (T3.4 whole-task dual review, fix round 1): +12 - corpus-verified
# definitionId/itemId rewrites in TP.INT.0016.Tests.ps1 (+1 net: an exact-itemId-match
# regression It, "a value that merely CONTAINS the definitionId... never satisfies") and
# TP.INT.0031.Tests.ps1 (+2 net: "Allow user to choose" child-default-fails and the
# ADJUDICATION PROOF "parent toggle alone never satisfies" It), the new
# tests/QA/SettingDefinitionCorpusCrossCheck.tests.ps1 gate (4 Its: the self-check-against-
# synthetic-input Describe including its own "prove the gate can fail" It, plus the real-
# repo-tree scan), the new depth-3 recursive-redaction Describe in
# ProtectTypedPolicySensitivePayload.Tests.ps1 (4 Its: the raw Protect-PulseTypedPolicyRow
# call, the public Protect-PulseTypedPolicySensitivePayload entry point, an array-of-depth-
# 3-elements case, and a hostile-scalar-at-depth-2 fail-closed case), plus discovery-time
# SecretScan.tests.ps1 per-file cases for the 2 new files (the QA gate test file itself and
# the new tests/Fixtures/SettingsCatalogCorpus/checked-definitions.json fixture). 1912 was
# the real, measured `./build.ps1 -Tasks build,test` total for that commit.
#
# Task 3.5 (exclusion-context wiring, TP.ENT.0004/0005): 9 new Its (4 in
# TP.ENT.0004.Tests.ps1, 3 in TP.ENT.0005.Tests.ps1, 2 in
# Get-PulseCaExclusionContext.Tests.ps1) covering honored-exclusion evidence, the
# enforced-vs-report-only split, and the "no -Context supplied" backward-compatibility
# case. 1921 was the real, measured `./build.ps1 -Tasks build,test` total for that commit.
#
# Task 3.5 dual-review fix round (MalformedDeclaredAccounts/GroupExclusionNote
# completeness fold-in + report-only misreading-risk warning): +8 new Its (4 each in
# TP.ENT.0004.Tests.ps1 and TP.ENT.0005.Tests.ps1) - malformed-account surfaced,
# group-exclusion-resolution note surfaced (and its backward-compat absence when nothing
# was declared), and the multi-identifier enforced/report-only/no-match/malformed hostile
# case the adversarial reviewer named. 1935 is the real, measured
# `./build.ps1 -Tasks build,test` total for this commit (Task 3.6: +6 from
# tests/QA/LicenseAttributionAudit.tests.ps1); both tracking locations bumped
# together in the same commit as these test changes, per the ratchet's own rule.
#
# Phase 3 whole-phase review, round A (task-3.6-report.md fix round, this catalog-
# coherence + security-walk dual-review fix wave): +20 - TP.INT.0016.Tests.ps1 (+2: the
# zero-satisfied redaction-Warn hostile case for I1, plus the per-rule Pass-evidence
# assertion for I4), TP.INT.0020/0021/0023/0026/0028.Tests.ps1 (+1 each, +5: one
# id-less-collision hostile fixture per file for I2), TP.INT.0020/0021/0028.Tests.ps1
# (+1 each, +3: Pass-path evidence assertions for M1 - 0023/0026 already carried Pass
# evidence, updated in place with no new It), TP.INT.0031.Tests.ps1 (+0 net: Pass-evidence
# assertion folded into the existing Pass It for I4), ProtectTypedPolicySensitivePayload.
# Tests.ps1 (+4: the new UNMAPPED @odata.type structural-fallback Describe for security
# walk finding 7 - deep-secret redacted, end-to-end redacted, no-string-leaf-passes-
# through, and the still-original-reference no-op case), plus discovery-time
# SecretScan.tests.ps1 per-file growth for every changed file this wave touched (+6, the
# five new root files added to $explicitRootFiles for finding 8 plus the README.md change
# for finding 9). 1955 is the real, measured `./build.ps1 -Tasks build,test` total for
# this wave; both tracking locations bumped together, per the ratchet's own rule.
#
# 1956 -> 1971 (Phase 3 closing fix series): net growth across a concurrent PS 7.4 compat
# hotfix landed mid-series by another session (5d8a548/4e5cc58, IDictionary.Contains not
# ContainsKey on manifest dictionaries) plus this series' own new coverage - item 2's
# prevention-pair widening (SettingDefinitionCorpusCrossCheck.tests.ps1's user_vendor_msft_*
# scope + Snapshot.Tests.ps1's datetime-culture regression) and its own new
# MinimumTests-ratchet-sync standing gate, item 3's TP.INT.0028 ESP-projection fixture
# split, and item 4's evidence-Detail-redaction regression coverage. 1971 is the real,
# measured `./build.ps1 -Tasks build,test` total (verified on both PowerShell 7.6.5 and
# 7.4.19) at the end of this series; all four tracking locations bumped together in the
# same commit, per the ratchet's own rule.
#
# 1971 -> 1972 (TP.INT.0005 RedactDetailKeys follow-up): +1 - strengthened
# deviceName/displayName redaction It in tests/Unit/Checks/TP.INT.0005.Tests.ps1
# (distinct managed/entra names + HMAC-shape + rule-evidence mark assertions).
# 1972 is the real, measured `./build.ps1 -Tasks test` total on this tree; all
# four tracking locations bumped together, per the ratchet's own rule.
#
# 1972 -> 1973 (TP.ENT.0012 AP08 v1.0 projection remap): +1 - NotApplicable when
# GraphKit 0.2.2's AuthorizationPolicy/Get omits
# permissionGrantPolicyIdsAssignedToDefaultUserRole.
# 1973 -> 2009 (TP.INT.0017/0018 App Control + Managed Installer): +36 -
# same-policy AND against live applicationcontrolv2 ids, presence-index
# policyIds, corpus extension, catalog 51 -> 53. 2009 is the real, measured
# `./build.ps1 -Tasks test` total on this tree.
# 2009 -> 2016 (R0 source/release truth): +6 package-identity and exact GraphKit
# dependency assertions across source, restore pin, built manifest, nupkg, and publisher file-set proof; +1 case-sensitivity regression.
$script:tenantPulseGateMinimumTests = 2016

task Record_Tested_Module_Digest {
    $moduleRoot = Join-Path $BuildRoot 'output/module/TenantPulse'
    $builtVersionDir = Get-ChildItem -LiteralPath $moduleRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1

    if (-not $builtVersionDir) {
        throw "Record_Tested_Module_Digest: no built module found under '$moduleRoot' - run the 'build' workflow before 'test'."
    }

    $shippedFiles = @(Get-ChildItem -LiteralPath $builtVersionDir.FullName -Recurse -File | Sort-Object { $_.FullName })

    $testResultsDir = Join-Path $BuildRoot 'output/testResults'
    if (-not (Test-Path -LiteralPath $testResultsDir -PathType Container)) {
        New-Item -Path $testResultsDir -ItemType Directory -Force | Out-Null
    }

    $digestPath = Join-Path $testResultsDir 'tested-module-digest.txt'
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($file in $shippedFiles) {
        $relativePath = $file.FullName.Substring($builtVersionDir.FullName.Length + 1) -replace '\\', '/'
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines.Add("$relativePath  $hash")
    }

    # Ordinal sort of the recorded lines (relative path first) - deterministic file
    # content regardless of filesystem enumeration order, matching this codebase's
    # "deterministic ordering everywhere" rule elsewhere.
    $sortedLines = [string[]] @($lines)
    [System.Array]::Sort($sortedLines, [System.StringComparer]::Ordinal)

    Set-Content -LiteralPath $digestPath -Value ($sortedLines -join [System.Environment]::NewLine) -NoNewline -Encoding utf8NoBOM
    Write-Build Green "Recorded $($sortedLines.Count) shipped-file digests to '$digestPath' for module version $($builtVersionDir.Name)."
}

task Assert_Gate_Result {
    $resultsDir = Join-Path $BuildRoot 'output/testResults'
    $resultFiles = @(Get-ChildItem -LiteralPath $resultsDir -Filter 'NUnitXml_*.xml' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)

    if ($resultFiles.Count -eq 0) {
        throw "Assert_Gate_Result: no NUnit test result file found under '$resultsDir' - the Pester task must run before this one."
    }

    # AllowNotRun 1 (GraphKit 0.1.1 migration, Task 1.11): tests/QA/ReadOnly.tests.ps1's
    # "every Pending dataset declares an expected Read/Safe descriptor" block is
    # legitimately empty now - all six datasets that used to be Pending shipped in
    # GraphKit 0.1.1 and had Pending dropped from DatasetMap.psd1 (see that file), leaving
    # zero Pending entries to drive the -ForEach. The mechanism itself stays covered by a
    # synthetic Pending fixture in Get-PulseTenantSnapshot.Tests.ps1's Invoke-PulseCollection
    # Describe block; this allowance only covers the QA gate's now-empty live-catalog block,
    # which will go back to 0 the moment a future descriptor ships Pending again.
    $gate = Join-Path $BuildRoot 'tests/QA/Assert-GateResult.ps1'
    # Platform-aware skips: the two $IsWindows-gated POSIX-permission tests (Identity
    # key file 0600 / key dir 0700) skip by design on Windows; zero-skip everywhere else.
    $allowedSkips = if ($IsWindows) { 2 } else { 0 }
    & $gate -ResultPath $resultFiles[0].FullName -MinimumTests $script:tenantPulseGateMinimumTests -AllowedSkips $allowedSkips -AllowNotRun 1
    if ($LASTEXITCODE -ne 0) {
        throw "Assert_Gate_Result: the local test run did not pass the whole-result gate (MinimumTests $script:tenantPulseGateMinimumTests) - see the Assert-GateResult.ps1 output above for the specific violation."
    }
}

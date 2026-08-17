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
# `./build.ps1 -Tasks test` total for this commit.
$script:tenantPulseGateMinimumTests = 1402

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
    & $gate -ResultPath $resultFiles[0].FullName -MinimumTests $script:tenantPulseGateMinimumTests -AllowedSkips 0 -AllowNotRun 1
    if ($LASTEXITCODE -ne 0) {
        throw "Assert_Gate_Result: the local test run did not pass the whole-result gate (MinimumTests $script:tenantPulseGateMinimumTests) - see the Assert-GateResult.ps1 output above for the specific violation."
    }
}

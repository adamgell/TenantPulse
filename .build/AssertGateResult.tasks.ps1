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
$script:tenantPulseGateMinimumTests = 1300

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

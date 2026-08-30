# TenantPulse Release Truth and Provider Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconcile the immutable TenantPulse 0.2.0 publication, start a unique 0.3.0 program-completion source identity before changing runtime bytes, fix review finding 6, record the evidence-backed rejection of finding 14, and ratchet every release gate to the resulting measured suite.

**Architecture:** Repository documentation records immutable 0.2.0 publication evidence separately from the developing 0.3.0 source line. Provider provenance becomes a stable, qualified set of primitive operation identities; legacy schema migration remains fail-closed for a `Partial` state no supported 1.x writer could emit.

**Tech Stack:** PowerShell 7.4/7.6, Pester 6.1.0, Sampler 0.120.1, ModuleBuilder 3.2.18, GitHub Actions, PSGallery.

**Spec:** `/Users/Adam.Gell/repo/GraphKit/.worktrees/program-completion/docs/superpowers/specs/2026-08-19-graphkit-tenantpulse-product-program-design.md`

## Global Constraints

- Preserve the immutable public TenantPulse `0.2.0` archive: 411284 bytes, SHA-256 `a0d5ff793b92753ab3efb4db20cf5bcf8b953e3cf81bf1a776c96a3d992417bd`, published `2026-08-30T14:07:39.587Z`; never republish or relabel rebuilt bytes as that archive.
- Preserve exact dependency GraphKit `0.3.0` in both the runtime manifest and restore pin until a separately verified GraphKit successor handoff occurs.
- Use reviewed SHA `24b3d4ebe522d9bf94d9a75c8625be438fa9b768`, merged-main SHA `b2eb7a882cc1fcb7994c39a606c7b9ac22f5a114`, PR-head CI `33295409637`, and exact-main CI `33295648250`; both CI runs executed 2277 tests with zero failures/errors/skips/NotRun across the six OS/PowerShell jobs plus gitleaks.
- Any runtime-byte change must use the unique unreleased TenantPulse `0.3.0` source identity; do not build changed runtime bytes under published version `0.2.0`.
- Review finding 6 is applicable: provider provenance must be a stable qualified primitive set, independent of tenant policy count.
- Review finding 14 is rejected on first-party schema evidence: schema 1.0.0/1.1.0 writers allowed only `Collected`, `Failed`, and `Skipped`; schema 2.0.0 introduced `Partial`. Continue rejecting legacy `Partial` rather than inventing compatibility.
- Run `./build.ps1 -Tasks pack` before `./build.ps1 -Tasks test`; the full gate must execute from the package-producing build.
- Do not touch the dirty primary checkout; work only in `.worktrees/program-completion` on `codex/program-completion`.

---

### Task 1: Reconcile immutable 0.2.0 publication truth

**Files:**
- Create: `tests/QA/ReleaseTruth.tests.ps1`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/STATUS.md`
- Modify: `tests/QA/ReadOnly.tests.ps1`
- Modify: `source/TenantPulse.psd1`
- Modify: `tests/QA/ModuleManifest.tests.ps1`
- Modify: `tests/QA/TransitiveRuntimePackaging.tests.ps1`

**Interfaces:**
- Consumes: immutable 0.2.0/public GraphKit 0.3.0 evidence in Global Constraints.
- Produces: a permanent current-publication QA contract, corrected user/internal documentation, and a unique unreleased 0.3.0 source/package identity before any runtime-byte change.

- [ ] **Step 1: Write the failing publication-truth QA container**

Create `tests/QA/ReleaseTruth.tests.ps1` with `BeforeAll` loading `README.md`, `CHANGELOG.md`, `docs/STATUS.md`, and `source/TenantPulse.psd1`, then add these five tests:

```powershell
Describe 'TenantPulse current release truth' -Tag 'QA' {
    It 'records TenantPulse 0.2.0 as the immutable current PSGallery release' {
        $readme | Should -Match 'TenantPulse `0\.2\.0` is the current immutable release on PSGallery'
        $readme | Should -Match 'a0d5ff793b92753ab3efb4db20cf5bcf8b953e3cf81bf1a776c96a3d992417bd'
    }

    It 'records the exact GraphKit 0.3.0 producer release' {
        $readme | Should -Match 'GraphKit `0\.3\.0`'
        $manifest.RequiredModules[0].RequiredVersion | Should -Be '0.3.0'
        [string] $manifest.ModuleVersion | Should -Be '0.3.0'
    }

    It 'records reviewed and merged exact-head CI evidence' {
        $status | Should -Match '24b3d4ebe522d9bf94d9a75c8625be438fa9b768'
        $status | Should -Match 'b2eb7a882cc1fcb7994c39a606c7b9ac22f5a114'
        $status | Should -Match '33295409637'
        $status | Should -Match '33295648250'
        $status | Should -Match '2,277 tests'
    }

    It 'does not call the released 0.2.0 package unpublished' {
        @($readme, $changelog, $status) -join "`n" |
            Should -Not -Match '(?i)0\.2\.0.{0,80}(?:unpublished|candidate)|(?:unpublished|candidate).{0,80}0\.2\.0'
    }

    It 'keeps deterministic CI live and publication evidence distinct' {
        $status | Should -Match 'Deterministic'
        $status | Should -Match 'CI'
        $status | Should -Match 'Live'
        $status | Should -Match 'Published'
    }
}
```

- [ ] **Step 2: Build and prove the QA test is red**

Run:

```powershell
./build.ps1 -Tasks build
Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force
Invoke-Pester -Path ./tests/QA/ReleaseTruth.tests.ps1 -Output Detailed
```

Expected: failures identify the current candidate/unpublished wording, old hash/test count, and missing final CI/publication ledger.

- [ ] **Step 3: Correct the public README**

Replace only current-state candidate claims. State that GraphKit 0.3.0 and TenantPulse 0.2.0 are the current immutable PSGallery pair; record both public links, TenantPulse archive hash, merged source SHA, exact-main CI run, and 2277-test result. State separately that current source starts the unreleased TenantPulse 0.3.0 product-program line and is not the public 0.2.0 archive. Preserve the no-user/no-legacy premise. Keep the coverage and scale limitations honest. Change `as of this candidate` to `as of TenantPulse 0.2.0`, and replace the unpublished local-staging installation warning with exact PSGallery resolution of GraphKit 0.3.0.

- [ ] **Step 4: Correct changelog and status evidence**

In `CHANGELOG.md`, add an `Unreleased / 0.3.0 program line` note for the unique successor identity, then keep the `0.2.0` source section date but replace candidate/not-published prose with the actual 2026-08-30 publication, both CI run IDs, 2277 tests, and public archive hash. In `docs/STATUS.md`, rename the top section `Released-package evidence (2026-08-30)`, identify the separate unreleased 0.3.0 source line, and replace the obsolete 2255/hash/no-CI/no-publication paragraph with a four-state table:

```markdown
| Evidence state | Proof |
|---|---|
| Deterministic | Reviewed tree `24b3d4e...`; 2,277 tests; zero failures/errors/skips/NotRun; bound archive hash `a0d5ff...`. |
| CI | PR-head run `33295409637` and merged-main run `33295648250`; six matrix jobs plus gitleaks green. |
| Live | Retain the exact-package Ivy24 rows and expansion counts already recorded below. |
| Published | TenantPulse 0.2.0 on PSGallery at `2026-08-30T14:07:39.587Z`; downloaded archive matches `a0d5ff...`. |
```

Keep older 0.1.x/GraphKit 0.2.2 evidence as dated history.

- [ ] **Step 5: Start the unique unreleased TenantPulse 0.3.0 source line**

Set `source/TenantPulse.psd1` `ModuleVersion = '0.3.0'` before the next pack. Replace its release notes with this exact initial record:

```markdown
## [0.3.0] - Unreleased

### Changed

- The approved product-program completion work now uses a unique successor identity. Published TenantPulse 0.2.0 and its exact GraphKit 0.3.0 dependency remain immutable.
```

Update `tests/QA/ModuleManifest.tests.ps1` to expect the exact 0.3.0 version/release-note text and `TenantPulse.0.3.0.nupkg`, retaining every exact GraphKit dependency assertion.

In `tests/QA/TransitiveRuntimePackaging.tests.ps1`, replace literal TenantPulse 0.2.0 in the child script with a `__TENANTPULSE_VERSION__` token, call `.Replace('__TENANTPULSE_VERSION__', $script:releaseVersion)` before invoking the child process, and assert `$probe.TenantPulse | Should -Be $script:releaseVersion`. Keep GraphKit 0.3.0 and Graph Authentication 2.39.0 assertions unchanged.

- [ ] **Step 6: Remove stale candidate wording from the read-only QA comment**

In `tests/QA/ReadOnly.tests.ps1`, replace `released-candidate` with `released` without changing assertions.

- [ ] **Step 7: Run focused release and identity QA green**

Run the focused command from Step 2, then:

```powershell
./build.ps1 -Tasks pack
Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force
Invoke-Pester -Path @('./tests/QA/ModuleManifest.tests.ps1','./tests/QA/TransitiveRuntimePackaging.tests.ps1') -Output Detailed
```

Expected: five release-truth tests pass; source, built manifest, package, and clean-process import all use TenantPulse 0.3.0 with exact GraphKit 0.3.0. The public 0.2.0 archive and retained release worktree are untouched.

- [ ] **Step 8: Run the full baseline-plus-truth gate**

```powershell
./build.ps1 -Tasks pack
./build.ps1 -Tasks test
```

Expected and measured: 2284 tests execute with zero failures/errors/skips/NotRun; the existing 2255 minimum remains green pending the final ratchet task. The two cases above the original 2282 estimate are the standing secret/PII and control-byte scans discovered for this newly tracked plan document.

- [ ] **Step 9: Commit immutable-release truth and successor identity**

```bash
git add README.md CHANGELOG.md docs/STATUS.md docs/superpowers/plans/2026-08-30-release-truth-and-provenance.md source/TenantPulse.psd1 tests/QA/ReleaseTruth.tests.ps1 tests/QA/ReadOnly.tests.ps1 tests/QA/ModuleManifest.tests.ps1 tests/QA/TransitiveRuntimePackaging.tests.ps1
git commit -m "docs: reconcile TenantPulse 0.2.0 release truth"
```

### Task 2: Fix provider provenance on the 0.3.0 source line

**Files:**
- Modify: `source/TenantPulse.psd1`
- Modify: `source/Private/Collect/Invoke-PulseEndpointSecurityPolicyPlan.ps1`
- Modify: `source/Private/Collect/Invoke-PulseWindowsDataProcessorPlan.ps1`
- Modify: `tests/QA/ModuleManifest.tests.ps1`
- Modify: `tests/Unit/Collect/EndpointSecurityPolicyPlan.Tests.ps1`
- Modify: `tests/Unit/Collect/ProviderPlanCollection.Tests.ps1`
- Modify: `tests/Unit/Snapshot/CollectionOutcomeSnapshot.Tests.ps1`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/STATUS.md`

**Interfaces:**
- Consumes: immutable public 0.2.0 evidence from Task 1; `New-PulseCollectionOutcome -Operations [string[]]`; `New-PulseCollectionGap -Operation [string]`; exact GraphKit `RequiredVersion = '0.3.0'`.
- Produces: stable operation set `@('ConfigurationPolicy.ListBeta','ConfigurationPolicySetting.ListBeta')`; qualified child-gap operation; explicit fail-closed legacy-Partial regression; updated 0.3.0 release notes.

- [ ] **Step 1: Write the failing provenance regressions**

In `tests/Unit/Collect/EndpointSecurityPolicyPlan.Tests.ps1`, add one parameterized `It` with `PolicyCount = 0, 1, 2` (three Pester cases). Build that many matching policies and assert each outcome records:

```powershell
$result.Outcome.Operations | Should -Be @(
    'ConfigurationPolicy.ListBeta'
    'ConfigurationPolicySetting.ListBeta'
)
```

The three cases prove the set is independent of selected policy count. In the existing partial child-failure test, assert `Gaps[0].Operation` is `ConfigurationPolicySetting.ListBeta`; in existing collected/failed tests, retain their outcome assertions.

In `tests/Unit/Collect/ProviderPlanCollection.Tests.ps1`, replace generic duplicate `@('ListBeta','ListBeta')` fixture values with the two qualified identities above and assert them exactly after manifest persistence.

- [ ] **Step 2: Write the finding-14 disposition regression**

In `tests/Unit/Snapshot/CollectionOutcomeSnapshot.Tests.ps1`, add one test that writes otherwise-valid schema 1.0.0 and 1.1.0 manifests containing a dataset with `status = 'Partial'`, opens each store, and asserts `Get-PulseSnapshotManifest` throws `*legacy dataset*unsupported status 'Partial'*`. Assert the manifest bytes remain unchanged. The test documents that supported 1.x writers never emitted Partial and must not broaden migration.

- [ ] **Step 3: Build and run the focused tests red**

```powershell
./build.ps1 -Tasks build
Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force
Invoke-Pester -Path @('./tests/Unit/Collect/EndpointSecurityPolicyPlan.Tests.ps1','./tests/Unit/Collect/ProviderPlanCollection.Tests.ps1','./tests/Unit/Snapshot/CollectionOutcomeSnapshot.Tests.ps1') -Output Detailed
```

Expected: qualified/stable provenance tests fail against tenant-count-dependent `ListBeta` values; the legacy-Partial rejection test passes against the intentionally fail-closed implementation.

- [ ] **Step 4: Implement the stable qualified operation set**

Replace the mutable list in `Invoke-PulseEndpointSecurityPolicyPlan.ps1` with:

```powershell
$operations = @(
    'ConfigurationPolicy.ListBeta'
    'ConfigurationPolicySetting.ListBeta'
)
```

Remove the per-policy `$operations.Add('ListBeta')`. Pass `$operations` directly to every outcome. Change the child settings gap operation to `ConfigurationPolicySetting.ListBeta`; preserve descriptor calls, row/gap sorting, partial behavior, and read-only enforcement.

- [ ] **Step 5: Add the provenance fix to the 0.3.0 release notes**

Keep `source/TenantPulse.psd1` at `ModuleVersion = '0.3.0'`. Replace its release notes with this exact updated development record:

```markdown
## [0.3.0] - Unreleased

### Fixed

- Endpoint Security composite provenance now records the stable qualified primitive set `ConfigurationPolicy.ListBeta` and `ConfigurationPolicySetting.ListBeta`, independent of tenant policy count; child gaps name the setting primitive explicitly.

### Changed

- The approved product-program completion work uses a unique successor identity. Published TenantPulse 0.2.0 and its exact GraphKit 0.3.0 dependency remain immutable.
```

Keep runtime and restore GraphKit pins at exact 0.3.0. Update `tests/QA/ModuleManifest.tests.ps1` to expect the exact new version/release-note text and a `TenantPulse.0.3.0.nupkg`, retaining every dependency assertion.

- [ ] **Step 6: Reconcile current-source wording and finding dispositions**

Add an `Unreleased / 0.3.0 program line` block to `CHANGELOG.md`, identifying the provenance fix and finding-14 ruling. Update README/status so 0.2.0 remains the public release while current source is the unreleased 0.3.0 program line. In `Invoke-PulseWindowsDataProcessorPlan.ps1`, replace `GraphKit 0.3.0 candidate` with `published GraphKit 0.3.0 release`; do not alter the evidence-backed PlatformUnavailable disposition.

- [ ] **Step 7: Run focused and package-identity QA green**

Run the Step 3 test set plus:

```powershell
./build.ps1 -Tasks pack
Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force
Invoke-Pester -Path @('./tests/QA/ModuleManifest.tests.ps1','./tests/QA/TransitiveRuntimePackaging.tests.ps1') -Output Detailed
```

Expected: qualified provenance, legacy rejection, exact 0.3.0 identity, exact GraphKit 0.3.0 dependency, and clean-process import all pass.

- [ ] **Step 8: Run the authoritative full gate**

```powershell
./build.ps1 -Tasks pack
./build.ps1 -Tasks test
```

Expected: 2288 tests execute with zero failures/errors/skips/NotRun and the tested-release proof names TenantPulse 0.3.0. Do not publish it. Actual discovery remains authoritative.

- [ ] **Step 9: Commit the provenance fix**

```bash
git add source/TenantPulse.psd1 source/Private/Collect/Invoke-PulseEndpointSecurityPolicyPlan.ps1 source/Private/Collect/Invoke-PulseWindowsDataProcessorPlan.ps1 tests/QA/ModuleManifest.tests.ps1 tests/Unit/Collect/EndpointSecurityPolicyPlan.Tests.ps1 tests/Unit/Collect/ProviderPlanCollection.Tests.ps1 tests/Unit/Snapshot/CollectionOutcomeSnapshot.Tests.ps1 README.md CHANGELOG.md docs/STATUS.md
git commit -m "fix: stabilize provider-plan provenance"
```

### Task 3: Synchronize the 2288-test release floor

**Files:**
- Modify: `.build/AssertGateResult.tasks.ps1`
- Modify: `.github/workflows/ci.yml`
- Modify: `scripts/Publish-TenantPulsePackage.ps1`
- Modify: `tests/QA/PublishTenantPulsePackage.tests.ps1`
- Modify: `tests/QA/TestProofGate.tests.ps1`
- Test: `tests/QA/MinimumTestsRatchetSync.tests.ps1`

**Interfaces:**
- Consumes: authoritative 2288-test result and tested-release proof from Task 2.
- Produces: one synchronized minimum-test value across build, CI, publisher, passing fixtures, and proof-failure fixtures.

- [ ] **Step 1: Set every synchronized floor to 2288**

Replace the current 2255 floor with 2288 in `.build/AssertGateResult.tasks.ps1`, `.github/workflows/ci.yml`, the publisher gate call/comment, and the passing publisher fixture. Append the measured history comment `2255 -> 2288 after publication closeout: the merged tree actually executed 2277 tests; +5 current-release truth tests, +2 per-file safety scans for the tracked plan, +3 stable qualified-provenance policy-count cases, and +1 fail-closed legacy-Partial regression.` If the authoritative Task 2 result differs from 2288, stop this mechanical step, reconcile discovery before changing the floor, and use the measured result rather than this estimate.

- [ ] **Step 2: Update rejection fixtures around the same floor**

In `tests/QA/TestProofGate.tests.ps1`, set the normal total to 2288 and the `Floor` failure total to 2287. Update the synthetic NUnit total in `tests/QA/PublishTenantPulsePackage.tests.ps1` to 2288. Preserve skip/failure/mismatched-pair behavior.

- [ ] **Step 3: Run the synchronization and publisher-focused gates**

```powershell
./build.ps1 -Tasks build
Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force
Invoke-Pester -Path @('./tests/QA/MinimumTestsRatchetSync.tests.ps1','./tests/QA/PublishTenantPulsePackage.tests.ps1','./tests/QA/TestProofGate.tests.ps1') -Output Detailed
```

Expected: every focused test passes and all parsed ratchet locations equal the authoritative total.

- [ ] **Step 4: Repack and run the final full local gate**

```powershell
./build.ps1 -Tasks pack
./build.ps1 -Tasks test
```

Expected: the exact measured test total, zero failures/errors/skips/NotRun, synchronized whole-result gate green, and a bound TenantPulse 0.3.0 release proof. Publication remains disabled.

- [ ] **Step 5: Commit the synchronized floor**

```bash
git add .build/AssertGateResult.tasks.ps1 .github/workflows/ci.yml scripts/Publish-TenantPulsePackage.ps1 tests/QA/PublishTenantPulsePackage.tests.ps1 tests/QA/TestProofGate.tests.ps1
git commit -m "test: ratchet TenantPulse program baseline"
```

Do not push, merge, or publish during this plan. Those occur only after task reviews and the broader train review.

BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceManifestPath = Join-Path $script:repoRoot 'source/TenantPulse.psd1'
    $script:sourceManifest = Import-PowerShellDataFile -Path $script:sourceManifestPath
    $script:releaseVersion = [string] $script:sourceManifest.ModuleVersion
    $script:expectedReleaseNotes = @'
## [0.3.0] - Unreleased

### Added

- Neutral `-ReportData Applications` collection on `Get-PulseTenantSnapshot` and
  `Invoke-PulseAssessment`, producing schema-v1, hash-verified application-assignment and
  app-install-error JSONL artifacts. The contract preserves raw report columns, assignment
  targets/settings, group resolution and member-count certainty, and explicit partial/failure
  gaps without adding Office rendering, branding, approval workflow, or derived severity.
- Self-contained HTML findings reports through `Export-PulseReport -Format Html` and
  `Invoke-PulseAssessment -Format Html`. JSON remains canonical and is always written by the
  assessment path; HTML is a second findings-only renderer with inline CSS, no scripts, no
  network-loading URLs, and no Graph or snapshot access.
- TenantPulse 1.0 privacy-classification constructors for `Identity`, `SecretSensitive`,
  `SafeTechnical`, `SafeOperatorLabel`, and `BoundedReviewedText`, plus fail-closed
  `ConvertTo-PulseSafeShareDocument` conversion and privacy mutation canaries.

### Fixed

- Composite datasets now use explicit TenantPulse provider-plan metadata instead of
  synthetic GraphKit `Pending` / `Walk` descriptors. Permission preflight includes every
  declared child operation, including Endpoint Security policy assignments, while the
  Windows data-processor disposition records no Graph operation or API version.
- Endpoint Security collection now gaps absent or unrecognized template metadata instead
  of silently publishing authoritative empty results, and current security baselines are
  still collected when the independent legacy-template surface fails.
- Administrative Template expansion now honors a shared authentication abort before any
  descriptor or Graph work and gaps presentation values without stable ids instead of
  inventing random evidence identities. App Control wording now matches its confirmed-
  assignment behavior.
- Application report collection now request-body pages the Intune install summary through
  `TotalRowCount`, records incomplete totals and partial group metadata as gaps, stops every
  later report read on authentication failure, recursively scrubs tenant identifiers before
  persistence, rejects semantically unknown report matrices, and uses a canonical total-order
  tie-breaker for content-addressed rows.
- Graph collection now fails closed unless `Get-GraphObject -PassThruResult` returns exactly one complete `GraphKit.OperationResult`; null, rows-only, multiple, type-spoofed, and malformed results can no longer be persisted as `Collected`, while bounded partial rows retain indeterminate, truncation, and page-cap detail.
- Review finding 6 is implemented: Endpoint Security composite provenance now records the stable qualified primitive set `ConfigurationPolicy.ListBeta` and `ConfigurationPolicySetting.ListBeta`, independent of tenant policy count; child gaps name the setting primitive explicitly.
- Direct, composite, and expansion collection paths now use one canonical Graph failure mapper. A request-time `403` is recorded as `Failed` / `PermissionDenied`; only `AuthenticationFailed` aborts subsequent network collection, while deadline expiration, cancellation, indeterminate certainty, permission denial, and provider failure remain explicit and isolated.

### Changed

- The approved product-program completion work uses a unique successor identity. Published TenantPulse 0.2.0 and its exact GraphKit 0.3.0 dependency remain immutable.
- `Data.PartialDatasets` is a strict Function-only opt-in that requires `DatasetOutcomes`. Exactly four checks opt in: universal checks `TP.INT.0013` and `TP.INT.0029` may Fail on a known offender but cannot Pass with gaps; existential checks `TP.INT.0014` and `TP.INT.0015` may Pass on a known witness but cannot Fail with gaps. BitLocker and LAPS witnesses require native Boolean values.
- The other 49 checks remain `NotApplicable` when their dataset status is `Partial`. For the four opt-ins, a structurally valid non-decisive Partial result is also `NotApplicable`; without decisive proof, zero usable rows or malformed outcomes, gaps, or rows are `Error`.
- Findings schema `1.0`, snapshot schema `2.0.0`, and scoring model `1.0` are unchanged. This deterministic source/package tranche makes no new live-service or publication claim.
- Review finding 14 remains rejected/obsolete on first-party schema evidence: supported schema 1.0.0/1.1.0 writers could not emit `Partial`, so migration rejects that later state without rewriting the manifest.
- Classified JSON export now requires complete field classification before it emits a
  `privacy.boundary = "classified"` document. `-Redact`, `RedactDetailKeys`, and
  `Protect-PulseReason` remain the local-only compatibility layer; C0 D6 still leaves the public
  safe-share workflow undecided, and no public operator-key rotate cmdlet was added.
'@
    $script:sourceReleaseNotes = [string] $script:sourceManifest.PrivateData.PSData.ReleaseNotes
    $script:builtManifestPath = Join-Path $script:repoRoot "output/module/TenantPulse/$script:releaseVersion/TenantPulse.psd1"
    $script:packagePath = Join-Path $script:repoRoot "output/TenantPulse.$script:releaseVersion.nupkg"

    function Assert-ExactGraphKitRequirement {
        param([Parameter(Mandatory)] [hashtable] $Manifest)

        $requirements = @($Manifest.RequiredModules | Where-Object { $_.ModuleName -eq 'GraphKit' })
        $requirements.Count | Should -Be 1
        [string] $requirements[0].RequiredVersion | Should -Be '0.3.0'
        $requirements[0].ContainsKey('ModuleVersion') | Should -BeFalse
        $requirements[0].ContainsKey('MaximumVersion') | Should -BeFalse
    }

    function Assert-ExactUnreleasedReleaseNotes {
        param([Parameter(Mandatory)] [string] $ReleaseNotes)

        # Sampler materializes CHANGELOG.md's [Unreleased] section into the built package
        # with the build date. Normalize only that generated header; the complete source
        # release-note body must remain byte-for-byte identical.
        $normalizedReleaseNotes = $ReleaseNotes -replace (
            '^## \[0\.3\.0\] - \d{4}-\d{2}-\d{2}',
            '## [0.3.0] - Unreleased'
        )
        $normalizedReleaseNotes.TrimEnd("`r", "`n") |
            Should -Be $script:sourceReleaseNotes.TrimEnd("`r", "`n")
    }
}

Describe 'TenantPulse package identity and GraphKit dependency' -Tag 'QA' {
    It 'uses the unique unreleased 0.3.0 identity for changed runtime and dependency bytes' {
        $script:releaseVersion | Should -Be '0.3.0'
    }

    It 'requires exact GraphKit 0.3.0 and the intended release notes in the source manifest' {
        Assert-ExactGraphKitRequirement -Manifest $script:sourceManifest
        $script:sourceReleaseNotes | Should -Be $script:expectedReleaseNotes
    }

    It 'keeps the independent restore-time GraphKit pin at 0.3.0' {
        $restoreDependencies = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'RequiredModules.psd1')
        [string] $restoreDependencies.GraphKit | Should -Be '0.3.0'
    }

    It 'preserves exact GraphKit 0.3.0 and source release notes in the built manifest' {
        Test-Path -LiteralPath $script:builtManifestPath -PathType Leaf | Should -BeTrue
        $builtManifest = Import-PowerShellDataFile -Path $script:builtManifestPath
        Assert-ExactGraphKitRequirement -Manifest $builtManifest
        Assert-ExactUnreleasedReleaseNotes -ReleaseNotes ([string] $builtManifest.PrivateData.PSData.ReleaseNotes)
    }

    It 'preserves exact GraphKit 0.3.0 and source release notes in the 0.3.0 nupkg manifest' {
        Test-Path -LiteralPath $script:packagePath -PathType Leaf | Should -BeTrue
        $extractRoot = Join-Path $TestDrive 'package'
        if (Test-Path -LiteralPath $extractRoot) {
            Remove-Item -LiteralPath $extractRoot -Recurse -Force
        }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($script:packagePath, $extractRoot)
        $packagedManifest = Import-PowerShellDataFile -Path (Join-Path $extractRoot 'TenantPulse.psd1')
        Assert-ExactGraphKitRequirement -Manifest $packagedManifest
        Assert-ExactUnreleasedReleaseNotes -ReleaseNotes ([string] $packagedManifest.PrivateData.PSData.ReleaseNotes)
    }
}

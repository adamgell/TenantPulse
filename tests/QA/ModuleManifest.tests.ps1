BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceManifestPath = Join-Path $script:repoRoot 'source/TenantPulse.psd1'
    $script:sourceManifest = Import-PowerShellDataFile -Path $script:sourceManifestPath
    $script:releaseVersion = [string] $script:sourceManifest.ModuleVersion
    $script:expectedReleaseNotes = @'
## [0.3.0] - Unreleased

### Added

- Neutral `-ReportData` profiles on both collection surfaces: `Applications` writes
  hash-verified assignment and install-error artifacts; `Devices` writes the managed-device
  worksheet source without inventing TPM state; and `Inventory` guarantees the 25-source IHA
  migration inventory. Raw columns and explicit certainty are preserved, overlapping roots are
  deduplicated, and Office rendering, branding, approvals, and derived severity stay outside.
- Self-contained HTML findings reports through `Export-PulseReport -Format Html` and
  `Invoke-PulseAssessment -Format Html`. JSON remains canonical and is always written by the
  assessment path; HTML is a second findings-only renderer with inline CSS, no scripts, no
  network-loading URLs, and no Graph or snapshot access.
- TenantPulse 1.0 privacy-classification constructors for `Identity`, `SecretSensitive`,
  `SafeTechnical`, `SafeOperatorLabel`, and `BoundedReviewedText`, plus fail-closed
  `ConvertTo-PulseSafeShareDocument` conversion and privacy mutation canaries.

### Fixed

- Conditional Access findings no longer promote policy presence to tenant-wide protection
  without evaluating effective user, resource, client-app, platform, location, risk,
  current and deprecated device, authentication-flow, workload/agent-identity, and grant
  semantics. Legacy-auth requires both legacy client buckets without letting an unknown
  ancillary condition broaden a recognized bucket. MFA checks distinguish mandatory grants
  from OR alternatives; a custom strength establishes generic MFA only when Graph reports
  `requirementsSatisfied=mfa`, and never establishes phishing resistance from that field alone.
  Unknown/future controls and invalid MFA/strength, block-sibling, password-change, or risk-
  remediation combinations remain indeterminate. Role checks use Microsoft's current 14-role
  minimum-admin baseline and treat undeclared user, group, and guest/external carve-outs as
  indeterminate, while canonical approved account exceptions remain explicit, deduplicated
  evidence. Beta authentication-context targets and time conditions retain known narrow-scope
  lower bounds, and any unrecognized non-null condition fails closed. Cross-tenant
  defaults now validate singleton cardinality and distinguish a decisive full block or
  scoped allowlist from a narrow denylist. Workload-identity awareness validates documented
  service-principal and beta agent-identity selectors and filters, reports malformed policies
  separately, and does not count the tenant-wide sentinel as one principal. Authentication-
  flow `none` and unknown enum values retain distinct meanings; malformed operator-supplied
  account values use operator-keyed privacy-safe evidence aliases rather than raw input.
- Endpoint Security BitLocker and LAPS composites now retain complete assignment-intent
  classification. Malformed or unknown assignment targets produce a policy-scoped,
  sanitized `InvalidProviderData` gap and a `Partial` dataset, so unresolved targeting can
  never be laundered into complete evidence or an existential `Fail`.
- Composite datasets now use explicit TenantPulse provider-plan metadata instead of
  synthetic GraphKit `Pending` / `Walk` descriptors. Permission preflight includes every
  declared child operation, including Endpoint Security policy assignments, while the
  Windows data-processor disposition records no Graph operation or API version.
- Compliance and legacy device-configuration collection now joins every unambiguous policy
  to its authoritative assignment response. `TP.INT.0002` and `TP.INT.0004` require positive
  assignment evidence and ignore unrelated policy-scoped gaps. Relevant uncertainty degrades
  only when it can affect the result; `TP.INT.0004` bounds distinct possible candidates against
  its two-ring threshold and rejects coercible non-numeric deadline shapes.
- Endpoint Security collection now gaps absent or unrecognized template metadata instead
  of silently publishing authoritative empty results, and current security baselines are
  still collected when the independent legacy-template surface fails.
- Administrative Template expansion now honors a shared authentication abort before any
  descriptor or Graph work and gaps presentation values without stable ids instead of
  inventing random evidence identities. App Control wording now matches its confirmed-
  assignment behavior.
- Application report collection now request-body pages the Intune install summary through
  `TotalRowCount`, binds continuation pages to a native, nonblank service-returned `SessionId`,
  and discards missing, mismatched, or shape-switched continuations without persisting session
  metadata. It records incomplete totals and partial group metadata as gaps, stops every
  later report read on authentication failure, recursively scrubs tenant identifiers before
  persistence, rejects semantically unknown report matrices, and uses a canonical total-order
  tie-breaker for content-addressed rows.
- Graph collection now fails closed unless `Get-GraphObject -PassThruResult` returns exactly one complete `GraphKit.OperationResult`; null, rows-only, multiple, type-spoofed, and malformed results can no longer be persisted as `Collected`, while bounded partial rows retain indeterminate, truncation, and page-cap detail.
- Review finding 6 is implemented: Endpoint Security composite provenance now records the stable qualified primitive set `ConfigurationPolicy.ListBeta`, `ConfigurationPolicySetting.ListBeta`, and `ConfigurationPolicyAssignment.ListBeta`, independent of tenant policy count; setting and assignment gaps name their respective primitives explicitly.
- Direct, composite, and expansion collection paths now use one canonical Graph failure mapper. A request-time `403` is recorded as `Failed` / `PermissionDenied`; only `AuthenticationFailed` aborts subsequent network collection, while deadline expiration, cancellation, indeterminate certainty, permission denial, and provider failure remain explicit and isolated.
- Final review hardening now derives privacy from classified evidence; validates native-string
  assignment and Endpoint Security shapes; fails closed on malformed or contradictory
  BitLocker/LAPS, expansion, ARM, group-closure, and update-ring evidence; deduplicates rings
  by identity with deterministic evidence and exact gap attribution; and preserves both errors
  when expansion and manifest persistence fail together.
- Privacy completeness is now independent from the sharing boundary: ordinary evaluation
  documents remain `local-only`, only protected safe-share clones become `classified`, and HTML
  retains a prominent local-only warning unless the classification, native Boolean flags,
  classified boundary, and `safe-share-v1` protection provenance are exact. HTML publication now
  uses same-directory atomic replacement so a failed write preserves the prior good report.
- Release CI now uses a base-controlled `pull_request_target` gate that checksum-pins its
  scanner and reviewed `.gitleaksignore`, fetches PR heads only as passive Git objects, blocks
  PR changes to both trust-root files, and scans the full PR or push comparison range. The
  offline release gate also scans that protected workflow, every tracked content root including
  `.patch` and `.diff` handoffs, and root control files including `.gitignore`, for secret-shaped
  content and raw control bytes.
- Normal CI checks out and asserts the exact event commit before building: pull requests test the
  pull-request head SHA and pushes test `github.sha`, preventing a moving ref from being mistaken
  for exact-revision evidence.

### Changed

- The approved product-program completion work uses a unique successor identity. Published TenantPulse 0.2.0 and its exact GraphKit 0.3.0 dependency remain immutable.
- `Data.PartialDatasets` is a strict Function-only opt-in that requires `DatasetOutcomes`. Exactly six checks opt in: assignment-scoped checks `TP.INT.0002` and `TP.INT.0004` use authoritative assignment evidence and scope gaps by policy; universal checks `TP.INT.0013` and `TP.INT.0029` may Fail on a known offender but cannot Pass with gaps; existential checks `TP.INT.0014` and `TP.INT.0015` may Pass on a known witness but cannot Fail with gaps. BitLocker and LAPS witnesses require native Boolean values.
- The other 47 checks remain `NotApplicable` when their dataset status is `Partial`. For the six opt-ins, structurally valid non-decisive Partial evidence is `NotApplicable`; zero usable Partial rows, malformed outcomes or gaps, and rule-invalid rows remain `Error`.
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

    It 'keeps release notes within the 10000-character manifest limit after a CRLF checkout' {
        $crlfReleaseNotes = $script:sourceReleaseNotes -replace '(?<!\r)\n', "`r`n"
        $crlfReleaseNotes.Length | Should -BeLessOrEqual 10000
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

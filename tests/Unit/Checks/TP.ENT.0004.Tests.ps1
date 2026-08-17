BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:Invoke-PulseCheckFixture {
        param(
            [Parameter(Mandatory)] [string] $CheckId,
            [Parameter(Mandatory)] [hashtable[]] $Datasets,
            [hashtable] $Context = @{}
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $evaluation = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $CheckId, $Datasets, $Context {
                param($storeRoot, $keyPath, $checkId, $datasets, $context)

                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq $checkId }
                if (-not $check) { throw "fixture setup: check '$checkId' not found in the catalog." }

                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
                foreach ($d in $datasets) {
                    $params = @{
                        Store      = $store
                        Name       = $d.Name
                        ApiVersion = $d.ApiVersion
                        Status     = $d.Status
                    }
                    if ($d.ContainsKey('Data')) { $params.Data = $d.Data }
                    if ($d.ContainsKey('Reason')) { $params.Reason = $d.Reason }
                    Write-PulseDataset @params
                }

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath -Context $context
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    function script:New-PulseLegacyAuthPolicy {
        param(
            [string] $DisplayName = 'Block Legacy Auth',
            [string] $State = 'enabled',
            [string[]] $ExcludeUsers = @()
        )
        [pscustomobject]@{
            id             = "ca-$DisplayName"
            displayName    = $DisplayName
            state          = $State
            conditions     = [pscustomobject]@{
                clientAppTypes = @('exchangeActiveSync', 'other')
                users          = [pscustomobject]@{ excludeUsers = $ExcludeUsers }
            }
            grantControls  = [pscustomobject]@{ builtInControls = @('block') }
        }
    }

    $script:bgGuid = '11111111-1111-1111-1111-111111111111'
}

Describe 'TP.ENT.0004 - Legacy authentication is blocked by an enforced Conditional Access policy' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0004' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: an enabled policy blocks legacy authentication' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
    }

    It 'Pass (post-review, L1): clientAppTypes "all" covers legacy protocols too, not just itemized exchangeActiveSync/other' {
        $allAppsPolicy = [pscustomobject]@{
            id            = 'ca-all-apps-block'
            displayName   = 'Block All Client App Types'
            state         = 'enabled'
            conditions    = [pscustomobject]@{ clientAppTypes = @('all') }
            grantControls = [pscustomobject]@{ builtInControls = @('block') }
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($allAppsPolicy) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: policy exists but is report-only, not enforced' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy -State 'enabledForReportingButNotEnforced') }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'report-only'
    }

    It 'Fail: no policy at all blocks legacy authentication' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'gate-degraded: NotApplicable when conditionalAccessPolicies was skipped (no EntraP1 data)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'permission-denied: Policy.Read.All' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'permission-denied: Policy.Read.All'
    }

    # ---- Task 3.5: exclusion-context wiring (evidence only, never a Status input) ----

    It 'no exclusion evidence at all when no -Context is supplied (empty exclusion context, existing evidence shape unchanged)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
    }

    It 'Pass with honored-exclusion evidence: a declared break-glass account excluded from the enforced block policy' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy -ExcludeUsers @($script:bgGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:bgGuid) }

        $finding.status | Should -Be 'Pass'
        $exclusionEntry = $finding.evidence | Where-Object { $_.identity -eq $script:bgGuid }
        $exclusionEntry | Should -Not -BeNullOrEmpty
        $exclusionEntry.detail.excludedFromEnforcedBlockPolicies | Should -Contain 'Block Legacy Auth'
        @($exclusionEntry.detail.excludedFromReportOnlyBlockPolicies).Count | Should -Be 0
        # fully enforced-honored - no misreading-risk warning needed
        $exclusionEntry.detail.PSObject.Properties.Name | Should -Not -Contain 'reportOnlyProtectionWarning'
    }

    It 'report-only exclusion is surfaced but distinguished from enforced honoring - never counted as protection' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy -State 'enabledForReportingButNotEnforced' -ExcludeUsers @($script:bgGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:bgGuid) }

        $finding.status | Should -Be 'Fail'
        $exclusionEntry = $finding.evidence | Where-Object { $_.identity -eq $script:bgGuid }
        $exclusionEntry | Should -Not -BeNullOrEmpty
        @($exclusionEntry.detail.excludedFromEnforcedBlockPolicies).Count | Should -Be 0
        $exclusionEntry.detail.excludedFromReportOnlyBlockPolicies | Should -Contain 'Block Legacy Auth'
        # misreading-risk fold-in: report-only-ONLY exclusion carries an explicit warning
        $exclusionEntry.detail.reportOnlyProtectionWarning | Should -Match 'do not protect'
    }

    It 'a declared identifier not named in any evaluated policy''s excludeUsers gets no per-identity exclusion evidence entry (fold-in: the group-exclusion-resolution note still surfaces, since something WAS declared)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        ) -Context @{ BreakGlassAccounts = @($script:bgGuid) }

        $finding.status | Should -Be 'Pass'
        ($finding.evidence | Where-Object { $_.identity -eq $script:bgGuid }) | Should -BeNullOrEmpty
        # policy evidence (1) + group-exclusion-resolution note (1, declared-context gate) = 2
        $finding.evidence.Count | Should -Be 2
        ($finding.evidence | Where-Object { $_.identity -eq 'group-exclusion-resolution' }) | Should -Not -BeNullOrEmpty
    }

    # ---- dual-review fix round: completeness fold-in hostile cases ----

    It 'a malformed (non-GUID) declared account is surfaced in evidence even though it can never match any policy' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        ) -Context @{ BreakGlassAccounts = @('not-a-guid@contoso.com') }

        $finding.status | Should -Be 'Pass'
        $malformedEntry = $finding.evidence | Where-Object { $_.identity -eq 'not-a-guid@contoso.com' }
        $malformedEntry | Should -Not -BeNullOrEmpty
        $malformedEntry.detail.issue | Should -Match 'not GUID-shaped'
    }

    It 'a group-exclusion-resolution note is surfaced when the operator declared something and group exclusions are unresolved' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy -ExcludeUsers @($script:bgGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:bgGuid) }

        $finding.status | Should -Be 'Pass'
        $noteEntry = $finding.evidence | Where-Object { $_.identity -eq 'group-exclusion-resolution' }
        $noteEntry | Should -Not -BeNullOrEmpty
        $noteEntry.detail.note | Should -Match 'Group-based exclusion'
    }

    It 'no group-exclusion-resolution note when -Context declares nothing at all (backward-compat, no noise)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
        ($finding.evidence | Where-Object { $_.identity -eq 'group-exclusion-resolution' }) | Should -BeNullOrEmpty
    }

    It 'multiple declared identifiers straddling enforced/report-only/no-match/malformed all resolve independently in one evaluation' {
        $enforcedGuid = '44444444-4444-4444-4444-444444444444'
        $reportOnlyGuid = '55555555-5555-5555-5555-555555555555'
        $noMatchGuid = '66666666-6666-6666-6666-666666666666'
        $malformed = 'still-not-a-guid'

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseLegacyAuthPolicy -DisplayName 'Enforced Block' -ExcludeUsers @($enforcedGuid))
                (New-PulseLegacyAuthPolicy -DisplayName 'Report-Only Block' -State 'enabledForReportingButNotEnforced' -ExcludeUsers @($reportOnlyGuid))
            ) }
        ) -Context @{ BreakGlassAccounts = @($enforcedGuid, $reportOnlyGuid, $noMatchGuid, $malformed) }

        # An enforced block policy exists, so this is Pass regardless of the report-only one.
        $finding.status | Should -Be 'Pass'

        $enforcedEntry = $finding.evidence | Where-Object { $_.identity -eq $enforcedGuid }
        $enforcedEntry | Should -Not -BeNullOrEmpty
        $enforcedEntry.detail.excludedFromEnforcedBlockPolicies | Should -Contain 'Enforced Block'
        $enforcedEntry.detail.PSObject.Properties.Name | Should -Not -Contain 'reportOnlyProtectionWarning'

        $reportOnlyEntry = $finding.evidence | Where-Object { $_.identity -eq $reportOnlyGuid }
        $reportOnlyEntry | Should -Not -BeNullOrEmpty
        @($reportOnlyEntry.detail.excludedFromEnforcedBlockPolicies).Count | Should -Be 0
        $reportOnlyEntry.detail.excludedFromReportOnlyBlockPolicies | Should -Contain 'Report-Only Block'
        $reportOnlyEntry.detail.reportOnlyProtectionWarning | Should -Match 'do not protect'

        # No-match identifier gets no evidence entry at all (unchanged prior behavior).
        ($finding.evidence | Where-Object { $_.identity -eq $noMatchGuid }) | Should -BeNullOrEmpty

        $malformedEntry = $finding.evidence | Where-Object { $_.identity -eq $malformed }
        $malformedEntry | Should -Not -BeNullOrEmpty
        $malformedEntry.detail.issue | Should -Match 'not GUID-shaped'

        $noteEntry = $finding.evidence | Where-Object { $_.identity -eq 'group-exclusion-resolution' }
        $noteEntry | Should -Not -BeNullOrEmpty

        # Pass-branch policy evidence only includes the ENFORCED block policy (1) + the
        # enforced-exclusion, report-only-exclusion, malformed, and note exclusion entries
        # (4) = 5; the no-match identifier and the report-only policy itself (not a Pass-
        # branch policy entry) contribute nothing to this count.
        $finding.evidence.Count | Should -Be 5
    }
}

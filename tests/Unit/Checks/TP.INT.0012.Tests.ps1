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
            [Parameter(Mandatory)] [hashtable[]] $Datasets
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $evaluation = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $CheckId, $Datasets {
                param($storeRoot, $keyPath, $checkId, $datasets)

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

                $manifest = Get-PulseSnapshotManifest -Store $store
                $gates = if ($null -eq $check.Data -or $null -eq $check.Data.Gates) { @() } else { @($check.Data.Gates) }
                if ($gates.Count -gt 0) {
                    if (-not $manifest.Contains('licenseEvidence') -or $manifest.licenseEvidence -isnot [System.Collections.IDictionary]) {
                        $manifest.licenseEvidence = [ordered]@{}
                    }
                    foreach ($gate in $gates) {
                        if ($null -ne $gate -and -not [string]::IsNullOrWhiteSpace([string] $gate)) {
                            $manifest.licenseEvidence[[string] $gate] = [ordered]@{
                                Status = 'Available'
                                Detail = 'fixture gate'
                            }
                        }
                    }
                    if ($manifest.licenseEvidence.Count -gt 0) {
                        $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $manifest
                        Set-PulseAtomicFileContent -Path $store.ManifestPath -Value $canonicalJson
                    }
                }

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    function script:New-PulseFeatureUpdateProfile {
        param(
            [string] $Id,
            [string] $DisplayName,
            [string] $FeatureUpdateVersion,
            [string] $EndOfSupportDate = $null
        )
        $profileProperties = [ordered]@{
            id                   = $Id
            displayName          = $DisplayName
            featureUpdateVersion = $FeatureUpdateVersion
            assignments          = @(
                @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-assigned' } }
            )
        }
        if ($PSBoundParameters.ContainsKey('EndOfSupportDate')) {
            $profileProperties.endOfSupportDate = $EndOfSupportDate
        }
        [pscustomobject] $profileProperties
    }
 }

Describe 'TP.INT.0012 - Windows Feature Update policy avoids end-of-support builds' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0012' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: every profile targets a version whose end-of-support date is far in the future' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0012' -Datasets @(
            @{ Name = 'windowsFeatureUpdateProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseFeatureUpdateProfile -Id 'p1' -DisplayName 'Ring A' -FeatureUpdateVersion 'Windows 11, version 25H2' -EndOfSupportDate '2028-10-11T06:59:59Z')) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: a profile targets a version whose end-of-support date has already passed' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0012' -Datasets @(
            @{ Name = 'windowsFeatureUpdateProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseFeatureUpdateProfile -Id 'p1' -DisplayName 'Ring A' -FeatureUpdateVersion 'Windows 11, version 22H2' -EndOfSupportDate '2025-10-15T06:59:59Z')) }
        )

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].detail.featureUpdateVersion | Should -Be 'Windows 11, version 22H2'
    }

    It 'Fail: a mix of expired and current profiles reports only the expired one(s) as evidence' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0012' -Datasets @(
            @{ Name = 'windowsFeatureUpdateProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseFeatureUpdateProfile -Id 'p1' -DisplayName 'Ring A (expired)' -FeatureUpdateVersion 'Windows 11, version 22H2' -EndOfSupportDate '2025-10-15T06:59:59Z')
                (New-PulseFeatureUpdateProfile -Id 'p2' -DisplayName 'Ring B (current)' -FeatureUpdateVersion 'Windows 11, version 25H2' -EndOfSupportDate '2028-10-11T06:59:59Z')
            ) }
        )

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'p1'
    }

    It 'NotApplicable: an assigned profile with an absent endOfSupportDate cannot prove current support' {
        $featureProfile = New-PulseFeatureUpdateProfile -Id 'p1' -DisplayName 'Ring A' -FeatureUpdateVersion 'Windows 11, version 25H2'
        $featureProfile.PSObject.Properties.Name | Should -Not -Contain 'endOfSupportDate'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0012' -Datasets @(
            @{ Name = 'windowsFeatureUpdateProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($featureProfile) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'endOfSupportDate'
    }

    It 'NotApplicable: an assigned profile with an invalid endOfSupportDate cannot prove current support' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0012' -Datasets @(
            @{ Name = 'windowsFeatureUpdateProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseFeatureUpdateProfile -Id 'p1' -DisplayName 'Ring A' -FeatureUpdateVersion 'Windows 11, version 25H2' -EndOfSupportDate 'not-a-date')) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'endOfSupportDate'
    }

    It 'Fail remains monotonic for a known expired assigned profile beside an assigned profile with unknown lifecycle evidence' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0012' -Datasets @(
            @{ Name = 'windowsFeatureUpdateProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseFeatureUpdateProfile -Id 'p1' -DisplayName 'Expired ring' -FeatureUpdateVersion 'Windows 11, version 22H2' -EndOfSupportDate '2025-10-15T06:59:59Z')
                (New-PulseFeatureUpdateProfile -Id 'p2' -DisplayName 'Unknown lifecycle ring' -FeatureUpdateVersion 'Windows 11, version 25H2')
            ) }
        )

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'p1'
    }

    It 'NotApplicable: missing assignment evidence cannot prove an otherwise-current profile is deployed' {
        $featureProfile = New-PulseFeatureUpdateProfile -Id 'p1' -DisplayName 'Ring A' -FeatureUpdateVersion 'Windows 11, version 25H2' -EndOfSupportDate '2028-10-11T06:59:59Z'
        $featureProfile.PSObject.Properties.Remove('assignments')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0012' -Datasets @(
            @{ Name = 'windowsFeatureUpdateProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($featureProfile) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'assignment evidence'
    }

    It 'Fail: a known assigned expired profile remains decisive when another profile has unknown assignments' {
        $unknown = New-PulseFeatureUpdateProfile -Id 'p2' -DisplayName 'Unknown ring' -FeatureUpdateVersion 'Windows 11, version 25H2' -EndOfSupportDate '2028-10-11T06:59:59Z'
        $unknown.PSObject.Properties.Remove('assignments')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0012' -Datasets @(
            @{ Name = 'windowsFeatureUpdateProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseFeatureUpdateProfile -Id 'p1' -DisplayName 'Expired ring' -FeatureUpdateVersion 'Windows 11, version 22H2' -EndOfSupportDate '2025-10-15T06:59:59Z')
                $unknown
            ) }
        )

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'p1'
    }

    It 'NotApplicable: an exclusion-only profile is not treated as deployed' {
        $featureProfile = New-PulseFeatureUpdateProfile -Id 'p1' -DisplayName 'Excluded ring' -FeatureUpdateVersion 'Windows 11, version 22H2' -EndOfSupportDate '2025-10-15T06:59:59Z'
        $featureProfile.assignments = @(
            @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'excluded-group' } }
        )
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0012' -Datasets @(
            @{ Name = 'windowsFeatureUpdateProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($featureProfile) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'effective include assignment'
    }

    It 'NotApplicable: zero Feature Update profiles configured (skip-if-none-configured, mirrors Maester, never a Pass)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0012' -Datasets @(
            @{ Name = 'windowsFeatureUpdateProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'No Windows Feature Update deployment profiles'
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0012' -Datasets @(
            @{ Name = 'windowsFeatureUpdateProfiles'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }
}

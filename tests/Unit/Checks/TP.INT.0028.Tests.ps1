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
}

Describe 'TP.INT.0028 - Enrollment Status Page configured with blocking failure behavior' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0028' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: an assigned ESP profile has blocking enabled' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP'; allowDeviceUseOnInstallFailure = $false; assignments = @([pscustomobject]@{ id = 'a1'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' } }) }
            ) }
        )
        $finding.status | Should -Be 'Pass'
        # M1 (Phase 3 whole-phase review): Pass now carries corroborating evidence too.
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'esp1'
    }

    It 'Fail: assigned but blocking disabled' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP'; allowDeviceUseOnInstallFailure = $true; assignments = @([pscustomobject]@{ id = 'a1'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' } }) }
            ) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: blocking enabled but not assigned to any group' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP'; allowDeviceUseOnInstallFailure = $false; assignments = @() }
            ) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'skips non-ESP rows in the mixed deviceEnrollmentConfigurations collection' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'cfg1'; '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; priority = 0 }
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP'; allowDeviceUseOnInstallFailure = $false; assignments = @([pscustomobject]@{ id = 'a1'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' } }) }
            ) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'NotApplicable: no ESP profile present' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'NotApplicable: blocking state without assignment evidence cannot prove deployment' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP'; allowDeviceUseOnInstallFailure = $false }
            ) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'assignment evidence'
    }

    It 'Pass: a known assigned blocking ESP remains decisive when another profile has unknown assignments' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP'; allowDeviceUseOnInstallFailure = $false; assignments = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' } }) }
                [pscustomobject]@{ id = 'esp2'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Unknown ESP'; allowDeviceUseOnInstallFailure = $true }
            ) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: an exclusion-only blocking ESP is not treated as deployed' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Excluded ESP'; allowDeviceUseOnInstallFailure = $false; assignments = @(
                    [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'excluded-group' } }
                ) }
            ) }
        )

        $finding.status | Should -Be 'Fail'
    }

    # RESOLVED-LIVE (2026-08-17): the live DeviceEnrollmentConfiguration/List endpoint
    # returns TRIMMED windows10EnrollmentCompletionPageConfiguration rows - 9 properties,
    # with allowDeviceUseOnInstallFailure (and showInstallationProgress) simply not
    # projected onto the list shape. When the property is absent from EVERY ESP row this
    # is that known, benign projection limitation, not an anomaly - NotApplicable, not
    # Error. See this check's own docstring RESOLVED-LIVE note and
    # docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md's TP.INT.0028 section.
    It 'NotApplicable (not Error): allowDeviceUseOnInstallFailure is absent from EVERY ESP row - the live List-endpoint projection limitation' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP' }
            ) }
        )
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'projection'
    }

    It 'NotApplicable (not Error): property absent from ALL of TWO ESP rows - still the projection limitation, not a mixed anomaly' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP One' }
                [pscustomobject]@{ id = 'esp2'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP Two' }
            ) }
        )
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'projection'
    }

    # The mixed case is the genuine anomaly the throw still exists for: if the projection
    # limitation explained absence, it would be absent from EVERY row uniformly, never
    # some-but-not-others. Some-but-not-others means the rows are not uniformly shaped and
    # deserves the loud failure, unchanged from before this fix.
    It 'Error: allowDeviceUseOnInstallFailure is absent on SOME but not all ESP rows (mixed - genuine anomaly, not the projection limitation)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP One'; allowDeviceUseOnInstallFailure = $false; assignments = @([pscustomobject]@{ id = 'a1'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' } }) }
                [pscustomobject]@{ id = 'esp2'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP Two' }
            ) }
        )
        $finding.status | Should -Be 'Error'
    }

    It 'Fail (not Error): two id-less ESP rows sharing the SAME displayName do not collide on evidence identity (I2 ordinal fallback)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Shared ESP'; allowDeviceUseOnInstallFailure = $true; assignments = @() }
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Shared ESP'; allowDeviceUseOnInstallFailure = $true; assignments = @() }
                ) }
        )
        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 2
        ($finding.evidence.identity | Select-Object -Unique).Count | Should -Be 2
    }
}

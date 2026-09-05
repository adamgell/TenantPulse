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
                    foreach ($field in @('ReasonCode', 'Detail', 'FailureClass', 'Provider', 'Operations', 'Gaps')) {
                        if ($d.ContainsKey($field)) { $params[$field] = $d[$field] }
                    }
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

    function script:New-PulseUpdateRing {
        param([string] $Id, [Nullable[int]] $FeatureDeadline = $null, [Nullable[int]] $QualityDeadline = $null)
        [pscustomobject]@{
            id                                 = $Id
            displayName                        = "ring-$Id"
            '@odata.type'                       = '#microsoft.graph.windowsUpdateForBusinessConfiguration'
            deadlineForFeatureUpdatesInDays     = $FeatureDeadline
            deadlineForQualityUpdatesInDays     = $QualityDeadline
            assignments                        = @(
                @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-assigned' } }
            )
        }
    }
}

Describe 'TP.INT.0004 - At least 2 Windows Update rings have deadlines configured' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0004' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: 2 rings, both with a feature-update deadline configured' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'pilot' -FeatureDeadline 3)
                (New-PulseUpdateRing -Id 'broad' -FeatureDeadline 14)
            ) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 2
    }

    It 'Pass: a quality-update-only deadline still counts' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'pilot' -QualityDeadline 2)
                (New-PulseUpdateRing -Id 'broad' -QualityDeadline 7)
            ) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Error: a persisted <Shape> deadline value cannot be coerced into a qualifying ring' -ForEach @(
        @{ Shape = 'string'; InvalidValue = 'not-a-number' }
        @{ Shape = 'boolean'; InvalidValue = $true }
        @{ Shape = 'array'; InvalidValue = [object[]] @(1, 2) }
    ) {
        $malformed = New-PulseUpdateRing -Id 'malformed'
        $malformed.deadlineForFeatureUpdatesInDays = $InvalidValue

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'known' -FeatureDeadline 3)
                $malformed
            ) }
        )

        $finding.status | Should -Be 'Error'
    }

    It 'Fail: only 1 of 2 rings has a deadline configured' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'pilot' -FeatureDeadline 3)
                (New-PulseUpdateRing -Id 'broad')
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'broad'
    }

    It 'Fail: no Windows Update ring profiles exist at all' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'gate-degraded: NotApplicable when deviceConfigurations failed to collect' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Skipped'; Reason = 'permission-denied: DeviceManagementConfiguration.Read.All' }
        )

        $finding.status | Should -Be 'NotApplicable'
    }

    It 'NotApplicable: one known ring plus an update ring with unresolved assignments cannot prove fewer than two assigned rings' {
        $unknown = New-PulseUpdateRing -Id 'unknown' -FeatureDeadline 7
        $unknown.assignments = $null
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'known' -FeatureDeadline 3)
                $unknown
            ) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'assignment evidence'
    }

    It 'Fail: exclusion-only rings do not count as assigned when evidence is complete' {
        $excluded = New-PulseUpdateRing -Id 'excluded' -FeatureDeadline 7
        $excluded.assignments = @(
            @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'group-excluded' } }
        )
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'known' -FeatureDeadline 3)
                $excluded
            ) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: a partial root list prevents fewer than two known rings from becoming Fail' {
        $gap = [pscustomobject]@{
            Scope = 'dataset:deviceConfigurations/root'; FailureClass = 'Indeterminate'
            ReasonCode = 'truncated'; Detail = @{ truncated = $true }
            Operation = 'DeviceConfiguration.List'; ApiVersion = 'v1.0'
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Partial'; Data = @(
                (New-PulseUpdateRing -Id 'known' -FeatureDeadline 3)
            ); ReasonCode = 'partial'; Detail = @{}; Provider = 'TenantPulse';
                Operations = @('DeviceConfiguration.List', 'DeviceConfigurationAssignment.List'); Gaps = @($gap) }
        )

        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Fail: an unrelated scoped assignment gap does not hide the known shortage of qualifying update rings' {
        $gap = [pscustomobject]@{
            Scope = 'policy:custom-unresolved/assignments'; FailureClass = 'Indeterminate'
            ReasonCode = 'indeterminate'; Detail = @{}
            Operation = 'DeviceConfigurationAssignment.List'; ApiVersion = 'v1.0'
        }
        $other = [pscustomobject]@{
            id = 'custom-unresolved'; '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'; assignments = $null
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Partial'; Data = @(
                (New-PulseUpdateRing -Id 'known' -FeatureDeadline 3)
                $other
            ); ReasonCode = 'partial'; Detail = @{}; Provider = 'TenantPulse';
                Operations = @('DeviceConfiguration.List', 'DeviceConfigurationAssignment.List'); Gaps = @($gap) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: a <Shape> configuration discriminator can still be a second qualifying update ring' -ForEach @(
        @{ Shape = 'missing'; TypeValue = $null }
        @{ Shape = 'blank'; TypeValue = '   ' }
        @{ Shape = 'unrecognized'; TypeValue = '#microsoft.graph.futureUpdateConfiguration' }
    ) {
        $candidate = New-PulseUpdateRing -Id 'unclassified' -FeatureDeadline 14
        if ($Shape -eq 'missing') {
            $candidate.PSObject.Properties.Remove('@odata.type')
        } else {
            $candidate.'@odata.type' = $TypeValue
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'known' -FeatureDeadline 3)
                $candidate
            ) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'type evidence'
    }

    It 'Fail: unclassified configuration evidence cannot qualify when it has <Disqualifier>' -ForEach @(
        @{ Shape = 'unrecognized'; TypeValue = '#microsoft.graph.futureUpdateConfiguration'; Disqualifier = 'no positive deadline'; AssignmentKind = 'assigned'; FeatureDeadline = $null }
        @{ Shape = 'missing'; TypeValue = $null; Disqualifier = 'authoritatively empty assignments'; AssignmentKind = 'empty'; FeatureDeadline = 14 }
        @{ Shape = 'blank'; TypeValue = '   '; Disqualifier = 'exclusion-only assignments'; AssignmentKind = 'excluded'; FeatureDeadline = 14 }
    ) {
        $candidate = New-PulseUpdateRing -Id 'unclassified' -FeatureDeadline $FeatureDeadline
        if ($Shape -eq 'missing') {
            $candidate.PSObject.Properties.Remove('@odata.type')
        } else {
            $candidate.'@odata.type' = $TypeValue
        }
        if ($AssignmentKind -eq 'empty') {
            $candidate.assignments = @()
        } elseif ($AssignmentKind -eq 'excluded') {
            $candidate.assignments = @(
                @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'grp-ex' } }
            )
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'known' -FeatureDeadline 3)
                $candidate
            ) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: unresolved assignment evidence on a ring without a deadline cannot change the known shortage' {
        $nonQualifying = New-PulseUpdateRing -Id 'no-deadline'
        $nonQualifying.assignments = $null

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'known' -FeatureDeadline 3)
                $nonQualifying
            ) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: one deadline-capable unclassified candidate cannot satisfy the two-ring minimum by itself' {
        $candidate = New-PulseUpdateRing -Id 'only-possible' -FeatureDeadline 14
        $candidate.'@odata.type' = '#microsoft.graph.futureUpdateConfiguration'

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($candidate) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: one deadline-capable ring with unresolved assignments cannot satisfy the two-ring minimum by itself' {
        $candidate = New-PulseUpdateRing -Id 'only-possible' -FeatureDeadline 14
        $candidate.assignments = $null

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($candidate) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: two distinct deadline-capable candidates can still satisfy the two-ring minimum' {
        $unclassified = New-PulseUpdateRing -Id 'possible-unclassified' -FeatureDeadline 7
        $unclassified.'@odata.type' = '#microsoft.graph.futureUpdateConfiguration'
        $unresolved = New-PulseUpdateRing -Id 'possible-unresolved' -FeatureDeadline 14
        $unresolved.assignments = $null

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                $unclassified
                $unresolved
            ) }
        )

        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Pass: two known assigned rings with deadlines are sufficient despite unrelated partial evidence' {
        $gap = [pscustomobject]@{
            Scope = 'policy:other/assignments'; FailureClass = 'Indeterminate'
            ReasonCode = 'indeterminate'; Detail = @{}
            Operation = 'DeviceConfigurationAssignment.List'; ApiVersion = 'v1.0'
        }
        $other = [pscustomobject]@{ id = 'other'; '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'; assignments = $null }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Partial'; Data = @(
                (New-PulseUpdateRing -Id 'pilot' -FeatureDeadline 3)
                (New-PulseUpdateRing -Id 'broad' -FeatureDeadline 14)
                $other
            ); ReasonCode = 'partial'; Detail = @{}; Provider = 'TenantPulse';
                Operations = @('DeviceConfiguration.List', 'DeviceConfigurationAssignment.List'); Gaps = @($gap) }
        )

        $finding.status | Should -Be 'Pass'
    }
}

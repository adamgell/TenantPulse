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

    function script:New-PulseManagedDevice {
        param([string] $Id, [string] $OperatingSystem)
        [pscustomobject]@{ id = $Id; deviceName = "device-$Id"; operatingSystem = $OperatingSystem }
    }

    function script:New-PulseAssignedCompliancePolicy {
        param([string] $Id, [string] $ODataType)
        [pscustomobject]@{
            id            = $Id
            '@odata.type' = $ODataType
            assignments   = @(
                @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-assigned' } }
            )
        }
    }
}

Describe 'TP.INT.0002 - A compliance policy exists for every enrolled platform' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0002' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: no managed devices enrolled at all' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: Windows and iOS enrolled, both have a compliance policy' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseAssignedCompliancePolicy -Id 'p1' -ODataType '#microsoft.graph.windows10CompliancePolicy')
                (New-PulseAssignedCompliancePolicy -Id 'p2' -ODataType '#microsoft.graph.iosCompliancePolicy')
            ) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
                (New-PulseManagedDevice -Id 'd2' -OperatingSystem 'iOS')
            ) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: Android is enrolled but has no compliance policy of any Android variant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseAssignedCompliancePolicy -Id 'p1' -ODataType '#microsoft.graph.windows10CompliancePolicy')
            ) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
                (New-PulseManagedDevice -Id 'd2' -OperatingSystem 'Android')
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'Android'
    }

    It 'Pass (post-review, M1): a Linux device is out-of-scope and never causes a Fail, even with zero compliance policies' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Linux')
            ) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'out-of-scope'
        $finding.reason | Should -Match 'Linux'
    }

    It 'Fail: Windows is missing a policy while Linux is separately noted as out-of-scope, never counted against Windows' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
                (New-PulseManagedDevice -Id 'd2' -OperatingSystem 'Linux')
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'Windows'
        $finding.reason | Should -Match 'out-of-scope'
    }

    It 'Pass: Android compliance matches any Android policy variant (androidWorkProfileCompliancePolicy)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseAssignedCompliancePolicy -Id 'p1' -ODataType '#microsoft.graph.androidWorkProfileCompliancePolicy')
            ) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Android')
            ) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'gate-degraded: NotApplicable when managedDevices failed to collect' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Failed'; Reason = 'throttled: too many requests' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'throttled: too many requests'
    }

    It 'Fail: exclude-only assignment does not cover an enrolled platform' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{
                    id            = 'p1'
                    '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'
                    assignments   = @(
                        @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'grp-ex' } }
                    )
                }
            ) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
            ) }
        )
        $finding.status | Should -Be 'Fail'
        $finding.evidence[0].identity | Should -Be 'Windows'
    }

    It 'NotApplicable: an applicable policy with unresolved assignment evidence cannot become an existence-only failure' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'p1'; '@odata.type' = '#microsoft.graph.windows10CompliancePolicy' }
            ) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
            ) }
        )
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'assignment evidence'
    }

    It 'NotApplicable: a partial root list cannot prove that an enrolled platform has no policy' {
        $gap = [pscustomobject]@{
            Scope = 'dataset:deviceCompliancePolicies/root'; FailureClass = 'Indeterminate'
            ReasonCode = 'truncated'; Detail = @{ truncated = $true }
            Operation = 'DeviceCompliancePolicy.List'; ApiVersion = 'v1.0'
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Partial'; Data = @(
                (New-PulseAssignedCompliancePolicy -Id 'known-android' -ODataType '#microsoft.graph.androidWorkProfileCompliancePolicy')
            );
                ReasonCode = 'partial'; Detail = @{}; Provider = 'TenantPulse';
                Operations = @('DeviceCompliancePolicy.List', 'DeviceCompliancePolicyAssignment.List'); Gaps = @($gap) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
            ) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'partial'
    }

    It 'Fail: an unrelated scoped assignment gap does not hide a known missing Windows policy' {
        $gap = [pscustomobject]@{
            Scope = 'policy:mac-unresolved/assignments'; FailureClass = 'Indeterminate'
            ReasonCode = 'indeterminate'; Detail = @{}
            Operation = 'DeviceCompliancePolicyAssignment.List'; ApiVersion = 'v1.0'
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Partial'; Data = @(
                [pscustomobject]@{
                    id = 'mac-unresolved'; '@odata.type' = '#microsoft.graph.macOSCompliancePolicy'; assignments = $null
                }
            ); ReasonCode = 'partial'; Detail = @{}; Provider = 'TenantPulse';
                Operations = @('DeviceCompliancePolicy.List', 'DeviceCompliancePolicyAssignment.List'); Gaps = @($gap) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'Windows'
    }

    It 'NotApplicable: a <Shape> compliance-policy discriminator cannot prove an enrolled platform is uncovered' -ForEach @(
        @{ Shape = 'missing'; TypeValue = $null }
        @{ Shape = 'blank'; TypeValue = '   ' }
        @{ Shape = 'unrecognized'; TypeValue = '#microsoft.graph.futureCompliancePolicy' }
    ) {
        $policy = New-PulseAssignedCompliancePolicy -Id 'unclassified' -ODataType $TypeValue
        if ($Shape -eq 'missing') {
            $policy.PSObject.Properties.Remove('@odata.type')
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
            ) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'type evidence'
    }

    It 'Fail: a <Shape> compliance-policy discriminator with <AssignmentKind> assignments cannot cover Windows' -ForEach @(
        @{ Shape = 'missing'; TypeValue = $null; AssignmentKind = 'authoritatively empty' }
        @{ Shape = 'blank'; TypeValue = '   '; AssignmentKind = 'authoritatively empty' }
        @{ Shape = 'unrecognized'; TypeValue = '#microsoft.graph.futureCompliancePolicy'; AssignmentKind = 'authoritatively empty' }
        @{ Shape = 'missing'; TypeValue = $null; AssignmentKind = 'exclusion-only' }
        @{ Shape = 'blank'; TypeValue = '   '; AssignmentKind = 'exclusion-only' }
        @{ Shape = 'unrecognized'; TypeValue = '#microsoft.graph.futureCompliancePolicy'; AssignmentKind = 'exclusion-only' }
    ) {
        $policy = New-PulseAssignedCompliancePolicy -Id 'unclassified' -ODataType $TypeValue
        if ($Shape -eq 'missing') {
            $policy.PSObject.Properties.Remove('@odata.type')
        }
        if ($AssignmentKind -eq 'authoritatively empty') {
            $policy.assignments = @()
        } else {
            $policy.assignments = @(
                @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'grp-ex' } }
            )
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence[0].identity | Should -Be 'Windows'
    }

    It 'Pass: known assigned coverage is monotonic even when unrelated root evidence is partial' {
        $gap = [pscustomobject]@{
            Scope = 'dataset:deviceCompliancePolicies/root'; FailureClass = 'Indeterminate'
            ReasonCode = 'truncated'; Detail = @{ truncated = $true }
            Operation = 'DeviceCompliancePolicy.List'; ApiVersion = 'v1.0'
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Partial'; Data = @(
                (New-PulseAssignedCompliancePolicy -Id 'p1' -ODataType '#microsoft.graph.windows10CompliancePolicy')
            ); ReasonCode = 'partial'; Detail = @{}; Provider = 'TenantPulse';
                Operations = @('DeviceCompliancePolicy.List', 'DeviceCompliancePolicyAssignment.List'); Gaps = @($gap) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
            ) }
        )

        $finding.status | Should -Be 'Pass'
    }
 }

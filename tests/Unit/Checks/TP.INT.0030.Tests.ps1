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

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    function script:New-PulseFleetData {
        param([int] $Compliant, [int] $Noncompliant, [int] $OtherState = 0, [string] $OtherStateValue = 'unknown')
        $rows = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $Compliant; $i++) { $rows.Add([pscustomobject]@{ id = "c$i"; complianceState = 'compliant' }) }
        for ($i = 0; $i -lt $Noncompliant; $i++) { $rows.Add([pscustomobject]@{ id = "n$i"; complianceState = 'noncompliant' }) }
        for ($i = 0; $i -lt $OtherState; $i++) { $rows.Add([pscustomobject]@{ id = "o$i"; complianceState = $OtherStateValue }) }
        return $rows.ToArray()
    }
}

Describe 'TP.INT.0030 - Fleet compliance rate below acceptable threshold' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0030' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: noncompliance rate below 5%' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = (New-PulseFleetData -Compliant 98 -Noncompliant 2) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Warn: noncompliance rate between 5% and 10%' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = (New-PulseFleetData -Compliant 93 -Noncompliant 7) }
        )
        $finding.status | Should -Be 'Warn'
    }

    It 'Fail: noncompliance rate above 10%' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = (New-PulseFleetData -Compliant 80 -Noncompliant 20) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: zero managed devices' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Error: complianceState is absent on an existing device row (field-absence lens)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'd1' }) }
        )
        $finding.status | Should -Be 'Error'
    }

    Context 'hostile bucket adjudication (post-review HIGH fix): no non-compliant/non-noncompliant state silently counts as compliant' {
        It '<State>: a material (5%) share never bare-Passes, even with a perfect verified-noncompliant rate of 0%' -TestCases @(
            @{ State = 'conflict' }
            @{ State = 'error' }
            @{ State = 'inGracePeriod' }
            @{ State = 'configManager' }
            @{ State = 'unknown' }
            @{ State = 'notEvaluated' }
            @{ State = 'someFutureStateNotYetDocumented' }
        ) {
            param($State)
            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
                @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = (New-PulseFleetData -Compliant 19 -Noncompliant 0 -OtherState 1 -OtherStateValue $State) }
            )
            $finding.status | Should -Not -Be 'Pass'
            $finding.status | Should -Be 'Warn'
            $finding.evidence[0].detail.unverifiedDevices | Should -Be 1
            $finding.evidence[0].detail.compliantDevices | Should -Be 19
        }

        It 'a single unverified device below the material 5% threshold does not escalate a fleet that would otherwise Pass' {
            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
                @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = (New-PulseFleetData -Compliant 99 -Noncompliant 0 -OtherState 1 -OtherStateValue 'unknown') }
            )
            $finding.status | Should -Be 'Pass'
            $finding.evidence[0].detail.unverifiedDevices | Should -Be 1
        }

        It 'a mixed unverified breakdown (conflict + error + configManager) is disclosed in the Reason and evidence, never dropped' {
            $rows = [System.Collections.Generic.List[object]]::new()
            for ($i = 0; $i -lt 90; $i++) { $rows.Add([pscustomobject]@{ id = "c$i"; complianceState = 'compliant' }) }
            $rows.Add([pscustomobject]@{ id = 'x1'; complianceState = 'conflict' })
            $rows.Add([pscustomobject]@{ id = 'x2'; complianceState = 'error' })
            $rows.Add([pscustomobject]@{ id = 'x3'; complianceState = 'configManager' })
            $rows.Add([pscustomobject]@{ id = 'x4'; complianceState = 'configManager' })
            $rows.Add([pscustomobject]@{ id = 'x5'; complianceState = 'inGracePeriod' })
            $rows.Add([pscustomobject]@{ id = 'x6'; complianceState = 'inGracePeriod' })

            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
                @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $rows.ToArray() }
            )

            $finding.status | Should -Be 'Warn'
            $finding.evidence[0].detail.unverifiedDevices | Should -Be 6
            $finding.evidence[0].detail.unverifiedStateBreakdown.conflict | Should -Be 1
            $finding.evidence[0].detail.unverifiedStateBreakdown.error | Should -Be 1
            $finding.evidence[0].detail.unverifiedStateBreakdown.configManager | Should -Be 2
            $finding.evidence[0].detail.unverifiedStateBreakdown.inGracePeriod | Should -Be 2
            $finding.reason | Should -Match 'unverified-or-unhealthy'
        }

        It 'Fail still wins over a material unverified share when the verified-noncompliant rate alone already exceeds 10%' {
            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
                @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = (New-PulseFleetData -Compliant 69 -Noncompliant 20 -OtherState 11 -OtherStateValue 'unknown') }
            )
            $finding.status | Should -Be 'Fail'
            $finding.evidence[0].detail.unverifiedDevices | Should -Be 11
        }
    }
}

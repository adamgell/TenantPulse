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
}

Describe 'TP.INT.0001 - MDM authority is set to Intune' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0001' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: mobileDeviceManagementAuthority is intune' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0001' -Datasets @(
            @{ Name = 'organization'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'org-1' }) }
            @{ Name = 'organizationMdmAuthority'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ mobileDeviceManagementAuthority = 'intune' }) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: mobileDeviceManagementAuthority is set to something other than intune' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0001' -Datasets @(
            @{ Name = 'organization'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'org-1' }) }
            @{ Name = 'organizationMdmAuthority'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ mobileDeviceManagementAuthority = 'thirdParty' }) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Error: an ABSENT mobileDeviceManagementAuthority property never reads as Pass or Fail (the live-tenant field-absence lens)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0001' -Datasets @(
            @{ Name = 'organization'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'org-1' }) }
            @{ Name = 'organizationMdmAuthority'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'org-1' }) }
        )

        $finding.status | Should -Be 'Error'
    }

    It 'Error: organizationMdmAuthority returning zero rows never reads as Pass or Fail' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0001' -Datasets @(
            @{ Name = 'organization'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'org-1' }) }
            @{ Name = 'organizationMdmAuthority'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Error'
    }

    It 'gate-degraded: NotApplicable when organizationMdmAuthority failed to collect (dependency-unavailable)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0001' -Datasets @(
            @{ Name = 'organization'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'org-1' }) }
            @{ Name = 'organizationMdmAuthority'; ApiVersion = 'v1.0'; Status = 'Failed'; Reason = 'dependency-unavailable: organization' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'dependency-unavailable: organization'
    }
}

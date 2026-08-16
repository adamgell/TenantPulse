BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:ConvertTo-PSObjectShape {
        param($Value)
        return ($Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20)
    }

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

    function script:New-PulseAuthMethodsPolicyRow {
        param($Fido2)
        return @{ id = 'auth-policy-1'; authenticationMethodConfigurations = @($Fido2) }
    }

    $script:compliantFido2Hashtable = @{
        id                                = 'Fido2'
        state                             = 'enabled'
        isSelfServiceRegistrationAllowed  = $true
        isAttestationEnforced             = $true
        keyRestrictions                   = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('00000000-0000-0000-0000-000000000001') }
    }
}

Describe 'TP.ENT.0006 - FIDO2 security key authentication method configuration' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0006' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: FIDO2 enabled, attestation enforced, key restrictions enforced (hashtable shape)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0006' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Fido2 $script:compliantFido2Hashtable) }
        )

        $finding.status | Should -Be 'Pass'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.AF01').detail.value | Should -Be 'enabled'
        $finding.evidence.Count | Should -Be 6
    }

    It 'Pass: FIDO2 enabled, attestation enforced, key restrictions enforced (PSObject shape)' {
        $pso = ConvertTo-PSObjectShape -Value $script:compliantFido2Hashtable
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0006' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Fido2 $pso) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: FIDO2 is not present in authenticationMethodConfigurations at all' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0006' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(@{ id = 'auth-policy-1'; authenticationMethodConfigurations = @(@{ id = 'Sms'; state = 'disabled' }) }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'EIDSCA.AF01'
    }

    It 'Fail: FIDO2 state is disabled (AF01)' {
        $disabled = $script:compliantFido2Hashtable.Clone()
        $disabled.state = 'disabled'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0006' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Fido2 $disabled) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'not enabled \(EIDSCA.AF01\)'
    }

    It 'Fail: FIDO2 enabled but attestation not enforced (AF03)' {
        $noAttestation = $script:compliantFido2Hashtable.Clone()
        $noAttestation.isAttestationEnforced = $false
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0006' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Fido2 $noAttestation) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'attestation is not enforced \(EIDSCA.AF03\)'
    }

    It 'Fail: FIDO2 enabled but key restrictions not enforced (AF04)' {
        $noKeyRestriction = $script:compliantFido2Hashtable.Clone()
        $noKeyRestriction.keyRestrictions = @{ isEnforced = $false; enforcementType = $null; aaGuids = @() }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0006' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Fido2 $noKeyRestriction) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'key restrictions are not enforced \(EIDSCA.AF04\)'
    }

    It 'gate-degraded: NotApplicable when authenticationMethodsPolicy was skipped' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0006' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'permission-denied: Policy.Read.All' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'permission-denied: Policy.Read.All'
    }
}

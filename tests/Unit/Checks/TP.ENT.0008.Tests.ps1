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
        param($Authenticator)
        return @{ id = 'auth-policy-1'; authenticationMethodConfigurations = @($Authenticator) }
    }

    $script:compliantAuthenticatorHashtable = @{
        id                     = 'MicrosoftAuthenticator'
        state                  = 'enabled'
        isSoftwareOathEnabled  = $false
        featureSettings        = @{
            numberMatchingRequiredState             = @{ state = 'enabled'; includeTarget = @{ id = 'all_users' } }
            displayAppInformationRequiredState       = @{ state = 'enabled'; includeTarget = @{ id = 'all_users' } }
            displayLocationInformationRequiredState  = @{ state = 'enabled'; includeTarget = @{ id = 'all_users' } }
        }
    }
}

Describe 'TP.ENT.0008 - Microsoft Authenticator method configuration' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0008' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: Authenticator enabled, OTP fallback off, number matching + app-name required tenant-wide (hashtable shape)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0008' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Authenticator $script:compliantAuthenticatorHashtable) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 5
    }

    It 'Pass (PSObject shape)' {
        $pso = ConvertTo-PSObjectShape -Value $script:compliantAuthenticatorHashtable
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0008' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Authenticator $pso) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: Microsoft Authenticator not configured at all (AM01)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0008' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(@{ id = 'auth-policy-1'; authenticationMethodConfigurations = @(@{ id = 'Sms'; state = 'disabled' }) }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'EIDSCA.AM01'
    }

    It 'Fail: OTP fallback still allowed (AM02)' {
        $otpAllowed = $script:compliantAuthenticatorHashtable.Clone()
        $otpAllowed.isSoftwareOathEnabled = $true
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0008' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Authenticator $otpAllowed) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'OTP fallback is still allowed \(EIDSCA.AM02\)'
    }

    It 'Fail: number matching disabled (AM03)' {
        $noNumberMatching = @{
            id = 'MicrosoftAuthenticator'; state = 'enabled'; isSoftwareOathEnabled = $false
            featureSettings = @{
                numberMatchingRequiredState = @{ state = 'disabled'; includeTarget = @{ id = 'all_users' } }
                displayAppInformationRequiredState = @{ state = 'enabled'; includeTarget = @{ id = 'all_users' } }
                displayLocationInformationRequiredState = @{ state = 'enabled'; includeTarget = @{ id = 'all_users' } }
            }
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0008' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Authenticator $noNumberMatching) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'Number matching is not enabled tenant-wide \(EIDSCA.AM03/AM04\)|EIDSCA.AM03/AM04'
    }

    It 'Fail: number matching enabled but scoped narrower than all_users (AM04)' {
        $narrowScope = $script:compliantAuthenticatorHashtable.Clone()
        $narrowScope.featureSettings = $script:compliantAuthenticatorHashtable.featureSettings.Clone()
        $narrowScope.featureSettings.numberMatchingRequiredState = @{ state = 'enabled'; includeTarget = @{ id = 'a-single-pilot-group-id' } }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0008' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Authenticator $narrowScope) }
        )

        $finding.status | Should -Be 'Fail'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.AM03-AM04').detail.scope | Should -Be 'a-single-pilot-group-id'
    }

    It 'gate-degraded: NotApplicable when authenticationMethodsPolicy was skipped' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0008' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'permission-denied: Policy.Read.All' }
        )

        $finding.status | Should -Be 'NotApplicable'
    }
}

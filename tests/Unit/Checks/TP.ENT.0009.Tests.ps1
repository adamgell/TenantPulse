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
        param($Sms)
        return @{ id = 'auth-policy-1'; authenticationMethodConfigurations = @($Sms) }
    }

    $script:disabledSmsHashtable = @{
        id             = 'Sms'
        state          = 'disabled'
        includeTargets = @(
            @{ id = 'all_users'; targetType = 'group'; isUsableForSignIn = $false }
        )
    }
}

Describe 'TP.ENT.0009 - SMS sign-in authentication method disabled (EIDSCA.AS04)' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0009' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: no target has isUsableForSignIn true (hashtable shape)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0009' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Sms $script:disabledSmsHashtable) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass (PSObject shape)' {
        $pso = ConvertTo-PSObjectShape -Value (New-PulseAuthMethodsPolicyRow -Sms $script:disabledSmsHashtable)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0009' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($pso) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: one target group still usable for sign-in - named in evidence and reason' {
        $sms = @{
            id             = 'Sms'
            state          = 'enabled'
            includeTargets = @(
                @{ id = 'all_users'; targetType = 'group'; isUsableForSignIn = $false }
                @{ id = 'legacy-pilot-group'; targetType = 'group'; isUsableForSignIn = $true }
            )
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0009' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Sms $sms) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'legacy-pilot-group'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.AS04').detail.usableForSignInTargetIds | Should -Contain 'legacy-pilot-group'
    }

    It 'Fail: no Sms entry exists in authenticationMethodConfigurations' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0009' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(@{ id = 'auth-policy-1'; authenticationMethodConfigurations = @() }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match "No 'Sms' entry"
    }

    It 'Fail: no authenticationMethodsPolicy row collected' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0009' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No authenticationMethodsPolicy row'
    }
}

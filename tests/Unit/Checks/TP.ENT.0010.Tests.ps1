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
        param($Tap)
        return @{ id = 'auth-policy-1'; authenticationMethodConfigurations = @($Tap) }
    }

    $script:compliantTapHashtable = @{
        id            = 'TemporaryAccessPass'
        state         = 'enabled'
        isUsableOnce  = $true
    }
}

Describe 'TP.ENT.0010 - Temporary Access Pass method configuration (EIDSCA.AT01-AT02)' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0010' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: enabled and one-time use (hashtable shape)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0010' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Tap $script:compliantTapHashtable) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass (PSObject shape)' {
        $pso = ConvertTo-PSObjectShape -Value (New-PulseAuthMethodsPolicyRow -Tap $script:compliantTapHashtable)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0010' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($pso) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: TemporaryAccessPass disabled' {
        $tap = @{ id = 'TemporaryAccessPass'; state = 'disabled'; isUsableOnce = $true }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0010' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Tap $tap) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'EIDSCA.AT01'
    }

    It 'Fail: enabled but reusable (isUsableOnce false) - AT02 gates only once AT01 is enabled' {
        $tap = @{ id = 'TemporaryAccessPass'; state = 'enabled'; isUsableOnce = $false }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0010' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAuthMethodsPolicyRow -Tap $tap) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'EIDSCA.AT02'
    }

    It 'Fail: no TemporaryAccessPass entry exists in authenticationMethodConfigurations' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0010' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(@{ id = 'auth-policy-1'; authenticationMethodConfigurations = @() }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match "No 'TemporaryAccessPass' entry"
    }

    It 'Fail: no authenticationMethodsPolicy row collected' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0010' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No authenticationMethodsPolicy row'
    }
}

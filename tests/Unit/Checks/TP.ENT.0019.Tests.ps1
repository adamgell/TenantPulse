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

    function script:New-PulseServicePrincipal {
        param(
            [string] $Id = 'sp-1',
            [string] $DisplayName = 'Test App',
            [int] $PasswordLifetimeDays,
            [int] $CertLifetimeDays,
            [switch] $UnparseablePassword
        )
        $passwordCreds = @()
        if ($PSBoundParameters.ContainsKey('PasswordLifetimeDays')) {
            $start = [datetimeoffset]::new(2025, 1, 1, 0, 0, 0, [timespan]::Zero)
            $end = $start.AddDays($PasswordLifetimeDays)
            $passwordCreds = @(@{ keyId = "$Id-pw"; startDateTime = $start.ToString('o'); endDateTime = $end.ToString('o') })
        }
        if ($UnparseablePassword) {
            $passwordCreds = @(@{ keyId = "$Id-pw-bad"; startDateTime = $null; endDateTime = $null })
        }
        $keyCreds = @()
        if ($PSBoundParameters.ContainsKey('CertLifetimeDays')) {
            $start = [datetimeoffset]::new(2025, 1, 1, 0, 0, 0, [timespan]::Zero)
            $end = $start.AddDays($CertLifetimeDays)
            $keyCreds = @(@{ keyId = "$Id-cert"; startDateTime = $start.ToString('o'); endDateTime = $end.ToString('o') })
        }
        @{ id = $Id; displayName = $DisplayName; passwordCredentials = $passwordCreds; keyCredentials = $keyCreds }
    }
}

Describe 'TP.ENT.0019 - service principal credential hygiene' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0019' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: all credentials within threshold' {
        $sp = New-PulseServicePrincipal -PasswordLifetimeDays 90 -CertLifetimeDays 300
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0019' -Datasets @(
            @{ Name = 'servicePrincipals'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($sp) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: a password credential exceeds 180 days (PSObject shape)' {
        $sp = ConvertTo-PSObjectShape -Value (New-PulseServicePrincipal -PasswordLifetimeDays 200)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0019' -Datasets @(
            @{ Name = 'servicePrincipals'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($sp) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence[0].detail.credentialType | Should -Be 'password'
        $finding.reason | Should -Match '1 of 1'
    }

    It 'Fail: a certificate credential exceeds 365 days' {
        $sp = New-PulseServicePrincipal -CertLifetimeDays 400
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0019' -Datasets @(
            @{ Name = 'servicePrincipals'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($sp) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence[0].detail.credentialType | Should -Be 'certificate'
    }

    It 'Fail: an unparseable credential date is never silently skipped or counted as compliant' {
        $sp = New-PulseServicePrincipal -UnparseablePassword -CertLifetimeDays 400
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0019' -Datasets @(
            @{ Name = 'servicePrincipals'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($sp) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'unparseable'
    }

    It 'evidence is capped to 50 rows and the reason states the total offending count' {
        $servicePrincipals = @(1..60 | ForEach-Object { New-PulseServicePrincipal -Id "sp-$_" -PasswordLifetimeDays (200 + $_) })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0019' -Datasets @(
            @{ Name = 'servicePrincipals'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $servicePrincipals }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 50
        $finding.reason | Should -Match '60 of 60'
        $finding.reason | Should -Match 'capped to the 50 worst offenders'
    }

    It 'worst offenders (by degree over threshold) are the ones kept when capped' {
        $servicePrincipals = @(1..51 | ForEach-Object { New-PulseServicePrincipal -Id "sp-$_" -PasswordLifetimeDays (181 + $_) })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0019' -Datasets @(
            @{ Name = 'servicePrincipals'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $servicePrincipals }
        )

        # sp-51 has the longest lifetime (181+51=232 days) - it must be kept, sp-1
        # (181+1=182 days, the least-overdue) must be the one dropped by the cap.
        ($finding.evidence.identity -contains 'sp-51:sp-51-pw') | Should -Be $true
        ($finding.evidence.identity -contains 'sp-1:sp-1-pw') | Should -Be $false
    }
}

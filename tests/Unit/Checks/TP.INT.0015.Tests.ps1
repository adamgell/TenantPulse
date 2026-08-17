BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    # [object]-typed (not [bool]) so a caller can pass $null to mean "omit this property
    # entirely" - a [bool]-typed param cannot ever be $null, which made the absent-field
    # case this check's own field-absence lens needs to test unbuildable. $null means
    # "leave the property off the row" (absent); $true/$false mean "include it with this
    # value" (present, decidable either way).
    function script:New-PulseLapsPolicyFixture {
        param(
            [string] $PolicyId,
            [string] $PolicyName,
            [object] $BacksUpToEntra = $true,
            [object] $HasSufficientComplexity = $true,
            [object] $HasSufficientLength = $true,
            [object] $HasPostAuthAction = $true
        )
        $row = [ordered]@{
            policyId   = $PolicyId
            policyName = $PolicyName
        }
        if ($null -ne $BacksUpToEntra) { $row.backsUpToEntra = $BacksUpToEntra }
        if ($null -ne $HasSufficientComplexity) { $row.hasSufficientComplexity = $HasSufficientComplexity }
        if ($null -ne $HasSufficientLength) { $row.hasSufficientLength = $HasSufficientLength }
        if ($null -ne $HasPostAuthAction) { $row.hasPostAuthAction = $HasPostAuthAction }
        [pscustomobject] $row
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
}

Describe 'TP.INT.0015 - LAPS configuration policy meets minimum security bar' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0015' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: a single policy meets all four criteria' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'LAPS Baseline')) }
        )

        $finding.status | Should -Be 'Pass'
        @($finding.evidence).Count | Should -Be 1
    }

    It 'Fail: zero LAPS policies exist' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No Windows LAPS Endpoint Security policy'
    }

    It 'Fail: a policy missing exactly one criterion (password length) does not pass, and is not compensated by another policy missing a different criterion' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Short passwords' -HasSufficientLength $false)
                (New-PulseLapsPolicyFixture -PolicyId 'p2' -PolicyName 'Weak complexity' -HasSufficientComplexity $false)
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'not OR''d across separate policies'
        @($finding.evidence).Count | Should -Be 2
    }

    It 'Fail: backs up to AD instead of Entra (backsUpToEntra false) alone is disqualifying' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'AD-backed' -BacksUpToEntra $false)) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Pass: one fully-compliant policy passes even alongside a non-compliant one, both carried as evidence' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Baseline (compliant)')
                (New-PulseLapsPolicyFixture -PolicyId 'p2' -PolicyName 'Legacy (weak)' -HasPostAuthAction $false)
            ) }
        )

        $finding.status | Should -Be 'Pass'
        @($finding.evidence).Count | Should -Be 2
    }

    It 'Error: a policy has no backsUpToEntra value - absent must never read as does-not-meet-the-bar' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Unresolved' -BacksUpToEntra $null)) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'backsUpToEntra'
    }

    It 'Error: a policy has no hasSufficientComplexity value - absent must never read as does-not-meet-the-bar' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Unresolved' -HasSufficientComplexity $null)) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'hasSufficientComplexity'
    }

    It 'Error: a policy has no hasSufficientLength value - absent must never read as does-not-meet-the-bar' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Unresolved' -HasSufficientLength $null)) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'hasSufficientLength'
    }

    It 'Error: a policy has no hasPostAuthAction value - absent must never read as does-not-meet-the-bar' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Unresolved' -HasPostAuthAction $null)) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'hasPostAuthAction'
    }

    It 'Fail still holds: all four criteria present-$false is decidable and correctly Fails (not an Error)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Non-compliant' -BacksUpToEntra $false -HasSufficientComplexity $false -HasSufficientLength $false -HasPostAuthAction $false)) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }
}

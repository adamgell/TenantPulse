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

    function script:New-PulseCrossTenantPolicy {
        param([string] $InboundAccessType = 'allowed', [string] $OutboundAccessType = 'allowed')
        @{
            id                       = 'default'
            b2bCollaborationInbound  = @{ usersAndGroups = @{ accessType = $InboundAccessType } }
            b2bCollaborationOutbound = @{ usersAndGroups = @{ accessType = $OutboundAccessType } }
        }
    }
}

Describe 'TP.ENT.0023 - Cross-tenant access default settings restrict inbound/outbound B2B collaboration' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0023' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: both directions restricted (blocked)' {
        $policy = New-PulseCrossTenantPolicy -InboundAccessType 'blocked' -OutboundAccessType 'blocked'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Warn: default wide-open inbound and outbound (Microsoft''s own default, PSObject shape)' {
        $policy = ConvertTo-PSObjectShape -Value (New-PulseCrossTenantPolicy)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Warn'
        $finding.reason | Should -Match 'inbound and outbound'
        $finding.evidence.Count | Should -Be 2
    }

    It 'Warn: only inbound wide-open, outbound restricted - both directions evaluated independently' {
        $policy = New-PulseCrossTenantPolicy -InboundAccessType 'allowed' -OutboundAccessType 'blocked'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Warn'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.direction | Should -Be 'inbound'
    }

    It 'Fail: no crossTenantAccessPolicyDefault row collected' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Warn (conservative, never thrown): an absent b2bCollaborationInbound/Outbound block is treated as unrestricted, not silently assumed compliant' {
        $policy = @{ id = 'default' }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Warn'
        $finding.evidence.Count | Should -Be 2
    }
}

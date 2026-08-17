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

Describe 'TP.INT.0013 - Intune RBAC groups protected via RMAU or role-assignable groups' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0013' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: zero role-assignment groups exist at all (mirrors Maester, never a skip)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'nothing to protect'
    }

    It 'Pass: the only group is isAssignableToRole' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $true }) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: the only group is isManagementRestricted' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $true; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: a group is neither RMAU-scoped nor role-assignable' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'g1'
    }

    It 'Fail: the same unprotected group backing two role assignments is deduplicated to one evidence entry' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }
                [pscustomobject]@{ roleDefinitionName = 'School Administrator'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }
            ) }
        )

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
    }

    It 'Fail: one protected and one unprotected group - only the unprotected one is offending' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $true }
                [pscustomobject]@{ roleDefinitionName = 'School Administrator'; groupId = 'g2'; groupDisplayName = 'School Admins'; isManagementRestricted = $false; isAssignableToRole = $false }
            ) }
        )

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'g2'
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }
}

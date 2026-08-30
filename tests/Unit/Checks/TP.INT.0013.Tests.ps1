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
            [Parameter(Mandatory)] [hashtable[]] $Datasets,
            [Parameter()] $GateProvider = @{ Intune = @{ Status = 'Available'; Detail = 'fixture gate' } }
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $evaluation = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $CheckId, $Datasets, $GateProvider {
                param($storeRoot, $keyPath, $checkId, $datasets, $gateProvider)

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
                    if ($d.ContainsKey('Gaps')) { $params.Gaps = $d.Gaps }
                    if ($d.ContainsKey('Reason')) { $params.Reason = $d.Reason }
                    Write-PulseDataset @params
                }

                $manifest = Get-PulseSnapshotManifest -Store $store
                $gates = if ($null -eq $check.Data -or $null -eq $check.Data.Gates) { @() } else { @($check.Data.Gates) }
                if ($gates.Count -gt 0) {
                    if (-not $manifest.Contains('licenseEvidence') -or $manifest.licenseEvidence -isnot [System.Collections.IDictionary]) {
                        $manifest.licenseEvidence = [ordered]@{}
                    }
                    foreach ($gate in $gates) {
                        if ($null -ne $gate -and -not [string]::IsNullOrWhiteSpace([string] $gate)) {
                            $manifest.licenseEvidence[[string] $gate] = [ordered]@{
                                Status = 'Available'
                                Detail = 'fixture gate'
                            }
                        }
                    }
                    if ($manifest.licenseEvidence.Count -gt 0) {
                        $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $manifest
                        Set-PulseAtomicFileContent -Path $store.ManifestPath -Value $canonicalJson
                    }
                }

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath -GateProvider $gateProvider
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

    It 'Error: an unprotected row has a missing groupId - must throw, never silently vanish into a false Pass' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'groupId'
    }

    It 'Error: an unprotected row has an empty-string groupId - must throw, never silently vanish into a false Pass' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = ''; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'groupId'
    }

    It 'Error: a row is missing isManagementRestricted entirely - a failed sub-call must never read as verified unprotected' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'isManagementRestricted'
    }

    It 'Error: a row is missing isAssignableToRole entirely - a failed sub-call must never read as verified unprotected' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'isAssignableToRole'
    }

    It 'Error: isManagementRestricted is explicitly $null - absent, not decidable, must throw' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $null; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'isManagementRestricted'
    }

    It 'Error: string-valued protection flags are not native booleans and cannot become a false Pass' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = 'false'; isAssignableToRole = 'false' }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'native boolean'
    }

    It 'Pass still holds: present-$false on both fields is decidable and correctly Fails (not a false Pass, not an Error)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Fail'
    }
    
    It 'NotApplicable: a failed group lookup with no rows never becomes an empty-result Pass' {
        $gap = InModuleScope TenantPulse {
            New-PulseCollectionGap -Scope 'group:g1' -FailureClass 'PermissionDenied' -ReasonCode 'permission-denied' `
                -Detail @{ groupId = 'g1' } -Operation 'Get' -ApiVersion 'v1.0'
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Failed'; Reason = 'provider-failed'; Gaps = @($gap) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'provider-failed'
    }
}

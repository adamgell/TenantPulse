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

    $script:compliantAuthzPolicyHashtable = @{
        id                                                 = 'authz-1'
        allowedToUseSSPR                                   = $false
        allowInvitesFrom                                   = 'adminsAndGuestInviters'
        allowedToSignUpEmailBasedSubscriptions             = $false
        allowEmailVerifiedUsersToJoinOrganization          = $false
        guestUserRoleId                                    = '2af84b1e-32c8-42b7-82bc-daa82404023b'
        permissionGrantPolicyIdsAssignedToDefaultUserRole  = @('ManagePermissionGrantsForSelf.microsoft-user-default-low')
        allowUserConsentForRiskyApps                       = $false
        defaultUserRolePermissions                         = @{ allowedToCreateApps = $false; allowedToReadOtherUsers = $true }
    }
}

Describe 'TP.ENT.0012 - Default authorization policy settings cluster' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0012' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: every gating default matches the recommended value (hashtable shape)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0012' -Datasets @(
            @{ Name = 'authorizationPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($script:compliantAuthzPolicyHashtable) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 9
    }

    It 'Pass (PSObject shape)' {
        $pso = ConvertTo-PSObjectShape -Value $script:compliantAuthzPolicyHashtable
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0012' -Datasets @(
            @{ Name = 'authorizationPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($pso) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: every out-of-the-box Microsoft default deviates from the recommended value' {
        $default = @{
            id                                                 = 'authz-1'
            allowedToUseSSPR                                   = $true
            allowInvitesFrom                                   = 'everyone'
            allowedToSignUpEmailBasedSubscriptions             = $true
            allowEmailVerifiedUsersToJoinOrganization          = $true
            guestUserRoleId                                    = '10dae51f-b6af-4016-8d66-8c2a99b929b3'
            permissionGrantPolicyIdsAssignedToDefaultUserRole  = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy')
            allowUserConsentForRiskyApps                       = $true
            defaultUserRolePermissions                         = @{ allowedToCreateApps = $true; allowedToReadOtherUsers = $true }
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0012' -Datasets @(
            @{ Name = 'authorizationPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($default) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match '8 of 8'
        $finding.reason | Should -Match 'AP01'
        $finding.reason | Should -Match 'AP08'
    }

    It 'Fail: only AP10 (allowedToCreateApps) deviates, everything else compliant' {
        $onlyAp10Bad = $script:compliantAuthzPolicyHashtable.Clone()
        $onlyAp10Bad.defaultUserRolePermissions = @{ allowedToCreateApps = $true; allowedToReadOtherUsers = $true }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0012' -Datasets @(
            @{ Name = 'authorizationPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($onlyAp10Bad) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match '1 of 8.*AP10'
    }

    It 'Error: authorizationPolicy row is missing a required property (field-absence lens)' {
        $malformed = $script:compliantAuthzPolicyHashtable.Clone()
        $malformed.Remove('guestUserRoleId')

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0012' -Datasets @(
            @{ Name = 'authorizationPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($malformed) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match "guestUserRoleId"
    }

    It 'NotApplicable: v1.0 authorizationPolicy omits AP08 permissionGrantPolicyIdsAssignedToDefaultUserRole (GraphKit 0.2.2 projection)' {
        $v1 = $script:compliantAuthzPolicyHashtable.Clone()
        $v1.Remove('permissionGrantPolicyIdsAssignedToDefaultUserRole')

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0012' -Datasets @(
            @{ Name = 'authorizationPolicy'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($v1) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'permissionGrantPolicyIdsAssignedToDefaultUserRole'
        $finding.reason | Should -Match 'v1.0'
        @($finding.evidence | Where-Object { $_.identity -eq 'EIDSCA.AP08' }).Count | Should -Be 1
        $finding.evidence.Count | Should -Be 9
    }

    It 'descriptor-pending: NotApplicable when authorizationPolicy was skipped (no released GraphKit descriptor)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0012' -Datasets @(
            @{ Name = 'authorizationPolicy'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }
}

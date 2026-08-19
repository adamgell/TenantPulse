BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'New-PulseCollectionGap' {
    It 'creates a gap with the exact contract fields in deterministic insertion order' {
        $gap = InModuleScope TenantPulse {
            New-PulseCollectionGap -Scope 'child-a' -FailureClass 'PermissionDenied' -ReasonCode 'permission-denied' -Detail @{ permission = 'Device.Read.All' } -Operation 'List' -ApiVersion 'beta'
        }

        $gap.PSObject.Properties.Name | Should -Be @('Scope', 'FailureClass', 'ReasonCode', 'Detail', 'Operation', 'ApiVersion')
        $gap.Scope | Should -Be 'child-a'
        $gap.FailureClass | Should -Be 'PermissionDenied'
        $gap.ReasonCode | Should -Be 'permission-denied'
        $gap.Detail.permission | Should -Be 'Device.Read.All'
        $gap.Operation | Should -Be 'List'
        $gap.ApiVersion | Should -Be 'beta'
    }

    It 'rejects an unsupported failure class' {
        {
            InModuleScope TenantPulse {
                New-PulseCollectionGap -Scope 'child-a' -FailureClass 'NotARealFailure' -ReasonCode 'bad' -Detail $null -Operation 'List' -ApiVersion 'beta'
            }
        } | Should -Throw -ExpectedMessage '*FailureClass*'
    }
}

Describe 'New-PulseCollectionOutcome' {
    It 'creates Collected, Partial, Failed, and Skipped records with the contract fields' {
        $outcomes = InModuleScope TenantPulse {
            $gap = New-PulseCollectionGap -Scope 'child-a' -FailureClass 'ProviderFailed' -ReasonCode 'child-failed' -Detail $null -Operation 'List' -ApiVersion 'beta'
            @(
                (New-PulseCollectionOutcome -Dataset 'collected' -Status 'Collected' -Rows @([pscustomobject]@{ id = '1' }) -ReasonCode 'collected' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' -Operations @('List'))
                (New-PulseCollectionOutcome -Dataset 'partial' -Status 'Partial' -Rows @([pscustomobject]@{ id = '1' }) -Gaps @($gap) -ReasonCode 'partial' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' -Operations @('List'))
                (New-PulseCollectionOutcome -Dataset 'failed' -Status 'Failed' -FailureClass 'ProviderFailed' -ReasonCode 'provider-failed' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' -Operations @('List'))
                (New-PulseCollectionOutcome -Dataset 'skipped' -Status 'Skipped' -FailureClass 'GateUnknown' -ReasonCode 'gate-unknown' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' -Operations @())
            )
        }

        $outcomes.Count | Should -Be 4
        $outcomes.Status | Should -Be @('Collected', 'Partial', 'Failed', 'Skipped')
        $outcomes[0].PSObject.Properties.Name | Should -Be @('Dataset', 'Status', 'Rows', 'Gaps', 'FailureClass', 'ReasonCode', 'Detail', 'Provider', 'ApiVersion', 'Operations')
        $outcomes[1].Gaps.Count | Should -Be 1
        $outcomes[2].FailureClass | Should -Be 'ProviderFailed'
        $outcomes[3].FailureClass | Should -Be 'GateUnknown'
    }

    It 'rejects a missing Status' {
        {
            InModuleScope TenantPulse {
                New-PulseCollectionOutcome -Dataset 'missing-status' -ReasonCode 'bad' -Detail $null -Provider $null -ApiVersion $null
            }
        } | Should -Throw -ExpectedMessage '*Status*'
    }

    It 'rejects an invalid status value' {
        {
            InModuleScope TenantPulse {
                New-PulseCollectionOutcome -Dataset 'bad-status' -Status 'Unknown' -ReasonCode 'bad' -Detail $null -Provider $null -ApiVersion $null
            }
        } | Should -Throw -ExpectedMessage '*Status*'
    }

    It 'rejects an invalid top-level failure class' {
        {
            InModuleScope TenantPulse {
                New-PulseCollectionOutcome -Dataset 'bad-class' -Status 'Failed' -FailureClass 'NotARealFailure' -ReasonCode 'bad' -Detail $null -Provider $null -ApiVersion $null
            }
        } | Should -Throw -ExpectedMessage '*FailureClass*'
    }

    It 'rejects Partial without a gap' {
        {
            InModuleScope TenantPulse {
                New-PulseCollectionOutcome -Dataset 'partial-without-gap' -Status 'Partial' -ReasonCode 'partial' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta'
            }
        } | Should -Throw -ExpectedMessage '*Partial*gap*'
    }

    It 'rejects Collected with a failure class or gap' {
        $gap = InModuleScope TenantPulse {
            New-PulseCollectionGap -Scope 'child-a' -FailureClass 'ProviderFailed' -ReasonCode 'child-failed' -Detail $null -Operation 'List' -ApiVersion 'beta'
        }

        {
            InModuleScope TenantPulse {
                New-PulseCollectionOutcome -Dataset 'collected-failure' -Status 'Collected' -FailureClass 'ProviderFailed' -ReasonCode 'bad' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta'
            }
        } | Should -Throw -ExpectedMessage '*Collected*failure*'

        {
            InModuleScope TenantPulse -ArgumentList $gap {
                param($gap)
                New-PulseCollectionOutcome -Dataset 'collected-gap' -Status 'Collected' -Gaps @($gap) -ReasonCode 'bad' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta'
            }
        } | Should -Throw -ExpectedMessage '*Collected*gap*'
    }
}

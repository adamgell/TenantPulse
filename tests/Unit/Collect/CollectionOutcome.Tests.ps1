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
    It 'rejects a gap with a missing required field or invalid detail type' {
        $cases = @(
            @{ Name = 'Scope'; Gap = [pscustomobject]@{ Scope = $null; FailureClass = 'ProviderFailed'; ReasonCode = 'child-failed'; Detail = $null; Operation = 'List'; ApiVersion = 'beta' } }
            @{ Name = 'ReasonCode'; Gap = [pscustomobject]@{ Scope = 'child-a'; FailureClass = 'ProviderFailed'; ReasonCode = ''; Detail = $null; Operation = 'List'; ApiVersion = 'beta' } }
            @{ Name = 'Operation'; Gap = [pscustomobject]@{ Scope = 'child-a'; FailureClass = 'ProviderFailed'; ReasonCode = 'child-failed'; Detail = $null; Operation = $null; ApiVersion = 'beta' } }
            @{ Name = 'ApiVersion'; Gap = [pscustomobject]@{ Scope = 'child-a'; FailureClass = 'ProviderFailed'; ReasonCode = 'child-failed'; Detail = $null; Operation = 'List'; ApiVersion = $null } }
            @{ Name = 'Detail'; Gap = [pscustomobject]@{ Scope = 'child-a'; FailureClass = 'ProviderFailed'; ReasonCode = 'child-failed'; Detail = 'not-a-hashtable'; Operation = 'List'; ApiVersion = 'beta' } }
            @{ Name = 'FailureClass'; Gap = [pscustomobject]@{ Scope = 'child-a'; FailureClass = $null; ReasonCode = 'child-failed'; Detail = $null; Operation = 'List'; ApiVersion = 'beta' } }
        )

        foreach ($case in $cases) {
            {
                InModuleScope TenantPulse -ArgumentList $case.Gap {
                    param($gap)
                    New-PulseCollectionOutcome -Dataset 'malformed-gap' -Status 'Partial' -Rows @() -Gaps ([object[]]@($gap)) -ReasonCode 'partial' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta'
                }
            } | Should -Throw -ExpectedMessage "*$($case.Name)*"
        }

        {
            InModuleScope TenantPulse {
                New-PulseCollectionOutcome -Dataset 'null-gap' -Status 'Partial' -Rows @() -Gaps ([object[]]@($null)) -ReasonCode 'partial' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta'
            }
        } | Should -Throw -ExpectedMessage '*Gaps*null*'
    }

    It 'preserves Rows, Gaps, and Operations as object arrays for zero, one, and many values' {
        $shapes = InModuleScope TenantPulse {
            $gap = New-PulseCollectionGap -Scope 'child-a' -FailureClass 'ProviderFailed' -ReasonCode 'child-failed' -Detail $null -Operation 'List' -ApiVersion 'beta'
            $gap2 = New-PulseCollectionGap -Scope 'child-b' -FailureClass 'PermissionDenied' -ReasonCode 'child-denied' -Detail @{} -Operation 'List' -ApiVersion 'beta'
            $scalar = New-PulseCollectionOutcome -Dataset 'scalar' -Status 'Partial' -Rows ([pscustomobject]@{ id = 'scalar' }) -Gaps $gap -ReasonCode 'scalar' -Detail @{} -Operations 'List'
            @(
                (New-PulseCollectionOutcome -Dataset 'zero' -Status 'Collected' -Rows ([object[]]@()) -Gaps ([object[]]@()) -ReasonCode 'zero' -Detail @{} -Operations ([object[]]@())),
                (New-PulseCollectionOutcome -Dataset 'one' -Status 'Partial' -Rows ([object[]]@([pscustomobject]@{ id = '1' })) -Gaps ([object[]]@($gap)) -ReasonCode 'one' -Detail @{} -Operations ([object[]]@('List'))),
                (New-PulseCollectionOutcome -Dataset 'many' -Status 'Partial' -Rows ([object[]]@([pscustomobject]@{ id = '1' }, [pscustomobject]@{ id = '2' })) -Gaps ([object[]]@($gap, $gap2)) -ReasonCode 'many' -Detail @{} -Operations ([object[]]@('List', 'Get'))),
                $scalar
            )
        }

        foreach ($shape in $shapes) {
            $shape.Rows.GetType().FullName | Should -Be 'System.Object[]'
            $shape.Gaps.GetType().FullName | Should -Be 'System.Object[]'
            $shape.Operations.GetType().FullName | Should -Be 'System.Object[]'
        }
        $shapes[0].Rows.Count | Should -Be 0
        $shapes[1].Rows.Count | Should -Be 1
        $shapes[2].Rows.Count | Should -Be 2
        $shapes[3].Rows.Count | Should -Be 1
        $shapes[0].Gaps.Count | Should -Be 0
        $shapes[1].Gaps.Count | Should -Be 1
        $shapes[2].Gaps.Count | Should -Be 2
        $shapes[3].Gaps.Count | Should -Be 1
        $shapes[0].Operations.Count | Should -Be 0
        $shapes[1].Operations.Count | Should -Be 1
        $shapes[2].Operations.Count | Should -Be 2
        $shapes[3].Operations.Count | Should -Be 1
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

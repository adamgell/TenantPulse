BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Test-PulseMaesterLicenseGate' {
    It 'Available: the required service plan is present with a Success provisioning status' {
        $datasets = @{
            subscribedSkus = @(
                [pscustomobject]@{ skuPartNumber = 'ENTERPRISEPREMIUM'; servicePlans = @(
                        [pscustomobject]@{ servicePlanName = 'AAD_PREMIUM_P2'; provisioningStatus = 'Success' }
                    )
                }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Test-PulseMaesterLicenseGate -Datasets $datasets -DatasetName 'subscribedSkus' -RequiredServicePlanNames @('AAD_PREMIUM_P2')
        }

        $result.Available | Should -BeTrue
        $result.Reason | Should -BeNullOrEmpty
    }

    It 'Available: satisfied by ANY one of several required service plan names' {
        $datasets = @{
            subscribedSkus = @(
                [pscustomobject]@{ skuPartNumber = 'SKU1'; servicePlans = @(
                        [pscustomobject]@{ servicePlanName = 'OTHER_PLAN'; provisioningStatus = 'Success' }
                    )
                }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Test-PulseMaesterLicenseGate -Datasets $datasets -DatasetName 'subscribedSkus' -RequiredServicePlanNames @('AAD_PREMIUM_P2', 'OTHER_PLAN')
        }

        $result.Available | Should -BeTrue
    }

    It 'Not available: the required service plan exists but is not provisioned Success' {
        $datasets = @{
            subscribedSkus = @(
                [pscustomobject]@{ skuPartNumber = 'SKU1'; servicePlans = @(
                        [pscustomobject]@{ servicePlanName = 'AAD_PREMIUM_P2'; provisioningStatus = 'Disabled' }
                    )
                }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Test-PulseMaesterLicenseGate -Datasets $datasets -DatasetName 'subscribedSkus' -RequiredServicePlanNames @('AAD_PREMIUM_P2')
        }

        $result.Available | Should -BeFalse
        $result.Reason | Should -Match 'AAD_PREMIUM_P2'
    }

    It 'Not available: the named dataset is not present in -Datasets at all' {
        $result = InModuleScope TenantPulse -ArgumentList @{} {
            param($datasets)
            Test-PulseMaesterLicenseGate -Datasets $datasets -DatasetName 'subscribedSkus' -RequiredServicePlanNames @('AAD_PREMIUM_P2')
        }

        $result.Available | Should -BeFalse
        $result.Reason | Should -Match "dataset 'subscribedSkus' is not present"
    }
}

Describe 'ConvertTo-PulseMaesterEvidence' {
    It 'maps rows onto Identity/Detail/SortKey using the default SortKey-falls-back-to-Identity rule' {
        $rows = @(
            [pscustomobject]@{ id = 'row-1'; name = 'First'; value = 42 }
        )

        $evidence = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            ConvertTo-PulseMaesterEvidence -Rows $rows -IdentityProperty 'id'
        }

        $evidence.Count | Should -Be 1
        $evidence[0].Identity | Should -Be 'row-1'
        $evidence[0].SortKey | Should -Be 'row-1'
        $evidence[0].Detail.name | Should -Be 'First'
        $evidence[0].Detail.value | Should -Be 42
    }

    It 'uses -SortKeyProperty when supplied, distinct from Identity' {
        $rows = @([pscustomobject]@{ id = 'row-1'; sortHint = 'aaa-first'; name = 'First' })

        $evidence = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            ConvertTo-PulseMaesterEvidence -Rows $rows -IdentityProperty 'id' -SortKeyProperty 'sortHint'
        }

        $evidence[0].SortKey | Should -Be 'aaa-first'
    }

    It 'restricts Detail to -DetailProperties when supplied' {
        $rows = @([pscustomobject]@{ id = 'row-1'; name = 'First'; secret = 'do-not-carry' })

        $evidence = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            ConvertTo-PulseMaesterEvidence -Rows $rows -IdentityProperty 'id' -DetailProperties @('name')
        }

        $evidence[0].Detail.ContainsKey('name') | Should -BeTrue
        $evidence[0].Detail.ContainsKey('secret') | Should -BeFalse
    }

    It 'skips a row whose Identity property is null/empty rather than throwing' {
        $rows = @(
            [pscustomobject]@{ id = ''; name = 'skip-me' }
            [pscustomobject]@{ id = 'row-2'; name = 'keep-me' }
        )

        $evidence = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            ConvertTo-PulseMaesterEvidence -Rows $rows -IdentityProperty 'id'
        }

        $evidence.Count | Should -Be 1
        $evidence[0].Identity | Should -Be 'row-2'
    }

    It 'returns an empty array for an empty -Rows input' {
        $evidence = InModuleScope TenantPulse {
            ConvertTo-PulseMaesterEvidence -Rows @() -IdentityProperty 'id'
        }

        @($evidence).Count | Should -Be 0
    }

    It 'output feeds New-PulseFinding -Evidence without error (integration with the RuleResult contract)' {
        $rows = @([pscustomobject]@{ id = 'row-1'; name = 'First' })

        $finding = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            $evidence = ConvertTo-PulseMaesterEvidence -Rows $rows -IdentityProperty 'id'
            New-PulseFinding -Status Fail -Reason 'test' -Evidence $evidence
        }

        $finding.Evidence.Count | Should -Be 1
        $finding.Evidence[0].Identity | Should -Be 'row-1'
    }
}

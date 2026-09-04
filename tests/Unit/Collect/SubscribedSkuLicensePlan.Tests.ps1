BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
    $script:graphEnvelopeHelperPath = Join-Path $script:repoRoot 'tests/Helpers/New-PulseTestGraphEnvelope.ps1'
    . $script:graphEnvelopeHelperPath
    InModuleScope TenantPulse -ArgumentList $script:graphEnvelopeHelperPath {
        param($helperPath)
        . $helperPath
    }
}

Describe 'Invoke-PulseSubscribedSkuLicensePlan' {
    BeforeEach {
        Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }
    }

    It 'persists independent Intune, Entra P1, and Entra P2 decisions from successful service plans' {
        Mock Get-GraphObject -ModuleName TenantPulse {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{
                    capabilityStatus = 'Enabled'
                    servicePlans = @(
                        [pscustomobject]@{ servicePlanId = 'c1ec4a95-1f05-45b3-a911-aa3fa01094f5'; provisioningStatus = 'Success' }
                        [pscustomobject]@{ servicePlanId = 'eec0eb4f-6444-4f95-aba0-50c24d67f998'; provisioningStatus = 'Success' }
                    )
                })
        }

        $outcome = InModuleScope TenantPulse {
            Invoke-PulseSubscribedSkuLicensePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'subscribedSkus' `
                -ManifestEntry ([pscustomobject]@{ Dataset = 'subscribedSkus'; ApiVersion = 'beta' }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Collected'
        @($outcome.Rows).Count | Should -Be 1
        $outcome.Detail.Gates.Intune.Status | Should -Be 'Available'
        $outcome.Detail.Gates.EntraP1.Status | Should -Be 'Available'
        $outcome.Detail.Gates.EntraP2.Status | Should -Be 'Available'
        Should-Invoke Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse -Exactly 1 -ParameterFilter {
            $Type -eq 'SubscribedSku' -and $Operation -eq 'List' -and $ApiVersion -eq 'beta'
        }
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Exactly 1 -ParameterFilter {
            $Type -eq 'SubscribedSku' -and $Operation -eq 'List'
        }
    }

    It 'keeps a fully provisioned qualifying plan available while its SKU is in the warning grace state' {
        Mock Get-GraphObject -ModuleName TenantPulse {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{
                    capabilityStatus = 'Warning'
                    servicePlans = @(
                        [pscustomobject]@{ servicePlanId = 'c1ec4a95-1f05-45b3-a911-aa3fa01094f5'; provisioningStatus = 'Success' }
                    )
                })
        }

        $outcome = InModuleScope TenantPulse {
            Invoke-PulseSubscribedSkuLicensePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'subscribedSkus' `
                -ManifestEntry ([pscustomobject]@{ Dataset = 'subscribedSkus'; ApiVersion = 'beta' }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Collected'
        $outcome.Detail.Gates.Intune.Status | Should -Be 'Available'
        $outcome.Detail.Gates.Intune.FailureClass | Should -BeNullOrEmpty
    }

    It 'treats disabled plans as unavailable and keeps the three gate decisions independent' {
        Mock Get-GraphObject -ModuleName TenantPulse {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{
                    capabilityStatus = 'Enabled'
                    servicePlans = @(
                        [pscustomobject]@{ servicePlanId = 'c1ec4a95-1f05-45b3-a911-aa3fa01094f5'; provisioningStatus = 'Disabled' }
                        [pscustomobject]@{ servicePlanId = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'; provisioningStatus = 'Success' }
                    )
                })
        }

        $outcome = InModuleScope TenantPulse {
            Invoke-PulseSubscribedSkuLicensePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'subscribedSkus' `
                -ManifestEntry ([pscustomobject]@{ Dataset = 'subscribedSkus'; ApiVersion = 'beta' }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'
        }

        $outcome.Detail.Gates.Intune.Status | Should -Be 'Unavailable'
        $outcome.Detail.Gates.Intune.FailureClass | Should -Be 'LicenseRequired'
        $outcome.Detail.Gates.EntraP1.Status | Should -Be 'Available'
        $outcome.Detail.Gates.EntraP2.Status | Should -Be 'Unavailable'
    }

    It 'does not let a qualifying plan on a non-enabled SKU prove availability' {
        Mock Get-GraphObject -ModuleName TenantPulse {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{
                    capabilityStatus = 'Suspended'
                    servicePlans = @(
                        [pscustomobject]@{ servicePlanId = 'c1ec4a95-1f05-45b3-a911-aa3fa01094f5'; provisioningStatus = 'Success' }
                    )
                })
        }

        $outcome = InModuleScope TenantPulse {
            Invoke-PulseSubscribedSkuLicensePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'subscribedSkus' `
                -ManifestEntry ([pscustomobject]@{ Dataset = 'subscribedSkus'; ApiVersion = 'beta' }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Collected'
        $outcome.Detail.Gates.Intune.Status | Should -Be 'Unavailable'
        $outcome.Detail.Gates.Intune.FailureClass | Should -Be 'LicenseRequired'
    }

    It 'fails closed for <Case> without copying malformed provider values into classifications' -ForEach @(
        @{
            Case = 'missing capabilityStatus'
            Category = 'MalformedCapabilityStatus'
            Marker = 'must-not-appear-capability-missing'
            Rows = @([pscustomobject]@{
                    servicePlans = @(
                        [pscustomobject]@{ servicePlanId = '11111111-1111-1111-1111-111111111111'; provisioningStatus = 'Success' }
                    )
                })
        }
        @{
            Case = 'non-string capabilityStatus'
            Category = 'MalformedCapabilityStatus'
            Marker = 'must-not-appear-capability-type'
            Rows = @([pscustomobject]@{
                    capabilityStatus = [pscustomobject]@{ value = 'must-not-appear-capability-type' }
                    servicePlans = @()
                })
        }
        @{
            Case = 'unrecognized capabilityStatus'
            Category = 'MalformedCapabilityStatus'
            Marker = 'must-not-appear-capability-value'
            Rows = @([pscustomobject]@{
                    capabilityStatus = 'must-not-appear-capability-value'
                    servicePlans = @()
                })
        }
        @{
            Case = 'missing servicePlans'
            Category = 'MalformedServicePlans'
            Marker = 'must-not-appear-serviceplans-missing'
            Rows = @([pscustomobject]@{
                    capabilityStatus = 'Enabled'
                    marker = 'must-not-appear-serviceplans-missing'
                })
        }
        @{
            Case = 'non-collection servicePlans'
            Category = 'MalformedServicePlans'
            Marker = 'must-not-appear-serviceplans-shape'
            Rows = @([pscustomobject]@{
                    capabilityStatus = 'Enabled'
                    servicePlans = [pscustomobject]@{ marker = 'must-not-appear-serviceplans-shape' }
                })
        }
        @{
            Case = 'missing provisioningStatus'
            Category = 'MalformedProvisioningStatus'
            Marker = 'must-not-appear-provisioning-missing'
            Rows = @([pscustomobject]@{
                    capabilityStatus = 'Enabled'
                    servicePlans = @(
                        [pscustomobject]@{ servicePlanId = 'c1ec4a95-1f05-45b3-a911-aa3fa01094f5'; marker = 'must-not-appear-provisioning-missing' }
                    )
                })
        }
        @{
            Case = 'non-string provisioningStatus'
            Category = 'MalformedProvisioningStatus'
            Marker = 'must-not-appear-provisioning-type'
            Rows = @([pscustomobject]@{
                    capabilityStatus = 'Enabled'
                    servicePlans = @(
                        [pscustomobject]@{ servicePlanId = 'c1ec4a95-1f05-45b3-a911-aa3fa01094f5'; provisioningStatus = [pscustomobject]@{ value = 'must-not-appear-provisioning-type' } }
                    )
                })
        }
        @{
            Case = 'unrecognized provisioningStatus'
            Category = 'MalformedProvisioningStatus'
            Marker = 'must-not-appear-provisioning-value'
            Rows = @([pscustomobject]@{
                    capabilityStatus = 'Enabled'
                    servicePlans = @(
                        [pscustomobject]@{ servicePlanId = 'c1ec4a95-1f05-45b3-a911-aa3fa01094f5'; provisioningStatus = 'must-not-appear-provisioning-value' }
                    )
                })
        }
        @{
            Case = 'missing servicePlanId'
            Category = 'MalformedServicePlanId'
            Marker = 'must-not-appear-planid-missing'
            Rows = @([pscustomobject]@{
                    capabilityStatus = 'Enabled'
                    servicePlans = @(
                        [pscustomobject]@{ provisioningStatus = 'Success'; marker = 'must-not-appear-planid-missing' }
                    )
                })
        }
        @{
            Case = 'non-string servicePlanId'
            Category = 'MalformedServicePlanId'
            Marker = 'must-not-appear-planid-type'
            Rows = @([pscustomobject]@{
                    capabilityStatus = 'Enabled'
                    servicePlans = @(
                        [pscustomobject]@{ servicePlanId = [pscustomobject]@{ value = 'must-not-appear-planid-type' }; provisioningStatus = 'Success' }
                    )
                })
        }
        @{
            Case = 'non-guid servicePlanId'
            Category = 'MalformedServicePlanId'
            Marker = 'must-not-appear-planid-value'
            Rows = @([pscustomobject]@{
                    capabilityStatus = 'Enabled'
                    servicePlans = @(
                        [pscustomobject]@{ servicePlanId = 'must-not-appear-planid-value'; provisioningStatus = 'Success' }
                    )
                })
        }
    ) {
        Mock Get-GraphObject -ModuleName TenantPulse { New-PulseTestGraphEnvelope -Data @($Rows) }

        $outcome = InModuleScope TenantPulse {
            Invoke-PulseSubscribedSkuLicensePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'subscribedSkus' `
                -ManifestEntry ([pscustomobject]@{ Dataset = 'subscribedSkus'; ApiVersion = 'beta' }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Partial'
        @($outcome.Gaps).Count | Should -Be 1
        $outcome.Gaps[0].Scope | Should -Be 'license-evidence'
        $outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $outcome.Gaps[0].ReasonCode | Should -Be 'invalid-provider-data'
        @($outcome.Gaps[0].Detail.Categories) | Should -Contain $Category
        foreach ($gate in @('Intune', 'EntraP1', 'EntraP2')) {
            $outcome.Detail.Gates[$gate].Status | Should -Be 'Unknown'
            $outcome.Detail.Gates[$gate].FailureClass | Should -Be 'GateUnknown'
        }
        ($outcome.Gaps | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match ([regex]::Escape($Marker))
        ($outcome.Detail | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match ([regex]::Escape($Marker))
    }

    It 'keeps an independently proven gate available when another SKU is malformed' {
        Mock Get-GraphObject -ModuleName TenantPulse {
            New-PulseTestGraphEnvelope -Data @(
                [pscustomobject]@{
                    capabilityStatus = 'Enabled'
                    servicePlans = @(
                        [pscustomobject]@{ servicePlanId = 'c1ec4a95-1f05-45b3-a911-aa3fa01094f5'; provisioningStatus = 'Success' }
                    )
                }
                [pscustomobject]@{
                    capabilityStatus = 'Enabled'
                }
            )
        }

        $outcome = InModuleScope TenantPulse {
            Invoke-PulseSubscribedSkuLicensePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'subscribedSkus' `
                -ManifestEntry ([pscustomobject]@{ Dataset = 'subscribedSkus'; ApiVersion = 'beta' }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Partial'
        $outcome.Detail.Gates.Intune.Status | Should -Be 'Available'
        $outcome.Detail.Gates.Intune.FailureClass | Should -BeNullOrEmpty
        $outcome.Detail.Gates.EntraP1.Status | Should -Be 'Unknown'
        $outcome.Detail.Gates.EntraP1.FailureClass | Should -Be 'GateUnknown'
        $outcome.Detail.Gates.EntraP2.Status | Should -Be 'Unknown'
        $outcome.Detail.Gates.EntraP2.FailureClass | Should -Be 'GateUnknown'
    }

    It 'lets Partial evidence preserve Available and Unknown decisions but never prove Unavailable' {
        $manifest = @{
            datasets = @{
                subscribedSkus = @{
                    status = 'Partial'
                    detail = @{
                        Gates = @{
                            Intune  = @{ Status = 'Available'; Detail = 'fixed available detail.' }
                            EntraP1 = @{ Status = 'Unknown'; Detail = 'fixed unknown detail.'; FailureClass = 'GateUnknown' }
                            EntraP2 = @{ Status = 'Unavailable'; Detail = 'must not be trusted.'; FailureClass = 'LicenseRequired' }
                        }
                    }
                }
            }
        }

        $intune = InModuleScope TenantPulse -ArgumentList $manifest {
            param($manifest)
            Get-PulseGateStatus -Gate 'Intune' -Manifest $manifest
        }
        $entraP1 = InModuleScope TenantPulse -ArgumentList $manifest {
            param($manifest)
            Get-PulseGateStatus -Gate 'EntraP1' -Manifest $manifest
        }
        $entraP2 = InModuleScope TenantPulse -ArgumentList $manifest {
            param($manifest)
            Get-PulseGateStatus -Gate 'EntraP2' -Manifest $manifest
        }

        $intune.Status | Should -Be 'Available'
        $intune.FailureClass | Should -BeNullOrEmpty
        $entraP1.Status | Should -Be 'Unknown'
        $entraP1.FailureClass | Should -Be 'GateUnknown'
        $entraP2.Status | Should -Be 'Unknown'
        $entraP2.FailureClass | Should -Be 'GateUnknown'
    }

    It 'maps a denied subscribedSkus read to an explicit failed provider outcome' {
        Mock Get-GraphObject -ModuleName TenantPulse {
            $target = [pscustomobject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Outcome = 'Failed'
                Certainty = 'Known'
                Telemetry = @([pscustomobject]@{ Attempt = 1; StatusCode = 403 })
            }
            $record = [System.Management.Automation.ErrorRecord]::new(
                [System.InvalidOperationException]::new('synthetic denied read'),
                'GraphKit.OperationFailed.403',
                [System.Management.Automation.ErrorCategory]::PermissionDenied,
                $target)
            throw $record
        }

        $outcome = InModuleScope TenantPulse {
            Invoke-PulseSubscribedSkuLicensePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'subscribedSkus' `
                -ManifestEntry ([pscustomobject]@{ Dataset = 'subscribedSkus'; ApiVersion = 'beta' }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be 'PermissionDenied'
        $outcome.ReasonCode | Should -Be 'permission-denied'
        @($outcome.Rows).Count | Should -Be 0
    }

    It 'is active in the normal built-in provider-plan registry' {
        $registry = InModuleScope TenantPulse { Resolve-PulseProviderPlanRegistry }

        $registry.ContainsKey('subscribedSkus') | Should -BeTrue
        $registry.subscribedSkus.Command | Should -BeOfType ([scriptblock])
        $registry.subscribedSkus.RequiresNetwork | Should -BeTrue
        $registry.subscribedSkus.SupportsNetworkAbortState | Should -BeTrue
    }

    It 'sorts persisted category names ordinally regardless of the current culture' {
        $result = InModuleScope TenantPulse {
            $command = Get-Command ConvertTo-PulseOrdinalStringArray -ErrorAction SilentlyContinue
            if ($null -eq $command) {
                return [pscustomobject]@{ Exists = $false; Values = [string[]]@() }
            }

            $originalCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
            try {
                [System.Threading.Thread]::CurrentThread.CurrentCulture =
                    [System.Globalization.CultureInfo]::GetCultureInfo('tr-TR')
                $values = ConvertTo-PulseOrdinalStringArray -Values @('ı', 'I', 'i', 'İ')
                return [pscustomobject]@{ Exists = $true; Values = [string[]]@($values) }
            }
            finally {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
            }
        }

        $result.Exists | Should -BeTrue
        if ($result.Exists) {
            @($result.Values) -join '|' | Should -Be 'I|i|İ|ı'
        }
    }
}

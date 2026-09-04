BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    InModuleScope TenantPulse {
        function Get-GraphContext { param() }
        function Get-GraphObject { param() }
        function Get-GraphOperation { param() }
        function Test-GraphPermission { param() }
    }

    Mock Get-GraphContext -ModuleName TenantPulse { throw 'Get-GraphContext must be mocked in this test.' }
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }
    Mock Get-GraphOperation -ModuleName TenantPulse { throw 'Get-GraphOperation must be mocked in this test.' }
    Mock Test-GraphPermission -ModuleName TenantPulse { throw 'Test-GraphPermission must be mocked in this test.' }

    function New-TestPermissionFindings {
        param(
            [string] $Configured = 'Unknown',
            [string] $Granted = 'Yes',
            [string] $MissingGrant = 'None',
            [string] $ExcessGranted = 'None',
            [string] $AuthenticationCompatible = 'Yes',
            [switch] $ServicePrincipalMissing
        )

        $findings = @(
            [pscustomobject]@{ Finding = 'Configured'; Value = $Configured; Detail = 'configured' }
            [pscustomobject]@{ Finding = 'Granted'; Value = $Granted; Detail = 'granted' }
            [pscustomobject]@{ Finding = 'MissingGrant'; Value = $MissingGrant; Detail = 'missing' }
            [pscustomobject]@{ Finding = 'ExcessGranted'; Value = $ExcessGranted; Detail = 'excess' }
            [pscustomobject]@{ Finding = 'AuthenticationCompatible'; Value = $AuthenticationCompatible; Detail = 'auth' }
        )
        if ($ServicePrincipalMissing) {
            $findings += [pscustomobject]@{ Finding = 'ServicePrincipalMissing'; Value = 'Yes'; Detail = 'sp missing' }
        }
        return $findings
    }

    function New-TestDescriptor {
        param(
            [Parameter(Mandatory)]
            [string] $Type,
            [Parameter(Mandatory)]
            [string] $Operation,
            [string] $ApiVersion = 'v1.0',
            [object[]] $RequiredPermissions = @(@{ Type = 'Application'; Value = 'Policy.Read.All' }),
            [string] $Stability = 'GenerallyAvailable'
        )

        return @{
            Type                = $Type
            Operation           = $Operation
            ApiVersion          = $ApiVersion
            Stability           = $Stability
            ThrottleClass       = 'Read'
            ReplayPolicy        = 'Safe'
            RequiredPermissions = $RequiredPermissions
        }
    }

    function New-TestContext {
        [pscustomobject]@{
            ProfileId = 'contoso'
            TenantId  = '11111111-1111-1111-1111-111111111111'
            ClientId  = [guid]'22222222-2222-2222-2222-222222222222'
        }
    }

    function Get-TestManifestStatus {
        param([Parameter(Mandatory)] $Store, [Parameter(Mandatory)] [string] $Dataset)
        $manifest = Get-Content -LiteralPath $Store.ManifestPath -Raw | ConvertFrom-Json
        return $manifest.datasets.$Dataset
    }

    function Invoke-TestCollection {
        param(
            [Parameter(Mandatory)] $Manifest,
            $ProviderPlanRegistry = @{},
            [switch] $ExpandSettings
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $Manifest, $script:context, $ProviderPlanRegistry, $ExpandSettings.IsPresent {
            param($store, $manifest, $context, $registry, $expandSettings)
            $resolvedRegistry = Resolve-PulseProviderPlanRegistry -Overrides $registry
            $operations = @(Get-PulsePermissionPreflightOperations -Manifest $manifest -ExpandSettings:$expandSettings `
                    -ProviderPlanRegistry $resolvedRegistry)
            $authorization = Invoke-PulsePermissionPreflight -Context $context -Operations $operations
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' `
                -TenantPseudonym 'tp-abc123' -ProviderPlanRegistry $resolvedRegistry -AuthorizationDecision $authorization
        }
    }

}

Describe 'Get-PulsePermissionPreflightOperations' {
    It 'unions ordinary descriptors, composite children, expansion operations, and app-health additions' {
        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
            [pscustomobject]@{ Dataset = 'intuneRbacGroupProtection'; Type = 'IntuneRbacGroupProtectionWalk'; Operation = 'Walk'; ApiVersion = 'beta'; Pending = $true }
            [pscustomobject]@{ Dataset = 'dataProcessorServiceForWindowsFeaturesOnboarding'; Type = 'DataProcessorServiceForWindowsFeaturesOnboarding'; Operation = 'Get'; ApiVersion = 'beta'; Pending = $true }
        )
        $appHealth = @(
            @{ Type = 'MobileApp'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        )

        $operations = InModuleScope TenantPulse -ArgumentList $manifest, $appHealth {
            param($manifest, $appHealth)
            $registry = Resolve-PulseProviderPlanRegistry
            Get-PulsePermissionPreflightOperations -Manifest $manifest -ExpandSettings `
                -AdditionalOperations $appHealth -ProviderPlanRegistry $registry
        }

        $keys = @($operations | ForEach-Object { '{0}/{1}' -f $_.Type, $_.Operation } | Sort-Object)
        $keys | Should -Contain 'ConditionalAccessPolicy/List'
        $keys | Should -Contain 'DeviceManagementUnifiedRoleAssignment/ListBeta'
        $keys | Should -Contain 'Group/Get'
        $keys | Should -Contain 'ConfigurationPolicy/ListBeta'
        $keys | Should -Contain 'ConfigurationPolicySetting/ListBeta'
        $keys | Should -Contain 'ConfigurationSettingDefinition/ListBeta'
        $keys | Should -Contain 'DeviceCompliancePolicyAssignment/List'
        $keys | Should -Contain 'MobileApp/ListBeta'
        $keys | Should -Not -Contain 'IntuneRbacGroupProtectionWalk/Walk'
        $keys | Should -Not -Contain 'DataProcessorServiceForWindowsFeaturesOnboarding/Get'
        @($operations | Where-Object { $_.Type -eq 'ConfigurationPolicy' -and $_.Operation -eq 'ListBeta' }).Count | Should -Be 1
    }

    It 'unions the exact operations declared by the selected provider registration' {
        $manifest = @(
            [pscustomobject]@{
                Dataset = 'dataProcessorServiceForWindowsFeaturesOnboarding'
                Type = 'DataProcessorServiceForWindowsFeaturesOnboarding'
                Operation = 'Get'
                ApiVersion = 'beta'
                Pending = $true
            }
        )
        $registry = @{
            dataProcessorServiceForWindowsFeaturesOnboarding = @{
                Command = { throw 'the plan must not run while constructing the preflight union' }
                RequiresNetwork = $true
                Operations = @(
                    @{ Type = 'MobileApp'; Operation = 'ListBeta'; ApiVersion = 'beta' }
                )
            }
        }

        $operations = InModuleScope TenantPulse -ArgumentList $manifest, $registry {
            param($manifest, $registry)
            Get-PulsePermissionPreflightOperations -Manifest $manifest -ProviderPlanRegistry $registry
        }

        @($operations).Count | Should -Be 1
        $operations[0].Type | Should -Be 'MobileApp'
        $operations[0].Operation | Should -Be 'ListBeta'
        $operations[0].ApiVersion | Should -Be 'beta'
    }
}

Describe 'Invoke-PulsePermissionPreflight' {
    BeforeEach {
        $script:context = New-TestContext
        $script:preflightDone = $false
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation -ApiVersion 'beta' `
                -RequiredPermissions @(@{ Type = 'Application'; Value = 'Policy.Read.All' })
        }
    }

    It 'calls Test-GraphPermission once with TargetAppId equal to Context.ClientId and the descriptor union as Baseline' {
        $operations = @(
            @{ Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta' }
            @{ Type = 'DeviceCompliancePolicy'; Operation = 'List'; ApiVersion = 'v1.0' }
        )
        Mock Test-GraphPermission -ModuleName TenantPulse {
            $script:preflightDone = $true
            $TargetAppId | Should -Be $script:context.ClientId
            @($Baseline).Count | Should -Be 2
            New-TestPermissionFindings
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:context, $operations {
            param($context, $operations)
            Invoke-PulsePermissionPreflight -Context $context -Operations $operations
        }

        $result.Decision | Should -Be 'Granted'
        Should-Invoke Test-GraphPermission -ModuleName TenantPulse -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'does not treat Configured Unknown as a GraphKit permission denial' {
        Mock Test-GraphPermission -ModuleName TenantPulse {
            New-TestPermissionFindings -Configured 'Unknown' -Granted 'Yes' -MissingGrant 'None' -AuthenticationCompatible 'Yes'
        }
        $operations = @(@{ Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta' })
        $result = InModuleScope TenantPulse -ArgumentList $script:context, $operations {
            param($context, $operations)
            Invoke-PulsePermissionPreflight -Context $context -Operations $operations
        }
        $result.Decision | Should -Be 'Granted'
        $result.Decisions['ConditionalAccessPolicy/List'].Decision | Should -Be 'Granted'
        $result.Decisions['ConditionalAccessPolicy/List'].Decision | Should -Not -Be 'NotApplicable'
    }

    It 'fails closed locally when the target context has no client id' {
        $contextWithoutClientId = [pscustomobject]@{
            ProfileId = 'contoso'
            TenantId  = '11111111-1111-1111-1111-111111111111'
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            throw 'the analyzer must not receive an unbound target app id'
        }
        $operations = @(@{ Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta' })

        $result = InModuleScope TenantPulse -ArgumentList $contextWithoutClientId, $operations {
            param($context, $operations)
            Invoke-PulsePermissionPreflight -Context $context -Operations $operations
        }

        $result.Decision | Should -Be 'Unknown'
        $result.ReasonCode | Should -Be 'target-app-id-unavailable'
        $result.Decisions['ConditionalAccessPolicy/List'].Decision | Should -Be 'Unknown'
        Should-Invoke Test-GraphPermission -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'rejects an out-of-domain authentication finding as malformed' {
        Mock Test-GraphPermission -ModuleName TenantPulse {
            New-TestPermissionFindings -AuthenticationCompatible 'Maybe'
        }
        $operations = @(@{ Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta' })

        $result = InModuleScope TenantPulse -ArgumentList $script:context, $operations {
            param($context, $operations)
            Invoke-PulsePermissionPreflight -Context $context -Operations $operations
        }

        $result.Decision | Should -Be 'Unknown'
        $result.ReasonCode | Should -Be 'malformed-finding-set'
        $result.Decisions['ConditionalAccessPolicy/List'].Decision | Should -Be 'Unknown'
    }

    It 'rejects duplicate required findings as malformed instead of trusting the first value' {
        Mock Test-GraphPermission -ModuleName TenantPulse {
            @(
                New-TestPermissionFindings
                [pscustomobject]@{ Finding = 'MissingGrant'; Value = 'Policy.Read.All'; Detail = 'contradiction' }
            )
        }
        $operations = @(@{ Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta' })

        $result = InModuleScope TenantPulse -ArgumentList $script:context, $operations {
            param($context, $operations)
            Invoke-PulsePermissionPreflight -Context $context -Operations $operations
        }

        $result.Decision | Should -Be 'Unknown'
        $result.ReasonCode | Should -Be 'malformed-finding-set'
        $result.Decisions['ConditionalAccessPolicy/List'].Decision | Should -Be 'Unknown'
    }

    It 'rejects Granted No with no reported missing baseline grant as malformed' {
        Mock Test-GraphPermission -ModuleName TenantPulse {
            New-TestPermissionFindings -Granted 'No' -MissingGrant 'None' -AuthenticationCompatible 'Yes'
        }
        $operations = @(@{ Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta' })

        $result = InModuleScope TenantPulse -ArgumentList $script:context, $operations {
            param($context, $operations)
            Invoke-PulsePermissionPreflight -Context $context -Operations $operations
        }

        $result.Decision | Should -Be 'Unknown'
        $result.ReasonCode | Should -Be 'malformed-finding-set'
        $result.Decisions['ConditionalAccessPolicy/List'].Decision | Should -Be 'Unknown'
    }

    It 'does not authorize an operation when no authorization decision exists' {
        $authorized = InModuleScope TenantPulse {
            Test-PulseOperationAuthorized -AuthorizationDecision $null -Type 'ConditionalAccessPolicy' -Operation 'List'
        }

        $authorized | Should -BeFalse
    }
}

Describe 'Invoke-PulseCollection permission preflight' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
        $script:context = New-TestContext
        $script:preflightDone = $false
        $script:dataOperations = [System.Collections.Generic.List[string]]::new()
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }


    It 'never invokes the ordinary data operation when MissingGrant is non-empty and still writes a terminal Failed/PermissionDenied outcome' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation -RequiredPermissions @(@{ Type = 'Application'; Value = 'Policy.Read.All' })
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            $script:preflightDone = $true
            New-TestPermissionFindings -MissingGrant 'Policy.Read.All'
        }
        Mock Get-GraphObject -ModuleName TenantPulse {
            throw 'ordinary data operation must not run after MissingGrant'
        }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        Invoke-TestCollection -Manifest $manifest

        $entry = Get-TestManifestStatus -Store $script:store -Dataset 'conditionalAccessPolicies'
        $entry.status | Should -Be 'Failed'
        $entry.failureClass | Should -Be 'PermissionDenied'
        $entry.reasonCode | Should -Match 'missing-grant'
        $entry.status | Should -Not -Be 'NotApplicable'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
        $script:preflightDone | Should -BeTrue
    }

    It 'never invokes the selected data operation when ServicePrincipalMissing is present' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            New-TestPermissionFindings -Granted 'No' -AuthenticationCompatible 'Unknown' -ServicePrincipalMissing
        }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'must not send when the service principal is missing' }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        Invoke-TestCollection -Manifest $manifest

        $entry = Get-TestManifestStatus -Store $script:store -Dataset 'conditionalAccessPolicies'
        $entry.status | Should -Be 'Failed'
        $entry.failureClass | Should -Be 'PermissionDenied'
        $entry.reasonCode | Should -Match 'service-principal-missing'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'never invokes the selected data operation when AuthenticationCompatible is No' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            New-TestPermissionFindings -AuthenticationCompatible 'No'
        }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'must not send when authentication is incompatible' }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        Invoke-TestCollection -Manifest $manifest

        $entry = Get-TestManifestStatus -Store $script:store -Dataset 'conditionalAccessPolicies'
        $entry.status | Should -Be 'Failed'
        $entry.failureClass | Should -Be 'PermissionDenied'
        $entry.reasonCode | Should -Match 'authentication-incompatible'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'never invokes the selected data operation when AuthenticationCompatible is Unknown' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            New-TestPermissionFindings -AuthenticationCompatible 'Unknown'
        }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'must not send when authentication compatibility is unknown' }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        Invoke-TestCollection -Manifest $manifest

        $entry = Get-TestManifestStatus -Store $script:store -Dataset 'conditionalAccessPolicies'
        $entry.status | Should -Be 'Failed'
        $entry.failureClass | Should -Be 'GateUnknown'
        $entry.reasonCode | Should -Match 'authentication-unknown'
        $entry.failureClass | Should -Not -Be 'NotApplicable'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'never invokes the selected data operation when Test-GraphPermission throws a bootstrap-trap error' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            throw "The analyzer identity needs the application permission 'Application.Read.All' or 'Directory.Read.All' in that tenant."
        }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'must not send after bootstrap-trap' }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        Invoke-TestCollection -Manifest $manifest

        $entry = Get-TestManifestStatus -Store $script:store -Dataset 'conditionalAccessPolicies'
        $entry.status | Should -Be 'Failed'
        $entry.failureClass | Should -Be 'GateUnknown'
        $entry.reasonCode | Should -Match 'bootstrap-trap'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'never invokes the selected data operation when the finding set is malformed' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            @([pscustomobject]@{ Finding = 'Configured'; Value = 'Yes' })
        }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'must not send after malformed findings' }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        Invoke-TestCollection -Manifest $manifest

        $entry = Get-TestManifestStatus -Store $script:store -Dataset 'conditionalAccessPolicies'
        $entry.status | Should -Be 'Failed'
        $entry.failureClass | Should -Be 'GateUnknown'
        $entry.reasonCode | Should -Match 'malformed-finding-set'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'never invokes a selected data operation whose GraphKit descriptor cannot be resolved' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            throw "No Graph operation is registered for '$Type/$Operation'."
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            @($Baseline).Count | Should -Be 0
            New-TestPermissionFindings
        }
        Mock Get-GraphObject -ModuleName TenantPulse {
            throw 'an operation absent from the permission baseline must not be sent'
        }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'futureDataset'; Type = 'FutureGraphResource'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        Invoke-TestCollection -Manifest $manifest

        $entry = Get-TestManifestStatus -Store $script:store -Dataset 'futureDataset'
        $entry.status | Should -Be 'Failed'
        $entry.failureClass | Should -Be 'GateUnknown'
        $entry.reasonCode | Should -Be 'descriptor-unresolved'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'sends only the preflight-approved ordinary operation set' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            if ($Type -eq 'ConditionalAccessPolicy') {
                New-TestDescriptor -Type $Type -Operation $Operation -ApiVersion 'beta' `
                    -RequiredPermissions @(@{ Type = 'Application'; Value = 'Policy.Read.All' })
            }
            else {
                New-TestDescriptor -Type $Type -Operation $Operation -ApiVersion 'v1.0' `
                    -RequiredPermissions @(@{ Type = 'Application'; Value = 'DeviceManagementManagedDevices.Read.All' })
            }
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            $script:preflightDone = $true
            New-TestPermissionFindings -Granted 'Yes' -MissingGrant 'Policy.Read.All' -AuthenticationCompatible 'Yes'
        }
        Mock Get-GraphObject -ModuleName TenantPulse {
            if (-not $script:preflightDone) { throw 'data operation before preflight' }
            $script:dataOperations.Add(('{0}/{1}' -f $Type, $Operation))
            if ($Type -eq 'ConditionalAccessPolicy') {
                throw 'denied ordinary operation must not be sent'
            }
            return @([pscustomobject]@{ id = 'device-1' })
        }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
            [pscustomobject]@{ Dataset = 'managedDevices'; Type = 'ManagedDevice'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false }
        )
        Invoke-TestCollection -Manifest $manifest

        $denied = Get-TestManifestStatus -Store $script:store -Dataset 'conditionalAccessPolicies'
        $granted = Get-TestManifestStatus -Store $script:store -Dataset 'managedDevices'
        $denied.status | Should -Be 'Failed'
        $denied.failureClass | Should -Be 'PermissionDenied'
        $granted.status | Should -Be 'Collected'
        $script:dataOperations | Should -Be @('ManagedDevice/List')
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter { $Type -eq 'ManagedDevice' }
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' }
    }

    It 'never invokes composite child data operations when a required child grant is missing' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            if ($Type -eq 'Group') {
                New-TestDescriptor -Type $Type -Operation $Operation -ApiVersion 'v1.0' `
                    -RequiredPermissions @(@{ Type = 'Application'; Value = 'Group.Read.All' })
            }
            else {
                New-TestDescriptor -Type $Type -Operation $Operation -ApiVersion 'beta' `
                    -RequiredPermissions @(@{ Type = 'Application'; Value = 'DeviceManagementRBAC.Read.All' })
            }
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            New-TestPermissionFindings -Granted 'Yes' -MissingGrant 'Group.Read.All' -AuthenticationCompatible 'Yes'
        }
        Mock Get-GraphObject -ModuleName TenantPulse {
            $script:dataOperations.Add(('{0}/{1}' -f $Type, $Operation))
            throw 'composite child must not be sent'
        }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'intuneRbacGroupProtection'; Type = 'IntuneRbacGroupProtectionWalk'; Operation = 'Walk'; ApiVersion = 'beta'; Pending = $true }
        )
        Invoke-TestCollection -Manifest $manifest

        $entry = Get-TestManifestStatus -Store $script:store -Dataset 'intuneRbacGroupProtection'
        $entry.status | Should -Be 'Failed'
        $entry.failureClass | Should -Be 'PermissionDenied'
        $script:dataOperations | Should -BeNullOrEmpty
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'sends only preflight-approved composite children and preserves child gaps after a granted decision' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation -ApiVersion 'beta' `
                -RequiredPermissions @(@{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' })
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            $script:preflightDone = $true
            New-TestPermissionFindings
        }
        $planRegistry = InModuleScope TenantPulse {
            @{
                endpointSecurityDiskEncryptionPolicies = @{
                    Command = {
                        param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym)
                        $null = $Context; $null = $ManifestEntry; $null = $ProfileId; $null = $TenantPseudonym

                        $gap = New-PulseCollectionGap -Scope 'policy-2/settings' -FailureClass 'ProviderFailed' `
                            -ReasonCode 'child-failed' -Detail @{ child = 'policy-2' } `
                            -Operation 'ConfigurationPolicySetting.ListBeta' -ApiVersion 'beta'
                        New-PulseCollectionOutcome -Dataset $Dataset -Status Partial `
                            -Rows @([pscustomobject]@{ policyId = 'policy-1'; isFullDiskEncryption = $true }) -Gaps @($gap) `
                            -ReasonCode 'partial' -Detail @{ childCount = 2 } -Provider 'GraphKit' -ApiVersion 'beta' `
                            -Operations @('ConfigurationPolicy.ListBeta', 'ConfigurationPolicySetting.ListBeta')
                    }
                    Operations = @(
                        @{ Type = 'ConfigurationPolicy'; Operation = 'ListBeta'; ApiVersion = 'beta' }
                        @{ Type = 'ConfigurationPolicySetting'; Operation = 'ListBeta'; ApiVersion = 'beta' }
                    )
                }
            }
        }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'endpointSecurityDiskEncryptionPolicies'; Type = 'EndpointSecurityDiskEncryptionPolicyWalk'; Operation = 'Walk'; ApiVersion = 'beta'; Pending = $true }
        )
        Invoke-TestCollection -Manifest $manifest -ProviderPlanRegistry $planRegistry

        $entry = Get-TestManifestStatus -Store $script:store -Dataset 'endpointSecurityDiskEncryptionPolicies'
        $entry.status | Should -Be 'Partial'
        $entry.gaps[0].scope | Should -Be 'policy-2/settings'
        $entry.gaps[0].operation | Should -Be 'ConfigurationPolicySetting.ListBeta'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
        Should-Invoke Test-GraphPermission -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'includes expansion operations in the catalog-wide baseline before any expansion data operation' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation -ApiVersion 'beta' `
                -RequiredPermissions @(@{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' })
        }
        $capturedBaseline = [System.Collections.Generic.List[object]]::new()
        Mock Test-GraphPermission -ModuleName TenantPulse {
            foreach ($entry in @($Baseline)) { $capturedBaseline.Add($entry) }
            New-TestPermissionFindings -MissingGrant 'DeviceManagementConfiguration.Read.All'
        }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'expansion data operation must not run' }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        $operations = InModuleScope TenantPulse -ArgumentList $manifest {
            param($manifest)
            Get-PulsePermissionPreflightOperations -Manifest $manifest -ExpandSettings
        }
        $authorization = InModuleScope TenantPulse -ArgumentList $script:context, $operations {
            param($context, $operations)
            Invoke-PulsePermissionPreflight -Context $context -Operations $operations
        }

        $baselineTypes = @($capturedBaseline | ForEach-Object { '{0}/{1}' -f $_.Type, $_.Operation })
        $baselineTypes | Should -Contain 'ConfigurationPolicy/ListBeta'
        $baselineTypes | Should -Contain 'ConfigurationSettingDefinition/ListBeta'
        $authorization.Decisions['ConfigurationPolicy/ListBeta'].Decision | Should -Be 'Denied'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'includes app-health operations in the union and does not send them when denied' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation -ApiVersion 'beta' `
                -RequiredPermissions @(@{ Type = 'Application'; Value = 'DeviceManagementApps.Read.All' })
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            New-TestPermissionFindings -MissingGrant 'DeviceManagementApps.Read.All'
        }

        $operations = InModuleScope TenantPulse {
            Get-PulsePermissionPreflightOperations -Manifest @() -AdditionalOperations @(
                @{ Type = 'MobileApp'; Operation = 'ListBeta'; ApiVersion = 'beta' }
            )
        }
        $authorization = InModuleScope TenantPulse -ArgumentList $script:context, $operations {
            param($context, $operations)
            Invoke-PulsePermissionPreflight -Context $context -Operations $operations
        }

        $authorization.Decisions['MobileApp/ListBeta'].Decision | Should -Be 'Denied'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'still records Failed/PermissionDenied for a later 403 after a granted preflight' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation -ApiVersion 'beta'
        }

        Mock Test-GraphPermission -ModuleName TenantPulse {
            $script:preflightDone = $true
            New-TestPermissionFindings
        }
        Mock Get-GraphObject -ModuleName TenantPulse {
            throw "Get-GraphObject failed for 'ConditionalAccessPolicy/List': 403 Forbidden."
        }


        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        Invoke-TestCollection -Manifest $manifest

        $entry = Get-TestManifestStatus -Store $script:store -Dataset 'conditionalAccessPolicies'

        $entry.status | Should -Be 'Failed'
        $entry.failureClass | Should -Be 'PermissionDenied'
        $entry.reasonCode | Should -Be 'permission-denied'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'does not let a granted preflight erase Truncated or Indeterminate envelope certainty' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            New-TestDescriptor -Type $Type -Operation $Operation -ApiVersion 'beta'
        }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            New-TestPermissionFindings
        }
        Mock Get-GraphObject -ModuleName TenantPulse {
            [pscustomobject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Outcome    = 'Succeeded'
                Certainty  = 'Indeterminate'
                Truncated  = $true
                Data       = [pscustomobject]@{ id = 'p1' }
            }
        }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        Invoke-TestCollection -Manifest $manifest

        $entry = Get-TestManifestStatus -Store $script:store -Dataset 'conditionalAccessPolicies'
        $entry.status | Should -Be 'Partial'
        $entry.status | Should -Not -Be 'Collected'
        $entry.gaps | Should -Not -BeNullOrEmpty
        $entry.gaps[0].failureClass | Should -Be 'Indeterminate'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly
    }


}

BeforeDiscovery {
    $rootFailureCases = @(
        @{ Name = 'deadline'; Outcome = 'DeadlineExpired'; Certainty = 'Indeterminate'; StatusCode = 408; Category = [System.Management.Automation.ErrorCategory]::OperationTimeout; FailureClass = 'DeadlineExpired'; ReasonCode = 'deadline-expired'; Aborts = $false }
        @{ Name = 'cancellation'; Outcome = 'Cancelled'; Certainty = 'Known'; StatusCode = 0; Category = [System.Management.Automation.ErrorCategory]::OperationStopped; FailureClass = 'Cancelled'; ReasonCode = 'cancelled'; Aborts = $false }
        @{ Name = 'indeterminate certainty'; Outcome = 'Failed'; Certainty = 'Indeterminate'; StatusCode = 500; Category = [System.Management.Automation.ErrorCategory]::ResourceUnavailable; FailureClass = 'Indeterminate'; ReasonCode = 'indeterminate'; Aborts = $false }
        @{ Name = 'permission denial'; Outcome = 'Failed'; Certainty = 'Known'; StatusCode = 403; Category = [System.Management.Automation.ErrorCategory]::PermissionDenied; FailureClass = 'PermissionDenied'; ReasonCode = 'permission-denied'; Aborts = $false }
        @{ Name = 'authentication failure'; Outcome = 'Failed'; Certainty = 'Known'; StatusCode = 401; Category = [System.Management.Automation.ErrorCategory]::AuthenticationError; FailureClass = 'AuthenticationFailed'; ReasonCode = 'authentication-failed'; Aborts = $true }
        @{ Name = 'provider failure'; Outcome = 'Failed'; Certainty = 'Known'; StatusCode = 503; Category = [System.Management.Automation.ErrorCategory]::ResourceUnavailable; FailureClass = 'ProviderFailed'; ReasonCode = 'provider-failed'; Aborts = $false }
    )
}

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

    InModuleScope TenantPulse {
        function Get-GraphObject { param() }
        function Test-GraphPermission { param() }
    }
    InModuleScope TenantPulse -ArgumentList $script:graphEnvelopeHelperPath {
        param($helperPath)
        . $helperPath
    }
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }
    Mock Test-GraphPermission -ModuleName TenantPulse {
        @(
            [pscustomobject]@{ Finding = 'Configured'; Value = 'Unknown' }
            [pscustomobject]@{ Finding = 'Granted'; Value = 'Yes' }
            [pscustomobject]@{ Finding = 'MissingGrant'; Value = 'None' }
            [pscustomobject]@{ Finding = 'ExcessGranted'; Value = 'None' }
            [pscustomobject]@{ Finding = 'AuthenticationCompatible'; Value = 'Yes' }
        )
    }


    function New-ExpansionPipelineGraphErrorRecord {
        param($Outcome, $Certainty, $StatusCode, $Category, [string] $PrivateMarker)
        $target = [pscustomobject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Outcome = $Outcome
            Certainty = $Certainty
            Telemetry = @([pscustomobject]@{ Attempt = 1; StatusCode = $StatusCode })
        }
        [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new("Graph failure contained $PrivateMarker"),
            "GraphKit.OperationFailed.$StatusCode",
            $Category,
            $target)
    }
}

Describe 'Invoke-PulseSettingsCatalogExpansionPipeline' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
        $script:context = [pscustomobject]@{ TenantId = 'tenant-guid-not-real'; ProfileId = 'contoso-lab' }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'on a clean run: collects configurationPolicies, captures the corpus, and reaches Expanded' {
        $policies = @([pscustomobject]@{ id = 'policy-1'; name = 'P1'; templateReference = [pscustomobject]@{ templateId = ''; templateFamily = 'none' } })
        $definitions = @([pscustomobject]@{ id = 'setting-a'; name = 'a'; displayName = 'A' })
        $settingsResponse = @([pscustomobject]@{
                id             = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'setting-a'
                    simpleSettingValue   = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'v' }
                }
            })

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicy' -and $Operation -eq 'ListBeta' } { New-PulseTestGraphEnvelope -Data $policies }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' } { New-PulseTestGraphEnvelope -Data $definitions }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { New-PulseTestGraphEnvelope -Data $settingsResponse }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicyAssignment' } { New-PulseTestGraphEnvelope }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)
            Invoke-PulseSettingsCatalogExpansionPipeline -Store $store -Context $context -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.datasets.configurationPolicies.status | Should -Be 'Collected'
        $manifest.references.settingDefinitions.status | Should -Be 'Captured'
        $manifest.expansions.settingsCatalog.status | Should -Be 'Expanded'
        $manifest.expansions.settingsCatalog.rowCount | Should -Be 1

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $Type -eq 'ConfigurationPolicy' -and $Operation -eq 'ListBeta' -and $null -ne $Context -and $Context.ProfileId -eq 'contoso-lab'
        }
    }

    It 'maps a root <Name> through the canonical DTO, persists no provider text, and stops the expansion network path' -ForEach $rootFailureCases {
        $privateMarker = 'PRIVATE' + '-ROOT-BODY'
        $record = New-ExpansionPipelineGraphErrorRecord -Outcome $Outcome -Certainty $Certainty `
            -StatusCode $StatusCode -Category $Category -PrivateMarker $privateMarker
        $script:rootFailureRecord = $record
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicy' } { throw $script:rootFailureRecord }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)
            Invoke-PulseSettingsCatalogExpansionPipeline -Store $store -Context $context -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123'
        }

        $manifestText = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $manifest = $manifestText | ConvertFrom-Json
        $manifest.datasets.configurationPolicies.status | Should -Be 'Failed'
        $manifest.datasets.configurationPolicies.failureClass | Should -Be $FailureClass
        $manifest.datasets.configurationPolicies.reasonCode | Should -Be $ReasonCode
        $manifest.datasets.configurationPolicies.reason | Should -Be "graph-request-failed: failureClass=$FailureClass; reasonCode=$ReasonCode; statusCode=$StatusCode"
        $manifest.expansions.settingsCatalog.status | Should -Be 'NotExpanded'
        $manifest.expansions.settingsCatalog.reason | Should -Match 'configurationPolicies unavailable'
        $manifestText | Should -Not -Match ([regex]::Escape($privateMarker))
        if ($Aborts) {
            $manifest.collectionFailure | Should -Not -BeNullOrEmpty
        } else {
            $manifest.collectionFailure | Should -BeNullOrEmpty
        }

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' }
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' }
    }

    It 'a definitions-corpus capture failure still reaches Invoke-PulseSettingsCatalogExpansion, which writes NotExpanded itself' {
        $policies = @([pscustomobject]@{ id = 'policy-1'; name = 'P1' })
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicy' } { New-PulseTestGraphEnvelope -Data $policies }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' } { throw 'corpus fetch failed' }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)
            Invoke-PulseSettingsCatalogExpansionPipeline -Store $store -Context $context -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.datasets.configurationPolicies.status | Should -Be 'Collected'
        $manifest.references.settingDefinitions.status | Should -Be 'Failed'
        $manifest.expansions.settingsCatalog.status | Should -Be 'NotExpanded'
        $manifest.expansions.settingsCatalog.reason | Should -Match 'definitions corpus unavailable'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' }
    }

    It 'persists the global authentication failure when the expansion aborts authentication and then throws' {
        $policies = @([pscustomobject]@{
                id = 'policy-1'; name = 'P1'
                templateReference = [pscustomobject]@{ templateId = ''; templateFamily = 'none' }
            })
        $definitions = @([pscustomobject]@{ id = 'setting-a'; name = 'a'; displayName = 'A' })
        $privateMarker = 'PRIVATE' + '-POST-AUTH-SETTINGS-THROW'
        $script:settingsPostAuthThrowMarker = $privateMarker
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicy' } { New-PulseTestGraphEnvelope -Data $policies }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' } { New-PulseTestGraphEnvelope -Data $definitions }
        Mock Invoke-PulseSettingsCatalogExpansion -ModuleName TenantPulse {
            $NetworkAbortState.AuthenticationAborted = $true
            $NetworkAbortState.Reason = 'authentication-failed: collection aborted'
            throw $script:settingsPostAuthThrowMarker
        }
        $state = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $state {
            param($store, $context, $state)
            Invoke-PulseSettingsCatalogExpansionPipeline -Store $store -Context $context `
                -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123' -NetworkAbortState $state
        }

        $manifestText = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $manifest = $manifestText | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'Failed'
        $manifest.collectionFailure | Should -Not -BeNullOrEmpty
        $manifestText | Should -Not -Match ([regex]::Escape($privateMarker))
        $state.AuthenticationAborted | Should -BeTrue
        Should-Invoke Invoke-PulseSettingsCatalogExpansion -ModuleName TenantPulse -Times 1 -Exactly
    }
}

Describe 'Get-PulseTenantSnapshot -ExpandSettings' {
    BeforeEach {
        $script:outputRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    }

    AfterEach {
        Remove-Item -LiteralPath $script:outputRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'runs Administrative Templates and then publishes the expansion summary under the opt-in switch' {
        InModuleScope TenantPulse {
            function Get-GraphContext { param() }
            function Get-GraphOperation { param() }
            function Get-GraphObject { param() }
        }
        Mock Get-GraphContext -ModuleName TenantPulse {
            [pscustomobject]@{
                TenantId = '11111111-1111-1111-1111-111111111111'
                ProfileId = 'contoso-controller'
                ClientId = [guid]'22222222-2222-2222-2222-222222222222'
            }
        }
        Mock Get-GraphOperation -ModuleName TenantPulse {
            @{
                Type = $Type
                Operation = $Operation
                ApiVersion = if ($Type -in @('Organization', 'SubscribedSku')) { 'v1.0' } else { 'beta' }
                ThrottleClass = 'Read'
                ReplayPolicy = 'Safe'
                RequiredPermissions = @()
            }
        }
        Mock Get-GraphObject -ModuleName TenantPulse { @() }
        $script:ExpansionControllerCalls = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-PulseAdministrativeTemplateExpansion -ModuleName TenantPulse {
            $script:ExpansionControllerCalls.Add('administrativeTemplates') | Out-Null
            [pscustomobject]@{ Status = 'Expanded' }
        }
        Mock Invoke-PulseExpansionSummary -ModuleName TenantPulse {
            $script:ExpansionControllerCalls.Add('expansionSummary') | Out-Null
            [pscustomobject]@{ Status = 'Expanded' }
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:outputRoot {
            param($outputRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-controller' -OutputPath $outputRoot `
                -IncludeCheck 'TP.ENT.0001' -ExpandSettings
        }

        $result.Root | Should -Not -BeNullOrEmpty
        @($script:ExpansionControllerCalls) | Should -Be @('administrativeTemplates', 'expansionSummary')
        Should-Invoke Invoke-PulseAdministrativeTemplateExpansion -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $Requested -and $ProfileId -eq 'contoso-controller'
        }
        Should-Invoke Invoke-PulseExpansionSummary -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $Requested -and $ProfileId -eq 'contoso-controller'
        }
    }

    It 'is OFF by default: no configurationPolicies dataset and no settingsCatalog expansion entry are written' {
        InModuleScope TenantPulse {
            function Get-GraphContext { param() }
            function Get-GraphObject { param() }
        }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ TenantId = 'tenant-guid-default-off'; ProfileId = 'contoso-default' } }
        Mock Get-GraphObject -ModuleName TenantPulse { New-PulseTestGraphEnvelope }

        $store = InModuleScope TenantPulse -ArgumentList $script:outputRoot {
            param($outputRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-default' -OutputPath $outputRoot -IncludeCheck 'TP.ENT.0001'
        }

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        ($manifest.datasets.PSObject.Properties.Name -contains 'configurationPolicies') | Should -BeFalse
        ($manifest.expansions.PSObject.Properties.Name -contains 'settingsCatalog') | Should -BeFalse

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -eq 'ConfigurationPolicy' }
    }

    It 'suppresses every later network expansion after ordinary collection records AuthenticationFailed' {
        InModuleScope TenantPulse {
            function Get-GraphContext { param() }
            function Get-GraphObject { param() }
        }
        $privateMarker = 'PRIVATE' + '-COLLECTION-AUTH-BODY'
        $record = New-ExpansionPipelineGraphErrorRecord -Outcome 'Failed' -Certainty 'Known' `
            -StatusCode 401 -Category ([System.Management.Automation.ErrorCategory]::AuthenticationError) `
            -PrivateMarker $privateMarker
        $script:rootFailureRecord = $record
        Mock Get-GraphContext -ModuleName TenantPulse {
            [pscustomobject]@{
                TenantId = '11111111-1111-1111-1111-111111111111'
                ProfileId = 'contoso-auth-suppression'
                ClientId = [guid]'22222222-2222-2222-2222-222222222222'
            }
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' } {
            throw $script:rootFailureRecord
        }
        Mock Get-GraphObject -ModuleName TenantPulse { New-PulseTestGraphEnvelope }

        $store = InModuleScope TenantPulse -ArgumentList $script:outputRoot {
            param($outputRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-auth-suppression' -OutputPath $outputRoot `
                -IncludeCheck 'TP.ENT.0001' -ExpandSettings
        }

        $manifestText = Get-Content -LiteralPath $store.ManifestPath -Raw
        $manifest = $manifestText | ConvertFrom-Json
        $manifest.collectionFailure | Should -Not -BeNullOrEmpty
        $manifest.expansions.settingsCatalog.status | Should -Be 'NotExpanded'
        $manifest.expansions.compliance.status | Should -Be 'NotExpanded'
        $manifest.expansions.deviceConfiguration.status | Should -Be 'NotExpanded'
        $manifestText | Should -Not -Match ([regex]::Escape($privateMarker))

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -eq 'ConfigurationPolicy' }
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -like '*Assignment' }
    }

    # P0-1 review fix (reproduced defect): Get-PulseTenantSnapshot -ExpandSettings used to
    # return TWO objects on its output pipeline (the snapshot $store from its own `return`,
    # plus Invoke-PulseSettingsCatalogExpansionPipeline's own uncaptured summary object
    # leaking through) - which silently turned `$store = Get-PulseTenantSnapshot @params`
    # into a two-element array in Invoke-PulseAssessment, breaking `$store.Root` downstream.
    It 'ON-STATE (P0-1): -ExpandSettings still returns EXACTLY ONE object from the pipeline' {
        InModuleScope TenantPulse {
            function Get-GraphContext { param() }
            function Get-GraphObject { param() }
        }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ TenantId = 'tenant-guid-p0-1'; ProfileId = 'contoso-p0-1' } }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicy' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse { New-PulseTestGraphEnvelope }

        $results = @(InModuleScope TenantPulse -ArgumentList $script:outputRoot {
                param($outputRoot)
                Get-PulseTenantSnapshot -ProfileId 'contoso-p0-1' -OutputPath $outputRoot -IncludeCheck 'TP.ENT.0001' -ExpandSettings
            })

        $results.Count | Should -Be 1
        $results[0].Root | Should -Not -BeNullOrEmpty

        # Belt-and-suspenders: the pipeline function itself, called directly, also emits
        # nothing on the output pipeline.
        $store2Root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $store2 = InModuleScope TenantPulse -ArgumentList $store2Root {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
        try {
            $context = [pscustomobject]@{ TenantId = 'tenant-guid-p0-1-direct'; ProfileId = 'contoso-p0-1-direct' }
            $directResults = @(InModuleScope TenantPulse -ArgumentList $store2, $context {
                    param($store2, $context)
                    Invoke-PulseSettingsCatalogExpansionPipeline -Store $store2 -Context $context -ProfileId 'contoso-p0-1-direct' -TenantPseudonym 'tp-direct'
                })
            $directResults.Count | Should -Be 0
        } finally {
            Remove-Item -LiteralPath $store2Root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

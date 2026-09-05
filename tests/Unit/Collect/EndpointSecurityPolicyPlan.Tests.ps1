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

    function script:New-EndpointPolicy {
        param(
            [Parameter(Mandatory)] [string] $Id,
            [Parameter(Mandatory)] [string] $Name,
            [Parameter(Mandatory)] [string] $Family,
            [Parameter()] [string] $TemplateId = ''
        )
        [pscustomobject]@{
            id = $Id
            name = $Name
            templateReference = [pscustomobject]@{
                templateFamily = $Family
                templateId = $TemplateId
            }
        }
    }

    function script:New-EndpointSetting {
        param(
            [Parameter(Mandatory)] [string] $DefinitionId,
            [Parameter(Mandatory)] $Value,
            [Parameter()] [ValidateSet('choice', 'simple')] [string] $Kind = 'choice'
        )
        $valueNode = [pscustomobject]@{
            value = $Value
            children = @()
        }
        $instance = [pscustomobject]@{
            settingDefinitionId = $DefinitionId
        }
        if ($Kind -eq 'simple') {
            $instance | Add-Member -NotePropertyName simpleSettingValue -NotePropertyValue ([pscustomobject]@{ value = $Value })
        } else {
            $instance | Add-Member -NotePropertyName choiceSettingValue -NotePropertyValue $valueNode
        }
        [pscustomobject]@{ id = [guid]::NewGuid().ToString(); settingInstance = $instance }
    }

    function script:Invoke-EndpointPlanFixture {
        param(
            [Parameter(Mandatory)] [string] $Dataset,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policies,
            [Parameter(Mandatory)] [hashtable] $SettingsByPolicy,
            [Parameter()] [hashtable] $SettingErrors = @{},
            [Parameter()] [hashtable] $AssignmentErrors = @{},
            [Parameter()] [AllowNull()] $AssignmentResult,
            [Parameter()] [switch] $UseAssignmentResult
        )

        $fixture = @{
            Dataset          = $Dataset
            Policies         = @($Policies)
            SettingsByPolicy = $SettingsByPolicy
            SettingErrors    = $SettingErrors
            AssignmentErrors = $AssignmentErrors
            AssignmentResult = $AssignmentResult
            UseAssignmentResult = [bool] $UseAssignmentResult
        }

        InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            $script:EndpointFixture = $fixture
            $script:EndpointCalls = [System.Collections.Generic.List[object]]::new()

            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {
                param($Type, $Operation, $ApiVersion)
                $script:EndpointCalls.Add([pscustomobject]@{
                    Kind       = 'Descriptor'
                    Type       = $Type
                    Operation  = $Operation
                    ApiVersion = $ApiVersion
                })
            }
            Mock Get-GraphObject -ModuleName TenantPulse {
                param($Context, $Type, $Operation, $Parameters)
                $policyId = if ($null -ne $Parameters) { [string] $Parameters.id } else { $null }
                $script:EndpointCalls.Add([pscustomobject]@{
                    Kind       = 'Graph'
                    Type       = $Type
                    Operation  = $Operation
                    PolicyId   = $policyId
                })
                if ($Type -eq 'ConfigurationPolicy') {
                    return New-PulseTestGraphEnvelope -Data @($script:EndpointFixture.Policies)
                }
                if ($Type -eq 'ConfigurationPolicySetting') {
                    if ($script:EndpointFixture.SettingErrors.ContainsKey($policyId)) {
                        throw $script:EndpointFixture.SettingErrors[$policyId]
                    }
                    if (-not $script:EndpointFixture.SettingsByPolicy.ContainsKey($policyId)) {
                        return New-PulseTestGraphEnvelope -Data @()
                    }
                    return New-PulseTestGraphEnvelope -Data @($script:EndpointFixture.SettingsByPolicy[$policyId])
                }
                if ($Type -eq 'ConfigurationPolicyAssignment') {
                    if ($script:EndpointFixture.AssignmentErrors.ContainsKey($policyId)) {
                        throw $script:EndpointFixture.AssignmentErrors[$policyId]
                    }
                    if ($script:EndpointFixture.UseAssignmentResult) {
                        return $script:EndpointFixture.AssignmentResult
                    }
                    return New-PulseTestGraphEnvelope -Data @(
                        @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-assigned' } }
                    )
                }
                throw "Unexpected Graph call '$Type/$Operation'."
            }

            $abortState = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }
            $outcome = Invoke-PulseEndpointSecurityPolicyPlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset $fixture.Dataset `
                -ManifestEntry ([pscustomobject]@{ Dataset = $fixture.Dataset; ApiVersion = 'beta'; Type = 'EndpointSecurityPolicyWalk'; Operation = 'Walk' }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture' `
                -NetworkAbortState $abortState

            [pscustomobject]@{
                Outcome = $outcome
                Calls   = @($script:EndpointCalls)
                Abort   = $abortState
            }
        }
    }
}


Describe 'Invoke-PulseEndpointSecurityPolicyPlan' {
    It 'keeps extracted setting tokens scoped to their source setting' {
        $settings = @(
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_backupdirectory' -Value 'device_vendor_msft_laps_backupdirectory_1')
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordcomplexity' -Value 'device_vendor_msft_laps_passwordcomplexity_4')
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordlength' -Value '8' -Kind simple)
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_postauthenticationactions' -Value 'device_vendor_msft_laps_postauthenticationactions_0')
        )

        $fixture = [pscustomobject]@{ Settings = $settings }
        $rows = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            @(Get-PulseEndpointSecuritySettingTokens -Settings $fixture.Settings)
        }

        @($rows).Count | Should -Be 4
        @($rows | ForEach-Object { $_.Tokens.Count }) | Should -Be @(1, 1, 1, 1)
        @($rows | ForEach-Object DefinitionId) | Should -Be @(
            'device_vendor_msft_laps_backupdirectory'
            'device_vendor_msft_laps_passwordcomplexity'
            'device_vendor_msft_laps_passwordlength'
            'device_vendor_msft_laps_postauthenticationactions'
        )
        $rows[3].Tokens[0] | Should -Be 'device_vendor_msft_laps_postauthenticationactions_0'
    }

    It 'resolves LAPS criteria nested under groupSettingCollectionValue children' {
        $children = @(
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_backupdirectory' -Value 'device_vendor_msft_laps_backupdirectory_1').settingInstance
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordcomplexity' -Value 'device_vendor_msft_laps_passwordcomplexity_4').settingInstance
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordlength' -Value '16' -Kind simple).settingInstance
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_postauthenticationactions' -Value 'device_vendor_msft_laps_postauthenticationactions_3').settingInstance
        )
        $settings = @(
            [pscustomobject]@{
                id = 'laps-group'
                settingInstance = [pscustomobject]@{
                    settingDefinitionId       = 'device_vendor_msft_laps_group'
                    groupSettingCollectionValue = @(
                        [pscustomobject]@{ children = $children }
                    )
                }
            }
        )

        $fixture = [pscustomobject]@{ Settings = $settings }
        $resolved = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            Resolve-PulseLapsPolicyValues -Settings $fixture.Settings
        }

        $resolved.backsUpToEntra | Should -BeTrue
        $resolved.hasSufficientComplexity | Should -BeTrue
        $resolved.hasSufficientLength | Should -BeTrue
        $resolved.hasPostAuthAction | Should -BeTrue
    }

    It 'maps numeric LAPS PostAuthenticationActions <Value> to <Expected>' -ForEach @(
        @{ Value = 1; Expected = $true }
        @{ Value = 3; Expected = $true }
        @{ Value = 5; Expected = $true }
        @{ Value = 11; Expected = $true }
        @{ Value = 0; Expected = $false }
    ) {
        $settings = @(
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_backupdirectory' -Value 'device_vendor_msft_laps_backupdirectory_1')
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordcomplexity' -Value 'device_vendor_msft_laps_passwordcomplexity_4')
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordlength' -Value '16' -Kind simple)
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_postauthenticationactions' -Value "device_vendor_msft_laps_postauthenticationactions_$Value")
        )

        $fixture = [pscustomobject]@{ Settings = $settings }
        $resolved = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            Resolve-PulseLapsPolicyValues -Settings $fixture.Settings
        }

        $resolved.hasPostAuthAction | Should -Be $Expected
    }

    It 'collects BitLocker full and used-space-only policies with native booleans and one settings read per policy' {
        $full = New-EndpointPolicy -Id 'bitlocker-full' -Name 'Full encryption' -Family 'endpointSecurityDiskEncryption'
        $used = New-EndpointPolicy -Id 'bitlocker-used' -Name 'Used-space-only' -Family 'endpointSecurityDiskEncryption'
        $child = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityDiskEncryptionPolicies' `
            -Policies @($used, $full) `
            -SettingsByPolicy @{
                'bitlocker-full' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1'))
                'bitlocker-used' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_2'))
            }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 2
        @($result.Outcome.Rows | ForEach-Object policyId) | Should -Be @('bitlocker-full', 'bitlocker-used')
        $result.Outcome.Rows[0].isFullDiskEncryption | Should -BeTrue
        $result.Outcome.Rows[1].isFullDiskEncryption | Should -BeFalse
        $result.Outcome.Rows[0].isFullDiskEncryption.GetType().FullName | Should -Be 'System.Boolean'
        $result.Outcome.Rows[0].PSObject.Properties.Name | Should -Contain 'policyId'
        $result.Outcome.Rows[0].PSObject.Properties.Name | Should -Contain 'policyName'
        $result.Outcome.Rows[0].PSObject.Properties.Name | Should -Contain 'isFullDiskEncryption'
        @($result.Calls | Where-Object { $_.Kind -eq 'Graph' -and $_.Type -eq 'ConfigurationPolicySetting' }).Count | Should -Be 2
    }

    It 'never infers full encryption from the parent enablement option when the child setting is absent' {
        $policy = New-EndpointPolicy -Id 'bitlocker-parent-only' -Name 'Parent only' -Family 'endpointSecurityDiskEncryption'
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityDiskEncryptionPolicies' `
            -Policies @($policy) `
            -SettingsByPolicy @{
                'bitlocker-parent-only' = @(New-EndpointSetting -DefinitionId 'device_vendor_msft_bitlocker_systemdrivesencryptiontype' -Value 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_1')
            }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:bitlocker-parent-only'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
    }

    It 'keeps all LAPS criteria on each policy instead of combining near-miss policies' {
        $templateId = 'adc46e5a-f4aa-4ff6-aeff-4f27bc525796'
        $p1 = New-EndpointPolicy -Id 'laps-one' -Name 'LAPS one' -Family 'endpointSecurityAccountProtection' -TemplateId $templateId
        $p2 = New-EndpointPolicy -Id 'laps-two' -Name 'LAPS two' -Family 'endpointSecurityAccountProtection' -TemplateId $templateId
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityLapsPolicies' `
            -Policies @($p1, $p2) `
            -SettingsByPolicy @{
                'laps-one' = @(
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_backupdirectory' -Value 'device_vendor_msft_laps_backupdirectory_1')
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordcomplexity' -Value 'device_vendor_msft_laps_passwordcomplexity_4')
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordlength' -Value '8' -Kind simple)
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_postauthenticationactions' -Value 'device_vendor_msft_laps_postauthenticationactions_0')
                )
                'laps-two' = @(
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_backupdirectory' -Value 'device_vendor_msft_laps_backupdirectory_0')
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordcomplexity' -Value 'device_vendor_msft_laps_passwordcomplexity_3')
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordlength' -Value '16' -Kind simple)
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_postauthenticationactions' -Value 'device_vendor_msft_laps_postauthenticationactions_3')
                )
            }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 2
        $result.Outcome.Rows[0].backsUpToEntra | Should -BeTrue
        $result.Outcome.Rows[0].hasSufficientComplexity | Should -BeTrue
        $result.Outcome.Rows[0].hasSufficientLength | Should -BeFalse
        $result.Outcome.Rows[0].hasPostAuthAction | Should -BeFalse
        $result.Outcome.Rows[1].backsUpToEntra | Should -BeFalse
        $result.Outcome.Rows[1].hasSufficientComplexity | Should -BeFalse
        $result.Outcome.Rows[1].hasSufficientLength | Should -BeTrue
        $result.Outcome.Rows[1].hasPostAuthAction | Should -BeTrue
        @($result.Outcome.Rows | Where-Object { $_.backsUpToEntra -and $_.hasSufficientComplexity -and $_.hasSufficientLength -and $_.hasPostAuthAction }).Count | Should -Be 0
    }

    It 'excludes an account-protection policy with the wrong LAPS template identity without reading its settings' {
        $wrong = New-EndpointPolicy -Id 'laps-wrong-template' -Name 'Wrong template' -Family 'endpointSecurityAccountProtection' -TemplateId '00000000-0000-0000-0000-000000000000'
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityLapsPolicies' `
            -Policies @($wrong) `
            -SettingsByPolicy @{
                'laps-wrong-template' = @(New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_backupdirectory' -Value 'device_vendor_msft_laps_backupdirectory_1')
            }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Calls | Where-Object { $_.Kind -eq 'Graph' -and $_.Type -eq 'ConfigurationPolicySetting' }).Count | Should -Be 0
    }

    It 'surfaces absent or unrecognized template metadata instead of publishing an authoritative empty endpoint-security result' -ForEach @(
        @{
            Label             = 'missing templateReference'
            Dataset           = 'endpointSecurityDiskEncryptionPolicies'
            TemplateReference = $null
            ExpectedReason    = 'missing-template-metadata'
        }
        @{
            Label             = 'missing templateFamily'
            Dataset           = 'endpointSecurityDiskEncryptionPolicies'
            TemplateReference = [pscustomobject]@{ templateId = 'template-without-family' }
            ExpectedReason    = 'missing-template-metadata'
        }
        @{
            Label             = 'unrecognized templateFamily'
            Dataset           = 'endpointSecurityDiskEncryptionPolicies'
            TemplateReference = [pscustomobject]@{ templateFamily = 'futureUnknownFamily'; templateId = 'future-template' }
            ExpectedReason    = 'unrecognized-template-metadata'
        }
        @{
            Label             = 'LAPS-candidate family without templateId'
            Dataset           = 'endpointSecurityLapsPolicies'
            TemplateReference = [pscustomobject]@{ templateFamily = 'endpointSecurityAccountProtection' }
            ExpectedReason    = 'missing-template-metadata'
        }
    ) {
        $policy = [pscustomobject]@{
            id                = 'policy-metadata-gap'
            name              = $Label
            templateReference = $TemplateReference
        }
        $result = Invoke-EndpointPlanFixture -Dataset $Dataset -Policies @($policy) -SettingsByPolicy @{}

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:policy-metadata-gap'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $result.Outcome.Gaps[0].ReasonCode | Should -Be $ExpectedReason
        $result.Outcome.Gaps[0].Operation | Should -Be 'ConfigurationPolicy.ListBeta'
        @($result.Calls | Where-Object { $_.Kind -eq 'Graph' -and $_.Type -ne 'ConfigurationPolicy' }).Count | Should -Be 0
    }

    It 'fails closed when a relevant <Label> policy has no usable id' -ForEach @(
        @{
            Label      = 'BitLocker'
            Dataset    = 'endpointSecurityDiskEncryptionPolicies'
            Family     = 'endpointSecurityDiskEncryption'
            TemplateId = ''
            IncludeId  = $false
            IdValue    = $null
        }
        @{
            Label      = 'LAPS'
            Dataset    = 'endpointSecurityLapsPolicies'
            Family     = 'endpointSecurityAccountProtection'
            TemplateId = 'adc46e5a-f4aa-4ff6-aeff-4f27bc525796'
            IncludeId  = $true
            IdValue    = '   '
        }
    ) {
        $policyProperties = [ordered]@{
            name = "Malformed $Label policy"
            templateReference = [pscustomobject]@{
                templateFamily = $Family
                templateId     = $TemplateId
            }
        }
        if ($IncludeId) { $policyProperties.id = $IdValue }
        $policy = [pscustomobject] $policyProperties

        $result = Invoke-EndpointPlanFixture `
            -Dataset $Dataset `
            -Policies @($policy) `
            -SettingsByPolicy @{}

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:unknown'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $result.Outcome.Gaps[0].ReasonCode | Should -Be 'missing-policy-id'
        $result.Outcome.Gaps[0].Operation | Should -Be 'ConfigurationPolicy.ListBeta'
        @($result.Calls | Where-Object { $_.Kind -eq 'Graph' -and $_.Type -eq 'ConfigurationPolicySetting' }).Count | Should -Be 0
    }

    It 'keeps a valid BitLocker row but marks the collection partial when a relevant peer has no id' {
        $valid = New-EndpointPolicy -Id 'bitlocker-valid' -Name 'Valid BitLocker' -Family 'endpointSecurityDiskEncryption'
        $malformed = [pscustomobject]@{
            name = 'Malformed BitLocker'
            templateReference = [pscustomobject]@{
                templateFamily = 'endpointSecurityDiskEncryption'
                templateId     = ''
            }
        }
        $child = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'

        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityDiskEncryptionPolicies' `
            -Policies @($malformed, $valid) `
            -SettingsByPolicy @{
                'bitlocker-valid' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1'))
            }

        $result.Outcome.Status | Should -Be 'Partial'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Rows[0].policyId | Should -Be 'bitlocker-valid'
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $result.Outcome.Gaps[0].ReasonCode | Should -Be 'missing-policy-id'
        @($result.Calls | Where-Object { $_.Kind -eq 'Graph' -and $_.Type -eq 'ConfigurationPolicySetting' }).Count | Should -Be 1
    }

    It 'records the same qualified primitive provenance for <PolicyCount> selected policies' -ForEach @(
        @{ PolicyCount = 0 }
        @{ PolicyCount = 1 }
        @{ PolicyCount = 2 }
    ) {
        $policies = @()
        $settingsByPolicy = @{}
        $child = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
        if ($PolicyCount -gt 0) {
            foreach ($policyIndex in 1..$PolicyCount) {
                $policyId = "bitlocker-$policyIndex"
                $policies += New-EndpointPolicy -Id $policyId -Name "Policy $policyIndex" -Family 'endpointSecurityDiskEncryption'
                $settingsByPolicy[$policyId] = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1'))
            }
        }

        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityDiskEncryptionPolicies' `
            -Policies $policies `
            -SettingsByPolicy $settingsByPolicy

        $result.Outcome.Operations | Should -Be @(
            'ConfigurationPolicy.ListBeta'
            'ConfigurationPolicySetting.ListBeta'
            'ConfigurationPolicyAssignment.ListBeta'
        )
    }

    It 'retains usable policy rows and a scoped gap when one policy settings read fails' {
        $good = New-EndpointPolicy -Id 'laps-good' -Name 'Good LAPS' -Family 'endpointSecurityAccountProtection' -TemplateId 'adc46e5a-f4aa-4ff6-aeff-4f27bc525796'
        $bad = New-EndpointPolicy -Id 'laps-bad' -Name 'Unreadable LAPS' -Family 'endpointSecurityAccountProtection' -TemplateId 'adc46e5a-f4aa-4ff6-aeff-4f27bc525796'
        $goodSettings = @(
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_backupdirectory' -Value 'device_vendor_msft_laps_backupdirectory_1')
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordcomplexity' -Value 'device_vendor_msft_laps_passwordcomplexity_4')
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordlength' -Value '16' -Kind simple)
            (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_postauthenticationactions' -Value 'device_vendor_msft_laps_postauthenticationactions_3')
        )
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityLapsPolicies' `
            -Policies @($bad, $good) `
            -SettingsByPolicy @{ 'laps-good' = $goodSettings } `
            -SettingErrors @{ 'laps-bad' = 'settings endpoint failed' }

        $result.Outcome.Status | Should -Be 'Partial'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Rows[0].policyId | Should -Be 'laps-good'
        $result.Outcome.Rows[0].backsUpToEntra | Should -BeTrue
        $result.Outcome.Rows[0].hasSufficientComplexity | Should -BeTrue
        $result.Outcome.Rows[0].hasSufficientLength | Should -BeTrue
        $result.Outcome.Rows[0].hasPostAuthAction | Should -BeTrue
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:laps-bad'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'ProviderFailed'
        $result.Outcome.Gaps[0].Operation | Should -Be 'ConfigurationPolicySetting.ListBeta'
    }

    It 'classifies every remaining selected policy as not attempted after a settings authentication failure' {
        $child = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
        $policies = @(
            (New-EndpointPolicy -Id 'bitlocker-a' -Name 'A' -Family 'endpointSecurityDiskEncryption')
            (New-EndpointPolicy -Id 'bitlocker-b' -Name 'B' -Family 'endpointSecurityDiskEncryption')
            (New-EndpointPolicy -Id 'bitlocker-c' -Name 'C' -Family 'endpointSecurityDiskEncryption')
        )
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityDiskEncryptionPolicies' `
            -Policies $policies `
            -SettingsByPolicy @{
                'bitlocker-b' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1'))
                'bitlocker-c' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1'))
            } `
            -SettingErrors @{ 'bitlocker-a' = 'AADSTS700016: application not found' }

        $result.Outcome.Status | Should -Be 'Failed'
        $result.Outcome.FailureClass | Should -Be 'AuthenticationFailed'
        $result.Outcome.ReasonCode | Should -Be 'authentication-failed'
        $result.Abort.AuthenticationAborted | Should -BeTrue
        $result.Abort.Reason | Should -BeExactly 'authentication-failed: collection aborted'
        @($result.Calls | Where-Object Kind -eq 'Graph' | Where-Object Type -eq 'ConfigurationPolicySetting').Count | Should -Be 1
        @($result.Outcome.Gaps).Count | Should -Be 3
        @($result.Outcome.Gaps.Scope) | Should -Be @('policy:bitlocker-a', 'policy:bitlocker-b', 'policy:bitlocker-c')
        @($result.Outcome.Gaps.ReasonCode) | Should -Be @(
            'authentication-failed'
            'not-attempted-after-authentication-failure'
            'not-attempted-after-authentication-failure'
        )
        $result.Outcome.Detail.enumeratedCount | Should -Be 3
        $result.Outcome.Detail.notExpandedCount | Should -Be 3
    }

    It 'counts a failed assignment expansion as NotExpanded and continues with later policies' {
        $child = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
        $policies = @(
            (New-EndpointPolicy -Id 'bitlocker-a' -Name 'A' -Family 'endpointSecurityDiskEncryption')
            (New-EndpointPolicy -Id 'bitlocker-b' -Name 'B' -Family 'endpointSecurityDiskEncryption')
        )
        $settings = @{
            'bitlocker-a' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1'))
            'bitlocker-b' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1'))
        }
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityDiskEncryptionPolicies' `
            -Policies $policies `
            -SettingsByPolicy $settings `
            -AssignmentErrors @{ 'bitlocker-a' = 'assignment provider unavailable' }

        $result.Outcome.Status | Should -Be 'Partial'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Rows[0].policyId | Should -Be 'bitlocker-b'
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:bitlocker-a'
        $result.Outcome.Gaps[0].Operation | Should -Be 'ConfigurationPolicyAssignment.ListBeta'
        $result.Outcome.Detail.enumeratedCount | Should -Be 2
        $result.Outcome.Detail.expandedCount | Should -Be 1
        $result.Outcome.Detail.partialCount | Should -Be 0
        $result.Outcome.Detail.notExpandedCount | Should -Be 1
    }

    It 'stops sends and classifies all later policies after an assignment authentication failure' {
        $child = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
        $policies = @(
            (New-EndpointPolicy -Id 'bitlocker-a' -Name 'A' -Family 'endpointSecurityDiskEncryption')
            (New-EndpointPolicy -Id 'bitlocker-b' -Name 'B' -Family 'endpointSecurityDiskEncryption')
        )
        $settings = @{
            'bitlocker-a' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1'))
            'bitlocker-b' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1'))
        }
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityDiskEncryptionPolicies' `
            -Policies $policies `
            -SettingsByPolicy $settings `
            -AssignmentErrors @{ 'bitlocker-a' = 'AADSTS700016: application not found' }

        $result.Outcome.Status | Should -Be 'Failed'
        $result.Outcome.FailureClass | Should -Be 'AuthenticationFailed'
        $result.Outcome.ReasonCode | Should -Be 'authentication-failed'
        $result.Abort.AuthenticationAborted | Should -BeTrue
        $result.Abort.Reason | Should -BeExactly 'authentication-failed: collection aborted'
        @($result.Calls | Where-Object Kind -eq 'Graph').Count | Should -Be 3
        @($result.Outcome.Gaps).Count | Should -Be 2
        @($result.Outcome.Gaps.Scope) | Should -Be @('policy:bitlocker-a', 'policy:bitlocker-b')
        @($result.Outcome.Gaps.ReasonCode) | Should -Be @(
            'authentication-failed'
            'not-attempted-after-authentication-failure'
        )
        @($result.Outcome.Gaps.Operation) | Should -Be @(
            'ConfigurationPolicyAssignment.ListBeta'
            'ConfigurationPolicyAssignment.ListBeta'
        )
        $result.Outcome.Detail.enumeratedCount | Should -Be 2
        $result.Outcome.Detail.notExpandedCount | Should -Be 2
    }

    It 'fails closed when an assignment read returns rows without a GraphKit envelope' {
        $policy = New-EndpointPolicy -Id 'bitlocker-rows-only' -Name 'Rows only' -Family 'endpointSecurityDiskEncryption'
        $child = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityDiskEncryptionPolicies' `
            -Policies @($policy) `
            -SettingsByPolicy @{ 'bitlocker-rows-only' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1')) } `
            -UseAssignmentResult `
            -AssignmentResult ([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-unsafe' } })

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:bitlocker-rows-only'
        $result.Outcome.Gaps[0].Operation | Should -Be 'ConfigurationPolicyAssignment.ListBeta'
    }

    It 'marks valid <Label> settings Partial when a successful assignment envelope contains a malformed target' -ForEach @(
        @{
            Label      = 'BitLocker'
            Dataset    = 'endpointSecurityDiskEncryptionPolicies'
            PolicyId   = 'bitlocker-malformed-assignment'
            Family     = 'endpointSecurityDiskEncryption'
            TemplateId = ''
        }
        @{
            Label      = 'LAPS'
            Dataset    = 'endpointSecurityLapsPolicies'
            PolicyId   = 'laps-malformed-assignment'
            Family     = 'endpointSecurityAccountProtection'
            TemplateId = 'adc46e5a-f4aa-4ff6-aeff-4f27bc525796'
        }
    ) {
        $policy = New-EndpointPolicy -Id $PolicyId -Name "$Label malformed assignment" -Family $Family -TemplateId $TemplateId
        if ($Label -eq 'BitLocker') {
            $child = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
            $settings = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1'))
        } else {
            $settings = @(
                (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_backupdirectory' -Value 'device_vendor_msft_laps_backupdirectory_1')
                (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordcomplexity' -Value 'device_vendor_msft_laps_passwordcomplexity_4')
                (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordlength' -Value '16' -Kind simple)
                (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_postauthenticationactions' -Value 'device_vendor_msft_laps_postauthenticationactions_3')
            )
        }

        $rawTargetCanary = 'futureAssignmentTarget-raw-target-canary'
        $assignmentEnvelope = New-PulseTestGraphEnvelope -Data @(
            [pscustomobject]@{
                id     = 'assignment-malformed'
                source = 'direct'
                target = [pscustomobject]@{
                    '@odata.type' = "#microsoft.graph.$rawTargetCanary"
                }
            }
        )
        $result = Invoke-EndpointPlanFixture `
            -Dataset $Dataset `
            -Policies @($policy) `
            -SettingsByPolicy @{ $PolicyId = $settings } `
            -UseAssignmentResult `
            -AssignmentResult $assignmentEnvelope

        $result.Outcome.Status | Should -Be 'Partial'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Rows[0].policyId | Should -Be $PolicyId
        $result.Outcome.Rows[0].assignmentIntent | Should -Be 'Malformed'
        if ($Label -eq 'BitLocker') {
            $result.Outcome.Rows[0].isFullDiskEncryption | Should -BeTrue
        } else {
            $result.Outcome.Rows[0].backsUpToEntra | Should -BeTrue
            $result.Outcome.Rows[0].hasSufficientComplexity | Should -BeTrue
            $result.Outcome.Rows[0].hasSufficientLength | Should -BeTrue
            $result.Outcome.Rows[0].hasPostAuthAction | Should -BeTrue
        }
        @($result.Outcome.Gaps).Count | Should -Be 1
        $gap = $result.Outcome.Gaps[0]
        $gap.Scope | Should -Be "policy:$PolicyId"
        $gap.FailureClass | Should -Be 'InvalidProviderData'
        $gap.ReasonCode | Should -Be 'assignment-intent-incomplete'
        $gap.Operation | Should -Be 'ConfigurationPolicyAssignment.ListBeta'
        $gap.ApiVersion | Should -Be 'beta'
        @($gap.Detail.Keys | Sort-Object) | Should -Be @('assignmentState', 'malformedReasons', 'policyId')
        $gap.Detail.assignmentState | Should -Be 'Malformed'
        @($gap.Detail.malformedReasons) | Should -Be @('unknown-target-type')
        ($gap | ConvertTo-Json -Depth 20 -Compress) | Should -Not -Match ([regex]::Escape($rawTargetCanary))
        $result.Outcome.Detail.enumeratedCount | Should -Be 1
        $result.Outcome.Detail.expandedCount | Should -Be 0
        $result.Outcome.Detail.partialCount | Should -Be 1
        $result.Outcome.Detail.notExpandedCount | Should -Be 0
    }

    It 'fails rather than returning an authoritative empty result when the only selected policy is missing a LAPS criterion' {
        $policy = New-EndpointPolicy -Id 'laps-missing' -Name 'Missing criterion' -Family 'endpointSecurityAccountProtection' -TemplateId 'adc46e5a-f4aa-4ff6-aeff-4f27bc525796'
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityLapsPolicies' `
            -Policies @($policy) `
            -SettingsByPolicy @{
                'laps-missing' = @(
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_backupdirectory' -Value 'device_vendor_msft_laps_backupdirectory_1')
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordlength' -Value '16' -Kind simple)
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_postauthenticationactions' -Value 'device_vendor_msft_laps_postauthenticationactions_3')
                )
            }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:laps-missing'
        $result.Outcome.Gaps[0].ReasonCode | Should -Be 'missing-setting'
        $result.Outcome.Gaps[0].Detail.message | Should -Be 'LAPS Complexity setting was not returned.'
    }

    It 'asserts the released beta descriptors before the policy list and settings reads' {
        $policy = New-EndpointPolicy -Id 'bitlocker-one' -Name 'One' -Family 'endpointSecurityDiskEncryption'
        $child = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityDiskEncryptionPolicies' `
            -Policies @($policy) `
            -SettingsByPolicy @{ 'bitlocker-one' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1')) }

        @($result.Calls | Where-Object Kind -eq 'Descriptor').Count | Should -Be 3
        $result.Calls[0].Kind | Should -Be 'Descriptor'
        $result.Calls[0].Type | Should -Be 'ConfigurationPolicy'
        $result.Calls[0].Operation | Should -Be 'ListBeta'
        $result.Calls[0].ApiVersion | Should -Be 'beta'
        $result.Calls[1].Type | Should -Be 'ConfigurationPolicySetting'
        $result.Calls[1].Operation | Should -Be 'ListBeta'
        $result.Calls[1].ApiVersion | Should -Be 'beta'
        $result.Calls[2].Type | Should -Be 'ConfigurationPolicyAssignment'
        $result.Calls[2].Operation | Should -Be 'ListBeta'
        $result.Calls[3].Kind | Should -Be 'Graph'
        $result.Calls[3].Type | Should -Be 'ConfigurationPolicy'
    }

    It 'keeps an unrecognized BitLocker encryption token unknown instead of Boolean-coercing it' {
        $policy = New-EndpointPolicy -Id 'bitlocker-unknown' -Name 'Unknown token' -Family 'endpointSecurityDiskEncryption'
        $child = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityDiskEncryptionPolicies' `
            -Policies @($policy) `
            -SettingsByPolicy @{
                'bitlocker-unknown' = @(New-EndpointSetting -DefinitionId $child -Value 'not-a-known-encryption-type')
            }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $result.Outcome.Gaps[0].ReasonCode | Should -Be 'unknown-setting'
        $result.Outcome.Gaps[0].Operation | Should -Be 'ConfigurationPolicySetting.ListBeta'
        $result.Outcome.Gaps[0].ApiVersion | Should -Be 'beta'
        $result.Outcome.Detail.enumeratedCount | Should -Be 1
        $result.Outcome.Detail.expandedCount | Should -Be 0
        $result.Outcome.Detail.partialCount | Should -Be 1
        $result.Outcome.Detail.notExpandedCount | Should -Be 0
        ($result.Outcome.Detail.expandedCount + $result.Outcome.Detail.partialCount + $result.Outcome.Detail.notExpandedCount) |
            Should -Be $result.Outcome.Detail.enumeratedCount
    }

    It 'keeps an unparseable LAPS criterion unknown instead of Boolean-coercing it' {
        $policy = New-EndpointPolicy -Id 'laps-unknown' -Name 'Unknown LAPS' -Family 'endpointSecurityAccountProtection' -TemplateId 'adc46e5a-f4aa-4ff6-aeff-4f27bc525796'
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityLapsPolicies' `
            -Policies @($policy) `
            -SettingsByPolicy @{
                'laps-unknown' = @(
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_backupdirectory' -Value 'device_vendor_msft_laps_backupdirectory_1')
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordcomplexity' -Value 'device_vendor_msft_laps_passwordcomplexity_unspecified')
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_passwordlength' -Value '16' -Kind simple)
                    (New-EndpointSetting -DefinitionId 'device_vendor_msft_laps_postauthenticationactions' -Value 'device_vendor_msft_laps_postauthenticationactions_1')
                )
            }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $result.Outcome.Gaps[0].ReasonCode | Should -Be 'unknown-setting'
        ($result.Outcome.Detail.expandedCount + $result.Outcome.Detail.partialCount + $result.Outcome.Detail.notExpandedCount) |
            Should -Be $result.Outcome.Detail.enumeratedCount
    }

    It 'classifies every enumerated BitLocker policy as Expanded, Partial, or NotExpanded with equal totals' {
        $full = New-EndpointPolicy -Id 'bitlocker-full' -Name 'Full' -Family 'endpointSecurityDiskEncryption'
        $unknown = New-EndpointPolicy -Id 'bitlocker-unknown' -Name 'Unknown' -Family 'endpointSecurityDiskEncryption'
        $failed = New-EndpointPolicy -Id 'bitlocker-failed' -Name 'Failed' -Family 'endpointSecurityDiskEncryption'
        $child = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new('settings failed'),
            'GraphKit.OperationFailed.500',
            [System.Management.Automation.ErrorCategory]::InvalidResult,
            $null)
        $result = Invoke-EndpointPlanFixture `
            -Dataset 'endpointSecurityDiskEncryptionPolicies' `
            -Policies @($full, $unknown, $failed) `
            -SettingsByPolicy @{
                'bitlocker-full' = @(New-EndpointSetting -DefinitionId $child -Value ($child + '_1'))
                'bitlocker-unknown' = @(New-EndpointSetting -DefinitionId $child -Value 'mystery')
            } `
            -SettingErrors @{ 'bitlocker-failed' = $errorRecord }

        $result.Outcome.Status | Should -Be 'Partial'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Rows[0].isFullDiskEncryption | Should -BeTrue
        $result.Outcome.Rows[0].isFullDiskEncryption.GetType().FullName | Should -Be 'System.Boolean'
        $result.Outcome.Detail.enumeratedCount | Should -Be 3
        $result.Outcome.Detail.expandedCount | Should -Be 1
        $result.Outcome.Detail.partialCount | Should -Be 1
        $result.Outcome.Detail.notExpandedCount | Should -Be 1
        ($result.Outcome.Detail.expandedCount + $result.Outcome.Detail.partialCount + $result.Outcome.Detail.notExpandedCount) |
            Should -Be $result.Outcome.Detail.enumeratedCount
        @($result.Outcome.Gaps | ForEach-Object { $_.Operation }) | Should -Be @('ConfigurationPolicySetting.ListBeta', 'ConfigurationPolicySetting.ListBeta')
        @($result.Outcome.Gaps | ForEach-Object { $_.ApiVersion }) | Should -Be @('beta', 'beta')
    }
}

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:New-PulseCaView {
        param(
            [hashtable] $GrantControls = @{ builtInControls = @('mfa') },
            [hashtable] $ConditionOverrides = @{}
        )

        $conditions = @{
            users          = @{ includeUsers = @('All') }
            applications   = @{ includeApplications = @('All') }
            clientAppTypes = @('all')
        }
        foreach ($entry in $ConditionOverrides.GetEnumerator()) {
            if ($null -eq $entry.Value) { $conditions.Remove($entry.Key) }
            else { $conditions[$entry.Key] = $entry.Value }
        }

        $raw = @{
            id            = 'ca-classifier-fixture'
            displayName   = 'Classifier fixture'
            state         = 'enabled'
            conditions    = $conditions
            grantControls = $GrantControls
        }

        InModuleScope TenantPulse -ArgumentList $raw {
            param($raw)
            @($raw | ConvertTo-PulseCaPolicyView)[0]
        }
    }
}

Describe 'Conditional Access grant requirement classifier' {
    It 'requires MFA when mfa is the sole grant even when operator is omitted' {
        $view = New-PulseCaView -GrantControls @{ builtInControls = @('mfa') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }
        $result.State | Should -Be 'Required'
        $result.Mechanism | Should -Be 'builtInControls:mfa'
    }

    It 'treats a present invalid operator as incomplete even when MFA is the sole grant' {
        $view = New-PulseCaView -GrantControls @{ operator = 'XOR'; builtInControls = @('mfa') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }
        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'missing-or-invalid-operator'
    }

    It 'does not claim MFA is required when OR permits compliantDevice instead' {
        $view = New-PulseCaView -GrantControls @{ operator = 'OR'; builtInControls = @('mfa', 'compliantDevice') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }
        $result.State | Should -Be 'NotRequired'
        $result.ReasonCode | Should -Be 'or-allows-non-required-control'
    }

    It 'requires MFA when AND combines mfa with compliantDevice' {
        $view = New-PulseCaView -GrantControls @{ operator = 'AND'; builtInControls = @('mfa', 'compliantDevice') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }
        $result.State | Should -Be 'Required'
    }

    It 'treats a missing operator on a multi-control grant as incomplete' {
        $view = New-PulseCaView -GrantControls @{ builtInControls = @('mfa', 'compliantDevice') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }
        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'missing-or-invalid-operator'
    }

    It 'treats an empty authenticationStrength object as incomplete, never MFA proof' {
        $view = New-PulseCaView -GrantControls @{ authenticationStrength = @{} }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }
        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'unresolved-authentication-strength'
    }

    It 'treats an unrecognized custom authentication strength as incomplete until requirementsSatisfied is collected' {
        $view = New-PulseCaView -GrantControls @{ authenticationStrength = @{ id = '11111111-1111-1111-1111-111111111111' } }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }
        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'unresolved-authentication-strength'
    }

    It 'uses a custom strength requirementsSatisfied value to settle the generic MFA claim' -ForEach @(
        @{ RequirementsSatisfied = 'mfa'; ExpectedState = 'Required' }
        @{ RequirementsSatisfied = 'none'; ExpectedState = 'NotRequired' }
        @{ RequirementsSatisfied = 'unknownFutureValue'; ExpectedState = 'Incomplete' }
    ) {
        $view = New-PulseCaView -GrantControls @{
            authenticationStrength = @{
                id                    = '11111111-1111-1111-1111-111111111111'
                requirementsSatisfied = $RequirementsSatisfied
            }
        }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }

        $result.State | Should -Be $ExpectedState
    }

    It 'does not treat requirementsSatisfied mfa as proof that a custom strength is phishing-resistant' {
        $view = New-PulseCaView -GrantControls @{
            authenticationStrength = @{
                id                    = '11111111-1111-1111-1111-111111111111'
                requirementsSatisfied = 'mfa'
            }
        }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement PhishingResistant }

        $result.State | Should -Be 'Incomplete'
    }

    It 'recognizes each Microsoft built-in MFA-satisfying strength' -ForEach @(
        @{ StrengthId = '00000000-0000-0000-0000-000000000002' }
        @{ StrengthId = '00000000-0000-0000-0000-000000000003' }
        @{ StrengthId = '00000000-0000-0000-0000-000000000004' }
    ) {
        $view = New-PulseCaView -GrantControls @{ authenticationStrength = @{ id = $StrengthId } }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }
        $result.State | Should -Be 'Required'
    }

    It 'requires phishing resistance only for the documented built-in phishing-resistant strength' {
        $phishView = New-PulseCaView -GrantControls @{ authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004' } }
        $mfaView = New-PulseCaView -GrantControls @{ authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000002' } }
        (InModuleScope TenantPulse -ArgumentList $phishView { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement PhishingResistant }).State | Should -Be 'Required'
        (InModuleScope TenantPulse -ArgumentList $mfaView { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement PhishingResistant }).State | Should -Be 'NotRequired'
    }

    It 'rejects the documented-invalid combination of MFA and authentication strength' {
        $view = New-PulseCaView -GrantControls @{
            operator               = 'OR'
            builtInControls        = @('mfa')
            authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004' }
        }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement PhishingResistant }
        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'invalid-grant-control-combination'
    }

    It 'treats unknown or future built-in grant controls as incomplete' -ForEach @(
        @{ Control = 'unknownFutureValue' }
        @{ Control = 'futureGrantControl' }
    ) {
        $view = New-PulseCaView -GrantControls @{ builtInControls = @($Control) }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }
        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'unresolved-grant-control'
    }

    It 'accepts password change only with MFA and AND' {
        $valid = New-PulseCaView `
            -GrantControls @{ operator = 'AND'; builtInControls = @('mfa', 'passwordChange') } `
            -ConditionOverrides @{ userRiskLevels = @('high') }
        $invalid = New-PulseCaView -GrantControls @{ operator = 'OR'; builtInControls = @('mfa', 'passwordChange') }
        (InModuleScope TenantPulse -ArgumentList $valid { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }).State | Should -Be 'Required'
        $invalidResult = InModuleScope TenantPulse -ArgumentList $invalid { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }
        $invalidResult.State | Should -Be 'Incomplete'
        $invalidResult.ReasonCode | Should -Be 'invalid-grant-control-combination'
    }

    It 'accepts risk remediation only with authentication strength and AND' {
        $valid = New-PulseCaView `
            -GrantControls @{
                operator = 'AND'
                builtInControls = @('riskRemediation')
                authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000002' }
            } `
            -ConditionOverrides @{ userRiskLevels = @('high') }
        $invalid = New-PulseCaView -GrantControls @{ builtInControls = @('riskRemediation') }
        (InModuleScope TenantPulse -ArgumentList $valid { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }).State | Should -Be 'Required'
        $invalidResult = InModuleScope TenantPulse -ArgumentList $invalid { param($view) Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa }
        $invalidResult.State | Should -Be 'Incomplete'
        $invalidResult.ReasonCode | Should -Be 'invalid-grant-control-combination'
    }

    It 'rejects remediation grants unless applications are all and user risk is the only configured condition' -ForEach @(
        @{
            CaseName = 'password change narrowed to one application'
            GrantControls = @{ operator = 'AND'; builtInControls = @('mfa', 'passwordChange') }
            ConditionOverrides = @{
                userRiskLevels = @('high')
                applications = @{ includeApplications = @('11111111-1111-1111-1111-111111111111') }
            }
        }
        @{
            CaseName = 'risk remediation excludes an application'
            GrantControls = @{
                operator = 'AND'
                builtInControls = @('riskRemediation')
                authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000002' }
            }
            ConditionOverrides = @{
                userRiskLevels = @('high')
                applications = @{
                    includeApplications = @('All')
                    excludeApplications = @('22222222-2222-2222-2222-222222222222')
                }
            }
        }
        @{
            CaseName = 'password change also configures an all-platforms condition'
            GrantControls = @{ operator = 'AND'; builtInControls = @('mfa', 'passwordChange') }
            ConditionOverrides = @{
                userRiskLevels = @('high')
                platforms = @{ includePlatforms = @('all') }
            }
        }
        @{
            CaseName = 'risk remediation also configures sign-in risk'
            GrantControls = @{
                operator = 'AND'
                builtInControls = @('riskRemediation')
                authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000002' }
            }
            ConditionOverrides = @{
                userRiskLevels = @('high')
                signInRiskLevels = @('high')
            }
        }
    ) {
        $view = New-PulseCaView -GrantControls $GrantControls -ConditionOverrides $ConditionOverrides
        $result = InModuleScope TenantPulse -ArgumentList $view {
            param($view)
            Get-PulseCaGrantRequirement -PolicyView $view -Requirement Mfa
        }

        $result.State | Should -Be 'Incomplete' -Because $CaseName
        $result.ReasonCode | Should -Be 'invalid-remediation-policy-conditions' -Because $CaseName
    }
}

Describe 'Conditional Access block requirement classifier' {
    It 'treats an omitted optional grantControls block as definitive absence of block' {
        $view = New-PulseCaView -GrantControls $null
        $result = InModuleScope TenantPulse -ArgumentList $view {
            param($view)
            Get-PulseCaBlockRequirement -PolicyView $view
        }

        $result.State | Should -Be 'NotRequired'
        $result.ReasonCode | Should -Be 'no-block-control'
    }

    It 'does not let malformed non-block metadata hide the definitive absence of block' -ForEach @(
        @{
            CaseName = 'invalid operator on a known MFA control'
            GrantControls = @{ operator = 'XOR'; builtInControls = @('mfa') }
        }
        @{
            CaseName = 'empty authentication strength metadata'
            GrantControls = @{ authenticationStrength = @{} }
        }
    ) {
        $view = New-PulseCaView -GrantControls $GrantControls
        $result = InModuleScope TenantPulse -ArgumentList $view {
            param($view)
            Get-PulseCaBlockRequirement -PolicyView $view
        }

        $result.State | Should -Be 'NotRequired' -Because $CaseName
        $result.ReasonCode | Should -Be 'no-block-control' -Because $CaseName
    }

    It 'treats unknown or future controls as incomplete rather than proving no block' -ForEach @(
        @{ Control = 'unknownFutureValue' }
        @{ Control = 'futureGrantControl' }
    ) {
        $view = New-PulseCaView -GrantControls @{ builtInControls = @($Control) }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaBlockRequirement -PolicyView $view }
        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'unresolved-grant-control'
    }

    It 'rejects block combined with a sibling grant control' {
        $view = New-PulseCaView -GrantControls @{ operator = 'OR'; builtInControls = @('block', 'mfa') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaBlockRequirement -PolicyView $view }
        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'block-combined-with-other-controls'
    }
}

Describe 'Conditional Access sign-in scope classifier' {
    It 'recognizes explicit all client app types with no other conditions as universal' {
        $view = New-PulseCaView
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }
        $result.State | Should -Be 'Universal'
    }

    It 'treats a non-null beta times selector as known narrow scope' {
        $view = New-PulseCaView -ConditionOverrides @{
            times = @{ daysOfWeek = @('monday'); startTime = '09:00:00'; endTime = '17:00:00' }
        }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Narrow'
        $result.NarrowReasonCodes | Should -Contain 'time-condition-scope'
        $result.CouldBeUniversal | Should -BeFalse
    }

    It 'keeps an unrecognized non-null condition incomplete without inventing a narrow lower bound' {
        $view = New-PulseCaView -ConditionOverrides @{ futureCondition = @{ mode = 'include' } }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Incomplete'
        $result.IncompleteReasonCodes | Should -Contain 'unrecognized-condition-property'
        $result.NarrowReasonCodes | Should -Not -Contain 'unrecognized-condition-scope'
        $result.CouldBeUniversal | Should -BeTrue
    }

    It 'keeps an explicit empty value on an unknown future condition incomplete but potentially universal' {
        $view = New-PulseCaView -ConditionOverrides @{ futureCondition = @() }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Incomplete'
        $result.IncompleteReasonCodes | Should -Contain 'unrecognized-condition-property'
        $result.NarrowReasonCodes | Should -Not -Contain 'unrecognized-condition-scope'
        $result.CouldBeUniversal | Should -BeTrue
    }

    It 'treats absent clientAppTypes as incomplete for an all-sign-ins claim' {
        $view = New-PulseCaView -ConditionOverrides @{ clientAppTypes = $null }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }
        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Match 'client-app-types'
    }

    It 'treats browser-only client app scope as narrow for an all-sign-ins claim' {
        $view = New-PulseCaView -ConditionOverrides @{ clientAppTypes = @('browser') }
        (InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }).State | Should -Be 'Narrow'
    }

    It 'preserves a recognized MFA scope lower bound when a future client-app type is also present' {
        $view = New-PulseCaView -ConditionOverrides @{ clientAppTypes = @('browser', 'futureClient') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Incomplete'
        $result.IncompleteReasonCodes | Should -Contain 'unrecognized-client-app-type'
        $result.NarrowReasonCodes | Should -Contain 'client-app-types-not-all'
        $result.CouldBeUniversal | Should -BeFalse
    }

    It 'preserves a recognized MFA client-app lower bound beside a blank sibling' {
        $view = New-PulseCaView -ConditionOverrides @{ clientAppTypes = @('browser', '') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Incomplete'
        $result.IncompleteReasonCodes | Should -Contain 'blank-client-app-type'
        $result.NarrowReasonCodes | Should -Contain 'client-app-types-not-all'
        $result.CouldBeUniversal | Should -BeFalse
    }

    It 'preserves a recognized legacy client-app bucket beside a blank sibling' {
        $view = New-PulseCaView -ConditionOverrides @{ clientAppTypes = @('exchangeActiveSync', '') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Legacy }

        $result.State | Should -Be 'Incomplete'
        $result.IncompleteReasonCodes | Should -Contain 'blank-client-app-type'
        $result.CoversExchangeActiveSync | Should -BeTrue
        $result.CouldCoverExchangeActiveSync | Should -BeTrue
        $result.CoversOther | Should -BeFalse
        $result.CouldCoverOther | Should -BeFalse
    }

    It 'preserves a known narrow <Name> lower bound beside a malformed sibling' -ForEach @(
        @{
            Name             = 'platform'
            Override         = @{ platforms = @{ includePlatforms = @('android'); excludePlatforms = @('') } }
            IncompleteReason = 'invalid-platform-scope'
            NarrowReason     = 'narrow-platform-scope'
        }
        @{
            Name             = 'location'
            Override         = @{ locations = @{ includeLocations = @('11111111-1111-1111-1111-111111111111'); excludeLocations = @('') } }
            IncompleteReason = 'invalid-location-scope'
            NarrowReason     = 'narrow-location-scope'
        }
        @{
            Name             = 'sign-in risk'
            Override         = @{ signInRiskLevels = @('high', '') }
            IncompleteReason = 'invalid-sign-in-risk-scope'
            NarrowReason     = 'narrow-sign-in-risk-scope'
        }
        @{
            Name             = 'agent identity risk'
            Override         = @{ agentIdRiskLevels = @('high', '') }
            IncompleteReason = 'invalid-agent-id-risk-scope'
            NarrowReason     = 'narrow-agent-id-risk-scope'
        }
    ) {
        $view = New-PulseCaView -ConditionOverrides $Override
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Incomplete'
        $result.IncompleteReasonCodes | Should -Contain $IncompleteReason
        $result.NarrowReasonCodes | Should -Contain $NarrowReason
        $result.CouldBeUniversal | Should -BeFalse
    }

    It 'preserves a known <Name> exclusion lower bound when the include selector is empty' -ForEach @(
        @{
            Name             = 'platform'
            Override         = @{ platforms = @{ includePlatforms = @(); excludePlatforms = @('android') } }
            IncompleteReason = 'invalid-platform-scope'
            NarrowReason     = 'narrow-platform-scope'
        }
        @{
            Name             = 'location'
            Override         = @{ locations = @{ includeLocations = @(); excludeLocations = @('33333333-3333-3333-3333-333333333333') } }
            IncompleteReason = 'invalid-location-scope'
            NarrowReason     = 'narrow-location-scope'
        }
    ) {
        $view = New-PulseCaView -ConditionOverrides $Override
        $result = InModuleScope TenantPulse -ArgumentList $view {
            param($view)
            Get-PulseCaSignInScope -PolicyView $view -Mode Mfa
        }

        $result.State | Should -Be 'Incomplete'
        $result.IncompleteReasonCodes | Should -Contain $IncompleteReason
        $result.NarrowReasonCodes | Should -Contain $NarrowReason
        $result.CouldBeUniversal | Should -BeFalse
    }

    It 'preserves known device exclusions beside malformed or conflicting siblings' -ForEach @(
        @{
            Name     = 'current selector'
            Override = @{ devices = @{ includeDevices = @('All'); excludeDevices = @('Compliant', '') } }
            Reason   = 'invalid-device-selector-scope'
        }
        @{
            Name     = 'current selector with blank include sibling'
            Override = @{ devices = @{ includeDevices = @('All', ''); excludeDevices = @('Compliant') } }
            Reason   = 'invalid-device-selector-scope'
        }
        @{
            Name     = 'deprecated selector'
            Override = @{ deviceStates = @{ includeStates = @('All'); excludeStates = @('DomainJoined', '') } }
            Reason   = 'invalid-device-state-scope'
        }
        @{
            Name     = 'filter-selector conflict'
            Override = @{ devices = @{ includeDevices = @('All'); excludeDevices = @('Compliant'); deviceFilter = @{ mode = 'include'; rule = 'device.deviceId -ne null' } } }
            Reason   = 'conflicting-device-scope'
        }
    ) {
        $view = New-PulseCaView -ConditionOverrides $Override
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Incomplete'
        $result.IncompleteReasonCodes | Should -Contain $Reason
        $result.NarrowReasonCodes.Count | Should -BeGreaterThan 0
        $result.CouldBeUniversal | Should -BeFalse
    }

    It 'preserves a known <Name> lower bound from a malformed condition selector' -ForEach @(
        @{
            Name         = 'current device exclusion with no include'
            Override     = @{ devices = @{ includeDevices = @(); excludeDevices = @('Compliant') } }
            NarrowReason = 'device-selector-exclusion'
        }
        @{
            Name         = 'future current-device include'
            Override     = @{ devices = @{ includeDevices = @('futureDeviceState') } }
            NarrowReason = 'device-selector-scope'
        }
        @{
            Name         = 'legacy device exclusion with no include'
            Override     = @{ devices = @{ includeDeviceStates = @(); excludeDeviceStates = @('DomainJoined') } }
            NarrowReason = 'device-selector-exclusion'
        }
        @{
            Name         = 'deprecated top-level device-state exclusion with no include'
            Override     = @{ deviceStates = @{ excludeStates = @('DomainJoined') } }
            NarrowReason = 'device-state-exclusion'
        }
        @{
            Name         = 'future agent identity risk'
            Override     = @{ agentIdRiskLevels = @('futureRiskLevel') }
            NarrowReason = 'narrow-agent-id-risk-scope'
        }
        @{
            Name         = 'malformed workload identity include'
            Override     = @{ clientApplications = @{ includeServicePrincipals = @('not-a-guid') } }
            NarrowReason = 'workload-identity-client-application-scope'
        }
    ) {
        $view = New-PulseCaView -ConditionOverrides $Override
        $result = InModuleScope TenantPulse -ArgumentList $view {
            param($view)
            Get-PulseCaSignInScope -PolicyView $view -Mode Mfa
        }

        $result.State | Should -Be 'Incomplete'
        $result.NarrowReasonCodes | Should -Contain $NarrowReason
        $result.CouldBeUniversal | Should -BeFalse
    }

    It 'treats every known extra sign-in condition as narrow' -ForEach @(
        @{ Name = 'specific platform'; Override = @{ platforms = @{ includePlatforms = @('iOS') } } }
        @{ Name = 'specific location'; Override = @{ locations = @{ includeLocations = @('11111111-1111-1111-1111-111111111111') } } }
        @{ Name = 'sign-in risk'; Override = @{ signInRiskLevels = @('high') } }
        @{ Name = 'user risk'; Override = @{ userRiskLevels = @('high') } }
        @{ Name = 'service-principal risk'; Override = @{ servicePrincipalRiskLevels = @('high') } }
        @{ Name = 'insider risk'; Override = @{ insiderRiskLevels = @('elevated') } }
        @{ Name = 'device filter'; Override = @{ devices = @{ deviceFilter = @{ mode = 'include'; rule = 'device.deviceId -ne null' } } } }
        @{ Name = 'device state exclusion'; Override = @{ devices = @{ includeDevices = @('All'); excludeDevices = @('DomainJoined') } } }
        @{ Name = 'deprecated device state exclusion'; Override = @{ deviceStates = @{ includeStates = @('All'); excludeStates = @('Compliant') } } }
        @{ Name = 'authentication flow'; Override = @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow' } } }
        @{ Name = 'agent identity risk'; Override = @{ agentIdRiskLevels = @('high') } }
        @{ Name = 'workload identity target'; Override = @{ clientApplications = @{ includeServicePrincipals = @('ServicePrincipalsInMyTenant') } } }
        @{ Name = 'workload identity filter'; Override = @{ clientApplications = @{ servicePrincipalFilter = @{ mode = 'include'; rule = 'customSecurityAttributes.Project -eq "Tier0"' } } } }
    ) {
        $view = New-PulseCaView -ConditionOverrides $Override
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }
        $result.State | Should -Be 'Narrow'
    }

    It 'treats an explicitly empty optional risk collection as no risk restriction' {
        $view = New-PulseCaView -ConditionOverrides @{ signInRiskLevels = @() }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }
        $result.State | Should -Be 'Universal'
    }

    It 'treats authenticationFlows none as no authentication-flow restriction' {
        $view = New-PulseCaView -ConditionOverrides @{ authenticationFlows = @{ transferMethods = 'none' } }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }
        $result.State | Should -Be 'Universal'
    }

    It 'treats explicit all-device selectors without exclusions as unrestricted' -ForEach @(
        @{ Override = @{ devices = @{ includeDevices = @('All'); excludeDevices = @() } } }
        @{ Override = @{ deviceStates = @{ includeStates = @('All'); excludeStates = @() } } }
    ) {
        $view = New-PulseCaView -ConditionOverrides $Override
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }
        $result.State | Should -Be 'Universal'
    }

    It 'treats malformed device and agent-risk conditions as incomplete' -ForEach @(
        @{ Override = @{ devices = @{ includeDevices = @('futureDeviceState') } } }
        @{ Override = @{ deviceStates = @{ includeStates = @('All'); excludeStates = @('futureDeviceState') } } }
        @{ Override = @{ agentIdRiskLevels = @('futureAgentRisk') } }
    ) {
        $view = New-PulseCaView -ConditionOverrides $Override
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }
        $result.State | Should -Be 'Incomplete'
    }

    It 'recognizes the documented unknownFutureValue agent-risk sentinel as narrow' {
        $view = New-PulseCaView -ConditionOverrides @{ agentIdRiskLevels = @('unknownFutureValue') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Narrow'
        $result.NarrowReasonCodes | Should -Contain 'narrow-agent-id-risk-scope'
        $result.IncompleteReasonCodes | Should -HaveCount 0
    }

    It 'treats mutually exclusive device selectors and a device filter as incomplete' {
        $view = New-PulseCaView -ConditionOverrides @{
            devices = @{
                includeDevices = @('All')
                deviceFilter = @{ mode = 'include'; rule = 'device.deviceId -ne null' }
            }
        }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }
        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'conflicting-device-scope'
    }

    It 'treats valid beta agent-identity targeting as a narrow sign-in condition' {
        $agentServicePrincipalId = [guid]::ParseExact(('a' * 32), 'N').ToString('D')
        $view = New-PulseCaView -ConditionOverrides @{
            clientApplications = @{ includeAgentIdServicePrincipals = @($agentServicePrincipalId) }
        }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }
        $result.State | Should -Be 'Narrow'
    }

    It 'treats the documented beta All agent-identity selector as valid narrow workload scope' {
        $view = New-PulseCaView -ConditionOverrides @{
            clientApplications = @{ includeAgentIdServicePrincipals = @('All') }
        }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Narrow'
        $result.NarrowReasonCodes | Should -Contain 'workload-identity-client-application-scope'
        $result.IncompleteReasonCodes | Should -HaveCount 0
    }

    It 'preserves a valid workload-identity lower bound beside a malformed blank selector' {
        $servicePrincipalId = [guid]::ParseExact(('b' * 32), 'N').ToString('D')
        $view = New-PulseCaView -ConditionOverrides @{
            clientApplications = @{ includeServicePrincipals = @($servicePrincipalId, '') }
        }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Incomplete'
        $result.IncompleteReasonCodes | Should -Contain 'invalid-client-application-scope'
        $result.NarrowReasonCodes | Should -Contain 'workload-identity-client-application-scope'
        $result.CouldBeUniversal | Should -BeFalse
    }

    It 'recognizes the documented unknownFutureValue authentication-flow sentinel as narrow' {
        $view = New-PulseCaView -ConditionOverrides @{ authenticationFlows = @{ transferMethods = 'unknownFutureValue' } }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Narrow'
        $result.NarrowReasonCodes | Should -Contain 'authentication-flow-scope'
        $result.IncompleteReasonCodes | Should -HaveCount 0
    }

    It 'recognizes a comma-separated combination of authentication-flow flags without degrading certainty' {
        $view = New-PulseCaView -ConditionOverrides @{
            authenticationFlows = @{ transferMethods = 'deviceCodeFlow, authenticationTransfer' }
        }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Narrow'
        $result.NarrowReasonCodes | Should -Contain 'authentication-flow-scope'
        $result.IncompleteReasonCodes | Should -HaveCount 0
    }

    It 'preserves a non-none authentication-flow lower bound when the value is unrecognized' {
        $view = New-PulseCaView -ConditionOverrides @{ authenticationFlows = @{ transferMethods = 'futureTransferMethod' } }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Mfa }

        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'invalid-authentication-flow-scope'
        $result.NarrowReasonCodes | Should -Contain 'authentication-flow-scope'
        $result.CouldBeUniversal | Should -BeFalse
    }

    It 'requires both legacy client buckets for one-policy universal legacy coverage' {
        $one = New-PulseCaView -ConditionOverrides @{ clientAppTypes = @('exchangeActiveSync') }
        $both = New-PulseCaView -ConditionOverrides @{ clientAppTypes = @('exchangeActiveSync', 'other') }
        $oneResult = InModuleScope TenantPulse -ArgumentList $one { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Legacy }
        $bothResult = InModuleScope TenantPulse -ArgumentList $both { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Legacy }
        $oneResult.State | Should -Be 'Universal'
        $oneResult.CoversExchangeActiveSync | Should -BeTrue
        $oneResult.CoversOther | Should -BeFalse
        $bothResult.State | Should -Be 'Universal'
        $bothResult.CoversExchangeActiveSync | Should -BeTrue
        $bothResult.CoversOther | Should -BeTrue
    }

    It 'does not let a future client-app type alias the recognized other legacy bucket' {
        $view = New-PulseCaView -ConditionOverrides @{ clientAppTypes = @('exchangeActiveSync', 'futureClient') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Legacy }

        $result.State | Should -Be 'Incomplete'
        $result.IncompleteReasonCodes | Should -Contain 'unrecognized-client-app-type'
        $result.CoversExchangeActiveSync | Should -BeTrue
        $result.CouldCoverExchangeActiveSync | Should -BeTrue
        $result.CoversOther | Should -BeFalse
        $result.CouldCoverOther | Should -BeFalse
    }

    It 'treats all client app types as covering both legacy buckets' {
        $view = New-PulseCaView -ConditionOverrides @{ clientAppTypes = @('all') }
        $result = InModuleScope TenantPulse -ArgumentList $view { param($view) Get-PulseCaSignInScope -PolicyView $view -Mode Legacy }
        $result.State | Should -Be 'Universal'
        $result.CoversExchangeActiveSync | Should -BeTrue
        $result.CoversOther | Should -BeTrue
    }
}

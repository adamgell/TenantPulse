BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'ConvertTo-PulseAssignmentIntent' {
    It 'classifies null assignments as Unknown and not assigned' {
        $result = InModuleScope TenantPulse { ConvertTo-PulseAssignmentIntent -Assignments $null }
        $result.State | Should -Be 'Unknown'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
    }

    It 'classifies an authoritative empty array as Empty' {
        $result = InModuleScope TenantPulse { ConvertTo-PulseAssignmentIntent -Assignments @() }
        $result.State | Should -Be 'Empty'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeTrue
    }

    It 'classifies an include group target as Include' {
        $assignments = @(
            @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-include' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Include'
        $result.IsAssigned | Should -BeTrue
        $result.IncludeGroupIds | Should -Contain 'grp-include'
        $result.IncludeKinds | Should -Contain 'Group'
    }

    It 'classifies exclude-only group targets as ExcludeOnly, not assigned' {
        $assignments = @(
            @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'grp-ex' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'ExcludeOnly'
        $result.IsAssigned | Should -BeFalse
        $result.ExcludeGroupIds | Should -Contain 'grp-ex'
    }

    It 'records a filter id without treating a filter as assignment by itself' {
        $assignments = @(
            @{
                target = @{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = 'grp-include'
                    deviceAndAppManagementAssignmentFilterId = 'filter-1'
                    deviceAndAppManagementAssignmentFilterType = 'include'
                }
            }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.HasFilter | Should -BeTrue
        $result.FilterIds | Should -Contain 'filter-1'
        $result.IsAssigned | Should -BeTrue
    }

    It 'classifies all-users and all-devices typed include intents' {
        $assignments = @(
            @{ target = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }
            @{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Include'
        $result.IncludeKinds | Should -Be @('AllDevices', 'AllUsers')
    }

    It 'classifies documented branding and enrollment scope-tag group targets as includes' {
        $assignments = @(
            @{
                '@odata.type' = '#microsoft.graph.intuneBrandingProfileAssignment'
                id            = 'branding-assignment-1'
                target        = @{
                    '@odata.type' = 'microsoft.graph.scopeTagGroupAssignmentTarget'
                    targetType    = 'user'
                    entraObjectId = 'branding-group-id'
                }
            }
            @{
                '@odata.type' = '#microsoft.graph.enrollmentConfigurationAssignment'
                id            = 'enrollment-assignment-1'
                target        = @{
                    '@odata.type' = '#microsoft.graph.scopeTagGroupAssignmentTarget'
                    targetType    = 'device'
                    entraObjectId = 'enrollment-group-id'
                }
            }
        )

        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Include'
        $result.IsAssigned | Should -BeTrue
        $result.Complete | Should -BeTrue
        $result.IncludeKinds | Should -Contain 'Group'
        $result.IncludeGroupIds | Should -Be @('branding-group-id', 'enrollment-group-id')
    }

    It 'keeps malformed documented scope-tag group targets indeterminate' {
        $assignments = @(
            @{ target = @{ '@odata.type' = 'microsoft.graph.scopeTagGroupAssignmentTarget'; entraObjectId = 'missing-type-id' } }
            @{ target = @{ '@odata.type' = '#microsoft.graph.scopeTagGroupAssignmentTarget'; targetType = 'unknownFutureValue'; entraObjectId = 'future-id' } }
            @{ target = @{ '@odata.type' = '#microsoft.graph.scopeTagGroupAssignmentTarget'; targetType = 'device'; entraObjectId = ' ' } }
        )

        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
        $result.MalformedReasons | Should -Contain 'missing-scope-tag-target-type'
        $result.MalformedReasons | Should -Contain 'unsupported-scope-tag-target-type:unknownFutureValue'
        $result.MalformedReasons | Should -Contain 'missing-entra-object-id'
    }

    It 'classifies a missing target type as Malformed' {
        $assignments = @(
            @{ target = @{ groupId = 'grp-1' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
        $result.MalformedReasons | Should -Contain 'missing-target-type'
    }

    It 'classifies a non-string <Shape> target discriminator as Malformed' -ForEach @(
        @{ Shape = 'array'; Value = [object[]] @('#microsoft.graph.groupAssignmentTarget') }
        @{ Shape = 'numeric'; Value = 42 }
        @{ Shape = 'boolean'; Value = $true }
    ) {
        $assignments = @(
            @{ target = @{ '@odata.type' = $Value; groupId = 'grp-1' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
    }

    It 'classifies a non-string <Shape> normalized targetType as Malformed' -ForEach @(
        @{ Shape = 'array'; Value = [object[]] @('group') }
        @{ Shape = 'numeric'; Value = 42 }
        @{ Shape = 'boolean'; Value = $true }
    ) {
        $assignments = @(
            @{ intent = 'include'; targetType = $Value; groupId = 'grp-1' }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
    }

    It 'classifies a non-string <Shape> scope-tag targetType as Malformed' -ForEach @(
        @{ Shape = 'array'; Value = [object[]] @('device') }
        @{ Shape = 'numeric'; Value = 42 }
        @{ Shape = 'boolean'; Value = $true }
    ) {
        $assignments = @(
            @{ target = @{
                    '@odata.type' = '#microsoft.graph.scopeTagGroupAssignmentTarget'
                    targetType = $Value
                    entraObjectId = 'grp-1'
                } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
    }

    It 'rejects non-string <Shape> values in every assignment text field used as proof' -ForEach @(
        @{ Shape = 'array' }
        @{ Shape = 'numeric' }
        @{ Shape = 'boolean' }
    ) {
        $invalidValue = switch ($Shape) {
            'array' { , [object[]] @('coercible-value') }
            'numeric' { 42 }
            'boolean' { $true }
        }
        $assignmentCases = [ordered]@{
            intent = @{ intent = $invalidValue; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-1' } }
            'raw groupId' = @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $invalidValue } }
            'normalized groupId' = @{ intent = 'include'; targetType = 'group'; groupId = $invalidValue }
            'raw filter id' = @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-1'; deviceAndAppManagementAssignmentFilterId = $invalidValue } }
            'raw filter type' = @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-1'; deviceAndAppManagementAssignmentFilterType = $invalidValue } }
            'normalized filter id' = @{ intent = 'include'; targetType = 'group'; groupId = 'grp-1'; filterId = $invalidValue }
            'normalized filter type' = @{ intent = 'include'; targetType = 'group'; groupId = 'grp-1'; filterType = $invalidValue }
            entraObjectId = @{ target = @{ '@odata.type' = '#microsoft.graph.scopeTagGroupAssignmentTarget'; targetType = 'device'; entraObjectId = $invalidValue } }
        }

        foreach ($fieldName in $assignmentCases.Keys) {
            $assignments = @($assignmentCases[$fieldName])
            $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
                param($assignments)
                ConvertTo-PulseAssignmentIntent -Assignments $assignments
            }

            $result.State | Should -Be 'Malformed' -Because "$fieldName must not accept a $Shape value"
            $result.IsAssigned | Should -BeFalse -Because "$fieldName must not prove assignment"
            $result.Complete | Should -BeFalse -Because "$fieldName evidence is malformed"
            @($result.IncludeKinds).Count | Should -Be 0
            @($result.IncludeGroupIds).Count | Should -Be 0
            @($result.ExcludeGroupIds).Count | Should -Be 0
            @($result.FilterIds).Count | Should -Be 0
            $result.HasFilter | Should -BeFalse
        }
    }

    It 'accepts the legacy native-string odata.type alias when the primary discriminator is absent' {
        $assignments = @(
            @{ target = @{ 'odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-alias' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Include'
        $result.IncludeGroupIds | Should -Be @('grp-alias')
    }

    It 'does not accept an array-valued legacy odata.type alias' {
        $assignments = @(
            @{ target = @{ 'odata.type' = [object[]] @('#microsoft.graph.groupAssignmentTarget'); groupId = 'grp-alias' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
    }

    It 'does not fall back to a valid alias when the primary discriminator has a non-string shape' {
        $assignments = @(
            @{ target = @{
                    '@odata.type' = [object[]] @()
                    'odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = 'grp-alias'
                } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
    }

    It 'does not fall back to a valid raw target when normalized targetType is present but <Shape>' -ForEach @(
        @{ Shape = 'empty'; Value = '' }
        @{ Shape = 'whitespace'; Value = '   ' }
        @{ Shape = 'null'; Value = $null }
    ) {
        $assignments = @(
            @{
                targetType = $Value
                target     = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }
            }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
    }

    It 'does not fall back to an outer target discriminator when the target property is present null' {
        $assignments = @(
            @{
                target        = $null
                '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'
            }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
        $result.MalformedReasons | Should -Contain 'missing-target'
    }

    It 'does not fall back to a valid legacy alias when the primary discriminator is present but <Shape>' -ForEach @(
        @{ Shape = 'empty'; Value = '' }
        @{ Shape = 'whitespace'; Value = '   ' }
        @{ Shape = 'null'; Value = $null }
    ) {
        $assignments = @(
            @{ target = @{
                    '@odata.type' = $Value
                    'odata.type'  = '#microsoft.graph.allDevicesAssignmentTarget'
                } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
    }

    It 'classifies an unknown native assignment intent as Malformed' {
        $assignments = @(
            @{ intent = 'futureValue'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-1' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
    }

    It 'classifies a present <Shape> assignment intent as Malformed instead of falling through to include' -ForEach @(
        @{ Shape = 'null'; Value = $null }
        @{ Shape = 'empty string'; Value = '' }
        @{ Shape = 'whitespace string'; Value = '   ' }
    ) {
        $assignments = @(
            @{ intent = $Value; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-1' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
    }

    It 'does not coerce composite assignmentIntent <Shape> into an assigned row' -ForEach @(
        @{ Shape = 'array'; Value = [object[]] @('Include') }
        @{ Shape = 'numeric'; Value = 42 }
        @{ Shape = 'boolean'; Value = $true }
    ) {
        $row = [pscustomobject]@{
            assignmentIntent = $Value
            assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })
        }
        $isAssigned = InModuleScope TenantPulse -ArgumentList $row {
            param($row)
            Test-PulseCompositeRowIsAssigned -Row $row
        }

        $isAssigned | Should -BeFalse
    }

    It 'does not fall back from a present malformed or unknown composite assignmentIntent' -ForEach @(
        @{ Shape = 'null'; Value = $null }
        @{ Shape = 'empty array'; Value = [object[]] @() }
        @{ Shape = 'empty string'; Value = '' }
        @{ Shape = 'whitespace string'; Value = '   ' }
        @{ Shape = 'unknown string'; Value = 'FutureValue' }
    ) {
        $row = [pscustomobject]@{
            assignmentIntent = $Value
            assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })
        }
        $isAssigned = InModuleScope TenantPulse -ArgumentList $row {
            param($row)
            Test-PulseCompositeRowIsAssigned -Row $row
        }

        $isAssigned | Should -BeFalse
    }

    It 'classifies a group target with no groupId as Malformed' {
        $assignments = @(
            @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Malformed'
        $result.MalformedReasons | Should -Contain 'missing-group-id'
    }

    It 'treats settings-catalog intent=exclude as exclude-only' {
        $assignments = @(
            @{
                intent = 'exclude'
                target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-ex' }
            }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'ExcludeOnly'
        $result.IsAssigned | Should -BeFalse
    }

    It 'classifies a normalized group target as Include (parity with raw graph shape)' {
        $assignments = @(
            @{ intent = 'include'; targetType = 'group'; groupId = 'grp-include-norm' }
        )
        $caseVariantAssignments = @(
            @{ intent = 'INCLUDE'; targetType = 'GROUP'; groupId = 'grp-include-case' }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $caseVariant = InModuleScope TenantPulse -ArgumentList @(, $caseVariantAssignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Include'
        $result.IsAssigned | Should -BeTrue
        $result.IncludeGroupIds | Should -Contain 'grp-include-norm'
        $result.IncludeKinds | Should -Contain 'Group'
        $caseVariant.State | Should -Be 'Include'
        $caseVariant.IsAssigned | Should -BeTrue
        $caseVariant.IncludeGroupIds | Should -Contain 'grp-include-case'
    }

    It 'derives normalized null intent from the authoritative targetType' {
        $includeAssignments = @(
            @{ intent = $null; targetType = 'group'; groupId = 'grp-null-intent' }
        )
        $excludeAssignments = @(
            @{ intent = $null; targetType = 'exclusionGroup'; groupId = 'grp-null-exclusion' }
        )

        $include = InModuleScope TenantPulse -ArgumentList @(, $includeAssignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $exclude = InModuleScope TenantPulse -ArgumentList @(, $excludeAssignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $include.State | Should -Be 'Include'
        $include.IsAssigned | Should -BeTrue
        $include.IncludeGroupIds | Should -Contain 'grp-null-intent'
        $exclude.State | Should -Be 'ExcludeOnly'
        $exclude.IsAssigned | Should -BeFalse
        $exclude.ExcludeGroupIds | Should -Contain 'grp-null-exclusion'
    }

    It 'rejects a normalized non-null intent that contradicts its targetType' {
        $cases = @(
            @{ intent = 'exclude'; targetType = 'group'; groupId = 'grp-conflicting-include' }
            @{ intent = 'include'; targetType = 'exclusionGroup'; groupId = 'grp-conflicting-exclude' }
        )

        foreach ($assignment in $cases) {
            $result = InModuleScope TenantPulse -ArgumentList $assignment {
                param($assignment)
                ConvertTo-PulseAssignmentIntent -Assignments @($assignment)
            }

            $result.State | Should -Be 'Malformed' -Because 'normalized intent must match target-derived row-schema intent'
            $result.IsAssigned | Should -BeFalse
            $result.Complete | Should -BeFalse
            $result.MalformedReasons | Should -Contain 'unsupported-assignment-intent'
        }
    }

    It 'classifies a normalized exclusionGroup target as ExcludeOnly (parity with raw graph shape)' {
        $assignments = @(
            @{ intent = 'exclude'; targetType = 'exclusionGroup'; groupId = 'grp-ex-norm' }
        )
        $caseVariantAssignments = @(
            @{ intent = 'EXCLUDE'; targetType = 'EXCLUSIONGROUP'; groupId = 'grp-ex-case' }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $caseVariant = InModuleScope TenantPulse -ArgumentList @(, $caseVariantAssignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'ExcludeOnly'
        $result.IsAssigned | Should -BeFalse
        $result.ExcludeGroupIds | Should -Contain 'grp-ex-norm'
        $caseVariant.State | Should -Be 'ExcludeOnly'
        $caseVariant.IsAssigned | Should -BeFalse
        $caseVariant.ExcludeGroupIds | Should -Contain 'grp-ex-case'
    }

    It 'classifies a normalized allLicensedUsers target as Include (parity with raw graph shape)' {
        $assignments = @(
            @{ intent = 'include'; targetType = 'allLicensedUsers' }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Include'
        $result.IsAssigned | Should -BeTrue
        $result.IncludeKinds | Should -Contain 'AllUsers'
    }

    It 'classifies a normalized allDevices target as Include (parity with raw graph shape)' {
        $assignments = @(
            @{ intent = 'include'; targetType = 'allDevices' }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Include'
        $result.IsAssigned | Should -BeTrue
        $result.IncludeKinds | Should -Contain 'AllDevices'
    }

    It 'rejects an unexpected groupId on a <Shape> <TargetKind> target' -ForEach @(
        @{ Shape = 'raw'; TargetKind = 'allDevices'; TypeName = '#microsoft.graph.allDevicesAssignmentTarget' }
        @{ Shape = 'raw'; TargetKind = 'allLicensedUsers'; TypeName = '#microsoft.graph.allLicensedUsersAssignmentTarget' }
        @{ Shape = 'normalized'; TargetKind = 'allDevices'; TypeName = $null }
        @{ Shape = 'normalized'; TargetKind = 'allLicensedUsers'; TypeName = $null }
    ) {
        $assignments = if ($Shape -eq 'raw') {
            @(@{ target = @{ '@odata.type' = $TypeName; groupId = 'unexpected-group' } })
        } else {
            @(@{ intent = 'include'; targetType = $TargetKind; groupId = 'unexpected-group' })
        }
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
        @($result.IncludeKinds).Count | Should -Be 0
        $result.MalformedReasons | Should -Contain 'unexpected-group-id'
    }

# ---- Normalized include/exclude parity: mixing shapes in one policy. ----

    It 'classifies a mix of normalized group-include and raw graph-exclude as Include with excluded groups' {
        $assignments = @(
            @{ intent = 'include'; targetType = 'group'; groupId = 'grp-include-norm' }
            @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'grp-ex-raw' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Include'
        $result.IsAssigned | Should -BeTrue
        $result.IncludeGroupIds | Should -Contain 'grp-include-norm'
        $result.ExcludeGroupIds | Should -Contain 'grp-ex-raw'
    }

# ---- Normalized filter parity: flat filterId/filterType matches raw behavior. ----

    It 'records a normalized filter id and type without treating it as assignment by itself' {
        $assignments = @(
            @{
                intent         = 'include'
                targetType     = 'group'
                groupId        = 'grp-filter-norm'
                filterId       = 'filter-1-norm'
                filterType     = 'include'
            }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.HasFilter | Should -BeTrue
        $result.FilterIds | Should -Contain 'filter-1-norm'
        $result.State | Should -Be 'Include'
        $result.IsAssigned | Should -BeTrue
    }

    It 'accepts a schema-valid <Shape> assignment filter pair: <FilterCase>' -ForEach @(
        @{ Shape = 'raw'; FilterCase = 'unfiltered fields omitted'; HasFilterId = $false; FilterId = $null; HasFilterType = $false; FilterType = $null; ExpectedHasFilter = $false; ExpectedFilterIds = @() }
        @{ Shape = 'raw'; FilterCase = 'explicit none without an id'; HasFilterId = $false; FilterId = $null; HasFilterType = $true; FilterType = 'none'; ExpectedHasFilter = $false; ExpectedFilterIds = @() }
        @{ Shape = 'raw'; FilterCase = 'include with a native nonblank id'; HasFilterId = $true; FilterId = 'filter-include'; HasFilterType = $true; FilterType = 'include'; ExpectedHasFilter = $true; ExpectedFilterIds = @('filter-include') }
        @{ Shape = 'raw'; FilterCase = 'exclude with a native nonblank id'; HasFilterId = $true; FilterId = 'filter-exclude'; HasFilterType = $true; FilterType = 'exclude'; ExpectedHasFilter = $true; ExpectedFilterIds = @('filter-exclude') }
        @{ Shape = 'normalized'; FilterCase = 'unfiltered fields omitted'; HasFilterId = $false; FilterId = $null; HasFilterType = $false; FilterType = $null; ExpectedHasFilter = $false; ExpectedFilterIds = @() }
        @{ Shape = 'normalized'; FilterCase = 'explicit none without an id'; HasFilterId = $false; FilterId = $null; HasFilterType = $true; FilterType = 'none'; ExpectedHasFilter = $false; ExpectedFilterIds = @() }
        @{ Shape = 'normalized'; FilterCase = 'include with a native nonblank id'; HasFilterId = $true; FilterId = 'filter-include'; HasFilterType = $true; FilterType = 'include'; ExpectedHasFilter = $true; ExpectedFilterIds = @('filter-include') }
        @{ Shape = 'normalized'; FilterCase = 'exclude with a native nonblank id'; HasFilterId = $true; FilterId = 'filter-exclude'; HasFilterType = $true; FilterType = 'exclude'; ExpectedHasFilter = $true; ExpectedFilterIds = @('filter-exclude') }
    ) {
        if ($Shape -eq 'raw') {
            $target = [ordered]@{
                '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                groupId       = 'grp-filter'
            }
            if ($HasFilterId) {
                $target.deviceAndAppManagementAssignmentFilterId = $FilterId
            }
            if ($HasFilterType) {
                $target.deviceAndAppManagementAssignmentFilterType = $FilterType
            }
            $assignments = @(@{ target = $target })
        } else {
            $assignment = [ordered]@{
                intent     = 'include'
                targetType = 'group'
                groupId    = 'grp-filter'
            }
            if ($HasFilterId) {
                $assignment.filterId = $FilterId
            }
            if ($HasFilterType) {
                $assignment.filterType = $FilterType
            }
            $assignments = @($assignment)
        }

        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Include'
        $result.IsAssigned | Should -BeTrue
        $result.Complete | Should -BeTrue
        $result.HasFilter | Should -Be $ExpectedHasFilter
        @($result.FilterIds) | Should -Be $ExpectedFilterIds
    }

    It 'rejects a schema-invalid <Shape> assignment filter pair: <FilterCase>' -ForEach @(
        @{ Shape = 'raw'; FilterCase = 'include without an id'; HasFilterId = $false; FilterId = $null; HasFilterType = $true; FilterType = 'include' }
        @{ Shape = 'raw'; FilterCase = 'exclude with a blank id'; HasFilterId = $true; FilterId = ' '; HasFilterType = $true; FilterType = 'exclude' }
        @{ Shape = 'raw'; FilterCase = 'orphaned id'; HasFilterId = $true; FilterId = 'filter-orphaned'; HasFilterType = $false; FilterType = $null }
        @{ Shape = 'raw'; FilterCase = 'none with an id'; HasFilterId = $true; FilterId = 'filter-contradiction'; HasFilterType = $true; FilterType = 'none' }
        @{ Shape = 'raw'; FilterCase = 'unknown type'; HasFilterId = $true; FilterId = 'filter-future'; HasFilterType = $true; FilterType = 'futureValue' }
        @{ Shape = 'raw'; FilterCase = 'case-variant type'; HasFilterId = $true; FilterId = 'filter-case'; HasFilterType = $true; FilterType = 'Include' }
        @{ Shape = 'normalized'; FilterCase = 'include without an id'; HasFilterId = $false; FilterId = $null; HasFilterType = $true; FilterType = 'include' }
        @{ Shape = 'normalized'; FilterCase = 'exclude with a blank id'; HasFilterId = $true; FilterId = ' '; HasFilterType = $true; FilterType = 'exclude' }
        @{ Shape = 'normalized'; FilterCase = 'orphaned id'; HasFilterId = $true; FilterId = 'filter-orphaned'; HasFilterType = $false; FilterType = $null }
        @{ Shape = 'normalized'; FilterCase = 'none with an id'; HasFilterId = $true; FilterId = 'filter-contradiction'; HasFilterType = $true; FilterType = 'none' }
        @{ Shape = 'normalized'; FilterCase = 'unknown type'; HasFilterId = $true; FilterId = 'filter-future'; HasFilterType = $true; FilterType = 'futureValue' }
        @{ Shape = 'normalized'; FilterCase = 'case-variant type'; HasFilterId = $true; FilterId = 'filter-case'; HasFilterType = $true; FilterType = 'Include' }
    ) {
        if ($Shape -eq 'raw') {
            $target = [ordered]@{
                '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                groupId       = 'grp-filter'
            }
            if ($HasFilterId) {
                $target.deviceAndAppManagementAssignmentFilterId = $FilterId
            }
            if ($HasFilterType) {
                $target.deviceAndAppManagementAssignmentFilterType = $FilterType
            }
            $assignments = @(@{ target = $target })
        } else {
            $assignment = [ordered]@{
                intent     = 'include'
                targetType = 'group'
                groupId    = 'grp-filter'
            }
            if ($HasFilterId) {
                $assignment.filterId = $FilterId
            }
            if ($HasFilterType) {
                $assignment.filterType = $FilterType
            }
            $assignments = @($assignment)
        }

        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }

        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
        $result.HasFilter | Should -BeFalse
        @($result.FilterIds).Count | Should -Be 0
        @($result.IncludeKinds).Count | Should -Be 0
        @($result.IncludeGroupIds).Count | Should -Be 0
        @($result.ExcludeGroupIds).Count | Should -Be 0
        $result.MalformedReasons | Should -Contain 'invalid-assignment-filter-shape'
    }
}

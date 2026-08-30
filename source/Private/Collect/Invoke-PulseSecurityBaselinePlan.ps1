<#
    Private: collect TP.INT.0029 security-baseline assignment/version state.

    Current baselines are configurationPolicies whose template ids join to a
    configurationPolicyTemplates record in one of the four families in the check contract.
    The joined template metadata is authoritative; a missing or disagreeing policy-side
    template family remains structured uncertainty. The template lifecycleState establishes
    whether the referenced version is active or obsolete. Assignments are read through the
    per-policy assignment operation. Read-only legacy intent records retain their separate
    join to deviceManagement/templates because existing profiles can remain on that surface.

    TenantPulse emits one compact row
    {id,name,templateFamily,hasAssignment,isDeprecated}. Missing joins, malformed native
    booleans, child-read failures, or a template intentCount mismatch remain structured
    uncertainty and can never become an authoritative empty collection.
#>

function Invoke-PulseSecurityBaselinePlan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Context,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Dataset,

        [Parameter(Mandatory)]
        [pscustomobject] $ManifestEntry,

        [Parameter(Mandatory)]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [string] $TenantPseudonym,

        [Parameter()]
        [AllowNull()]
        [pscustomobject] $NetworkAbortState = $null
    )

    if ($null -eq $NetworkAbortState) {
        $NetworkAbortState = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }
    }

    $null = $ProfileId
    $null = $TenantPseudonym

    $descriptorSpecs = @(
        @{ Type = 'DeviceManagementTemplate'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'DeviceManagementConfigurationPolicyTemplate'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'ConfigurationPolicy'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'ConfigurationPolicyAssignment'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'DeviceManagementIntent'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    )
    foreach ($spec in $descriptorSpecs) {
        Assert-PulseReadOnlyDescriptor -Type $spec.Type -Operation $spec.Operation -ApiVersion $spec.ApiVersion
    }

    $apiVersion = if ($ManifestEntry.PSObject.Properties['ApiVersion'] -and $ManifestEntry.ApiVersion) {
        [string] $ManifestEntry.ApiVersion
    } else {
        'beta'
    }
    $operations = @(
        'DeviceManagementTemplate.ListBeta'
        'DeviceManagementConfigurationPolicyTemplate.ListBeta'
        'ConfigurationPolicy.ListBeta'
        'ConfigurationPolicyAssignment.ListBeta'
        'DeviceManagementIntent.ListBeta'
    )

    function Get-BaselinePropertyValue {
        param($InputObject, [string] $Name)
        if ($null -eq $InputObject) { return $null }
        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
            return $null
        }
        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        return $property.Value
    }

    function Test-BaselinePropertyPresent {
        param($InputObject, [string] $Name)
        if ($null -eq $InputObject) { return $false }
        if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject.Contains($Name) }
        return $null -ne $InputObject.PSObject.Properties[$Name]
    }

    function Test-BaselineIntegralCount {
        param($Value)
        return $Value -is [sbyte] -or $Value -is [byte] -or
            $Value -is [int16] -or $Value -is [uint16] -or
            $Value -is [int32] -or $Value -is [uint32] -or
            $Value -is [int64] -or $Value -is [uint64]
    }

    function Get-BaselineDetailSortKey {
        param([AllowNull()] $Detail)
        if ($null -eq $Detail) { return '' }
        $keys = [string[]]@($Detail.Keys)
        if ($keys.Count -gt 1) { [System.Array]::Sort($keys, [System.StringComparer]::Ordinal) }
        $parts = foreach ($key in $keys) { "$key=$([string] $Detail[$key])" }
        return [string]::Join([char] 31, [string[]] $parts)
    }

    function Sort-BaselineObjectsById {
        param([AllowEmptyCollection()] [object[]] $Items)
        $sorted = [object[]]@($Items)
        if ($sorted.Count -gt 1) {
            $comparison = [System.Comparison[object]] {
                param($left, $right)
                $leftId = [string] (Get-BaselinePropertyValue -InputObject $left -Name 'id')
                $rightId = [string] (Get-BaselinePropertyValue -InputObject $right -Name 'id')
                return [string]::CompareOrdinal($leftId, $rightId)
            }
            [System.Array]::Sort($sorted, $comparison)
        }
        return $sorted
    }

    function Get-BaselineFailureMetadata {
        param([System.Management.Automation.ErrorRecord] $ErrorRecord)
        return Resolve-PulseGraphFailure -ErrorRecord $ErrorRecord
    }

    function New-BaselineReadFailure {
        param(
            [Parameter(Mandatory)] [string] $Operation,
            [Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord
        )
        $metadata = Get-BaselineFailureMetadata -ErrorRecord $ErrorRecord
        if ($metadata.AbortCollection) {
            $NetworkAbortState.AuthenticationAborted = $true
            $NetworkAbortState.Reason = 'auth-failure: collection aborted'
        }
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
            -FailureClass $metadata.FailureClass -ReasonCode $metadata.ReasonCode `
            -Detail @{ operation = $Operation } -Provider 'GraphKit' -ApiVersion $apiVersion `
            -Operations $operations
    }

    function New-BaselineReadGap {
        param(
            [Parameter(Mandatory)] [string] $Scope,
            [Parameter(Mandatory)] [string] $Operation,
            [Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord
        )
        $metadata = Get-BaselineFailureMetadata -ErrorRecord $ErrorRecord
        if ($metadata.AbortCollection) {
            $NetworkAbortState.AuthenticationAborted = $true
            $NetworkAbortState.Reason = 'auth-failure: collection aborted'
        }
        return New-PulseCollectionGap -Scope $Scope -FailureClass $metadata.FailureClass `
            -ReasonCode $metadata.ReasonCode -Detail @{ operation = $Operation } `
            -Operation $Operation -ApiVersion 'beta'
    }

    $currentFamilies = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($family in @('baseline', 'baselineDefenderForEndpoint', 'baselineMicrosoftEdge', 'baselineWindows365')) {
        $currentFamilies.Add($family) | Out-Null
    }
    $legacyFamilyMap = @{
        securityBaseline                           = 'baseline'
        advancedThreatProtectionSecurityBaseline = 'baselineDefenderForEndpoint'
        microsoftEdgeSecurityBaseline             = 'baselineMicrosoftEdge'
        cloudPC                                   = 'baselineWindows365'
    }

    $gaps = [System.Collections.Generic.List[object]]::new()
    try {
        $templates = @(Get-GraphObject -Context $Context -Type 'DeviceManagementTemplate' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        return New-BaselineReadFailure -Operation 'DeviceManagementTemplate.ListBeta' -ErrorRecord $_
    }

    try {
        $currentTemplates = @(Get-GraphObject -Context $Context -Type 'DeviceManagementConfigurationPolicyTemplate' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        $currentTemplates = @()
        $gaps.Add((New-BaselineReadGap -Scope 'surface:configurationPolicyTemplates' `
                -Operation 'DeviceManagementConfigurationPolicyTemplate.ListBeta' -ErrorRecord $_))
        if ($NetworkAbortState.AuthenticationAborted) {
            return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps $gaps.ToArray() `
                -FailureClass 'AuthenticationFailed' -ReasonCode 'authentication-failed' `
                -Detail @{ operation = 'DeviceManagementConfigurationPolicyTemplate.ListBeta' } `
                -Provider 'GraphKit' -ApiVersion $apiVersion -Operations $operations
        }
    }
    try {
        $policies = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicy' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        $policies = @()
        $gaps.Add((New-BaselineReadGap -Scope 'surface:configurationPolicies' `
                -Operation 'ConfigurationPolicy.ListBeta' -ErrorRecord $_))
        if ($NetworkAbortState.AuthenticationAborted) {
            return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps $gaps.ToArray() `
                -FailureClass 'AuthenticationFailed' -ReasonCode 'authentication-failed' `
                -Detail @{ operation = 'ConfigurationPolicy.ListBeta' } -Provider 'GraphKit' `
                -ApiVersion $apiVersion -Operations $operations
        }
    }
    try {
        $intents = @(Get-GraphObject -Context $Context -Type 'DeviceManagementIntent' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        $intents = @()
        $gaps.Add((New-BaselineReadGap -Scope 'surface:deviceManagementIntents' `
                -Operation 'DeviceManagementIntent.ListBeta' -ErrorRecord $_))
        if ($NetworkAbortState.AuthenticationAborted) {
            return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps $gaps.ToArray() `
                -FailureClass 'AuthenticationFailed' -ReasonCode 'authentication-failed' `
                -Detail @{ operation = 'DeviceManagementIntent.ListBeta' } -Provider 'GraphKit' `
                -ApiVersion $apiVersion -Operations $operations
        }
    }

    $templatesById = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $duplicateTemplateIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($template in (Sort-BaselineObjectsById -Items $templates)) {
        $templateId = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'id')
        $templateType = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'templateType')
        if ([string]::IsNullOrWhiteSpace($templateId)) {
            if ($legacyFamilyMap.ContainsKey($templateType)) {
                $gaps.Add((New-PulseCollectionGap -Scope 'template:unknown' -FailureClass 'InvalidProviderData' `
                        -ReasonCode 'invalid-provider-data' -Detail @{ missing = 'id' } `
                        -Operation 'DeviceManagementTemplate.ListBeta' -ApiVersion 'beta'))
            }
            continue
        }
        if ($templatesById.ContainsKey($templateId)) {
            $duplicateTemplateIds.Add($templateId) | Out-Null
            continue
        }
        $templatesById.Add($templateId, $template)
    }
    $duplicateTemplateIdArray = [string[]]@($duplicateTemplateIds)
    if ($duplicateTemplateIdArray.Count -gt 1) { [System.Array]::Sort($duplicateTemplateIdArray, [System.StringComparer]::Ordinal) }
    foreach ($templateId in $duplicateTemplateIdArray) {
        $gaps.Add((New-PulseCollectionGap -Scope "template:$templateId" -FailureClass 'InvalidProviderData' `
                -ReasonCode 'invalid-provider-data' -Detail @{ duplicateTemplateId = $templateId } `
                -Operation 'DeviceManagementTemplate.ListBeta' -ApiVersion 'beta'))
    }

    $currentTemplatesById = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $duplicateCurrentTemplateIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($template in (Sort-BaselineObjectsById -Items $currentTemplates)) {
        $templateId = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'id')
        $templateFamily = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'templateFamily')
        if ([string]::IsNullOrWhiteSpace($templateId)) {
            if ($currentFamilies.Contains($templateFamily)) {
                $gaps.Add((New-PulseCollectionGap -Scope 'current-template:unknown' -FailureClass 'InvalidProviderData' `
                        -ReasonCode 'invalid-provider-data' -Detail @{ missing = 'id' } `
                        -Operation 'DeviceManagementConfigurationPolicyTemplate.ListBeta' -ApiVersion 'beta'))
            }
            continue
        }
        if ($currentTemplatesById.ContainsKey($templateId)) {
            $duplicateCurrentTemplateIds.Add($templateId) | Out-Null
            continue
        }
        $currentTemplatesById.Add($templateId, $template)
    }
    $duplicateCurrentTemplateIdArray = [string[]]@($duplicateCurrentTemplateIds)
    if ($duplicateCurrentTemplateIdArray.Count -gt 1) { [System.Array]::Sort($duplicateCurrentTemplateIdArray, [System.StringComparer]::Ordinal) }
    foreach ($templateId in $duplicateCurrentTemplateIdArray) {
        $gaps.Add((New-PulseCollectionGap -Scope "current-template:$templateId" -FailureClass 'InvalidProviderData' `
                -ReasonCode 'invalid-provider-data' -Detail @{ duplicateTemplateId = $templateId } `
                -Operation 'DeviceManagementConfigurationPolicyTemplate.ListBeta' -ApiVersion 'beta'))
    }

    $duplicatePolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($policy in $policies) {
        $policyId = [string] (Get-BaselinePropertyValue -InputObject $policy -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($policyId) -and -not $seenPolicyIds.Add($policyId)) {
            $duplicatePolicyIds.Add($policyId) | Out-Null
        }
    }
    $duplicatePolicyIdArray = [string[]]@($duplicatePolicyIds)
    if ($duplicatePolicyIdArray.Count -gt 1) { [System.Array]::Sort($duplicatePolicyIdArray, [System.StringComparer]::Ordinal) }
    foreach ($policyId in $duplicatePolicyIdArray) {
        $gaps.Add((New-PulseCollectionGap -Scope "policy:$policyId" -FailureClass 'InvalidProviderData' `
                -ReasonCode 'invalid-provider-data' -Detail @{ duplicatePolicyId = $policyId } `
                -Operation 'ConfigurationPolicy.ListBeta' -ApiVersion 'beta'))
    }

    $rowsByKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($policy in (Sort-BaselineObjectsById -Items $policies)) {
        $templateReference = Get-BaselinePropertyValue -InputObject $policy -Name 'templateReference'
        $policyFamily = [string] (Get-BaselinePropertyValue -InputObject $templateReference -Name 'templateFamily')
        $policyId = [string] (Get-BaselinePropertyValue -InputObject $policy -Name 'id')
        $templateId = [string] (Get-BaselinePropertyValue -InputObject $templateReference -Name 'templateId')
        $scope = if ([string]::IsNullOrWhiteSpace($policyId)) { 'policy:unknown' } else { "policy:$policyId" }
        if ($duplicatePolicyIds.Contains($policyId)) { continue }

        if ([string]::IsNullOrWhiteSpace($templateId)) {
            if ([string]::IsNullOrWhiteSpace($policyFamily) -or $currentFamilies.Contains($policyFamily)) {
                $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                        -ReasonCode 'invalid-provider-data' -Detail @{ missing = 'id-templateReference-or-template-join' } `
                        -Operation 'ConfigurationPolicy.ListBeta' -ApiVersion 'beta'))
            }
            continue
        }
        if ([string]::IsNullOrWhiteSpace($policyId) -or -not $currentTemplatesById.ContainsKey($templateId) -or
            $duplicateCurrentTemplateIds.Contains($templateId)) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ missing = 'id-templateReference-or-template-join' } `
                    -Operation 'ConfigurationPolicy.ListBeta' -ApiVersion 'beta'))
            continue
        }

        $template = $currentTemplatesById[$templateId]
        $family = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'templateFamily')
        if ([string]::IsNullOrWhiteSpace($family)) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ invalid = 'templateFamily'; value = $family } `
                    -Operation 'DeviceManagementConfigurationPolicyTemplate.ListBeta' -ApiVersion 'beta'))
            continue
        }
        if ([string]::IsNullOrWhiteSpace($policyFamily) -or
            -not [string]::Equals($policyFamily, $family, [System.StringComparison]::OrdinalIgnoreCase)) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{
                        invalid              = 'templateFamily'
                        policyTemplateFamily = $policyFamily
                        joinedTemplateFamily = $family
                    } -Operation 'ConfigurationPolicy.ListBeta' -ApiVersion 'beta'))
            continue
        }
        if (-not $currentFamilies.Contains($family)) { continue }

        $lifecycleState = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'lifecycleState')
        $isDeprecated = switch ($lifecycleState.ToLowerInvariant()) {
            'active' { $false }
            { $_ -in @('superseded', 'deprecated', 'retired') } { $true }
            default { $null }
        }
        if ($null -eq $isDeprecated) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ invalid = 'lifecycleState'; value = $lifecycleState } `
                    -Operation 'DeviceManagementConfigurationPolicyTemplate.ListBeta' -ApiVersion 'beta'))
            continue
        }

        try {
            $assignments = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicyAssignment' `
                    -Operation 'ListBeta' -Parameters @{ id = $policyId } -ErrorAction Stop)
        } catch {
            $gaps.Add((New-BaselineReadGap -Scope $scope `
                    -Operation 'ConfigurationPolicyAssignment.ListBeta' -ErrorRecord $_))
            if ($NetworkAbortState.AuthenticationAborted) { break }
            continue
        }

        $positiveAssignmentCount = 0
        $assignmentDataInvalid = $false
        foreach ($assignment in $assignments) {
            $assignmentIdValue = Get-BaselinePropertyValue -InputObject $assignment -Name 'id'
            $target = Get-BaselinePropertyValue -InputObject $assignment -Name 'target'
            $targetType = [string] (Get-BaselinePropertyValue -InputObject $target -Name '@odata.type')
            $normalizedTargetType = $targetType.TrimStart('#').ToLowerInvariant()
            $requiresGroupId = $normalizedTargetType -in @(
                'microsoft.graph.groupassignmenttarget'
                'microsoft.graph.exclusiongroupassignmenttarget'
            )
            $groupIdValue = Get-BaselinePropertyValue -InputObject $target -Name 'groupId'
            $hasValidAssignmentId = $assignmentIdValue -is [string] -and
                -not [string]::IsNullOrWhiteSpace($assignmentIdValue)
            $hasValidGroupId = -not $requiresGroupId -or
                ($groupIdValue -is [string] -and -not [string]::IsNullOrWhiteSpace($groupIdValue))
            if (-not $hasValidAssignmentId -or [string]::IsNullOrWhiteSpace($normalizedTargetType) -or
                -not $hasValidGroupId) {
                $assignmentDataInvalid = $true
                break
            }
            switch ($normalizedTargetType) {
                'microsoft.graph.groupassignmenttarget' { $positiveAssignmentCount++; continue }
                'microsoft.graph.alldevicesassignmenttarget' { $positiveAssignmentCount++; continue }
                'microsoft.graph.alllicensedusersassignmenttarget' { $positiveAssignmentCount++; continue }
                'microsoft.graph.exclusiongroupassignmenttarget' { continue }
                default { $assignmentDataInvalid = $true; break }
            }
            if ($assignmentDataInvalid) { break }
        }
        if ($assignmentDataInvalid) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ invalid = 'assignment-target' } `
                    -Operation 'ConfigurationPolicyAssignment.ListBeta' -ApiVersion 'beta'))
            continue
        }

        $rowKey = "policy:$policyId"
        $name = [string] (Get-BaselinePropertyValue -InputObject $policy -Name 'name')
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $policyId }
        $rowsByKey.Add($rowKey, [pscustomobject][ordered]@{
                id             = $policyId
                name           = $name
                templateFamily = $family
                hasAssignment  = ($positiveAssignmentCount -gt 0)
                isDeprecated   = $isDeprecated
            })
    }

    $duplicateIntentIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenIntentIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($intent in $intents) {
        $intentId = [string] (Get-BaselinePropertyValue -InputObject $intent -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($intentId) -and -not $seenIntentIds.Add($intentId)) {
            $duplicateIntentIds.Add($intentId) | Out-Null
        }
    }
    $duplicateIntentIdArray = [string[]]@($duplicateIntentIds)
    if ($duplicateIntentIdArray.Count -gt 1) { [System.Array]::Sort($duplicateIntentIdArray, [System.StringComparer]::Ordinal) }
    foreach ($intentId in $duplicateIntentIdArray) {
        $gaps.Add((New-PulseCollectionGap -Scope "intent:$intentId" -FailureClass 'InvalidProviderData' `
                -ReasonCode 'invalid-provider-data' -Detail @{ duplicateIntentId = $intentId } `
                -Operation 'DeviceManagementIntent.ListBeta' -ApiVersion 'beta'))
    }

    $legacyIntentCounts = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($intent in (Sort-BaselineObjectsById -Items $intents)) {
        $intentId = [string] (Get-BaselinePropertyValue -InputObject $intent -Name 'id')
        $templateId = [string] (Get-BaselinePropertyValue -InputObject $intent -Name 'templateId')
        $scope = if ([string]::IsNullOrWhiteSpace($intentId)) { 'intent:unknown' } else { "intent:$intentId" }
        if ($duplicateIntentIds.Contains($intentId)) { continue }
        if ([string]::IsNullOrWhiteSpace($intentId) -or [string]::IsNullOrWhiteSpace($templateId) -or
            -not $templatesById.ContainsKey($templateId) -or $duplicateTemplateIds.Contains($templateId)) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ missing = 'id-templateId-or-template-join' } `
                    -Operation 'DeviceManagementIntent.ListBeta' -ApiVersion 'beta'))
            continue
        }

        if (-not $legacyIntentCounts.ContainsKey($templateId)) { $legacyIntentCounts[$templateId] = 0 }
        $legacyIntentCounts[$templateId]++
        $template = $templatesById[$templateId]
        $templateType = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'templateType')
        if (-not $legacyFamilyMap.ContainsKey($templateType)) { continue }

        $isAssigned = Get-BaselinePropertyValue -InputObject $intent -Name 'isAssigned'
        $isDeprecated = Get-BaselinePropertyValue -InputObject $template -Name 'isDeprecated'
        if (-not (Test-BaselinePropertyPresent -InputObject $intent -Name 'isAssigned') -or $isAssigned -isnot [bool] -or
            -not (Test-BaselinePropertyPresent -InputObject $template -Name 'isDeprecated') -or $isDeprecated -isnot [bool]) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ invalid = 'isAssigned-or-isDeprecated' } `
                    -Operation 'DeviceManagementIntent.ListBeta' -ApiVersion 'beta'))
            continue
        }

        $rowKey = "intent:$intentId"
        $name = [string] (Get-BaselinePropertyValue -InputObject $intent -Name 'displayName')
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $intentId }
        $rowsByKey.Add($rowKey, [pscustomobject][ordered]@{
                id             = $intentId
                name           = $name
                templateFamily = [string] $legacyFamilyMap[$templateType]
                hasAssignment  = $isAssigned
                isDeprecated   = $isDeprecated
            })
    }

    $templateIds = [string[]]@($templatesById.Keys)
    if ($templateIds.Count -gt 1) { [System.Array]::Sort($templateIds, [System.StringComparer]::Ordinal) }
    foreach ($templateId in $templateIds) {
        if ($duplicateTemplateIds.Contains($templateId)) { continue }
        $template = $templatesById[$templateId]
        $templateType = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'templateType')
        if (-not $legacyFamilyMap.ContainsKey($templateType)) {
            continue
        }
        if (-not (Test-BaselinePropertyPresent -InputObject $template -Name 'intentCount')) {
            $gaps.Add((New-PulseCollectionGap -Scope "template:$templateId" -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ invalid = 'intentCount' } `
                    -Operation 'DeviceManagementTemplate.ListBeta' -ApiVersion 'beta'))
            continue
        }
        $intentCount = Get-BaselinePropertyValue -InputObject $template -Name 'intentCount'
        $actualCount = if ($legacyIntentCounts.ContainsKey($templateId)) { $legacyIntentCounts[$templateId] } else { 0 }
        if (-not (Test-BaselineIntegralCount -Value $intentCount) -or [long] $intentCount -lt 0 -or
            [long] $intentCount -ne [long] $actualCount) {
            $gaps.Add((New-PulseCollectionGap -Scope "template:$templateId" -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' `
                    -Detail @{ expectedIntentCount = $intentCount; observedIntentCount = $actualCount } `
                    -Operation 'DeviceManagementTemplate.ListBeta' -ApiVersion 'beta'))
        }
    }

    $rowKeys = [string[]]@($rowsByKey.Keys)
    if ($rowKeys.Count -gt 1) { [System.Array]::Sort($rowKeys, [System.StringComparer]::Ordinal) }
    $rows = @($rowKeys | ForEach-Object { $rowsByKey[$_] })

    $gapArray = [object[]]@($gaps.ToArray())
    if ($gapArray.Count -gt 1) {
        $gapComparison = [System.Comparison[object]] {
            param($left, $right)
            foreach ($propertyName in @('Scope', 'Operation', 'ReasonCode', 'FailureClass')) {
                $comparison = [string]::CompareOrdinal([string] $left.$propertyName, [string] $right.$propertyName)
                if ($comparison -ne 0) { return $comparison }
            }
            return [string]::CompareOrdinal(
                (Get-BaselineDetailSortKey -Detail $left.Detail),
                (Get-BaselineDetailSortKey -Detail $right.Detail)
            )
        }
        [System.Array]::Sort($gapArray, $gapComparison)
    }

    if ($gapArray.Count -eq 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Collected' -Rows $rows -Gaps @() `
            -ReasonCode 'collected' -Detail @{ baselineCount = $rows.Count } -Provider 'GraphKit' `
            -ApiVersion $apiVersion -Operations $operations
    }
    if ($rows.Count -gt 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Partial' -Rows $rows -Gaps $gapArray `
            -ReasonCode 'partial' -Detail @{ baselineCount = $rows.Count; gapCount = $gapArray.Count } `
            -Provider 'GraphKit' -ApiVersion $apiVersion -Operations $operations
    }
    $topFailureClass = [string] $gapArray[0].FailureClass
    $topReasonCode = [string] $gapArray[0].ReasonCode
    foreach ($gap in $gapArray) {
        if ([string] $gap.FailureClass -ne $topFailureClass -or [string] $gap.ReasonCode -ne $topReasonCode) {
            $topFailureClass = 'ProviderFailed'
            $topReasonCode = 'provider-failed'
            break
        }
    }
    return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps $gapArray `
        -FailureClass $topFailureClass -ReasonCode $topReasonCode `
        -Detail @{ gapCount = $gapArray.Count } -Provider 'GraphKit' -ApiVersion $apiVersion `
        -Operations $operations
}

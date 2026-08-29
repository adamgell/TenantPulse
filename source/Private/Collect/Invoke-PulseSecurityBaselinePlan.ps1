<#
    Private: collect TP.INT.0029 security-baseline assignment/version state.

    Current baselines are configurationPolicies whose templateReference.templateFamily is
    one of the four families in the check contract. Their assignments are read through the
    released per-policy assignment operation. Read-only legacy intent records are retained
    as a second input because existing profiles can remain on that service surface even
    though new baseline management moved to configurationPolicies.

    Both shapes join their template id to DeviceManagementTemplate.ListBeta for the native
    isDeprecated disposition. TenantPulse emits one compact row
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
        [string] $TenantPseudonym
    )

    $null = $ProfileId
    $null = $TenantPseudonym

    $descriptorSpecs = @(
        @{ Type = 'DeviceManagementTemplate'; Operation = 'ListBeta'; ApiVersion = 'beta' }
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
        $classified = Get-PulseFailureClass -ErrorRecord $ErrorRecord
        switch ($classified) {
            'PermissionDenied' { return @{ FailureClass = 'PermissionDenied'; ReasonCode = 'permission-denied' } }
            'AuthFailure' { return @{ FailureClass = 'AuthenticationFailed'; ReasonCode = 'authentication-failed' } }
            default { return @{ FailureClass = 'ProviderFailed'; ReasonCode = 'provider-failed' } }
        }
    }

    function New-BaselineReadFailure {
        param(
            [Parameter(Mandatory)] [string] $Operation,
            [Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord
        )
        $metadata = Get-BaselineFailureMetadata -ErrorRecord $ErrorRecord
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

    try {
        $templates = @(Get-GraphObject -Context $Context -Type 'DeviceManagementTemplate' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        return New-BaselineReadFailure -Operation 'DeviceManagementTemplate.ListBeta' -ErrorRecord $_
    }

    $gaps = [System.Collections.Generic.List[object]]::new()
    try {
        $policies = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicy' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        $policies = @()
        $gaps.Add((New-BaselineReadGap -Scope 'surface:configurationPolicies' `
                -Operation 'ConfigurationPolicy.ListBeta' -ErrorRecord $_))
    }
    try {
        $intents = @(Get-GraphObject -Context $Context -Type 'DeviceManagementIntent' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        $intents = @()
        $gaps.Add((New-BaselineReadGap -Scope 'surface:deviceManagementIntents' `
                -Operation 'DeviceManagementIntent.ListBeta' -ErrorRecord $_))
    }

    $templatesById = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $duplicateTemplateIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($template in (Sort-BaselineObjectsById -Items $templates)) {
        $templateId = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'id')
        if ([string]::IsNullOrWhiteSpace($templateId)) { continue }
        if ($templatesById.ContainsKey($templateId)) {
            $duplicateTemplateIds.Add($templateId) | Out-Null
            continue
        }
        $templatesById.Add($templateId, $template)
    }

    $rowsByKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($policy in (Sort-BaselineObjectsById -Items $policies)) {
        $templateReference = Get-BaselinePropertyValue -InputObject $policy -Name 'templateReference'
        $family = [string] (Get-BaselinePropertyValue -InputObject $templateReference -Name 'templateFamily')
        if (-not $currentFamilies.Contains($family)) { continue }

        $policyId = [string] (Get-BaselinePropertyValue -InputObject $policy -Name 'id')
        $templateId = [string] (Get-BaselinePropertyValue -InputObject $templateReference -Name 'templateId')
        $scope = if ([string]::IsNullOrWhiteSpace($policyId)) { 'policy:unknown' } else { "policy:$policyId" }
        if ([string]::IsNullOrWhiteSpace($policyId) -or [string]::IsNullOrWhiteSpace($templateId) -or
            -not $templatesById.ContainsKey($templateId) -or $duplicateTemplateIds.Contains($templateId)) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ missing = 'id-templateReference-or-template-join' } `
                    -Operation 'ConfigurationPolicy.ListBeta' -ApiVersion 'beta'))
            continue
        }

        $template = $templatesById[$templateId]
        $isDeprecated = Get-BaselinePropertyValue -InputObject $template -Name 'isDeprecated'
        if (-not (Test-BaselinePropertyPresent -InputObject $template -Name 'isDeprecated') -or $isDeprecated -isnot [bool]) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ invalid = 'isDeprecated' } `
                    -Operation 'DeviceManagementTemplate.ListBeta' -ApiVersion 'beta'))
            continue
        }

        try {
            $assignments = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicyAssignment' `
                    -Operation 'ListBeta' -Parameters @{ id = $policyId } -ErrorAction Stop)
        } catch {
            $gaps.Add((New-BaselineReadGap -Scope $scope `
                    -Operation 'ConfigurationPolicyAssignment.ListBeta' -ErrorRecord $_))
            continue
        }

        $rowKey = "policy:$policyId"
        if ($rowsByKey.ContainsKey($rowKey)) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ duplicatePolicyId = $policyId } `
                    -Operation 'ConfigurationPolicy.ListBeta' -ApiVersion 'beta'))
            continue
        }
        $name = [string] (Get-BaselinePropertyValue -InputObject $policy -Name 'name')
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $policyId }
        $rowsByKey.Add($rowKey, [pscustomobject][ordered]@{
                id             = $policyId
                name           = $name
                templateFamily = $family
                hasAssignment  = (@($assignments).Count -gt 0)
                isDeprecated   = $isDeprecated
            })
    }

    $legacyIntentCounts = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($intent in (Sort-BaselineObjectsById -Items $intents)) {
        $intentId = [string] (Get-BaselinePropertyValue -InputObject $intent -Name 'id')
        $templateId = [string] (Get-BaselinePropertyValue -InputObject $intent -Name 'templateId')
        $scope = if ([string]::IsNullOrWhiteSpace($intentId)) { 'intent:unknown' } else { "intent:$intentId" }
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
        if ($rowsByKey.ContainsKey($rowKey)) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ duplicateIntentId = $intentId } `
                    -Operation 'DeviceManagementIntent.ListBeta' -ApiVersion 'beta'))
            continue
        }
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
        if (-not $legacyFamilyMap.ContainsKey($templateType) -or
            -not (Test-BaselinePropertyPresent -InputObject $template -Name 'intentCount')) {
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

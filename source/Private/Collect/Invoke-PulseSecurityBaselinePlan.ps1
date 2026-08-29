<#
    Private: collect TP.INT.0029 security-baseline assignment/version state.

    GraphKit supplies two released read primitives for this composite:

      - DeviceManagementTemplate.ListBeta exposes templateType, versionInfo, and the native
        Boolean isDeprecated.
      - DeviceManagementIntent.ListBeta exposes each profile's templateId and native Boolean
        isAssigned.

    TenantPulse joins intent.templateId to template.id, retains only the security-baseline
    template families, and emits the compact check row
    {id,name,templateFamily,hasAssignment,isDeprecated}. A missing relationship or wrongly
    typed Boolean is provider-data uncertainty, never an authoritative empty collection.
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

    $operations = @('DeviceManagementTemplate.ListBeta', 'DeviceManagementIntent.ListBeta')

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

    function New-BaselineReadFailure {
        param(
            [Parameter(Mandatory)] [string] $Operation,
            [Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord
        )

        $failureClass = Get-PulseFailureClass -ErrorRecord $ErrorRecord
        $normalized = switch ($failureClass) {
            'PermissionDenied' { 'PermissionDenied'; break }
            'AuthFailure' { 'AuthenticationFailed'; break }
            default { 'ProviderFailed' }
        }
        $reasonCode = switch ($normalized) {
            'PermissionDenied' { 'permission-denied'; break }
            'AuthenticationFailed' { 'authentication-failed'; break }
            default { 'provider-failed' }
        }

        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
            -FailureClass $normalized -ReasonCode $reasonCode -Detail @{ operation = $Operation } `
            -Provider 'GraphKit' -ApiVersion $apiVersion -Operations $operations
    }

    try {
        $templates = @(Get-GraphObject -Context $Context -Type 'DeviceManagementTemplate' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        return New-BaselineReadFailure -Operation 'DeviceManagementTemplate.ListBeta' -ErrorRecord $_
    }

    try {
        $intents = @(Get-GraphObject -Context $Context -Type 'DeviceManagementIntent' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        return New-BaselineReadFailure -Operation 'DeviceManagementIntent.ListBeta' -ErrorRecord $_
    }

    $trackedTemplateTypes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($templateType in @(
        'securityBaseline'
        'advancedThreatProtectionSecurityBaseline'
        'microsoftEdgeSecurityBaseline'
        'microsoftOffice365ProPlusSecurityBaseline'
        'cloudPC'
    )) {
        $trackedTemplateTypes.Add($templateType) | Out-Null
    }

    $templatesById = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $gaps = [System.Collections.Generic.List[object]]::new()
    foreach ($template in $templates) {
        $templateId = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'id')
        $templateType = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'templateType')
        if ([string]::IsNullOrWhiteSpace($templateId) -or [string]::IsNullOrWhiteSpace($templateType)) {
            $gaps.Add((New-PulseCollectionGap -Scope 'template:unknown' -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ missing = 'id-or-templateType' } `
                    -Operation 'DeviceManagementTemplate.ListBeta' -ApiVersion 'beta'))
            continue
        }
        if ($templatesById.ContainsKey($templateId)) {
            $gaps.Add((New-PulseCollectionGap -Scope "template:$templateId" -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ duplicateTemplateId = $templateId } `
                    -Operation 'DeviceManagementTemplate.ListBeta' -ApiVersion 'beta'))
            continue
        }
        $templatesById.Add($templateId, $template)
    }

    $rowsById = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($intent in $intents) {
        $intentId = [string] (Get-BaselinePropertyValue -InputObject $intent -Name 'id')
        $templateId = [string] (Get-BaselinePropertyValue -InputObject $intent -Name 'templateId')
        $scope = if ([string]::IsNullOrWhiteSpace($intentId)) { 'intent:unknown' } else { "intent:$intentId" }

        if ([string]::IsNullOrWhiteSpace($intentId) -or [string]::IsNullOrWhiteSpace($templateId) -or -not $templatesById.ContainsKey($templateId)) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ missing = 'id-templateId-or-template-join' } `
                    -Operation 'DeviceManagementIntent.ListBeta' -ApiVersion 'beta'))
            continue
        }

        $template = $templatesById[$templateId]
        $templateType = [string] (Get-BaselinePropertyValue -InputObject $template -Name 'templateType')
        if (-not $trackedTemplateTypes.Contains($templateType)) { continue }

        $hasIsAssigned = Test-BaselinePropertyPresent -InputObject $intent -Name 'isAssigned'
        $hasIsDeprecated = Test-BaselinePropertyPresent -InputObject $template -Name 'isDeprecated'
        $isAssigned = Get-BaselinePropertyValue -InputObject $intent -Name 'isAssigned'
        $isDeprecated = Get-BaselinePropertyValue -InputObject $template -Name 'isDeprecated'
        if (-not $hasIsAssigned -or $isAssigned -isnot [bool] -or -not $hasIsDeprecated -or $isDeprecated -isnot [bool]) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ invalid = 'isAssigned-or-isDeprecated' } `
                    -Operation 'DeviceManagementIntent.ListBeta' -ApiVersion 'beta'))
            continue
        }
        if ($rowsById.ContainsKey($intentId)) {
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ duplicateIntentId = $intentId } `
                    -Operation 'DeviceManagementIntent.ListBeta' -ApiVersion 'beta'))
            continue
        }

        $displayName = [string] (Get-BaselinePropertyValue -InputObject $intent -Name 'displayName')
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $intentId }
        $rowsById.Add($intentId, [pscustomobject][ordered]@{
                id             = $intentId
                name           = $displayName
                templateFamily = $templateType
                hasAssignment  = $isAssigned
                isDeprecated   = $isDeprecated
            })
    }

    $rowIds = [string[]] @($rowsById.Keys)
    if ($rowIds.Count -gt 1) { [System.Array]::Sort($rowIds, [System.StringComparer]::Ordinal) }
    $rows = @($rowIds | ForEach-Object { $rowsById[$_] })
    $gapArray = $gaps.ToArray()

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

    return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps $gapArray `
        -FailureClass 'InvalidProviderData' -ReasonCode 'invalid-provider-data' `
        -Detail @{ gapCount = $gapArray.Count } -Provider 'GraphKit' -ApiVersion $apiVersion `
        -Operations $operations
}

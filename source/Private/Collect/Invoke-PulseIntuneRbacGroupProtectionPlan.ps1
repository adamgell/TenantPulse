<#
    Private: collect the compact, group-keyed input for TP.INT.0013.

    This is a TenantPulse-owned composite plan. GraphKit remains responsible for one
    operation at a time: one expanded Intune unified-RBAC assignment read and one selected
    Group.Get read per distinct principal group. Every call receives the same resolved context
    and is made in deterministic sequence; there is deliberately no generic Walk or parallel
    fan-out.

    Only expanded principals whose @odata.type is microsoft.graph.group are passed to
    Group.Get; known user and service-principal records are outside this group-protection
    check, while a missing, base-directory-object, or unknown discriminator is invalid
    provider data. A child group failure is a structured collection gap. Rows from successful
    child reads remain usable as a Partial outcome, while a run with no usable rows is Failed
    so the evaluator cannot mistake an unresolved walk for an authoritative empty collection.
#>

function Invoke-PulseIntuneRbacGroupProtectionPlan {
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

    # Required by the common provider-plan contract; this plan does not use either value.
    $null = $ProfileId
    $null = $TenantPseudonym

    $descriptorSpecs = @(
        @{ Type = 'DeviceManagementUnifiedRoleAssignment'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'Group'; Operation = 'Get'; ApiVersion = 'v1.0' }
    )

    # Resolve and validate every released primitive before the first network call. A missing
    # or unsafe descriptor is a module/package gate failure, not a child gap that can be
    # partially evaluated.
    foreach ($spec in $descriptorSpecs) {
        Assert-PulseReadOnlyDescriptor -Type $spec.Type -Operation $spec.Operation -ApiVersion $spec.ApiVersion
    }

    $operations = @('ListBeta', 'Get')
    $apiVersion = if ($ManifestEntry.PSObject.Properties['ApiVersion'] -and $ManifestEntry.ApiVersion) {
        [string] $ManifestEntry.ApiVersion
    } else {
        'beta'
    }

    function New-RbacFailureOutcome {
        param(
            [Parameter(Mandatory)] [string] $Operation,
            [Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord
        )

        $failure = Resolve-PulseGraphFailure -ErrorRecord $ErrorRecord

        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
            -FailureClass $failure.FailureClass -ReasonCode $failure.ReasonCode `
            -Detail @{ operation = $Operation } -Provider 'GraphKit' -ApiVersion $apiVersion `
            -Operations $operations
    }

    $roleAssignments = @()
    try {
        $roleAssignments = @(Get-GraphObject -Context $Context -Type 'DeviceManagementUnifiedRoleAssignment' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        return New-RbacFailureOutcome -Operation 'DeviceManagementUnifiedRoleAssignment.ListBeta' -ErrorRecord $_
    }

    # The ordered map is keyed case-insensitively so the same group is read once even if
    # assignments use inconsistent casing. Each value is a case-insensitive set of role
    # names, later rendered into one deterministic compact string for the check's existing
    # roleDefinitionName field.
    $groupRoleNames = [ordered]@{}
    $gaps = [System.Collections.Generic.List[object]]::new()
    foreach ($assignment in $roleAssignments) {
        $assignmentId = $null
        $roleDefinitionName = $null
        $principals = @()
        $roleDefinition = $null
        $hasPrincipals = $false
        if ($null -eq $assignment) {
            $assignmentId = 'unknown'
        } elseif ($assignment -is [System.Collections.IDictionary]) {
            if ($assignment.Contains('id')) { $assignmentId = [string] $assignment['id'] }
            if ($assignment.Contains('roleDefinition')) { $roleDefinition = $assignment['roleDefinition'] }
            if ($assignment.Contains('principals')) {
                $hasPrincipals = $true
                $principals = @($assignment['principals'])
            }
        } else {
            if ($assignment.PSObject.Properties['id']) { $assignmentId = [string] $assignment.id }
            if ($assignment.PSObject.Properties['roleDefinition']) { $roleDefinition = $assignment.roleDefinition }
            if ($assignment.PSObject.Properties['principals']) {
                $hasPrincipals = $true
                $principals = @($assignment.principals)
            }
        }

        if ($null -ne $roleDefinition) {
            if ($roleDefinition -is [System.Collections.IDictionary]) {
                if ($roleDefinition.Contains('displayName')) {
                    $roleDefinitionName = [string] $roleDefinition['displayName']
                }
            } else {
                if ($roleDefinition.PSObject.Properties['displayName']) {
                    $roleDefinitionName = [string] $roleDefinition.displayName
                }
            }
        }

        # This descriptor promises both expansions. Any returned assignment missing either
        # relationship is invalid provider data, not evidence that no group-backed RBAC
        # assignments exist.
        if (-not $hasPrincipals -or $principals.Count -eq 0 -or [string]::IsNullOrWhiteSpace($roleDefinitionName)) {
            $scopeId = if ([string]::IsNullOrWhiteSpace($assignmentId)) { 'unknown' } else { $assignmentId }
            $gaps.Add((New-PulseCollectionGap -Scope "assignment:$scopeId" -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ assignmentId = $scopeId } -Operation 'ListBeta' -ApiVersion 'beta'))
            continue
        }

        $hasInvalidPrincipal = $false
        foreach ($principal in $principals) {
            $groupId = $null
            $principalType = $null
            if ($principal -is [System.Collections.IDictionary]) {
                if ($principal.Contains('id')) { $groupId = [string] $principal['id'] }
                if ($principal.Contains('@odata.type')) { $principalType = [string] $principal['@odata.type'] }
            } elseif ($null -ne $principal) {
                if ($principal.PSObject.Properties['id']) { $groupId = [string] $principal.id }
                if ($principal.PSObject.Properties['@odata.type']) { $principalType = [string] $principal.'@odata.type' }
            }

            if ([string]::IsNullOrWhiteSpace($principalType)) {
                $hasInvalidPrincipal = $true
                continue
            }
            $normalizedPrincipalType = $principalType.Trim().TrimStart('#')
            $isGroup = [string]::Equals(
                $normalizedPrincipalType,
                'microsoft.graph.group',
                [System.StringComparison]::OrdinalIgnoreCase
            )
            if (-not $isGroup) {
                $isKnownNonGroup = [string]::Equals(
                    $normalizedPrincipalType,
                    'microsoft.graph.user',
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -or [string]::Equals(
                    $normalizedPrincipalType,
                    'microsoft.graph.servicePrincipal',
                    [System.StringComparison]::OrdinalIgnoreCase
                )
                if (-not $isKnownNonGroup) { $hasInvalidPrincipal = $true }
                continue
            }
            if ([string]::IsNullOrWhiteSpace($groupId)) {
                $hasInvalidPrincipal = $true
                continue
            }
            if (-not $groupRoleNames.Contains($groupId)) {
                $groupRoleNames[$groupId] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
            $groupRoleNames[$groupId].Add($roleDefinitionName) | Out-Null
        }
        if ($hasInvalidPrincipal) {
            $scopeId = if ([string]::IsNullOrWhiteSpace($assignmentId)) { 'unknown' } else { $assignmentId }
            $gaps.Add((New-PulseCollectionGap -Scope "assignment:$scopeId" -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ assignmentId = $scopeId } -Operation 'ListBeta' -ApiVersion 'beta'))
        }
    }

    $groupIds = [string[]] @($groupRoleNames.Keys)
    if ($groupIds.Count -gt 1) {
        [System.Array]::Sort($groupIds, [System.StringComparer]::OrdinalIgnoreCase)
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($groupId in $groupIds) {
        $groupRows = @()
        try {
            $groupRows = @(Get-GraphObject -Context $Context -Type 'Group' -Operation 'Get' -Parameters @{ id = $groupId } -ErrorAction Stop)
        } catch {
            $failure = Resolve-PulseGraphFailure -ErrorRecord $_
            $gaps.Add((New-PulseCollectionGap -Scope "group:$groupId" -FailureClass $failure.FailureClass `
                    -ReasonCode $failure.ReasonCode -Detail @{ groupId = $groupId } -Operation 'Get' -ApiVersion 'v1.0'))
            continue
        }

        if ($groupRows.Count -ne 1 -or $null -eq $groupRows[0]) {
            $gaps.Add((New-PulseCollectionGap -Scope "group:$groupId" -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ groupId = $groupId } -Operation 'Get' -ApiVersion 'v1.0'))
            continue
        }

        $group = $groupRows[0]
        $propertyNames = if ($group -is [System.Collections.IDictionary]) {
            @($group.Keys | ForEach-Object { [string] $_ })
        } else {
            @($group.PSObject.Properties.Name)
        }
        $hasRestricted = $propertyNames -contains 'isManagementRestricted'
        $hasAssignable = $propertyNames -contains 'isAssignableToRole'
        $restricted = if ($hasRestricted) { if ($group -is [System.Collections.IDictionary]) { $group['isManagementRestricted'] } else { $group.isManagementRestricted } } else { $null }
        $assignable = if ($hasAssignable) { if ($group -is [System.Collections.IDictionary]) { $group['isAssignableToRole'] } else { $group.isAssignableToRole } } else { $null }
        # Graph declares both flags nullable. Present-null means the protection is not
        # enabled and is normalized to native false; an absent property or any non-null,
        # non-Boolean value is still invalid provider data and remains fail-closed.
        if (-not $hasRestricted -or -not $hasAssignable -or
            ($null -ne $restricted -and $restricted -isnot [bool]) -or
            ($null -ne $assignable -and $assignable -isnot [bool])) {
            $gaps.Add((New-PulseCollectionGap -Scope "group:$groupId" -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ groupId = $groupId } -Operation 'Get' -ApiVersion 'v1.0'))
            continue
        }
        $restricted = if ($null -eq $restricted) { [bool] $false } else { [bool] $restricted }
        $assignable = if ($null -eq $assignable) { [bool] $false } else { [bool] $assignable }

        $displayName = if ($group -is [System.Collections.IDictionary]) {
            if ($group.Contains('displayName')) { [string] $group['displayName'] } else { $groupId }
        } elseif ($group.PSObject.Properties['displayName']) {
            [string] $group.displayName
        } else {
            $groupId
        }
        $roleNames = [string[]] @($groupRoleNames[$groupId])
        if ($roleNames.Count -gt 1) {
            [System.Array]::Sort($roleNames, [System.StringComparer]::OrdinalIgnoreCase)
        }
        $rows.Add([pscustomobject][ordered]@{
                roleDefinitionName    = ($roleNames -join ', ')
                groupId               = $groupId
                groupDisplayName      = $displayName
                isManagementRestricted = $restricted
                isAssignableToRole    = $assignable
            })
    }

    $rowArray = $rows.ToArray()
    $gapArray = $gaps.ToArray()
    if ($gapArray.Count -eq 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Collected' -Rows $rowArray -Gaps @() `
            -ReasonCode 'collected' -Detail @{ groupCount = $rowArray.Count } -Provider 'GraphKit' `
            -ApiVersion $apiVersion -Operations $operations
    }
    if ($rowArray.Count -gt 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Partial' -Rows $rowArray -Gaps $gapArray `
            -ReasonCode 'partial' -Detail @{ groupCount = $rowArray.Count; gapCount = $gapArray.Count } `
            -Provider 'GraphKit' -ApiVersion $apiVersion -Operations $operations
    }

    $topFailureClass = 'ProviderFailed'
    $topReasonCode = 'provider-failed'
    if ($gapArray.Count -gt 0) {
        $candidateFailureClass = [string] $gapArray[0].FailureClass
        $candidateReasonCode = [string] $gapArray[0].ReasonCode
        $uniformFailureTuple = $true
        foreach ($gap in $gapArray) {
            if ([string] $gap.FailureClass -ne $candidateFailureClass -or
                [string] $gap.ReasonCode -ne $candidateReasonCode) {
                $uniformFailureTuple = $false
                break
            }
        }
        if ($uniformFailureTuple) {
            $topFailureClass = $candidateFailureClass
            $topReasonCode = $candidateReasonCode
        }
    }

    return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps $gapArray `
        -FailureClass $topFailureClass -ReasonCode $topReasonCode `
        -Detail @{ gapCount = $gapArray.Count } -Provider 'GraphKit' -ApiVersion $apiVersion -Operations $operations
}

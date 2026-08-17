<#
    Private: TP.ENT.0021 rule function - fewer than 10 total active assignments across
    every Entra role flagged `isPrivileged=true` (not just Global Administrator). See
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0021.

    isPrivileged/templateId-complete role metadata is beta-only (same reason
    directoryRoleDefinitions is mapped to the beta List operation in DatasetMap.psd1 - see
    that file's own docstring, already true for TP.ENT.0002/0020's Global-Administrator-only
    join). A role definition row missing the isPrivileged property entirely is treated as
    NOT privileged (conservative default matching Microsoft Graph's own documented default
    for a role that predates the isPrivileged flag) rather than thrown on - unlike CA
    policy `state` (ConvertTo-PulseCaPolicyView) or authorizationPolicy's own required
    properties, isPrivileged genuinely IS optional/defaultable on this dataset's real Graph
    shape, not a regressed/unrecognized one.

    HONEST LIMITATION, CARRIED FORWARD FROM THE RESEARCH ENTRY'S OWN NOTES (not silently
    dropped): this counts DIRECT roleAssignments only. A role assigned to a GROUP (Entra
    role-assignable groups) with many members is a single directoryRoleAssignments row by
    principalId (the group's own object id) - this check counts that as ONE assignment, not
    N (one per group member), because no group-membership-expansion dataset exists yet
    (same gap Get-PulseCaExclusionContext's own docstring already names for CA exclusion
    resolution - groupMembers is not a real DatasetMap.psd1 entry). This can UNDERCOUNT the
    true blast radius on a tenant that assigns privileged roles to groups rather than
    individual principals - stated here and in this check's own Consulting text, not hidden
    behind an apparently-precise count.
#>

function Test-PulsePrivilegedRoleAssignmentCount {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $threshold = 10

    $roleDefinitions = @($Datasets.directoryRoleDefinitions)
    $privilegedRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($roleDefinition in $roleDefinitions) {
        $isPrivileged = Get-PulseSettingsCatalogValueProperty -Node $roleDefinition -PropertyName 'isPrivileged'
        if ($null -ne $isPrivileged -and [bool] $isPrivileged) {
            $roleDefId = Get-PulseSettingsCatalogValueProperty -Node $roleDefinition -PropertyName 'id'
            if ($null -ne $roleDefId) {
                $privilegedRoleIds.Add([string] $roleDefId) | Out-Null
            }
        }
    }

    if ($privilegedRoleIds.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No role definition in directoryRoleDefinitions is flagged isPrivileged=true - cannot identify the privileged-role set to count assignments against.'
    }

    $roleAssignments = @($Datasets.directoryRoleAssignments)
    $privilegedAssignments = @($roleAssignments | Where-Object { $privilegedRoleIds.Contains([string] $_.roleDefinitionId) })

    $roleNameById = @{}
    foreach ($roleDefinition in $roleDefinitions) {
        $roleDefId = Get-PulseSettingsCatalogValueProperty -Node $roleDefinition -PropertyName 'id'
        $displayName = Get-PulseSettingsCatalogValueProperty -Node $roleDefinition -PropertyName 'displayName'
        if ($null -ne $roleDefId) {
            $roleNameById[[string] $roleDefId] = [string] $displayName
        }
    }

    if ($privilegedAssignments.Count -lt $threshold) {
        return New-PulseFinding -Status Pass -Reason "$($privilegedAssignments.Count) active privileged-role assignment(s) across $($privilegedRoleIds.Count) privileged role(s) - below Microsoft's fewer-than-$threshold guidance. Note: direct assignments only, does not expand role-assignable-group membership (see this check's own Consulting text for that known limitation)."
    }

    $evidence = @($privilegedAssignments | ForEach-Object {
        $roleName = if ($roleNameById.ContainsKey([string] $_.roleDefinitionId)) { $roleNameById[[string] $_.roleDefinitionId] } else { $null }
        @{ Identity = [string] $_.id; Detail = @{ principalId = $_.principalId; roleDefinitionId = $_.roleDefinitionId; roleDisplayName = $roleName } }
    })

    return New-PulseFinding -Status Fail -Reason "$($privilegedAssignments.Count) active privileged-role assignments across $($privilegedRoleIds.Count) privileged role(s) meets or exceeds Microsoft's fewer-than-$threshold guidance. Note: direct assignments only - a role assigned to a group undercounts true blast radius (see this check's own Consulting text)." -Evidence $evidence
}

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

    GROUP CLOSURE: current snapshots collect the bounded `groupMembers` composite and the
    check counts effective members of role-assignable groups. Imported historical snapshots
    can legitimately lack that dataset; those remain direct-assignment-only and say so in
    the result. A present but sampled/capped closure is incomplete and cannot produce Pass.
#>

function Test-PulsePrivilegedRoleAssignmentCount {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $threshold = 10
    $closure = Get-PulseRoleAssignmentClosure -Datasets $Datasets

    if ($closure.PrivilegedRoleCount -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No role definition in directoryRoleDefinitions is flagged isPrivileged=true - cannot identify the privileged-role set to count assignments against.'
    }

    $count = $closure.UniqueEffectiveActiveCount
    if ($closure.Incomplete -and $count -lt $threshold) {
        return New-PulseFinding -Status Fail -Reason "Group membership closure is incomplete (sampled or capped); cannot prove privileged-role assignment count is below $threshold. Caps are visible and this check does not Pass."
    }

    $roleNameById = $closure.RoleDisplayNames
    $privilegedAssignments = @($closure.DirectActiveAssignments)

    if ($count -lt $threshold) {
        $limitNote = if ($closure.GroupMembersPresent) {
            'Effective count expands role-assignable-group membership.'
        } else {
            'Historical snapshot note: direct assignments only because no group-membership closure artifact is present.'
        }
        return New-PulseFinding -Status Pass -Reason "$count active privileged-role assignment(s) across $($closure.PrivilegedRoleCount) privileged role(s) - below Microsoft's fewer-than-$threshold guidance. $limitNote"
    }

    $evidence = @($privilegedAssignments | ForEach-Object {
        $roleName = $null
        $roleDefinitionId = [string] $_.roleDefinitionId
        if ($roleNameById.Contains($roleDefinitionId)) { $roleName = $roleNameById[$roleDefinitionId] }
        @{ Identity = [string] $_.id; Detail = @{ principalId = $_.principalId; roleDefinitionId = $_.roleDefinitionId; roleDisplayName = $roleName } }
    })

    return New-PulseFinding -Status Fail -Reason "$count active privileged-role assignments across $($closure.PrivilegedRoleCount) privileged role(s) meets or exceeds Microsoft's fewer-than-$threshold guidance." -Evidence $evidence
}

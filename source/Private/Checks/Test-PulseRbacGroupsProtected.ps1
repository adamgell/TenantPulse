<#
    Private: TP.INT.0013 rule function - Intune RBAC groups protected via RMAU or
    role-assignable groups (Task 3.2, Maester port MT.1103 -
    Test-MtIntuneRbacGroupsProtected, MIT).

    PENDING COMPOSITE DATASET: this check's real input is a 4-call Graph fan-out
    (deviceManagement/roleDefinitions -> .../roleAssignments -> roleAssignments/{id} ->
    groups/{id}?$select=displayName,isManagementRestricted,isAssignableToRole,id) that has
    no released GraphKit 0.1.1 descriptor as a single composite operation - the research
    entry itself names this the most expensive Maester Intune port call graph in this
    batch. DatasetMap.psd1 declares 'intuneRbacGroupProtection' Pending=$true, holding the
    ALREADY-FLATTENED per-group shape Maester's own function itself builds internally
    ({roleDefinitionName, groupId, groupDisplayName, isManagementRestricted,
    isAssignableToRole} - one row per distinct role-assignment-member-group pair) rather
    than the four raw Graph call shapes, so the composite descriptor (whenever a G-batch
    ships it) only needs to hand this rule the walk's END RESULT. On a live tenant this
    resolves NotApplicable until that descriptor exists. Rule logic is real and
    fixture-tested regardless.

    RULE (ported verbatim - live-verified against
    https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept,
    fetched for this check, which confirms isAssignableToRole is the correct, real,
    immutable-at-creation property this check keys on): a group row is UNPROTECTED when
    NEITHER isManagementRestricted NOR isAssignableToRole is true. Fail when any
    unprotected group exists (deduplicated by groupId - the same group can back more than
    one role assignment). Pass when zero unprotected groups exist, INCLUDING when zero
    rows exist at all (mirrors Maester's own behavior exactly: an empty
    $roleAssignmentsExpanded still satisfies "$unprotectedGroups.Count -eq 0" - a tenant
    with no Intune RBAC role assignments using groups at all has nothing to protect, which
    is a real Pass, not a skip).
#>

function Test-PulseRbacGroupsProtected {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $rows = @($Datasets.intuneRbacGroupProtection)

    $unprotectedByGroupId = [ordered]@{}
    foreach ($row in $rows) {
        $isManagementRestricted = ($row.isManagementRestricted -eq $true)
        $isAssignableToRole = ($row.isAssignableToRole -eq $true)
        if ($isManagementRestricted -or $isAssignableToRole) { continue }

        $groupId = [string] $row.groupId
        if ([string]::IsNullOrEmpty($groupId)) { continue }
        if (-not $unprotectedByGroupId.Contains($groupId)) {
            $unprotectedByGroupId[$groupId] = $row
        }
    }

    if ($unprotectedByGroupId.Count -eq 0) {
        $reason = if ($rows.Count -eq 0) {
            'No Intune RBAC role assignments use a group as a member target - there is nothing to protect.'
        } else {
            "All $($rows.Count) group(s) backing an Intune RBAC role assignment are either a Restricted Management Administrative Unit scope or an isAssignableToRole group - none can have members silently added by an administrator outside the intended privileged-role governance."
        }
        return New-PulseFinding -Status Pass -Reason $reason
    }

    $offendingRows = @($unprotectedByGroupId.Values)
    $evidence = ConvertTo-PulseMaesterEvidence -Rows $offendingRows -IdentityProperty 'groupId' -SortKeyProperty 'groupDisplayName' -DetailProperties @('groupDisplayName', 'roleDefinitionName', 'isManagementRestricted', 'isAssignableToRole')

    $reason = "$($unprotectedByGroupId.Count) group(s) backing an Intune RBAC role assignment are neither an RMAU scope nor an isAssignableToRole group - an administrator with ordinary group-membership rights (e.g. a dynamic-membership rule, or Group.ReadWrite.All) could add themselves to one of these groups and silently inherit the Intune-privileged role it backs, with no privileged-role governance step in the way."
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence
}

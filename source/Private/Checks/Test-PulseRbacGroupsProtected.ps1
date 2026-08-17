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

    FIELD-ABSENCE LENS (POST-REVIEW FIX): isManagementRestricted, isAssignableToRole, and
    groupId are each read from a live, 4-call Graph fan-out - a failed sub-call in that
    chain is exactly the kind of gap that must never silently read as "verified
    unprotected". An absent (missing or $null) isManagementRestricted or
    isAssignableToRole now throws (-> engine Error), never coerces to $false. Likewise a
    row identified as unprotected with no groupId now throws instead of being silently
    dropped - dropping it would have let a real unprotected group vanish into a false
    Pass (empirically reproduced by review). Present-and-$false on either boolean remains
    fully decidable and participates in the Fail path exactly as before.

    COMPOSITE-SHAPE CAVEAT (Phase 3 whole-phase review, catalog-coherence finding M3,
    documentation-only): this rule currently cannot distinguish "zero rows because the
    tenant genuinely has no Intune RBAC role assignments using groups" from "zero rows
    because the 4-call fan-out itself partially failed before producing any rows" - both
    read as a real Pass today (see RULE above), by design, because $Datasets is only ever
    populated with successfully-collected rows or not populated at all; there is no
    third, partial-failure shape a Function-type rule can currently observe. THIS MATTERS
    for the composite descriptor whenever it ships: if that descriptor's own fan-out can
    fail PARTWAY through the 4-call chain (e.g. roleDefinitions succeeds but a downstream
    groups/{id} lookup for one group fails) and still surface whatever rows it managed to
    collect, the descriptor's own spec must distinguish "confirmed zero role assignments"
    from "partial collection, unknown true row count" - collapsing the latter into a
    silent zero-rows Pass here would be a false-negative-of-omission, not the honest
    "nothing to protect" Pass this rule currently returns. This rule itself cannot fix
    that gap (a Function rule only ever sees $Datasets as handed to it) - the composite
    descriptor's own gap/partial-fetch signaling design is where this must be addressed,
    not here.
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
        if ($null -eq $row.isManagementRestricted) {
            throw "Test-PulseRbacGroupsProtected: a row for group '$($row.groupDisplayName)' has no isManagementRestricted value - this rule's input is a 4-call Graph fan-out and an absent value here means a sub-call failed or returned an unreadable shape, not that the group is unprotected. Refusing to read absence as unprotected."
        }
        if ($null -eq $row.isAssignableToRole) {
            throw "Test-PulseRbacGroupsProtected: a row for group '$($row.groupDisplayName)' has no isAssignableToRole value - this rule's input is a 4-call Graph fan-out and an absent value here means a sub-call failed or returned an unreadable shape, not that the group is unprotected. Refusing to read absence as unprotected."
        }

        $isManagementRestricted = ([bool] $row.isManagementRestricted -eq $true)
        $isAssignableToRole = ([bool] $row.isAssignableToRole -eq $true)
        if ($isManagementRestricted -or $isAssignableToRole) { continue }

        $groupId = [string] $row.groupId
        if ([string]::IsNullOrEmpty($groupId)) {
            throw "Test-PulseRbacGroupsProtected: an unprotected row (roleDefinitionName '$($row.roleDefinitionName)') has no groupId value - this row cannot be identified or deduplicated, and silently dropping it would let an unprotected group vanish into a false Pass. Refusing to skip it."
        }
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

<#
    Private: TP.ENT.0022 rule function - zero PERMANENT ACTIVE assignments for privileged
    roles (ScuBA MS.AAD.7.4v1, SHALL NOT). See
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0022.

    GraphKit 0.2.2 shipped the official descriptors for
    roleAssignmentScheduleInstances and roleEligibilityScheduleInstances; DatasetMap Pending
    was dropped and this check evaluates live. Both PIM datasets use v1.0 List operations.

    LICENSE GATE IS A FIRST-CLASS OUTCOME, PER THE RESEARCH ENTRY: this check's own
    descriptor declares Data.Gates = @('EntraP2'). Get-PulseGateStatus is implemented; for
    snapshot evaluation, only successfully collected subscribedSkus gate evidence can prove
    that Entra P2 is absent. A 400/403 from roleAssignmentScheduleInstances or
    roleEligibilityScheduleInstances is a provider/permission outcome, not license proof.
    When collected gate evidence proves EntraP2 unavailable, evaluation assigns
    NotApplicable with an explicit "gate 'EntraP2' unavailable" reason - never a silent
    Pass. This function does not implement gate detection itself; the evaluator resolves its
    declared gate before invoking the rule.

    PERMANENT-ACTIVE DEFINITION: a roleAssignmentScheduleInstance row is "permanent active"
    when assignmentType == 'Assigned' (a direct/standing active assignment, not an
    'Activated' PIM-eligible-turned-temporarily-active instance, which always carries a
    real, bounded endDateTime) AND endDateTime is absent/null (no expiration set). Scoped to
    privileged roles only, via the same isPrivileged join TP.ENT.0021 already established
    against directoryRoleDefinitions.

    SERVICE-ACCOUNT / BREAK-GLASS FALSE-POSITIVE GUARD (plan's own Task 4.4 note, omp LOW):
    a permanent-active assignment whose principalId is in the operator-declared
    -Context.ServiceAccounts OR -Context.BreakGlassAccounts is EXCLUDED from the offending
    set - break-glass is the one Microsoft-documented legitimate case for permanent Global
    Administrator (see TP.ENT.0002/0020's own docstrings), and a service account performing
    an automated, non-interactive privileged operation is frequently unable to use PIM's
    interactive activation flow at all. These are reported SEPARATELY in evidence
    (Detail.exempt = $true) rather than silently dropped, so an operator reviewing the
    finding still sees every permanent assignment that exists, just distinguished from the
    ones this check is actually flagging as a gap.

    A group assignment is itself one standing assignment and is never replaced by its
    expanded members for pass/fail counting. Group expansion is retained only as blast-radius
    evidence; an empty group or a group whose current members are all exempt still leaves the
    standing group assignment in place.

    Graph normally supplies an id for every schedule instance, but incomplete captured rows
    must remain independently reviewable rather than collapsing the check to Error. When id is
    absent or blank, evidence uses a deterministic per-evaluation ordinal alias; it does not
    invent or imply a Microsoft Graph object id.
#>

function Test-PulsePimPermanentAssignments {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $closure = Get-PulseRoleAssignmentClosure -Datasets $Datasets -Context $Context
    if ($closure.PrivilegedRoleCount -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No role definition in directoryRoleDefinitions is flagged isPrivileged=true - cannot identify the privileged-role set to evaluate PIM posture against.'
    }

    $memberMap = ConvertTo-PulseGroupMemberMap -GroupMembers $(
        if ($Datasets -and $Datasets.ContainsKey('groupMembers')) { $Datasets.groupMembers } else { $null }
    )

    $offending = [System.Collections.Generic.List[object]]::new()
    $exempt = [System.Collections.Generic.List[object]]::new()
    $permanentInstanceOrdinal = -1
    foreach ($instance in @($closure.PermanentActiveInstances)) {
        $permanentInstanceOrdinal++
        $principalId = [string] (Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'principalId')
        $instanceId = [string] (Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'id')
        $evidenceIdentity = if ([string]::IsNullOrWhiteSpace($instanceId)) {
            "pim-permanent-assignment-$permanentInstanceOrdinal"
        } else {
            $instanceId
        }
        $groupAssignment = $false
        $blastRadiusPrincipalIds = if ([string]::IsNullOrWhiteSpace($principalId)) { @() } else { @($principalId) }
        if ($memberMap.Present -and $memberMap.Map.Contains($principalId)) {
            $groupAssignment = $true
            $blastRadiusPrincipalIds = @($memberMap.Map[$principalId])
        }

        $entry = [pscustomobject]@{
            Instance                = $instance
            EvidenceIdentity        = $evidenceIdentity
            GroupAssignment         = $groupAssignment
            BlastRadiusPrincipalIds = @($blastRadiusPrincipalIds)
        }

        $assignmentIsExempt = -not $groupAssignment -and
            -not [string]::IsNullOrWhiteSpace($principalId) -and
            $closure.PermanentExemptPrincipals -contains $principalId
        if ($assignmentIsExempt) {
            $exempt.Add($entry) | Out-Null
        } else {
            $offending.Add($entry) | Out-Null
        }
    }

    if ($closure.Incomplete -and $offending.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason "Group membership closure is incomplete (sampled or capped); cannot prove zero permanent-active privileged-role assignments. Caps are visible and this check does not Pass."
    }

    if ($offending.Count -eq 0) {
        $reason = "0 non-exempt permanent-active assignments across $($closure.PrivilegedRoleCount) privileged role(s)."
        if ($exempt.Count -gt 0) {
            $reason += " $($exempt.Count) permanent-active assignment(s) held by a declared break-glass/service account and treated as legitimate."
        }
        return New-PulseFinding -Status Pass -Reason $reason
    }

    $evidence = @($offending | ForEach-Object {
        $instance = $_.Instance
        @{
            Identity = $_.EvidenceIdentity
            Detail   = @{
                principalId             = Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'principalId'
                roleDefinitionId        = Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'roleDefinitionId'
                exempt                  = $false
                groupAssignment         = [bool] $_.GroupAssignment
                blastRadiusPrincipalIds = @($_.BlastRadiusPrincipalIds)
            }
        }
    })
    $evidence += @($exempt | ForEach-Object {
        $instance = $_.Instance
        @{
            Identity = $_.EvidenceIdentity
            Detail   = @{
                principalId             = Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'principalId'
                roleDefinitionId        = Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'roleDefinitionId'
                exempt                  = $true
                groupAssignment         = [bool] $_.GroupAssignment
                blastRadiusPrincipalIds = @($_.BlastRadiusPrincipalIds)
            }
        }
    })

    return New-PulseFinding -Status Fail -Reason "$($offending.Count) permanent-active (not PIM-eligible, no expiration) assignment(s) across $($closure.PrivilegedRoleCount) privileged role(s) are not covered by a declared break-glass/service-account exemption - ScuBA MS.AAD.7.4v1 (SHALL NOT)." -Evidence $evidence
}

<#
    Private: TP.ENT.0022 rule function - zero PERMANENT ACTIVE assignments for privileged
    roles (ScuBA MS.AAD.7.4v1, SHALL NOT). See
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0022.

    DATASET STATUS: -Datasets.roleAssignmentScheduleInstances/roleEligibilityScheduleInstances
    are BOTH Pending in DatasetMap.psd1 (no matching Type in the installed GraphKit 0.1.1
    catalog, confirmed via Get-GraphOperation -List at implementation time - see that file's
    own entry docstring and the T4.4 report's descriptor-needs list). A Pending dataset
    degrades this whole check to engine-assigned NotApplicable at real-run time via the
    normal manifest mechanism (same as TP.ENT.0012/TP.ENT.0013's own Pending-dataset
    checks) - this function's own logic below is real and unit-tested against fixtures, not
    dead code, the same way those checks' own rule functions are.

    LICENSE GATE IS A FIRST-CLASS OUTCOME, PER THE RESEARCH ENTRY: this check's own
    descriptor declares Data.Gates = @('EntraP2') - PIM's roleAssignmentScheduleInstances/
    roleEligibilityScheduleInstances endpoints 400/403 on a non-P2 tenant. Once the
    datasets ship and gate detection goes live (Get-PulseGateStatus is presently a Phase 1
    stub that never returns 'Unavailable' - see that function's own docstring), an
    unlicensed tenant degrades to NotApplicable with an explicit "gate 'EntraP2'
    unavailable" reason - never a silent Pass. This function does not implement that
    detection itself; it only declares the gate so the engine's existing NotApplicable
    wiring covers this case once real detection exists.

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

    $roleDefinitions = @($Datasets.directoryRoleDefinitions)
    $privilegedRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($roleDefinition in $roleDefinitions) {
        $isPrivileged = Get-PulseSettingsCatalogValueProperty -Node $roleDefinition -PropertyName 'isPrivileged'
        if ($null -ne $isPrivileged -and [bool] $isPrivileged) {
            $roleDefId = Get-PulseSettingsCatalogValueProperty -Node $roleDefinition -PropertyName 'id'
            if ($null -ne $roleDefId) { $privilegedRoleIds.Add([string] $roleDefId) | Out-Null }
        }
    }

    if ($privilegedRoleIds.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No role definition in directoryRoleDefinitions is flagged isPrivileged=true - cannot identify the privileged-role set to evaluate PIM posture against.'
    }

    $exclusionContext = Get-PulseCaExclusionContext -Context $Context -Datasets $Datasets
    $exemptPrincipals = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in (@($exclusionContext.ServiceAccounts) + @($exclusionContext.BreakGlassAccounts))) {
        if ($id) { $exemptPrincipals.Add([string] $id) | Out-Null }
    }

    $instances = @($Datasets.roleAssignmentScheduleInstances)
    $permanentActive = @($instances | Where-Object {
        $assignmentType = Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'assignmentType'
        $endDateTime = Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'endDateTime'
        $roleDefinitionId = [string] (Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'roleDefinitionId')
        ([string] $assignmentType -eq 'Assigned') -and [string]::IsNullOrEmpty([string] $endDateTime) -and $privilegedRoleIds.Contains($roleDefinitionId)
    })

    $offending = @()
    $exempt = @()
    foreach ($instance in $permanentActive) {
        $principalId = [string] (Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'principalId')
        if ($exemptPrincipals.Contains($principalId)) {
            $exempt += $instance
        } else {
            $offending += $instance
        }
    }

    if ($offending.Count -eq 0) {
        $reason = "0 non-exempt permanent-active assignments across $($privilegedRoleIds.Count) privileged role(s)."
        if ($exempt.Count -gt 0) {
            $reason += " $($exempt.Count) permanent-active assignment(s) held by a declared break-glass/service account and treated as legitimate."
        }
        return New-PulseFinding -Status Pass -Reason $reason
    }

    $evidence = @($offending | ForEach-Object {
        @{
            Identity = [string] (Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'id')
            Detail   = @{
                principalId      = Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'principalId'
                roleDefinitionId = Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'roleDefinitionId'
                exempt           = $false
            }
        }
    })
    $evidence += @($exempt | ForEach-Object {
        @{
            Identity = [string] (Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'id')
            Detail   = @{
                principalId      = Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'principalId'
                roleDefinitionId = Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'roleDefinitionId'
                exempt           = $true
            }
        }
    })

    return New-PulseFinding -Status Fail -Reason "$($offending.Count) permanent-active (not PIM-eligible, no expiration) assignment(s) across $($privilegedRoleIds.Count) privileged role(s) are not covered by a declared break-glass/service-account exemption - ScuBA MS.AAD.7.4v1 (SHALL NOT)." -Evidence $evidence
}

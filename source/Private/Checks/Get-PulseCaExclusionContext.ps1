<#
    Private: build the shared "who is legitimately excluded from Conditional Access"
    context that TP.ENT.0003/0004/0005 all consume (Phase 1 v1 stub - see the task brief).

    Two sources are folded together into one flat, de-duplicated identifier set:

        1. Operator-declared exclusions: -Context.BreakGlassAccounts and
           -Context.ServiceAccounts (see Resolve-PulseSelectionParams and
           Invoke-PulseEvaluation's own -Context docstring for how these arrive here - an
           -AssessmentProfile's own declared arrays, threaded through unchanged). Read
           defensively: a missing/empty/non-array value on either key yields an empty list
           for that source rather than throwing - a check descriptor's own evaluation must
           never fail just because the operator profile omitted an optional key.

        2. Permanent Global Administrator heuristic: every DISTINCT principalId with an
           ACTIVE Global Administrator role assignment in -Datasets.directoryRoleAssignments
           (when that dataset was actually collected - see below). directoryRoleAssignments
           (DirectoryRoleAssignment.List) only ever returns ACTIVE assignments; a PIM-
           eligible-but-not-activated Global Administrator assignment does not appear here
           at all, so every principal this heuristic finds already IS "permanently" a GA in
           the sense that matters for CA-exclusion review (they hold the role right now,
           with no activation step an auditor could point to as the safety net) - "PIM
           eligible-only" is a materially different, lower-risk posture this heuristic
           deliberately does not flag. This is a heuristic, not a certified enumeration:
           it is only as complete as the collected dataset, and it is silently skipped
           (contributes zero identifiers, never throws) when directoryRoleAssignments is
           absent from -Datasets - the caller (a check's Function rule) is expected to
           reason about a degraded exclusion context itself if that matters to its finding.

        Global Administrator resolution prefers a join against
        -Datasets.directoryRoleDefinitions (DisplayName -eq 'Global Administrator', or
        TemplateId -eq the well-known constant below, whichever the definition object
        actually carries) - falling back to matching roleDefinitionId directly against the
        well-known template id when directoryRoleDefinitions was not collected. The
        well-known Global Administrator template id (stable across every Entra tenant,
        documented by Microsoft) is '62e90394-69f5-4237-9190-012177145e10'.

    Returns a single flat pscustomobject:
        BreakGlassAccounts    - [string[]] as declared in -Context, unmodified.
        ServiceAccounts       - [string[]] as declared in -Context, unmodified.
        PermanentGlobalAdmins - [string[]] distinct principalIds found by the heuristic
                                above, ordinally sorted (deterministic ordering).
        ExcludedIdentifiers   - [string[]] the de-duplicated union of all three lists
                                above, ordinally sorted - the single list a check's
                                Function rule actually wants to test CA policy
                                excludeUsers/excludeGroups membership against.

    Consuming checks decide for themselves how to MATCH ExcludedIdentifiers against a CA
    policy's own exclusion lists (excludeUsers holds ids or UPNs depending on tenant
    configuration; this function does not attempt that resolution - see each consuming
    check's own function docstring for exactly what it does and does not claim to verify).
#>

function Get-PulseCaExclusionContext {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [hashtable] $Context = @{},

        [Parameter()]
        [hashtable] $Datasets = @{}
    )

    $breakGlass = @()
    if ($Context -and $Context.ContainsKey('BreakGlassAccounts') -and $null -ne $Context.BreakGlassAccounts) {
        $breakGlass = [string[]] @($Context.BreakGlassAccounts)
    }

    $serviceAccounts = @()
    if ($Context -and $Context.ContainsKey('ServiceAccounts') -and $null -ne $Context.ServiceAccounts) {
        $serviceAccounts = [string[]] @($Context.ServiceAccounts)
    }

    $wellKnownGlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'

    $permanentGlobalAdmins = @()
    if ($Datasets -and $Datasets.ContainsKey('directoryRoleAssignments') -and $null -ne $Datasets.directoryRoleAssignments) {
        $assignments = @($Datasets.directoryRoleAssignments)

        $gaRoleDefinitionIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $gaRoleDefinitionIds.Add($wellKnownGlobalAdminTemplateId) | Out-Null

        if ($Datasets.ContainsKey('directoryRoleDefinitions') -and $null -ne $Datasets.directoryRoleDefinitions) {
            foreach ($definition in @($Datasets.directoryRoleDefinitions)) {
                $displayName = $definition.displayName
                $templateId = $definition.templateId
                if ($displayName -eq 'Global Administrator' -or $templateId -eq $wellKnownGlobalAdminTemplateId) {
                    if ($definition.id) {
                        $gaRoleDefinitionIds.Add([string] $definition.id) | Out-Null
                    }
                    if ($templateId) {
                        $gaRoleDefinitionIds.Add([string] $templateId) | Out-Null
                    }
                }
            }
        }

        $foundPrincipals = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($assignment in $assignments) {
            $roleDefinitionId = [string] $assignment.roleDefinitionId
            if ($gaRoleDefinitionIds.Contains($roleDefinitionId) -and $assignment.principalId) {
                $foundPrincipals.Add([string] $assignment.principalId) | Out-Null
            }
        }

        $permanentGlobalAdmins = [string[]] @($foundPrincipals)
        [System.Array]::Sort($permanentGlobalAdmins, [System.StringComparer]::Ordinal)
    }

    $union = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $breakGlass) { if ($id) { $union.Add([string] $id) | Out-Null } }
    foreach ($id in $serviceAccounts) { if ($id) { $union.Add([string] $id) | Out-Null } }
    foreach ($id in $permanentGlobalAdmins) { if ($id) { $union.Add([string] $id) | Out-Null } }

    $excludedIdentifiers = [string[]] @($union)
    [System.Array]::Sort($excludedIdentifiers, [System.StringComparer]::Ordinal)

    return [pscustomobject]@{
        BreakGlassAccounts    = $breakGlass
        ServiceAccounts       = $serviceAccounts
        PermanentGlobalAdmins = $permanentGlobalAdmins
        ExcludedIdentifiers   = $excludedIdentifiers
    }
}

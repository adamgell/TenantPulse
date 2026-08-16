<#
    Private: build the shared "who is legitimately excluded from Conditional Access"
    context that every CA check consumes (Task 4.1 FULL REWORK - replaces the Task 1.9/
    Phase 1 v1 stub; same public shape, three additions below).

    Three sources are folded together into one flat, de-duplicated identifier set:

        1. Operator-declared exclusions: -Context.BreakGlassAccounts and
           -Context.ServiceAccounts (see Resolve-PulseSelectionParams and
           Invoke-PulseEvaluation's own -Context docstring for how these arrive here - an
           -AssessmentProfile's own declared arrays, threaded through unchanged). Read
           defensively: a missing/empty/non-array value on either key yields an empty list
           for that source rather than throwing - a check descriptor's own evaluation must
           never fail just because the operator profile omitted an optional key.

        2. Active Global Administrator heuristic: every DISTINCT principalId with an ACTIVE
           Global Administrator role assignment in -Datasets.directoryRoleAssignments (when
           that dataset was actually collected - see below). NAMED "Active", NOT "Permanent"
           (post-review, L4 - the original name overclaimed what this list actually is):
           directoryRoleAssignments (DirectoryRoleAssignment.List) returns every ACTIVE
           assignment, which includes BOTH a genuinely permanent/standing assignment AND a
           PIM-ELIGIBLE assignment that has been ACTIVATED (temporarily active, will expire
           and drop back to eligible-only) - this dataset shape cannot distinguish the two,
           so this heuristic cannot either. It can also include a SERVICE PRINCIPAL holding
           the role, not only a human account. A caller must not assume every entry here is
           a standing, human, forever-Global-Admin - only that it held the role, actively,
           at collection time. This is a heuristic, not a certified enumeration: it is only
           as complete as the collected dataset, and it is silently skipped (contributes
           zero identifiers, never throws) when directoryRoleAssignments is absent from
           -Datasets - the caller (a check's Function rule) is expected to reason about a
           degraded exclusion context itself if that matters to its finding.

        Global Administrator resolution prefers a join against
        -Datasets.directoryRoleDefinitions (DisplayName -eq 'Global Administrator', or
        TemplateId -eq the well-known constant below, whichever the definition object
        actually carries) - falling back to matching roleDefinitionId directly against the
        well-known template id when directoryRoleDefinitions was not collected. The
        well-known Global Administrator template id (stable across every Entra tenant,
        documented by Microsoft) is '62e90394-69f5-4237-9190-012177145e10'.

        3. GUID CONTRACT ON DECLARED ACCOUNTS (Task 4.1, new - centralizes what
           TP.ENT.0003/Test-PulseBreakGlassExcluded previously only applied to its own
           BreakGlassAccounts, and ServiceAccounts never got at all): CA
           conditions.users.excludeUsers/includeUsers hold GUID principal ids per the Graph
           schema. A declared BreakGlassAccounts or ServiceAccounts entry that is not
           GUID-shaped (a UPN, a display name, anything else) can never be matched against
           excludeUsers - that is a DIFFERENT problem from "genuinely not excluded", and is
           surfaced here as a Warn-not-Fail signal (MalformedDeclaredAccounts below) so
           every consuming check gets this classification for free instead of
           reimplementing its own GUID regex (TP.ENT.0003's own function previously did,
           and only for BreakGlassAccounts). WARN-NOT-FAIL is a caller-facing convention,
           not enforced here: this function only classifies and reports; a consuming
           check's own Function rule decides what Status that classification produces (see
           Test-PulseBreakGlassExcluded's own docstring for its Warn/Fail split). A
           malformed identifier is EXCLUDED from ExcludedIdentifiers (unresolvable, so it
           can never usefully match a policy's excludeUsers list) but is NEVER silently
           dropped - it is always enumerated in MalformedDeclaredAccounts so a caller that
           cares can still report it.

        4. RESOLVED GROUP EXCLUSIONS (Task 4.1, new, HONEST LIMITATION carried forward, not
           silent): every consuming check's own docstring up to now has documented the same
           gap - exclusion matching only ever covers excludeUsers, never excludeGroups,
           because resolving "is this account a MEMBER of this excluded group" needs a
           group-membership dataset that does not exist in DatasetMap.psd1 yet
           (descriptor-pending, no GraphKit descriptor wired up as of this task). This
           function now names that gap in its OWN return shape (GroupExclusionsResolved /
           GroupExclusionNote below) instead of leaving it as scattered prose in three
           different consuming checks' docstrings - the shape is ready for a caller to
           check `if ($context.GroupExclusionsResolved)` the moment a group-membership
           dataset (e.g. `groupMembers`) actually ships; until then this function makes the
           gap visible on every call rather than silently returning as if resolution had
           been attempted and found nothing. -Datasets.groupMembers (WHEN present -
           forward-compatible, not yet a real DatasetMap.psd1 entry) is expected to be a
           `[string]groupId -> [string[]]memberPrincipalIds` map; if it is ever populated,
           ResolvedGroupExclusions below is a flat, de-duplicated union of every member id
           reachable through -Datasets.conditionalAccessPolicies' own excludeGroups lists
           across ENABLED policies, folded into ExcludedIdentifiers same as every other
           source.

    Returns a single flat pscustomobject:
        BreakGlassAccounts        - [string[]] as declared in -Context, unmodified (same
                                     as the Task 1.9 stub - includes malformed entries, a
                                     consuming check that wants the raw declared list
                                     unchanged still gets it here).
        ServiceAccounts           - [string[]] as declared in -Context, unmodified.
        ActiveGlobalAdmins        - [string[]] distinct principalIds found by the heuristic
                                     above, ordinally sorted (deterministic ordering).
        MalformedDeclaredAccounts - [string[]] the subset of BreakGlassAccounts and
                                     ServiceAccounts combined that is not GUID-shaped -
                                     ordinally sorted, de-duplicated. Empty when every
                                     declared account is GUID-shaped (the common case).
        GroupExclusionsResolved   - [bool] $true only when -Datasets.groupMembers was
                                     present and non-null; $false (always, today) when it
                                     was not - see point 4 above.
        ResolvedGroupExclusions   - [string[]] member ids resolved through excludeGroups
                                     when GroupExclusionsResolved is $true; always empty
                                     today (see point 4 above) - never $null, so a caller
                                     can @() -wrap unconditionally.
        GroupExclusionNote        - [string] a fixed, non-null explanation of the group-
                                     exclusion gap when GroupExclusionsResolved is $false;
                                     $null when it is $true. Exists so "group exclusions
                                     were not resolved" is a value a caller can read and
                                     surface, not a silence a caller has to already know to
                                     expect.
        ExcludedIdentifiers        - [string[]] the de-duplicated union of BreakGlassAccounts,
                                     ServiceAccounts, ActiveGlobalAdmins, and
                                     ResolvedGroupExclusions, ordinally sorted (deterministic
                                     ordering) - UNCHANGED from the Task 1.9 stub's own
                                     contract: still includes a malformed (non-GUID)
                                     declared account, same as before this rework, so no
                                     existing consumer that reads ExcludedIdentifiers
                                     changes behavior. MalformedDeclaredAccounts is an
                                     ADDITIVE classification field, not a filter applied to
                                     this list.

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

    # Graph principal-id GUID shape, e.g. '11111111-2222-3333-4444-555555555555'.
    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

    $breakGlass = @()
    if ($Context -and $Context.ContainsKey('BreakGlassAccounts') -and $null -ne $Context.BreakGlassAccounts) {
        $breakGlass = [string[]] @($Context.BreakGlassAccounts)
    }

    $serviceAccounts = @()
    if ($Context -and $Context.ContainsKey('ServiceAccounts') -and $null -ne $Context.ServiceAccounts) {
        $serviceAccounts = [string[]] @($Context.ServiceAccounts)
    }

    $wellKnownGlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'

    $activeGlobalAdmins = @()
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

        $activeGlobalAdmins = [string[]] @($foundPrincipals)
        [System.Array]::Sort($activeGlobalAdmins, [System.StringComparer]::Ordinal)
    }

    # GUID CONTRACT (point 3 above): classify, don't filter ExcludedIdentifiers -
    # BreakGlassAccounts/ServiceAccounts/ExcludedIdentifiers all keep carrying a malformed
    # entry unchanged from the Task 1.9 stub's own contract; this is purely additive.
    $malformed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in (@($breakGlass) + @($serviceAccounts))) {
        if ($id -and ([string] $id) -notmatch $guidPattern) {
            $malformed.Add([string] $id) | Out-Null
        }
    }
    $malformedDeclaredAccounts = [string[]] @($malformed)
    [System.Array]::Sort($malformedDeclaredAccounts, [System.StringComparer]::Ordinal)

    # RESOLVED GROUP EXCLUSIONS (point 4 above): forward-compatible shape only - no
    # DatasetMap.psd1 entry backs -Datasets.groupMembers yet (descriptor-pending), so this
    # branch is dead in every real collection today and GroupExclusionsResolved is always
    # $false. It stays real, exercised code (not a stub the whole way down) so the moment a
    # group-membership dataset ships, wiring it into -Datasets.groupMembers is the only
    # change needed here.
    $groupExclusionsResolved = $false
    $resolvedGroupExclusions = @()
    $groupExclusionNote = 'Group-based exclusion (excludeGroups membership) cannot be resolved: no group-membership dataset is collected yet (descriptor-pending). Only excludeUsers-based exclusion is verifiable today.'

    if ($Datasets -and $Datasets.ContainsKey('groupMembers') -and $null -ne $Datasets.groupMembers) {
        $groupExclusionsResolved = $true
        $groupExclusionNote = $null

        $excludedGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if ($Datasets.ContainsKey('conditionalAccessPolicies') -and $null -ne $Datasets.conditionalAccessPolicies) {
            foreach ($policy in @($Datasets.conditionalAccessPolicies)) {
                if ($policy.state -ne 'enabled') { continue }
                foreach ($groupId in @($policy.conditions.users.excludeGroups)) {
                    if ($groupId) { $excludedGroupIds.Add([string] $groupId) | Out-Null }
                }
            }
        }

        $memberUnion = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $groupMembers = $Datasets.groupMembers
        foreach ($groupId in $excludedGroupIds) {
            if ($groupMembers -is [System.Collections.IDictionary] -and $groupMembers.Contains($groupId)) {
                foreach ($memberId in @($groupMembers[$groupId])) {
                    if ($memberId) { $memberUnion.Add([string] $memberId) | Out-Null }
                }
            }
        }

        $resolvedGroupExclusions = [string[]] @($memberUnion)
        [System.Array]::Sort($resolvedGroupExclusions, [System.StringComparer]::Ordinal)
    }

    $union = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $breakGlass) { if ($id) { $union.Add([string] $id) | Out-Null } }
    foreach ($id in $serviceAccounts) { if ($id) { $union.Add([string] $id) | Out-Null } }
    foreach ($id in $activeGlobalAdmins) { if ($id) { $union.Add([string] $id) | Out-Null } }
    foreach ($id in $resolvedGroupExclusions) { if ($id) { $union.Add([string] $id) | Out-Null } }

    $excludedIdentifiers = [string[]] @($union)
    [System.Array]::Sort($excludedIdentifiers, [System.StringComparer]::Ordinal)

    return [pscustomobject]@{
        BreakGlassAccounts        = $breakGlass
        ServiceAccounts           = $serviceAccounts
        ActiveGlobalAdmins        = $activeGlobalAdmins
        MalformedDeclaredAccounts = $malformedDeclaredAccounts
        GroupExclusionsResolved   = $groupExclusionsResolved
        ResolvedGroupExclusions   = $resolvedGroupExclusions
        GroupExclusionNote        = $groupExclusionNote
        ExcludedIdentifiers       = $excludedIdentifiers
    }
}

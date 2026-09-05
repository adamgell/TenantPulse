<#
    Private: TP.ENT.0023 rule function - the tenant's DEFAULT cross-tenant access policy
    does not allow unrestricted inbound B2B collaboration from every external tenant, and
    outbound collaboration is scoped deliberately. See
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0023.

    GraphKit 0.2.2 shipped the official crossTenantAccessPolicyDefault descriptor; DatasetMap
    Pending was dropped and this check evaluates live. CrossTenantAccessPolicy/GetDefault is
    v1.0.

    NO DEDICATED SCUBA CONTROL (re-fetched, see the research entry's own RE-FETCHED note):
    live-fetched against cisagov/ScubaGear's own aad.md baseline confirms Section 8 (Guest
    User Access) has exactly three numbered controls, 8.1-8.3, none of which define a
    testable control for the crossTenantAccessPolicy object itself - MS.AAD.8.1v1 is cited
    here as directional/analogous authority only (guest-access restriction, the closest
    ScuBA anchor), never claimed as the specific SHALL/SHOULD this object maps to. Primary
    authority is the Microsoft Learn cross-tenant-access-overview doc.

    b2bCollaborationInbound/b2bCollaborationOutbound EACH carry `usersAndGroups` and
    `applications` target configurations. Microsoft's API overview defines the wide-open
    default as BOTH configurations using accessType=allowed with an AllUsers or
    AllApplications target respectively. AccessType alone is not enough: allowed access to
    one group or one application is deliberately scoped, while an absent/malformed target
    collection is unclassifiable. Inbound and outbound use the same logic and are evaluated
    independently (an org may deliberately restrict one direction but not the other).

    THREE-WAY CLASSIFICATION, BEHAVIOR MATCHES THE CLAIM (post-review, Low fix): an earlier
    draft's docstring already claimed an unrecognized accessType value was a distinct
    "cannot classify" case, but the CODE folded any value not literally equal to 'allowed'
    (including a genuinely unrecognized/regressed string) into "restricted" - an optimistic
    Pass on a sparse or regressed shape this check has never actually seen. Each direction
    now classifies to exactly one of four outcomes:
        'unrestricted'   - usersAndGroups allows AllUsers AND applications allows
                            AllApplications/AllMicrosoftApps.
        'restricted'     - at least one structurally valid target configuration is a full
                            block or a narrower allowlist. That configuration is decisive:
                            a malformed sibling cannot undo the restriction it proves.
        'narrow-block'   - the only departure from allow-all is a selected-target denylist;
                            unlisted users/applications remain allowed, so this does not
                            prove broad default restriction.
        'unclassifiable' - no target configuration proves restriction and a direction/
                            configuration, accessType, target collection, target value, or
                            targetType is absent or unrecognized.
    ONLY 'restricted' counts toward the overall Pass; both 'unrestricted' AND
    'unclassifiable' degrade the finding to Warn and are surfaced in evidence with their
    own distinct classification and (for 'unclassifiable') the raw observed value - an
    unrecognized shape must never silently read as compliant.

    CONSERVATIVE ON ABSENCE: an absent b2bCollaborationInbound/Outbound block is classified
    'unclassifiable' (flagged), never silently assumed compliant or asserted to be the
    documented allow-all default. Both unclassifiable and unrestricted remain Warn.
#>

function Test-PulseCrossTenantAccessDefaultRestricted {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $rows = @($Datasets.crossTenantAccessPolicyDefault | Where-Object { $null -ne $_ })
    if ($rows.Count -ne 1) {
        $cardinalityEvidence = @(
            @{
                Identity = 'crossTenantAccessPolicyDefault:cardinality'
                Detail   = @{
                    classification   = 'invalid-singleton-cardinality'
                    expectedRowCount = 1
                    observedRowCount = $rows.Count
                }
            }
        )
        return New-PulseFinding -Status NotApplicable -Reason "The crossTenantAccessPolicyDefault dataset has invalid singleton cardinality: expected exactly 1 row, observed $($rows.Count). No tenant posture was evaluated." -Evidence $cardinalityEvidence
    }
    $policy = $rows[0]

    function Get-PulseTargetConfigurationClassification {
        param(
            $Configuration,
            [Parameter(Mandatory)]
            [ValidateSet('UsersAndGroups', 'Applications')]
            [string] $Kind
        )

        $invalid = [ordered]@{
            IsValid    = $false
            AccessType = $null
            Scope      = 'unclassifiable'
            TargetCount = 0
        }
        if ($null -eq $Configuration) { return $invalid }

        $rawAccessType = Get-PulseSettingsCatalogValueProperty -Node $Configuration -PropertyName 'accessType'
        $accessType = if ($null -ne $rawAccessType) { ([string] $rawAccessType).Trim() } else { $null }
        $invalid.AccessType = $accessType
        if ($accessType -notin @('allowed', 'blocked')) { return $invalid }

        $rawTargets = Get-PulseSettingsCatalogValueProperty -Node $Configuration -PropertyName 'targets'
        if ($null -eq $rawTargets) { return $invalid }
        $targets = @($rawTargets)
        $invalid.TargetCount = $targets.Count
        if ($targets.Count -eq 0) { return $invalid }

        $hasAllTarget = $false
        foreach ($targetNode in $targets) {
            if ($null -eq $targetNode) { return $invalid }
            $target = [string] (Get-PulseSettingsCatalogValueProperty -Node $targetNode -PropertyName 'target')
            $targetType = [string] (Get-PulseSettingsCatalogValueProperty -Node $targetNode -PropertyName 'targetType')
            if ([string]::IsNullOrWhiteSpace($target) -or [string]::IsNullOrWhiteSpace($targetType)) {
                return $invalid
            }

            if ($Kind -eq 'UsersAndGroups') {
                if ([string]::Equals($target, 'AllUsers', [System.StringComparison]::OrdinalIgnoreCase)) {
                    if (-not [string]::Equals($targetType, 'user', [System.StringComparison]::OrdinalIgnoreCase)) {
                        return $invalid
                    }
                    $hasAllTarget = $true
                    continue
                }
                if ($targetType -notin @('user', 'group')) { return $invalid }
            } else {
                if (-not [string]::Equals($targetType, 'application', [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $invalid
                }
                if ($target -in @('AllApplications', 'AllMicrosoftApps')) {
                    $hasAllTarget = $true
                    continue
                }
                if ([string]::Equals($target, 'Office365', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            }

            # Non-reserved targets are directory object/application identifiers. Treat an
            # arbitrary label as malformed instead of silently upgrading it to a scoped
            # allowlist or denylist.
            $parsedTarget = [guid]::Empty
            if (-not [guid]::TryParse($target, [ref] $parsedTarget)) {
                return $invalid
            }
        }

        $effectiveScope = if ([string]::Equals($accessType, 'allowed', [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($hasAllTarget) { 'open-all' } else { 'scoped-allow' }
        } else {
            if ($hasAllTarget) { 'full-block' } else { 'scoped-block' }
        }

        return [ordered]@{
            IsValid     = $true
            AccessType  = $accessType
            Scope       = $effectiveScope
            TargetCount = $targets.Count
        }
    }

    function Get-PulseDirectionClassification {
        param($DirectionNode)
        if ($null -eq $DirectionNode) {
            return @{
                Classification          = 'unclassifiable'
                RawAccessType           = $null
                RawApplicationAccessType = $null
                UsersTargetScope        = 'unclassifiable'
                ApplicationsTargetScope = 'unclassifiable'
            }
        }

        $usersAndGroups = Get-PulseSettingsCatalogValueProperty -Node $DirectionNode -PropertyName 'usersAndGroups'
        $applications = Get-PulseSettingsCatalogValueProperty -Node $DirectionNode -PropertyName 'applications'
        $usersResult = Get-PulseTargetConfigurationClassification -Configuration $usersAndGroups -Kind UsersAndGroups
        $applicationsResult = Get-PulseTargetConfigurationClassification -Configuration $applications -Kind Applications

        $scopes = @([string] $usersResult.Scope, [string] $applicationsResult.Scope)
        # Either target configuration can be a decisive restriction because access must
        # satisfy both the users/groups and application sides. Once one valid side blocks
        # all targets or narrows an allowlist, malformed sibling evidence cannot reverse
        # that proven restriction. Without a decisive side, malformed evidence remains
        # unclassifiable rather than being promoted by inference.
        $classification = if ($scopes -contains 'full-block' -or $scopes -contains 'scoped-allow') {
            'restricted'
        } elseif (-not $usersResult.IsValid -or -not $applicationsResult.IsValid) {
            'unclassifiable'
        } elseif (@($scopes | Where-Object { $_ -eq 'open-all' }).Count -eq 2) {
            'unrestricted'
        } else {
            # A selected-target block is a denylist. Microsoft documents that everyone
            # or every application not named by it remains allowed, so it cannot prove
            # the default has been broadly restricted.
            'narrow-block'
        }

        return @{
            Classification           = $classification
            RawAccessType            = $usersResult.AccessType
            RawApplicationAccessType = $applicationsResult.AccessType
            UsersTargetScope         = $usersResult.Scope
            ApplicationsTargetScope  = $applicationsResult.Scope
        }
    }

    $inbound = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'b2bCollaborationInbound'
    $outbound = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'b2bCollaborationOutbound'

    $inboundResult = Get-PulseDirectionClassification -DirectionNode $inbound
    $outboundResult = Get-PulseDirectionClassification -DirectionNode $outbound

    $flagged = @()
    if ($inboundResult.Classification -ne 'restricted') { $flagged += @{ Direction = 'inbound'; Result = $inboundResult } }
    if ($outboundResult.Classification -ne 'restricted') { $flagged += @{ Direction = 'outbound'; Result = $outboundResult } }

    if ($flagged.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason 'The tenant''s default cross-tenant access policy restricts both inbound and outbound B2B collaboration away from Microsoft''s wide-open default.'
    }

    $evidence = @($flagged | ForEach-Object {
        @{
            Identity = "crossTenantAccessPolicyDefault:$($_.Direction)"
            Detail   = @{
                direction      = $_.Direction
                classification = $_.Result.Classification
                accessType     = $_.Result.RawAccessType
                applicationAccessType = $_.Result.RawApplicationAccessType
                usersTargetScope       = $_.Result.UsersTargetScope
                applicationsTargetScope = $_.Result.ApplicationsTargetScope
            }
        }
    })

    $unclassifiableDirections = @($flagged | Where-Object { $_.Result.Classification -eq 'unclassifiable' } | ForEach-Object { $_.Direction })
    $unrestrictedDirections = @($flagged | Where-Object { $_.Result.Classification -eq 'unrestricted' } | ForEach-Object { $_.Direction })
    $narrowBlockDirections = @($flagged | Where-Object { $_.Result.Classification -eq 'narrow-block' } | ForEach-Object { $_.Direction })

    $reasonParts = @()
    if ($unrestrictedDirections.Count -gt 0) {
        $reasonParts += "allows unrestricted B2B collaboration ($($unrestrictedDirections -join ' and ')) from every external tenant - Microsoft's out-of-the-box default, not necessarily a deliberate choice"
    }
    if ($unclassifiableDirections.Count -gt 0) {
        $reasonParts += "is unclassifiable on $($unclassifiableDirections -join ' and ') because a target/access configuration is absent, malformed, or unrecognized - cannot confirm restriction, not counted as a Pass"
    }
    if ($narrowBlockDirections.Count -gt 0) {
        $reasonParts += "uses only a narrow denylist on $($narrowBlockDirections -join ' and ') - unlisted users and applications remain allowed, so this is not a full default restriction"
    }

    return New-PulseFinding -Status Warn -Reason "The tenant's default cross-tenant access policy $($reasonParts -join '; '). No dedicated ScuBA SHALL/SHOULD control anchors this specific object; verify this posture is intentional for this tenant's collaboration needs, not merely unreviewed." -Evidence $evidence
}

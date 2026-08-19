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

    b2bCollaborationInbound/b2bCollaborationOutbound EACH carry an `allowedCloudTenants` and
    `usersAndGroups`/`applications` include/exclude structure per Microsoft's documented
    crossTenantAccessPolicyConfigurationDefault shape. This check evaluates the
    RESTRICTIVENESS SIGNAL Microsoft's own defaults doc names as the permissive-by-default
    case: `usersAndGroups.accessType` equal to 'allowed' with no target restriction at all
    is the "wide open" state this check flags for inbound; outbound uses the identical
    shape/logic, evaluated independently (an org may deliberately restrict one direction but
    not the other - report both, never collapse to one bullet).

    THREE-WAY CLASSIFICATION, BEHAVIOR MATCHES THE CLAIM (post-review, Low fix): an earlier
    draft's docstring already claimed an unrecognized accessType value was a distinct
    "cannot classify" case, but the CODE folded any value not literally equal to 'allowed'
    (including a genuinely unrecognized/regressed string) into "restricted" - an optimistic
    Pass on a sparse or regressed shape this check has never actually seen. Each direction
    now classifies to exactly one of three outcomes:
        'unrestricted'   - accessType is literally 'allowed' (or the whole direction block
                            is absent - see CONSERVATIVE ON ABSENCE below).
        'restricted'      - accessType is literally 'blocked'.
        'unclassifiable'  - accessType is present but neither 'allowed' nor 'blocked' - an
                            unrecognized/regressed value this check has never seen.
    ONLY 'restricted' counts toward the overall Pass; both 'unrestricted' AND
    'unclassifiable' degrade the finding to Warn and are surfaced in evidence with their
    own distinct classification and (for 'unclassifiable') the raw observed value - an
    unrecognized shape must never silently read as compliant.

    CONSERVATIVE ON ABSENCE: an absent b2bCollaborationInbound/Outbound block is classified
    'unrestricted' (flagged), never silently assumed compliant - this codebase's
    field-absence lens applied here means "cannot verify restriction" and "confirmed
    unrestricted" produce the identical, safer outward Warn rather than a false Pass a
    genuinely sparse/regressed response shape could otherwise earn.
#>

function Test-PulseCrossTenantAccessDefaultRestricted {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $rows = @($Datasets.crossTenantAccessPolicyDefault)
    if ($rows.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No crossTenantAccessPolicyDefault row was collected - cannot evaluate the tenant''s default cross-tenant access posture.'
    }
    $policy = $rows[0]

    function Get-PulseDirectionClassification {
        param($DirectionNode)
        if ($null -eq $DirectionNode) { return @{ Classification = 'unrestricted'; RawAccessType = $null } }
        $usersAndGroups = Get-PulseSettingsCatalogValueProperty -Node $DirectionNode -PropertyName 'usersAndGroups'
        $accessType = Get-PulseSettingsCatalogValueProperty -Node $usersAndGroups -PropertyName 'accessType'
        $accessTypeString = if ($null -ne $accessType) { [string] $accessType } else { $null }

        $classification = switch ($accessTypeString) {
            'allowed' { 'unrestricted' }
            'blocked' { 'restricted' }
            default { 'unclassifiable' }
        }

        return @{ Classification = $classification; RawAccessType = $accessTypeString }
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
            }
        }
    })

    $unclassifiableDirections = @($flagged | Where-Object { $_.Result.Classification -eq 'unclassifiable' } | ForEach-Object { $_.Direction })
    $unrestrictedDirections = @($flagged | Where-Object { $_.Result.Classification -eq 'unrestricted' } | ForEach-Object { $_.Direction })

    $reasonParts = @()
    if ($unrestrictedDirections.Count -gt 0) {
        $reasonParts += "allows unrestricted B2B collaboration ($($unrestrictedDirections -join ' and ')) from every external tenant - Microsoft's out-of-the-box default, not necessarily a deliberate choice"
    }
    if ($unclassifiableDirections.Count -gt 0) {
        $reasonParts += "has an unrecognized/unclassifiable accessType value on $($unclassifiableDirections -join ' and ') - cannot confirm restriction, not counted as a Pass"
    }

    return New-PulseFinding -Status Warn -Reason "The tenant's default cross-tenant access policy $($reasonParts -join '; '). No dedicated ScuBA SHALL/SHOULD control anchors this specific object; verify this posture is intentional for this tenant's collaboration needs, not merely unreviewed." -Evidence $evidence
}

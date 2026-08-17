<#
    Private: TP.ENT.0023 rule function - the tenant's DEFAULT cross-tenant access policy
    does not allow unrestricted inbound B2B collaboration from every external tenant, and
    outbound collaboration is scoped deliberately. See
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0023.

    DATASET STATUS: -Datasets.crossTenantAccessPolicyDefault is Pending in DatasetMap.psd1
    (no CrossTenantAccessPolicy Type in the installed GraphKit 0.1.1 catalog, confirmed via
    Get-GraphOperation -List at implementation time - see that file's own entry docstring
    and the T4.4 report's descriptor-needs list). Degrades this check to engine-assigned
    NotApplicable at real-run time via the normal manifest mechanism, same as every other
    Pending-dataset check in this catalog - this function's own logic is real and
    unit-tested against fixtures, not dead code.

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
    case: `usersAndGroups.accessType` (or, on the older/simpler shape, a bare
    `isServiceDefault`/allow-all flag) equal to 'allowed' with no target restriction at all
    is the "wide open" state this check flags for inbound; outbound uses the identical
    shape/logic, evaluated independently (an org may deliberately restrict one direction but
    not the other - report both, never collapse to one bullet).
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

    function Test-PulseDirectionUnrestricted {
        param($DirectionNode)
        # CONSERVATIVE ON ABSENCE: an absent b2bCollaborationInbound/Outbound block is
        # treated as UNRESTRICTED (flagged), never silently assumed compliant - this
        # codebase's field-absence lens applied here means "cannot verify restriction" and
        # "confirmed unrestricted" produce the identical, safer outward Warn rather than a
        # false Pass a genuinely sparse/regressed response shape could otherwise earn.
        if ($null -eq $DirectionNode) { return $true }
        $usersAndGroups = Get-PulseSettingsCatalogValueProperty -Node $DirectionNode -PropertyName 'usersAndGroups'
        $accessType = Get-PulseSettingsCatalogValueProperty -Node $usersAndGroups -PropertyName 'accessType'
        # 'allowed' with no target list is Microsoft's own permissive-by-default shape;
        # anything else (e.g. 'blocked', or an accessType this check does not recognize) is
        # treated as at least a deliberate departure from the wide-open default, not
        # unrestricted - a genuinely unrecognized value is a shape this check has not seen,
        # which is a different, honest "cannot classify" case (see the field-absence lens
        # this codebase applies elsewhere), not silently folded into "restricted".
        return ([string] $accessType -eq 'allowed')
    }

    $inbound = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'b2bCollaborationInbound'
    $outbound = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'b2bCollaborationOutbound'

    $inboundUnrestricted = Test-PulseDirectionUnrestricted -DirectionNode $inbound
    $outboundUnrestricted = Test-PulseDirectionUnrestricted -DirectionNode $outbound

    $findings = @()
    if ($inboundUnrestricted) { $findings += 'inbound' }
    if ($outboundUnrestricted) { $findings += 'outbound' }

    if ($findings.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason 'The tenant''s default cross-tenant access policy restricts both inbound and outbound B2B collaboration away from Microsoft''s wide-open default.'
    }

    $evidence = @($findings | ForEach-Object { @{ Identity = "crossTenantAccessPolicyDefault:$_"; Detail = @{ direction = $_; accessType = 'allowed' } } })
    return New-PulseFinding -Status Warn -Reason "The tenant's default cross-tenant access policy allows unrestricted B2B collaboration ($($findings -join ' and ')) from every external tenant - Microsoft's out-of-the-box default, not necessarily a deliberate choice. No dedicated ScuBA SHALL/SHOULD control anchors this specific object; verify this permissive default is intentional for this tenant's collaboration needs, not merely unreviewed." -Evidence $evidence
}

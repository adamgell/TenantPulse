<#
    Private: TP.ENT.0012 rule function - default authorization policy settings cluster
    (EIDSCA.AP01, AP04-AP10, AP14 port; see
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md).

    GraphKit 0.2.2 shipped the official authorizationPolicy descriptor; DatasetMap Pending
    was dropped and this check evaluates live. authorizationPolicy Get is v1.0.

    Property mapping - verified directly against the EIDSCA config source at implementation
    time (https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json),
    a NINE-PROPERTY FAN-IN off the single authorizationPolicy object (per the research
    entry's own Notes - each reported as its own evidence row, not flattened):
        AP01 allowedToUseSSPR                                      (want $false)
        AP04 allowInvitesFrom                                      (want 'adminsAndGuestInviters' or 'none')
        AP05 allowedToSignUpEmailBasedSubscriptions                (want $false)
        AP06 allowEmailVerifiedUsersToJoinOrganization              (want $false)
        AP07 guestUserRoleId                                       (want the built-in Restricted Guest User role id, 2af84b1e-32c8-42b7-82bc-daa82404023b)
        AP08 permissionGrantPolicyIdsAssignedToDefaultUserRole      (want NOT the legacy default, ManagePermissionGrantsForSelf.microsoft-user-default-legacy)
        AP09 allowUserConsentForRiskyApps                           (want $false)
        AP10 defaultUserRolePermissions.allowedToCreateApps         (want $false)
        AP14 defaultUserRolePermissions.allowedToReadOtherUsers     (want $true - matches the platform default; Informational, evidence-only)

    ABSENT PROPERTY -> ERROR (field-absence lens), with one documented exception: a missing
    top-level property on this singleton is an unrecognized/regressed shape, not a
    legitimate "never customized" tenant state - throws, same convention
    ConvertTo-PulseCaPolicyView/ConvertTo-PulseAuthMethodView apply to an absent `state`.
    EXCEPTION (GraphKit 0.2.2 live): `permissionGrantPolicyIdsAssignedToDefaultUserRole`
    (EIDSCA.AP08) is not on the v1.0 authorizationPolicy resource
    (https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0)
    and GraphKit's official Get is v1.0, so a live v1.0 row never carries it. Same class
    as TP.INT.0028's List-endpoint ESP trim: absent AP08 is NotApplicable when every other
    gating setting passes; other missing properties still throw. If a remaining gating
    setting fails, that Fail still surfaces - AP08 absence does not hide a real gap.
    AP08 present (a beta-shaped fixture, or a future descriptor that projects it) keeps
    the original gate.

    GATING: every property except AP14 gates Status when readable (AP14's recommended value
    already equals its platform default, so it is evidence-only per the research entry's
    own Informational severity tag). AP08 drops out of the gating set when the v1.0
    projection omits it.
#>

function Test-PulseAuthorizationPolicyDefaults {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $rows = @($Datasets.authorizationPolicy)
    if ($rows.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No authorizationPolicy row was collected - cannot evaluate default authorization policy settings.'
    }
    $policy = $rows[0]

    function Get-PulseRequiredProperty {
        param($Node, [string] $PropertyName)
        $has = if ($Node -is [System.Collections.IDictionary]) { $Node.Contains($PropertyName) } else { $null -ne $Node.PSObject.Properties[$PropertyName] }
        if (-not $has) {
            throw "Test-PulseAuthorizationPolicyDefaults: authorizationPolicy has no '$PropertyName' property - cannot evaluate an unrecognized/absent-field authorizationPolicy shape."
        }
        # UNARY COMMA MANDATORY (see ConvertTo-PulseAuthMethodView's own ARRAY-RETURN
        # UNROLLING TRAP section for the reproduced defect this avoids repeating): a bare
        # `return <array-typed expression>` here would already come back from
        # Get-PulseSettingsCatalogValueProperty as ONE comma-protected array object, but
        # returning it again through THIS function's own `return` without re-protecting it
        # would still be a scalar-vs-array ambiguity for the one array-typed caller below
        # (permissionGrantPolicyIdsAssignedToDefaultUserRole) - wrap defensively so every
        # caller gets back exactly what Get-PulseSettingsCatalogValueProperty produced,
        # array-ness intact, with no reliance on how many function-call hops away it is.
        $value = Get-PulseSettingsCatalogValueProperty -Node $Node -PropertyName $PropertyName
        if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) { return , $value }
        return $value
    }

    $allowedToUseSSPR = [bool] (Get-PulseRequiredProperty -Node $policy -PropertyName 'allowedToUseSSPR')
    $allowInvitesFrom = [string] (Get-PulseRequiredProperty -Node $policy -PropertyName 'allowInvitesFrom')
    $allowedToSignUpEmailBasedSubscriptions = [bool] (Get-PulseRequiredProperty -Node $policy -PropertyName 'allowedToSignUpEmailBasedSubscriptions')
    $allowEmailVerifiedUsersToJoinOrganization = [bool] (Get-PulseRequiredProperty -Node $policy -PropertyName 'allowEmailVerifiedUsersToJoinOrganization')
    $guestUserRoleId = [string] (Get-PulseRequiredProperty -Node $policy -PropertyName 'guestUserRoleId')
    $ap08Present = Test-PulseRowPropertyPresent -Row $policy -PropertyName 'permissionGrantPolicyIdsAssignedToDefaultUserRole'
    $permissionGrantPolicyIds = $null
    if ($ap08Present) {
        $permissionGrantPolicyIds = [array] (Get-PulseRequiredProperty -Node $policy -PropertyName 'permissionGrantPolicyIdsAssignedToDefaultUserRole')
    }
    $allowUserConsentForRiskyApps = [bool] (Get-PulseRequiredProperty -Node $policy -PropertyName 'allowUserConsentForRiskyApps')

    $defaultUserRolePermissions = Get-PulseRequiredProperty -Node $policy -PropertyName 'defaultUserRolePermissions'
    $allowedToCreateApps = [bool] (Get-PulseRequiredProperty -Node $defaultUserRolePermissions -PropertyName 'allowedToCreateApps')
    $allowedToReadOtherUsers = [bool] (Get-PulseRequiredProperty -Node $defaultUserRolePermissions -PropertyName 'allowedToReadOtherUsers')

    $restrictedGuestRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b'
    $legacyConsentPolicyId = 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'

    $ap01Ok = -not $allowedToUseSSPR
    $ap04Ok = $allowInvitesFrom -in @('adminsAndGuestInviters', 'none')
    $ap05Ok = -not $allowedToSignUpEmailBasedSubscriptions
    $ap06Ok = -not $allowEmailVerifiedUsersToJoinOrganization
    $ap07Ok = [string]::Equals($guestUserRoleId, $restrictedGuestRoleId, [System.StringComparison]::OrdinalIgnoreCase)
    $ap08Ok = if ($ap08Present) { $permissionGrantPolicyIds -notcontains $legacyConsentPolicyId } else { $true }
    $ap09Ok = -not $allowUserConsentForRiskyApps
    $ap10Ok = -not $allowedToCreateApps

    $evidence = @(
        @{ Identity = 'EIDSCA.AP01'; Detail = @{ setting = 'allowedToUseSSPR'; value = $allowedToUseSSPR; expected = $false; severity = 'High'; ok = $ap01Ok } }
        @{ Identity = 'EIDSCA.AP04'; Detail = @{ setting = 'allowInvitesFrom'; value = $allowInvitesFrom; expected = @('adminsAndGuestInviters', 'none'); severity = 'Medium'; ok = $ap04Ok } }
        @{ Identity = 'EIDSCA.AP05'; Detail = @{ setting = 'allowedToSignUpEmailBasedSubscriptions'; value = $allowedToSignUpEmailBasedSubscriptions; expected = $false; severity = 'Medium'; ok = $ap05Ok } }
        @{ Identity = 'EIDSCA.AP06'; Detail = @{ setting = 'allowEmailVerifiedUsersToJoinOrganization'; value = $allowEmailVerifiedUsersToJoinOrganization; expected = $false; severity = 'Medium'; ok = $ap06Ok } }
        @{ Identity = 'EIDSCA.AP07'; Detail = @{ setting = 'guestUserRoleId'; value = $guestUserRoleId; expected = $restrictedGuestRoleId; severity = 'High'; ok = $ap07Ok } }
        @{ Identity = 'EIDSCA.AP08'; Detail = @{ setting = 'permissionGrantPolicyIdsAssignedToDefaultUserRole'; value = $permissionGrantPolicyIds; expected = "not $legacyConsentPolicyId"; severity = 'Medium'; ok = $ap08Ok; readable = $ap08Present } }
        @{ Identity = 'EIDSCA.AP09'; Detail = @{ setting = 'allowUserConsentForRiskyApps'; value = $allowUserConsentForRiskyApps; expected = $false; severity = 'Medium'; ok = $ap09Ok } }
        @{ Identity = 'EIDSCA.AP10'; Detail = @{ setting = 'defaultUserRolePermissions.allowedToCreateApps'; value = $allowedToCreateApps; expected = $false; severity = 'High'; ok = $ap10Ok } }
        @{ Identity = 'EIDSCA.AP14'; Detail = @{ setting = 'defaultUserRolePermissions.allowedToReadOtherUsers'; value = $allowedToReadOtherUsers; expected = $true; severity = 'Informational' } }
    )

    $gating = @(
        @{ Ok = $ap01Ok; Id = 'AP01' }, @{ Ok = $ap04Ok; Id = 'AP04' }, @{ Ok = $ap05Ok; Id = 'AP05' },
        @{ Ok = $ap06Ok; Id = 'AP06' }, @{ Ok = $ap07Ok; Id = 'AP07' },
        @{ Ok = $ap09Ok; Id = 'AP09' }, @{ Ok = $ap10Ok; Id = 'AP10' }
    )
    if ($ap08Present) {
        $gating = @($gating[0..4] + @{ Ok = $ap08Ok; Id = 'AP08' } + $gating[5..6])
    }
    $failingIds = @($gating | Where-Object { -not $_.Ok } | ForEach-Object { $_.Id })
    $gateCount = @($gating).Count

    if ($failingIds.Count -gt 0) {
        return New-PulseFinding -Status Fail -Reason "$($failingIds.Count) of $gateCount gating default authorization policy settings deviate from their recommended value: $($failingIds -join ', ')." -Evidence $evidence
    }

    if (-not $ap08Present) {
        return New-PulseFinding -Status NotApplicable -Reason "The live AuthorizationPolicy/Get v1.0 projection has no permissionGrantPolicyIdsAssignedToDefaultUserRole (EIDSCA.AP08) - that property is not on the v1.0 authorizationPolicy resource. The other gating defaults (AP01, AP04-AP07, AP09-AP10) match their recommended values. Evaluating AP08 requires a beta (or otherwise AP08-projecting) read, which this check does not perform." -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason 'Every gating default authorization policy setting (EIDSCA.AP01, AP04-AP10) matches its recommended value.' -Evidence $evidence
}

<#
    Private: TP.ENT.0012 rule function - default authorization policy settings cluster
    (EIDSCA.AP01, AP04-AP10, AP14 port; see
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md).

    Consumes $Datasets.authorizationPolicy (Pending in DatasetMap.psd1 - see this check's
    own descriptor/report for the G-batch request; a Pending dataset degrades this check to
    engine-assigned NotApplicable at real-run time via the normal manifest mechanism, never
    a silent skip - see Invoke-PulseEvaluation's own docstring).

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

    ABSENT PROPERTY -> ERROR (field-absence lens): authorizationPolicy is a real singleton
    resource Graph always returns fully populated on a modern tenant - unlike the
    directorySetting collection this cluster's CP01/PR01/ST08 siblings read (see
    Get-PulseDirectorySettingValue's own docstring for why THAT dataset's absence
    convention is deliberately different), a missing top-level property here is an
    unrecognized/regressed shape, not a legitimate "never customized" tenant state. Throws
    - same convention ConvertTo-PulseCaPolicyView/ConvertTo-PulseAuthMethodView apply to an
    absent `state`.

    GATING: every property except AP14 gates Status (AP14's recommended value already
    equals its platform default, so it is evidence-only per the research entry's own
    Informational severity tag - it would almost never be the property that turns a tenant
    from Pass to Fail, and treating it as gating would misleadingly suggest otherwise).
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
    $permissionGrantPolicyIds = [array] (Get-PulseRequiredProperty -Node $policy -PropertyName 'permissionGrantPolicyIdsAssignedToDefaultUserRole')
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
    $ap08Ok = $permissionGrantPolicyIds -notcontains $legacyConsentPolicyId
    $ap09Ok = -not $allowUserConsentForRiskyApps
    $ap10Ok = -not $allowedToCreateApps

    $evidence = @(
        @{ Identity = 'EIDSCA.AP01'; Detail = @{ setting = 'allowedToUseSSPR'; value = $allowedToUseSSPR; expected = $false; severity = 'High'; ok = $ap01Ok } }
        @{ Identity = 'EIDSCA.AP04'; Detail = @{ setting = 'allowInvitesFrom'; value = $allowInvitesFrom; expected = @('adminsAndGuestInviters', 'none'); severity = 'Medium'; ok = $ap04Ok } }
        @{ Identity = 'EIDSCA.AP05'; Detail = @{ setting = 'allowedToSignUpEmailBasedSubscriptions'; value = $allowedToSignUpEmailBasedSubscriptions; expected = $false; severity = 'Medium'; ok = $ap05Ok } }
        @{ Identity = 'EIDSCA.AP06'; Detail = @{ setting = 'allowEmailVerifiedUsersToJoinOrganization'; value = $allowEmailVerifiedUsersToJoinOrganization; expected = $false; severity = 'Medium'; ok = $ap06Ok } }
        @{ Identity = 'EIDSCA.AP07'; Detail = @{ setting = 'guestUserRoleId'; value = $guestUserRoleId; expected = $restrictedGuestRoleId; severity = 'High'; ok = $ap07Ok } }
        @{ Identity = 'EIDSCA.AP08'; Detail = @{ setting = 'permissionGrantPolicyIdsAssignedToDefaultUserRole'; value = $permissionGrantPolicyIds; expected = "not $legacyConsentPolicyId"; severity = 'Medium'; ok = $ap08Ok } }
        @{ Identity = 'EIDSCA.AP09'; Detail = @{ setting = 'allowUserConsentForRiskyApps'; value = $allowUserConsentForRiskyApps; expected = $false; severity = 'Medium'; ok = $ap09Ok } }
        @{ Identity = 'EIDSCA.AP10'; Detail = @{ setting = 'defaultUserRolePermissions.allowedToCreateApps'; value = $allowedToCreateApps; expected = $false; severity = 'High'; ok = $ap10Ok } }
        @{ Identity = 'EIDSCA.AP14'; Detail = @{ setting = 'defaultUserRolePermissions.allowedToReadOtherUsers'; value = $allowedToReadOtherUsers; expected = $true; severity = 'Informational' } }
    )

    $failingIds = @(
        @{ Ok = $ap01Ok; Id = 'AP01' }, @{ Ok = $ap04Ok; Id = 'AP04' }, @{ Ok = $ap05Ok; Id = 'AP05' },
        @{ Ok = $ap06Ok; Id = 'AP06' }, @{ Ok = $ap07Ok; Id = 'AP07' }, @{ Ok = $ap08Ok; Id = 'AP08' },
        @{ Ok = $ap09Ok; Id = 'AP09' }, @{ Ok = $ap10Ok; Id = 'AP10' }
    ) | Where-Object { -not $_.Ok } | ForEach-Object { $_.Id }

    if (@($failingIds).Count -gt 0) {
        return New-PulseFinding -Status Fail -Reason "$(@($failingIds).Count) of 8 gating default authorization policy settings deviate from their recommended value: $($failingIds -join ', ')." -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason 'Every gating default authorization policy setting (EIDSCA.AP01, AP04-AP10) matches its recommended value.' -Evidence $evidence
}

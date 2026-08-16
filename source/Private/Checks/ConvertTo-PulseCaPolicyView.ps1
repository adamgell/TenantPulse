<#
    Private: normalize a raw Conditional Access policy row (GraphKit ConditionalAccessPolicy
    List, beta - see source/Data/DatasetMap.psd1's own `conditionalAccessPolicies` entry)
    into TenantPulse's shared, stable CA policy view shape (Task 4.1).

    WHY A NORMALIZATION LAYER: every seeded CA check (TP.ENT.0003/0004/0005) and every new
    CA-family check in T4.3/T4.4 reads the same handful of raw Graph properties
    (conditions.users.*, grantControls.*, state) by hand, each with its own ad hoc
    @()-wrapping and $null-guarding. That is exactly the "two independent
    reimplementations" trap Resolve-PulseSettingsCatalogValueClassification's own docstring
    already documents for Settings Catalog value classification (P0-2) - a raw-shape read
    duplicated across N check functions can drift out of sync and silently diverge on a
    Graph response shape none of them were built against. This function is the ONE place a
    raw CA policy row gets turned into a stable view; a check function should never property-
    access a raw policy row's conditions/grantControls/state directly again.

    SHAPE NEUTRALITY: every raw-node property read goes through
    Get-PulseSettingsCatalogValueProperty (Resolve-PulseSettingsCatalogValueClassification.ps1)
    - the shared accessor already proven against both a [PSObject] tree (ConvertFrom-Json
    default) and an [IDictionary]/[OrderedHashtable] tree (ConvertFrom-Json -AsHashtable,
    GraphKit's real production shape). Reused here, not forked - see that function's own
    SHAPE NEUTRALITY docstring section for the exact bug class this avoids repeating.

    STATE NORMALIZATION (report-only NEVER counted enforced, downstream, ANYWHERE): Graph's
    three documented `state` values map onto this view's own three-value State enum:
        'enabled'                              -> 'enforced'
        'enabledForReportingButNotEnforced'    -> 'reportOnly'
        'disabled'                             -> 'disabled'
    ABSENT STATE THROWS (field-absence lens, matching TP.INT.0001's own convention for an
    absent mobileDeviceManagementAuthority property - see DatasetMap.psd1's own docstring):
    a CA policy row with no `state` property at all is not a policy TenantPulse has ever
    seen a real shape for - silently defaulting it to 'disabled' (the safe-looking choice)
    would bury a genuine shape regression as a quiet, wrong "policy is off" read instead of
    surfacing it as the Error a caller needs to see. Any OTHER unrecognized state string
    (present but not one of the three known values) throws for the identical reason - an
    unknown enum value is exactly as informative-when-surfaced as a missing property.

    -Context (OPTIONAL, forward-compatible): a plain hashtable a caller MAY populate with
    `AuthenticationStrengthDisplayNames` (a `[string]id -> [string]displayName` map, e.g.
    resolved from `Entra.AuthenticationStrengths.List` per TP.ENT.0018's own research entry
    for custom, tenant-defined strengths). When a raw policy's own
    grantControls.authenticationStrength node already carries a displayName (the common
    case - Graph typically returns both id and displayName inline), that value wins; the
    -Context lookup is only consulted as a fallback when the raw node's displayName is
    absent. Omitting -Context entirely is always safe: authenticationStrength.displayName
    is simply $null in that case, never a throw - unlike State, a missing display NAME is
    cosmetic, not evidence of an unrecognized shape.
#>

function ConvertTo-PulseCaPolicyView {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        $Policies,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    begin {
        $strengthNames = @{}
        if ($Context -and $Context.ContainsKey('AuthenticationStrengthDisplayNames') -and $null -ne $Context.AuthenticationStrengthDisplayNames) {
            $strengthNames = $Context.AuthenticationStrengthDisplayNames
        }

        # Normalizes a raw array-shaped property read to a real, always-present [string[]] -
        # Get-PulseSettingsCatalogValueProperty already protects a genuine array/collection
        # return with the unary comma operator (see that function's own ARRAY-RETURN
        # UNROLLING TRAP docstring), so a caller here still needs its own @() wrap to
        # normalize an absent ($null) read into an empty array rather than a one-element
        # array containing $null.
        function ConvertTo-StringArray {
            param($Value)
            if ($null -eq $Value) { return [string[]] @() }
            return [string[]] @($Value | ForEach-Object { [string] $_ })
        }
    }

    process {
        foreach ($policy in @($Policies)) {
            if ($null -eq $policy) { continue }

            $rawState = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'state'
            if ($null -eq $rawState -or [string]::IsNullOrEmpty([string] $rawState)) {
                throw "ConvertTo-PulseCaPolicyView: policy '$(Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'id')' has no 'state' property - cannot normalize an unrecognized/absent-state Conditional Access policy shape."
            }

            $state = switch ([string] $rawState) {
                'enabled' { 'enforced' }
                'enabledForReportingButNotEnforced' { 'reportOnly' }
                'disabled' { 'disabled' }
                default { throw "ConvertTo-PulseCaPolicyView: policy '$(Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'id')' has an unrecognized state '$rawState' - not one of Graph's three documented values." }
            }

            $conditions = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'conditions'
            $users = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'users'
            $includeUsers = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'includeUsers')

            $apps = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'applications'
            $locations = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'locations'
            $platforms = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'platforms'
            $signInRiskLevels = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'signInRiskLevels')

            $grantControls = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'grantControls'
            $rawStrength = Get-PulseSettingsCatalogValueProperty -Node $grantControls -PropertyName 'authenticationStrength'
            $authenticationStrength = $null
            if ($null -ne $rawStrength) {
                $strengthId = Get-PulseSettingsCatalogValueProperty -Node $rawStrength -PropertyName 'id'
                $strengthDisplayName = Get-PulseSettingsCatalogValueProperty -Node $rawStrength -PropertyName 'displayName'
                if ([string]::IsNullOrEmpty([string] $strengthDisplayName) -and $strengthId -and $strengthNames.ContainsKey([string] $strengthId)) {
                    $strengthDisplayName = $strengthNames[[string] $strengthId]
                }
                $authenticationStrength = [pscustomobject]@{
                    id          = if ($null -ne $strengthId) { [string] $strengthId } else { $null }
                    displayName = if ($null -ne $strengthDisplayName -and -not [string]::IsNullOrEmpty([string] $strengthDisplayName)) { [string] $strengthDisplayName } else { $null }
                }
            }

            $sessionRaw = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'sessionControls'

            [pscustomobject]@{
                id          = [string] (Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'id')
                displayName = [string] (Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'displayName')
                state       = $state
                conditions  = [pscustomobject]@{
                    users           = [pscustomobject]@{
                        includeAll    = ($includeUsers -contains 'All')
                        includeUsers  = $includeUsers
                        includeGroups = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'includeGroups')
                        includeRoles  = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'includeRoles')
                        excludeUsers  = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'excludeUsers')
                        excludeGroups = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'excludeGroups')
                        excludeRoles  = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'excludeRoles')
                    }
                    apps            = [pscustomobject]@{
                        includeApplications = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'includeApplications')
                        excludeApplications = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'excludeApplications')
                        includeUserActions  = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'includeUserActions')
                    }
                    clientAppTypes  = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'clientAppTypes')
                    platforms       = [pscustomobject]@{
                        includePlatforms = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $platforms -PropertyName 'includePlatforms')
                        excludePlatforms = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $platforms -PropertyName 'excludePlatforms')
                    }
                    locations       = [pscustomobject]@{
                        includeLocations = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $locations -PropertyName 'includeLocations')
                        excludeLocations = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $locations -PropertyName 'excludeLocations')
                    }
                    signInRisk      = $signInRiskLevels
                }
                grants      = [pscustomobject]@{
                    operator                = if ($null -ne $grantControls) { [string] (Get-PulseSettingsCatalogValueProperty -Node $grantControls -PropertyName 'operator') } else { $null }
                    builtInControls         = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $grantControls -PropertyName 'builtInControls')
                    authenticationStrength  = $authenticationStrength
                }
                session     = [pscustomobject]@{
                    signInFrequency            = Get-PulseSettingsCatalogValueProperty -Node $sessionRaw -PropertyName 'signInFrequency'
                    persistentBrowser          = Get-PulseSettingsCatalogValueProperty -Node $sessionRaw -PropertyName 'persistentBrowser'
                    cloudAppSecurity           = Get-PulseSettingsCatalogValueProperty -Node $sessionRaw -PropertyName 'cloudAppSecurity'
                    disableResilienceDefaults  = Get-PulseSettingsCatalogValueProperty -Node $sessionRaw -PropertyName 'disableResilienceDefaults'
                }
            }
        }
    }
}

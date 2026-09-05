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

    OPTIONAL PARENT NODES NEVER THROW (post-review, Critical): `conditions`,
    `grantControls`, and `sessionControls` are each OPTIONAL on a sparse-but-legitimate
    Graph response (a policy row that genuinely omits a whole optional block, as opposed to
    an absent/unrecognized STATE - see ABSENT STATE THROWS above, which remains the ONLY
    thing this function ever throws on). Get-PulseSettingsCatalogValueProperty already
    returns $null for every property read off a $null node, so an absent `conditions`
    cascades safely down through `users`/`apps`/`platforms`/`locations` to $null without
    any extra guard needed at each level - conditions/apps/platforms/locations/grants/
    session are ALWAYS constructed as real (never-null) pscustomobjects in the output,
    with their OWN fields null/empty-normalized instead.

    ARRAY-RETURN UNROLLING TRAP, REPRODUCED (post-review, Critical - the actual mechanism
    behind "a sparse response crashes the view"): ConvertTo-StringArray's own return value
    - even `[string[]] @()`, a well-typed EMPTY array - is subject to the exact same
    pipeline-unrolling trap Get-PulseSettingsCatalogValueProperty's own docstring already
    documents for a raw Graph node read. A bare `return $emptyArray` (zero elements) sends
    ZERO objects down the pipeline, and a caller capturing that into a pscustomobject
    property (`includeUsers = ConvertTo-StringArray (...)`) silently receives `$null`
    instead of an empty array - reproduced end to end: a policy with no `conditions` at
    all produced `$view.conditions.users.includeUsers -eq $null` (not `[string[]]@()`),
    and a downstream caller doing `.Count` or any method call on that $null is exactly the
    crash this finding reported. A single-element array has the identical trap in the OTHER
    direction: it unrolls to its bare scalar item, not a one-element array, silently
    breaking every caller that assumes an array-typed field can always be enumerated as
    one. ConvertTo-StringArray protects BOTH of its return statements with the unary comma
    operator (`return , [string[]] @(...)`) for exactly this reason - removing either comma
    reintroduces this bug.
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
            # UNARY COMMA MANDATORY on both branches - see this file's own ARRAY-RETURN
            # UNROLLING TRAP docstring section. Without it, an empty array collapses to
            # $null and a one-element array collapses to its bare scalar item on the way
            # out of this function - both silently break every caller's array-typed
            # contract for this field.
            if ($null -eq $Value) { return , ([string[]] @()) }
            return , ([string[]] @($Value | ForEach-Object { [string] $_ }))
        }

        function Test-NodePropertyPresent {
            param(
                [AllowNull()] $Node,
                [Parameter(Mandatory)] [string] $PropertyName
            )
            if ($null -eq $Node) { return $false }
            if ($Node -is [System.Collections.IDictionary]) {
                if ($Node.PSObject.Methods.Name -contains 'ContainsKey') {
                    return [bool] $Node.ContainsKey($PropertyName)
                }
                return [bool] $Node.Contains($PropertyName)
            }
            return $null -ne $Node.PSObject.Properties[$PropertyName]
        }

        function Get-NodePropertyNames {
            param([AllowNull()] $Node)
            if ($null -eq $Node) { return }
            if ($Node -is [System.Collections.IDictionary]) {
                return $Node.Keys | ForEach-Object { [string] $_ }
            }
            return $Node.PSObject.Properties.Name | ForEach-Object { [string] $_ }
        }

        $knownConditionProperties = @(
            'users', 'applications', 'clientApplications', 'clientAppTypes',
            'platforms', 'locations', 'signInRiskLevels', 'userRiskLevels',
            'servicePrincipalRiskLevels', 'insiderRiskLevels', 'agentIdRiskLevels',
            'devices', 'deviceStates', 'authenticationFlows', 'times'
        )
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
            $rawApplicationFilter = Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'applicationFilter'
            $applicationFilter = $null
            if ($null -ne $rawApplicationFilter) {
                $applicationFilter = [pscustomobject]@{
                    mode = Get-PulseSettingsCatalogValueProperty -Node $rawApplicationFilter -PropertyName 'mode'
                    rule = Get-PulseSettingsCatalogValueProperty -Node $rawApplicationFilter -PropertyName 'rule'
                }
            }
            $clientApps = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'clientApplications'
            $rawServicePrincipalFilter = Get-PulseSettingsCatalogValueProperty -Node $clientApps -PropertyName 'servicePrincipalFilter'
            $servicePrincipalFilter = $null
            if ($null -ne $rawServicePrincipalFilter) {
                $servicePrincipalFilter = [pscustomobject]@{
                    mode = Get-PulseSettingsCatalogValueProperty -Node $rawServicePrincipalFilter -PropertyName 'mode'
                    rule = Get-PulseSettingsCatalogValueProperty -Node $rawServicePrincipalFilter -PropertyName 'rule'
                }
            }
            $rawAgentIdServicePrincipalFilter = Get-PulseSettingsCatalogValueProperty -Node $clientApps -PropertyName 'agentIdServicePrincipalFilter'
            $agentIdServicePrincipalFilter = $null
            if ($null -ne $rawAgentIdServicePrincipalFilter) {
                $agentIdServicePrincipalFilter = [pscustomobject]@{
                    mode = Get-PulseSettingsCatalogValueProperty -Node $rawAgentIdServicePrincipalFilter -PropertyName 'mode'
                    rule = Get-PulseSettingsCatalogValueProperty -Node $rawAgentIdServicePrincipalFilter -PropertyName 'rule'
                }
            }
            $locations = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'locations'
            $platforms = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'platforms'
            $devices = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'devices'
            $deviceStates = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'deviceStates'
            $deviceFilter = Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'deviceFilter'
            $authenticationFlows = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'authenticationFlows'
            $times = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'times'
            [string[]] $unknownConditionPropertyNames = @(
                Get-NodePropertyNames -Node $conditions |
                    Where-Object {
                        -not $_.StartsWith('@', [System.StringComparison]::Ordinal) -and
                        $_ -notin $knownConditionProperties -and
                        $null -ne (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName $_)
                    } |
                    Sort-Object -Unique
            )
            $signInRiskLevels = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'signInRiskLevels')
            $userRiskLevels = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'userRiskLevels')
            $servicePrincipalRiskLevels = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'servicePrincipalRiskLevels')
            $insiderRiskLevels = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'insiderRiskLevels')
            $agentIdRiskLevels = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'agentIdRiskLevels')

            $grantControls = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'grantControls'
            $rawStrength = Get-PulseSettingsCatalogValueProperty -Node $grantControls -PropertyName 'authenticationStrength'
            $authenticationStrength = $null
            if ($null -ne $rawStrength) {
                $strengthId = Get-PulseSettingsCatalogValueProperty -Node $rawStrength -PropertyName 'id'
                $strengthDisplayName = Get-PulseSettingsCatalogValueProperty -Node $rawStrength -PropertyName 'displayName'
                $requirementsSatisfied = Get-PulseSettingsCatalogValueProperty -Node $rawStrength -PropertyName 'requirementsSatisfied'
                if ([string]::IsNullOrEmpty([string] $strengthDisplayName) -and $strengthId -and $strengthNames.ContainsKey([string] $strengthId)) {
                    $strengthDisplayName = $strengthNames[[string] $strengthId]
                }
                $authenticationStrength = [pscustomobject]@{
                    id          = if ($null -ne $strengthId) { [string] $strengthId } else { $null }
                    displayName = if ($null -ne $strengthDisplayName -and -not [string]::IsNullOrEmpty([string] $strengthDisplayName)) { [string] $strengthDisplayName } else { $null }
                    requirementsSatisfied = if ($null -ne $requirementsSatisfied -and -not [string]::IsNullOrWhiteSpace([string] $requirementsSatisfied)) { [string] $requirementsSatisfied } else { $null }
                    allowedCombinations = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $rawStrength -PropertyName 'allowedCombinations')
                }
            }

            $sessionRaw = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'sessionControls'

            [pscustomobject]@{
                id          = [string] (Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'id')
                displayName = [string] (Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'displayName')
                state       = $state
                conditions  = [pscustomobject]@{
                    present         = ($null -ne $conditions)
                    users           = [pscustomobject]@{
                        present       = ($null -ne $users)
                        includeAll    = ($includeUsers -contains 'All')
                        includeUsers  = $includeUsers
                        includeGroups = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'includeGroups')
                        includeRoles  = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'includeRoles')
                        hasIncludeGuestsOrExternalUsers = ($null -ne (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'includeGuestsOrExternalUsers'))
                        excludeUsers  = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'excludeUsers')
                        excludeGroups = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'excludeGroups')
                        excludeRoles  = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'excludeRoles')
                        hasExcludeGuestsOrExternalUsers = ($null -ne (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'excludeGuestsOrExternalUsers'))
                    }
                    apps            = [pscustomobject]@{
                        present             = ($null -ne $apps)
                        includeApplications = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'includeApplications')
                        excludeApplications = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'excludeApplications')
                        includeUserActions  = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'includeUserActions')
                        includeAuthenticationContextClassReferences = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'includeAuthenticationContextClassReferences')
                        applicationFilter   = $applicationFilter
                    }
                    # clientApplications is Graph's distinct workload-identity targeting
                    # block. Its service-principal fields must never be confused with the
                    # ordinary applications block above.
                    clientApplications = [pscustomobject]@{
                        present                  = ($null -ne $clientApps)
                        includeServicePrincipals = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $clientApps -PropertyName 'includeServicePrincipals')
                        excludeServicePrincipals = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $clientApps -PropertyName 'excludeServicePrincipals')
                        servicePrincipalFilter   = $servicePrincipalFilter
                        includeAgentIdServicePrincipals = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $clientApps -PropertyName 'includeAgentIdServicePrincipals')
                        excludeAgentIdServicePrincipals = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $clientApps -PropertyName 'excludeAgentIdServicePrincipals')
                        agentIdServicePrincipalFilter   = $agentIdServicePrincipalFilter
                    }
                    clientAppTypesPresent = Test-NodePropertyPresent -Node $conditions -PropertyName 'clientAppTypes'
                    clientAppTypes  = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'clientAppTypes')
                    platforms       = [pscustomobject]@{
                        present          = ($null -ne $platforms)
                        includePlatforms = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $platforms -PropertyName 'includePlatforms')
                        excludePlatforms = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $platforms -PropertyName 'excludePlatforms')
                    }
                    locations       = [pscustomobject]@{
                        present          = ($null -ne $locations)
                        includeLocations = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $locations -PropertyName 'includeLocations')
                        excludeLocations = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $locations -PropertyName 'excludeLocations')
                    }
                    signInRisk      = $signInRiskLevels
                    signInRiskPresent = Test-NodePropertyPresent -Node $conditions -PropertyName 'signInRiskLevels'
                    userRisk        = $userRiskLevels
                    userRiskPresent = Test-NodePropertyPresent -Node $conditions -PropertyName 'userRiskLevels'
                    servicePrincipalRisk = $servicePrincipalRiskLevels
                    servicePrincipalRiskPresent = Test-NodePropertyPresent -Node $conditions -PropertyName 'servicePrincipalRiskLevels'
                    insiderRisk     = $insiderRiskLevels
                    insiderRiskPresent = Test-NodePropertyPresent -Node $conditions -PropertyName 'insiderRiskLevels'
                    agentIdRisk     = $agentIdRiskLevels
                    agentIdRiskPresent = Test-NodePropertyPresent -Node $conditions -PropertyName 'agentIdRiskLevels'
                    devices         = [pscustomobject]@{
                        present       = ($null -ne $devices)
                        filterPresent = ($null -ne $deviceFilter)
                        filterMode    = Get-PulseSettingsCatalogValueProperty -Node $deviceFilter -PropertyName 'mode'
                        filterRule    = Get-PulseSettingsCatalogValueProperty -Node $deviceFilter -PropertyName 'rule'
                        includeDevices = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'includeDevices')
                        includeDevicesPresent = Test-NodePropertyPresent -Node $devices -PropertyName 'includeDevices'
                        excludeDevices = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'excludeDevices')
                        excludeDevicesPresent = Test-NodePropertyPresent -Node $devices -PropertyName 'excludeDevices'
                        includeDeviceStates = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'includeDeviceStates')
                        includeDeviceStatesPresent = Test-NodePropertyPresent -Node $devices -PropertyName 'includeDeviceStates'
                        excludeDeviceStates = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'excludeDeviceStates')
                        excludeDeviceStatesPresent = Test-NodePropertyPresent -Node $devices -PropertyName 'excludeDeviceStates'
                    }
                    deviceStates    = [pscustomobject]@{
                        present       = ($null -ne $deviceStates)
                        includeStates = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $deviceStates -PropertyName 'includeStates')
                        includeStatesPresent = Test-NodePropertyPresent -Node $deviceStates -PropertyName 'includeStates'
                        excludeStates = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $deviceStates -PropertyName 'excludeStates')
                        excludeStatesPresent = Test-NodePropertyPresent -Node $deviceStates -PropertyName 'excludeStates'
                    }
                    authenticationFlows = [pscustomobject]@{
                        present         = ($null -ne $authenticationFlows)
                        transferMethods = Get-PulseSettingsCatalogValueProperty -Node $authenticationFlows -PropertyName 'transferMethods'
                    }
                    timesPresent = ($null -ne $times)
                    unknownConditionPropertyNames = $unknownConditionPropertyNames
                    unknownConditionPropertyCount = $unknownConditionPropertyNames.Count
                }
                grants      = [pscustomobject]@{
                    present                 = ($null -ne $grantControls)
                    operatorPresent         = Test-NodePropertyPresent -Node $grantControls -PropertyName 'operator'
                    operator                = if ($null -ne $grantControls) { [string] (Get-PulseSettingsCatalogValueProperty -Node $grantControls -PropertyName 'operator') } else { $null }
                    builtInControls         = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $grantControls -PropertyName 'builtInControls')
                    authenticationStrength  = $authenticationStrength
                    customAuthenticationFactors = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $grantControls -PropertyName 'customAuthenticationFactors')
                    termsOfUse              = ConvertTo-StringArray (Get-PulseSettingsCatalogValueProperty -Node $grantControls -PropertyName 'termsOfUse')
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

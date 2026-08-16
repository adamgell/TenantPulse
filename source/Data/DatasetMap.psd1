<#
    The shared dataset -> GraphKit descriptor map.

    This is the single source of truth every TenantPulse layer that talks about datasets
    pivots on: check authors (Task 1.9) reference dataset names in a descriptor's
    Data.Datasets, Import-PulseCheckCatalog (Task 1.4) cross-checks those names against
    this file's top-level keys, the static read-only gate (Task 1.10) walks every entry
    here to prove every Type/Operation pair is Read/Safe without touching a live tenant,
    and the collector (Task 1.5) resolves each entry into the {Type;Operation;ApiVersion}
    GraphKit needs to actually collect it.

    Shape: a plain hashtable (not an array), keyed by dataset name, each value itself a
    hashtable with:
        Type          - the GraphKit operation Type, e.g. 'ConditionalAccessPolicy'.
        Operation     - the GraphKit operation Operation, e.g. 'List' or 'Get'.
        ApiVersion    - 'v1.0' or 'beta', matching the resolved GraphKit descriptor's own
                        ApiVersion (Write-PulseDataset validates against this same set).
        IdFromDataset - OPTIONAL. Names another dataset in THIS map that must be collected
                        first; the collector takes @(items)[0].id from that dataset's
                        already-collected rows and passes it as -Parameters @{ id = ... }
                        to Get-GraphObject for THIS entry (see Get-PulseCollectionManifest
                        and Invoke-PulseCollection's own docstrings for the ordering and
                        failure-propagation rules this implies). Used for
                        organizationMdmAuthority below, whose GraphKit operation
                        (Organization.GetMdmAuthority) is a $select-in-path read that needs
                        the org id.

    Pending flag: a dataset entry may also carry `Pending = $true`. This marks a dataset
    whose GraphKit descriptor does not exist yet in a RELEASED GraphKit version - the
    collector (Get-PulseTenantSnapshot / Invoke-PulseCollection) must classify it Skipped
    with reason 'descriptor-pending: awaiting GraphKit release' and must NOT call
    Get-GraphOperation or attempt any Graph call for it (there is nothing there to resolve
    or call). Once the corresponding GraphKit descriptor ships (0.1.1), drop the Pending
    flag and the collector starts actually collecting the dataset with no other code change
    required.

    LIVE-TENANT VERIFICATION NOTE (2026-08-15, Task 1.9): six datasets below are Pending as
    of GraphKit's currently-released version - their descriptors exist in GraphKit's
    committed-but-unreleased catalog and go live when 0.1.1 is cut:
        securityDefaultsPolicy, directoryRoleAssignments, directoryRoleDefinitions,
        organization, organizationMdmAuthority, entraDevices.
    mdmAuthority (the single-dataset shape this map used before this task) does NOT work
    against a live tenant - mobileDeviceManagementAuthority is not a property of the
    /organization collection response at all. It only appears on the dedicated
    Organization.GetMdmAuthority read (GET /organization/{id}?$select=...), which needs the
    org id up front - hence the two-dataset organization + organizationMdmAuthority split
    and the IdFromDataset mechanism above. See TP.INT.0001's check function for how an
    ABSENT mobileDeviceManagementAuthority property on that read is treated (Error, never
    Fail/Pass - the field-absence lens this whole task applies).

    CLARIFICATION (post-review, adjudicated, C1): Organization.GetMdmAuthority is a
    PROPERTY-SELECT PATH TEMPLATE against the organization ENTITY
    (GET /organization/{id}?$select=mobileDeviceManagementAuthority), not a Graph API
    "action" - Microsoft did remove an actual getMdmAuthority ACTION from the API surface at
    some point (the now-404ing organization-getmdmauthority action doc some tooling still
    cites), which is a different, dead thing this operation name can be confused with. This
    GraphKit operation is real and live-verified this week: 200 with 'intune' on both v1.0
    and beta. See TP.INT.0001's own descriptor for the corrected References.Authorities URL
    (the organization RESOURCE doc, not the dead action doc).

    directoryRoleDefinitions is deliberately mapped to the BETA List operation: isPrivileged
    and templateId-complete role metadata are beta-only - the v1.0 List silently omits
    fields TP.ENT.0002's Global Administrator join depends on.
#>
@{
    conditionalAccessPolicies   = @{ Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta' }
    deviceCompliancePolicies    = @{ Type = 'DeviceCompliancePolicy'; Operation = 'List'; ApiVersion = 'v1.0' }
    deviceConfigurations        = @{ Type = 'DeviceConfiguration'; Operation = 'List'; ApiVersion = 'v1.0' }
    appProtectionPolicies       = @{ Type = 'AppProtectionPolicy'; Operation = 'List'; ApiVersion = 'beta' }
    managedDevices               = @{ Type = 'ManagedDevice'; Operation = 'List'; ApiVersion = 'v1.0' }
    authenticationMethodsPolicy = @{ Type = 'AuthenticationMethodsPolicy'; Operation = 'Get'; ApiVersion = 'beta' }
    autopilotDevices             = @{ Type = 'AutopilotDevice'; Operation = 'List'; ApiVersion = 'beta' }
    domains                       = @{ Type = 'Domain'; Operation = 'List'; ApiVersion = 'beta' }

    # Read live against a real tenant this week; not marked Pending.
    #
    # CORRECTED (Task 1.10, static read-only gate): the GraphKit catalog's operation Type
    # for this descriptor is 'ManagedDeviceSetting' (OperationKind Singleton, PathTemplate
    # /deviceManagement/settings), NOT 'DeviceManagementSettings' - the latter never
    # resolved via Get-GraphOperation (it doesn't exist in the catalog at all), which is
    # exactly the class of drift the static gate exists to catch before it reaches a live
    # tenant. ThrottleClass=Read, ReplayPolicy=Safe, ApiVersion=beta - confirmed against
    # the real installed GraphKit 0.1.0 catalog.
    deviceManagementSettings = @{ Type = 'ManagedDeviceSetting'; Operation = 'Get'; ApiVersion = 'beta' }

    # Pending - GraphKit descriptor exists committed-but-unreleased; goes live at 0.1.1.
    # See the LIVE-TENANT VERIFICATION NOTE above.
    #
    # ExpectedThrottleClass / ExpectedReplayPolicy (Task 1.10): these Pending entries have
    # no live GraphKit descriptor to query yet, so the static read-only gate cannot resolve
    # them via Get-GraphOperation the way it does every non-Pending entry above. Instead
    # each Pending entry DECLARES the read-only shape its future descriptor is expected to
    # have - based on this week's live-tenant verification note - and the gate asserts
    # against that declaration (ThrottleClass 'Read', ReplayPolicy 'Safe') with a clearly
    # reported "descriptor-pending" reason instead of a live lookup. This still catches a
    # real authoring mistake (someone flipping Pending on a write-shaped or unsafe-replay
    # operation) even though it cannot verify the eventual GraphKit release matches; that
    # re-verification happens automatically the moment the Pending flag drops, because the
    # gate then falls through to the same live Get-GraphOperation path every other entry
    # uses.
    securityDefaultsPolicy    = @{ Type = 'SecurityDefaultsPolicy'; Operation = 'Get'; ApiVersion = 'v1.0'; Pending = $true; ExpectedThrottleClass = 'Read'; ExpectedReplayPolicy = 'Safe' }
    directoryRoleAssignments  = @{ Type = 'DirectoryRoleAssignment'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $true; ExpectedThrottleClass = 'Read'; ExpectedReplayPolicy = 'Safe' }
    directoryRoleDefinitions  = @{ Type = 'DirectoryRoleDefinition'; Operation = 'ListBeta'; ApiVersion = 'beta'; Pending = $true; ExpectedThrottleClass = 'Read'; ExpectedReplayPolicy = 'Safe' }
    organization               = @{ Type = 'Organization'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $true; ExpectedThrottleClass = 'Read'; ExpectedReplayPolicy = 'Safe' }
    # GetMdmAuthority is a $select-in-path property read on the organization entity
    # (/organization/{id}?$select=mobileDeviceManagementAuthority), NOT the removed
    # getMdmAuthority action - see the CLARIFICATION note above. Live-verified 200 'intune'
    # on both v1.0 and beta this week.
    organizationMdmAuthority  = @{ Type = 'Organization'; Operation = 'GetMdmAuthority'; ApiVersion = 'v1.0'; Pending = $true; IdFromDataset = 'organization'; ExpectedThrottleClass = 'Read'; ExpectedReplayPolicy = 'Safe' }
    entraDevices               = @{ Type = 'EntraDevice'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $true; ExpectedThrottleClass = 'Read'; ExpectedReplayPolicy = 'Safe' }
}

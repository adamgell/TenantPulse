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
    deviceManagementSettings = @{ Type = 'DeviceManagementSettings'; Operation = 'Get'; ApiVersion = 'beta' }

    # Pending - GraphKit descriptor exists committed-but-unreleased; goes live at 0.1.1.
    # See the LIVE-TENANT VERIFICATION NOTE above.
    securityDefaultsPolicy    = @{ Type = 'SecurityDefaultsPolicy'; Operation = 'Get'; ApiVersion = 'v1.0'; Pending = $true }
    directoryRoleAssignments  = @{ Type = 'DirectoryRoleAssignment'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $true }
    directoryRoleDefinitions  = @{ Type = 'DirectoryRoleDefinition'; Operation = 'ListBeta'; ApiVersion = 'beta'; Pending = $true }
    organization               = @{ Type = 'Organization'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $true }
    organizationMdmAuthority  = @{ Type = 'Organization'; Operation = 'GetMdmAuthority'; ApiVersion = 'v1.0'; Pending = $true; IdFromDataset = 'organization' }
    entraDevices               = @{ Type = 'EntraDevice'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $true }
}

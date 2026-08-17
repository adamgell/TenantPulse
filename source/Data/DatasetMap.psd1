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

    # GraphKit 0.1.1 (Task 1.11 migration): these six descriptors shipped in the release
    # the LIVE-TENANT VERIFICATION NOTE above anticipated. Pending dropped - the static
    # read-only gate now resolves each of these via a live Get-GraphOperation lookup
    # against the installed GraphKit 0.1.1 catalog, exactly like every other entry above,
    # instead of asserting against a declared ExpectedThrottleClass/ExpectedReplayPolicy.
    securityDefaultsPolicy    = @{ Type = 'SecurityDefaultsPolicy'; Operation = 'Get'; ApiVersion = 'v1.0' }
    directoryRoleAssignments  = @{ Type = 'DirectoryRoleAssignment'; Operation = 'List'; ApiVersion = 'v1.0' }
    directoryRoleDefinitions  = @{ Type = 'DirectoryRoleDefinition'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    organization               = @{ Type = 'Organization'; Operation = 'List'; ApiVersion = 'v1.0' }
    # GetMdmAuthority is a $select-in-path property read on the organization entity
    # (/organization/{id}?$select=mobileDeviceManagementAuthority), NOT the removed
    # getMdmAuthority action - see the CLARIFICATION note above. Live-verified 200 'intune'
    # on both v1.0 and beta this week.
    organizationMdmAuthority  = @{ Type = 'Organization'; Operation = 'GetMdmAuthority'; ApiVersion = 'v1.0'; IdFromDataset = 'organization' }
    entraDevices               = @{ Type = 'EntraDevice'; Operation = 'List'; ApiVersion = 'v1.0' }

    # Task 2.2 (Settings Catalog expansion, -ExpandSettings): declared here so the STATIC
    # read-only gate (tests/QA/ReadOnly.tests.ps1, which walks every key in this file) also
    # proves these two descriptors are Read/Safe - the same "single pivot, no documented
    # exception" this file is for every other Get-GraphObject call TenantPulse ever makes.
    # NEITHER is consumed by the ordinary check-driven Invoke-PulseCollection loop (no
    # T2.2-era check references either name in its own Data.Datasets, and
    # configurationPolicySettings needs a PER-POLICY id, not the single first-row
    # IdFromDataset semantics Invoke-PulseCollection implements) - both are instead fetched
    # directly by the Settings Catalog expansion pipeline
    # (Invoke-PulseSettingsCatalogExpansionPipeline for configurationPolicies,
    # Invoke-PulseSettingsCatalogPolicy - one call per policy - for
    # configurationPolicySettings), each of which calls Assert-PulseReadOnlyDescriptor
    # itself against the SAME {Type;Operation} pair declared here before ever calling
    # Get-GraphObject, exactly like Invoke-PulseCollection does for every check-driven
    # dataset.
    configurationPolicies       = @{ Type = 'ConfigurationPolicy'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    configurationPolicySettings = @{ Type = 'ConfigurationPolicySetting'; Operation = 'ListBeta'; ApiVersion = 'beta' }

    # Task 2.3 (compliance + legacy typed-policy expansion, -ExpandSettings): declared here
    # for the exact same reason as the two Task 2.2 entries directly above - so the STATIC
    # read-only gate proves both are Read/Safe - and consumed the exact same way: NOT
    # through the ordinary check-driven Invoke-PulseCollection loop (a PER-POLICY id, not
    # IdFromDataset's single first-row semantics), but fetched directly, once per policy,
    # by Invoke-PulseTypedPolicyExpansion, which calls Assert-PulseReadOnlyDescriptor
    # itself against these SAME {Type;Operation} pairs before ever calling Get-GraphObject.
    # Both descriptors are ALREADY RELEASED in GraphKit 0.1.1 (unlike T2.2's own
    # ConfigurationPolicyAssignment, still G-gate-pending) - see the plan's own G-gate
    # section for why T2.3's assignment fan-out is real, not deferred.
    deviceCompliancePolicyAssignments = @{ Type = 'DeviceCompliancePolicyAssignment'; Operation = 'List'; ApiVersion = 'v1.0' }
    deviceConfigurationAssignments    = @{ Type = 'DeviceConfigurationAssignment'; Operation = 'List'; ApiVersion = 'v1.0' }

    # Task 3.2 (TP.INT.0007, Maester MT.1053 port): the tenant-wide clean-up SETTINGS
    # singleton, not the newer per-platform managedDeviceCleanupRules collection Maester's
    # own function queries (that collection resource is not in GraphKit's released
    # catalog) - see Test-PulseDeviceCleanupRuleConfigured.ps1's own docstring for the
    # live-verified divergence. Already released in GraphKit 0.1.1 (Type
    # 'DeviceCleanupRule', Operation 'Get', PathTemplate
    # /deviceManagement/managedDeviceCleanupSettings) - confirmed via a live
    # Get-GraphOperation lookup, not Pending.
    managedDeviceCleanupSettings = @{ Type = 'DeviceCleanupRule'; Operation = 'Get'; ApiVersion = 'beta' }
}

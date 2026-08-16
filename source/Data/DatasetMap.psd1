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
        Type       - the GraphKit operation Type, e.g. 'ConditionalAccessPolicy'.
        Operation  - the GraphKit operation Operation, e.g. 'List' or 'Get'.
        ApiVersion - 'v1.0' or 'beta', matching the resolved GraphKit descriptor's own
                     ApiVersion (Write-PulseDataset validates against this same set).

    Pending flag: a dataset entry may also carry `Pending = $true`. This marks a dataset
    whose GraphKit descriptor does not exist yet - the collector (Get-PulseTenantSnapshot
    / Invoke-PulseCollection) must classify it Skipped with reason
    'descriptor-pending: awaiting GraphKit release' and must NOT call Get-GraphOperation
    or attempt any Graph call for it (there is nothing there to resolve or call). Once the
    corresponding GraphKit descriptor ships, drop the Pending flag and the collector
    starts actually collecting the dataset with no other code change required. As of this
    writing (GraphKit 0.0.2) two datasets below are Pending: mdmAuthority
    (needs an Organization.Get-shaped read) and entraDevices (needs an EntraDevice.List-
    shaped read).

    The ten entries below are exactly the datasets the ten Phase 1 seed checks (Task 1.9)
    need. Every non-Pending entry names a real GraphKit 0.0.2 operation descriptor
    (source/Data/Operations/<Type>.<Operation>.psd1 in the GraphKit repo) already
    confirmed ThrottleClass 'Read' and ReplayPolicy 'Safe' - the read-only predicate this
    module enforces everywhere (Assert-PulseReadOnlyDescriptor, and later the static
    Task 1.10 gate).
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

    # Pending - no GraphKit descriptor exists yet. See the Pending flag note above.
    mdmAuthority = @{ Type = 'Organization'; Operation = 'Get'; ApiVersion = 'v1.0'; Pending = $true }
    entraDevices = @{ Type = 'EntraDevice'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $true }
}

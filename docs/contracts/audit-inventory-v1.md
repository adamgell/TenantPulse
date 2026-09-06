# Audit inventory collection contract v1

TenantPulse `-ReportData Inventory` guarantees collection of the neutral source datasets used by
the IHA migration inventory, independently of which checks are selected. The profile uses the
ordinary snapshot collection pipeline: one catalog-wide permission preflight, GraphKit-owned
read-only transport, deduplicated operations, content-addressed dataset files, and explicit
`Collected`, `Partial`, `Failed`, or `Skipped` outcomes.

The profile includes these source datasets:

- `androidEnrollmentProfiles`, `appProtectionPolicies`, `authenticationMethodsPolicy`,
  `conditionalAccessPolicies`, `depOnboardingSettings`, `deviceCategories`,
  `deviceCompliancePolicies`, `deviceConfigurations`, `deviceEnrollmentConfigurations`,
  `deviceManagementScripts`, `deviceManagementSettings`, `domainConnectors`, `domains`, `groups`,
  `managedDeviceCleanupRules`, `managedDevices`, `mobileAppCategories`,
  `mobileAppConfigurations`, `ndesConnectors`, `roleAssignmentScheduleInstances`,
  `roleEligibilityScheduleInstances`, `subscribedSkus`, `vppTokens`,
  `windowsAutopilotDeviceIdentities`, and `windowsUpdateCatalogItems`.

The direct dataset entries added for the IHA port bind to the released GraphKit 0.3.0 operations
`AndroidEnrollmentProfile.List`, `AppConfigurationPolicy.List`, `DeviceCategory.ListBeta`,
`DeviceManagementScript.List`, `DomainConnector.List`, `Group.ListBeta`,
`MobileAppCategory.List`, and `WindowsUpdateCatalogItem.List`. The normal static read-only gate
resolves every entry and requires GraphKit to declare `ThrottleClass = Read` and
`ReplayPolicy = Safe`.

`Inventory` intentionally does not duplicate specialized artifact producers. Use
`-ReportData Inventory,Applications,Devices -ExpandSettings` when a run needs the complete current
successor evidence set: application assignments and install errors come from `Applications`, the
managed-device worksheet source comes from `Devices`, and setting conflicts require the existing
opt-in settings expansion. These profiles share the same collection manifest, so overlapping root
datasets are fetched once.

The datasets are local audit evidence, not customer-ready output. They can contain tenant user,
device, group, application, policy, and connector identifiers. TenantPulse does not render Office
files, apply branding, infer approval state, or turn a failed/partial source into empty success.

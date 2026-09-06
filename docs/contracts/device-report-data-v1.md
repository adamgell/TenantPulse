# Managed device report data contract v1

TenantPulse `-ReportData Devices` publishes one neutral, hash-verified JSONL expansion named
`managed-device-inventory`. It is the machine-data replacement for the six active IHA report
definitions that all read `managedDevices`:

| IHA report | Successor derivation |
|---|---|
| DeviceOSCompliance | Project the device, user, OS, version, model, sync, and compliance fields. |
| DevicesWithoutBitLocker | Select Windows rows whose native `isEncrypted` value is `false`; a missing value is unknown, not proven unencrypted. |
| HardwareInventoryReport | Project manufacturer, model, serial, physical memory, encryption, OS, sync, and compliance fields. |
| NonCompliantDevices | Select rows with an explicit, nonblank `complianceState` other than `compliant`; missing state remains unknown. |
| StaleWindowsDevices | Select Windows rows whose valid `lastSyncDateTime` is older than the declared report run's UTC cutoff. The Office builder must record that cutoff; it must not silently use the viewer's current clock. |
| TPMStatusReport | Use `tpmVersion` only when returned by the per-device hardware or attestation object. The legacy report definition itself collected no TPM property; encryption/compliance fields are never relabeled as TPM evidence. |

## Row schema

Every row carries `schemaVersion = "1"` and the normalized fields `deviceId`,
`azureAdDeviceId`, `deviceName`, `userPrincipalName`, `userId`, `operatingSystem`, `osVersion`,
`manufacturer`, `model`, `serialNumber`, `physicalMemoryInBytes`, `isEncrypted`,
`complianceState`, `lastSyncDateTime`, `enrolledDateTime`, `managementAgent`,
`managedDeviceOwnerType`, `deviceCategoryDisplayName`, `processorArchitecture`, `skuFamily`,
`skuNumber`, `ethernetMacAddress`, `bootstrapTokenEscrowed`, `hardwareInformation`,
`deviceHealthAttestationState`, `tpmVersion`, and `detailResolutionState`.

For Windows devices the public collection path requests `ManagedDevice.GetBeta`, whose fixed select
includes hardware and health-attestation detail. `baseSourceColumns`, `detailSourceColumns`, and the
merged `sourceColumns` preserve the exact inputs. Non-Windows detail is `NotApplicable`; a denied,
failed, invalid, or authentication-suppressed detail read remains `Partial` with a gap rather than
falling back to collection-shaped hardware defaults. Tenant identifiers are recursively pseudonymized before publication.
The snapshot and expansion remain local-only evidence and may contain user/device identifiers.

A usable row needs a Graph managed-device id, an Entra device id, or a device name. A null row or
row with none of those identities is excluded with an explicit gap. A source dataset with status
`Partial` always creates a `Partial` artifact; failed, skipped, missing, corrupt, or wholly unusable
source data never becomes an authoritative empty artifact.

## Determinism and module boundary

Rows sort ordinally by managed-device id, Entra device id, device name, serial number, and finally
the complete canonical row. Equivalent source order therefore produces identical bytes and a
stable digest. TenantPulse does not render Excel, brand the output, or decide customer approval.
The external Office delivery layer owns worksheet filters, presentation, and preservation of
customer-owned fields.

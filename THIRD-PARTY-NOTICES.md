# Third-Party Notices

TenantPulse depends on third-party software, and several of its checks adapt logic from
third-party projects. This file lists all of them and their licenses (post-review fix: an
earlier draft of this file claimed "no third-party content has been ported into this
repository yet", which contradicted TP.INT.0001 and TP.INT.0003 - both of which carry a
`Origin = @{ Project = 'Maester'; License = 'MIT' }` field in their own check descriptor
naming exactly this).

## Adapted code

### Maester

- **Project:** [Maester](https://github.com/maester365/maester)
- **License:** MIT
- **Adapted into:**
  - `source/Data/Checks/TP.INT.0001.psd1` ("MDM authority is set to Intune") - adapts the
    check logic behind Maester's `MT.1105`.
  - `source/Data/Checks/TP.INT.0003.psd1` ("default enrollment restrictions are configured
    to block unmanaged platforms" - see that file for its exact title) - adapts the check
    logic behind Maester's `MT.1054`.
  - `source/Data/Checks/TP.INT.0007.psd1` ("Intune device clean-up rule configured",
    Task 3.2) - adapts the check logic behind Maester's `MT.1053`
    (`Test-MtManagedDeviceCleanupSettings`), against the `managedDeviceCleanupSettings`
    singleton GraphKit actually exposes rather than Maester's own
    `managedDeviceCleanupRules` collection call - see
    `source/Private/Checks/Test-PulseDeviceCleanupRuleConfigured.ps1`'s own docstring for
    that divergence.
  - `source/Data/Checks/TP.INT.0008.psd1` ("Intune Multi Admin Approval policy
    configured", Task 3.2) - adapts the check logic behind Maester's `MT.1096`
    (`Test-MtOperationApprovalPolicies`).
  - `source/Data/Checks/TP.INT.0009.psd1` ("Windows diagnostic data processor
    configuration enabled", Task 3.2) - adapts the check logic behind Maester's `MT.1099`
    (`Test-MtWindowsDataProcessor`).
  - `source/Data/Checks/TP.INT.0011.psd1` ("Default branding profile customized",
    Task 3.2) - adapts the check logic behind Maester's `MT.1101`
    (`Test-MtTenantCustomization`).
  - `source/Data/Checks/TP.INT.0012.psd1` ("Windows Feature Update policy avoids
    end-of-support builds", Task 3.2) - adapts the check logic behind Maester's `MT.1102`
    (`Test-MtFeatureUpdatePolicy`), adapted for TenantPulse's own determinism model (a
    snapshot-time cutoff rather than live wall-clock `Get-Date`) - see
    `source/Private/Checks/Test-PulseFeatureUpdatePolicyAvoidsEos.ps1`'s own docstring.
  - `source/Data/Checks/TP.INT.0013.psd1` ("Intune RBAC groups protected via RMAU or
    role-assignable groups", Task 3.2) - adapts the check logic behind Maester's `MT.1103`
    (`Test-MtIntuneRbacGroupsProtected`).
  - `source/Data/Checks/TP.INT.0014.psd1` ("BitLocker full-disk encryption enforced via
    Endpoint Security policy", Task 3.2) - adapts the check logic behind Maester's
    `MT.1123` (`Test-MtBitLockerFullDiskEncryption`).
  - `source/Data/Checks/TP.INT.0015.psd1` ("LAPS configuration policy meets minimum
    security bar", Task 3.2) - adapts the check logic behind Maester's `MT.1177`
    (`Test-MtIntuneLAPSConfiguration`).
  - `source/Data/Checks/TP.INT.0016.psd1` ("Attack Surface Reduction 'Standard
    Protection' baseline rules configured", Task 3.4) - adapts the check logic behind
    Maester's `MT.1178`.
  - `source/Data/Checks/TP.INT.0017.psd1` ("App Control for Business policy enforcing
    (not audit-only)") - adapts the check logic behind Maester's `MT.1179`
    (`Test-MtIntuneAppControl`), keyed against the live
    `applicationcontrolv2` settingDefinitionIds (Maester's own
    `...applicationcontrolv2_policy` / `*upload_policy_selected` strings do not
    exist in the in-repo live capture).
  - `source/Data/Checks/TP.INT.0018.psd1` ("Managed Installer rules paired with an
    enforcing App Control policy") - adapts the check logic behind Maester's
    `MT.1180` (`Test-MtIntuneManagedInstallerRules`).
  - `source/Data/Checks/TP.INT.0019.psd1` ("Apple MDM Push (APNs) certificate valid for
    more than 30 days", Task 3.3) - adapts the check logic behind Maester's `MT.1092`
    (`Test-MtApplePushNotificationCertificate`).
  - `source/Data/Checks/TP.INT.0020.psd1` ("Apple Automated Device Enrollment tokens valid
    and syncing", Task 3.3) - adapts the check logic behind Maester's `MT.1093`
    (`Test-MtAppleAutomatedDeviceEnrollmentToken`).
  - `source/Data/Checks/TP.INT.0021.psd1` ("Apple Volume Purchase Program tokens valid and
    syncing", Task 3.3) - adapts the check logic behind Maester's `MT.1094`
    (`Test-MtAppleVolumePurchaseProgramToken`).
  - `source/Data/Checks/TP.INT.0022.psd1` ("Android Enterprise connection bound, validated,
    and syncing", Task 3.3) - adapts the check logic behind Maester's `MT.1095`
    (`Test-MtAndroidEnterpriseConnection`).
  - `source/Data/Checks/TP.INT.0023.psd1` ("Intune Certificate Connectors healthy and on a
    supported version", Task 3.3) - adapts the check logic behind Maester's `MT.1097`
    (`Test-MtCertificateConnectors`).
  - `source/Data/Checks/TP.INT.0024.psd1` ("Mobile Threat Defense connectors enabled and
    syncing", Task 3.3) - adapts the check logic behind Maester's `MT.1098`
    (`Test-MtMobileThreatDefenseConnectors`).

  Each descriptor's own `Origin` field (`Project`/`Id`/`License`) records this at the point
  of adaptation - `Get-PulseCheckCatalog` and every findings document surface it as
  provenance on the check itself, not only here.

### EIDSCA

- **Project:** [EIDSCA](https://maester.dev/docs/tests/eidsca/) (Entra ID Security Config
  Analyzer, part of the [Maester](https://github.com/maester365/maester) project - the
  same upstream project as the Maester adaptations above, distributed under the same MIT
  license)
- **License:** MIT
- **Ported into (Phase 4, Tasks 4.2-4.3):** each check below adapts the check logic behind
  the named EIDSCA control ID(s), recorded verbatim in the check descriptor's own `Origin`
  field:
  - `source/Data/Checks/TP.ENT.0006.psd1` - EIDSCA AF01-AF06 (FIDO2 security key method)
  - `source/Data/Checks/TP.ENT.0007.psd1` - EIDSCA AG01-AG03 (authentication methods policy general settings)
  - `source/Data/Checks/TP.ENT.0008.psd1` - EIDSCA AM01-AM04, AM06, AM07, AM09, AM10 (Microsoft Authenticator method)
  - `source/Data/Checks/TP.ENT.0009.psd1` - EIDSCA AS04 (SMS sign-in method disabled)
  - `source/Data/Checks/TP.ENT.0010.psd1` - EIDSCA AT01-AT02 (Temporary Access Pass)
  - `source/Data/Checks/TP.ENT.0011.psd1` - EIDSCA AV01 (Voice call method disabled)
  - `source/Data/Checks/TP.ENT.0012.psd1` - EIDSCA AP01, AP04-AP10, AP14 (authorization policy defaults)
  - `source/Data/Checks/TP.ENT.0013.psd1` - EIDSCA CP01, CP03, CP04 (owner/risk-based consent restrictions)
  - `source/Data/Checks/TP.ENT.0015.psd1` - EIDSCA PR01, PR02, PR03, PR05, PR06 (Password Protection/Smart Lockout)
  - `source/Data/Checks/TP.ENT.0016.psd1` - EIDSCA ST08-ST09 (guest group ownership/content access)

  Same provenance-surfacing contract as the Maester entries above: each descriptor's own
  `Origin` field is what `Get-PulseCheckCatalog` and every findings document expose - this
  file is a discoverable summary of that, not the sole record of it. EIDSCA's own copyright
  notice and license terms are the same MIT text reproduced immediately below, since EIDSCA
  ships as part of the Maester repository.

Maester's (and, by the same repository, EIDSCA's) MIT license and copyright notice:

```
MIT License

Copyright (c) 2024 Maester Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Runtime dependencies

| Component | License | Notes |
|-----------|---------|-------|
| [GraphKit](https://github.com/AdamGell/GraphKit) | See GraphKit's own repository | The sole Graph-access layer TenantPulse calls through. `source/TenantPulse.psd1` requires exact GraphKit `0.2.2`; `RequiredModules.psd1` separately pins `0.2.2` for build restore. GraphKit is not vendored and resolves from PSGallery. |

## Build/test-only dependencies

Build and test tooling (Sampler, InvokeBuild, ModuleBuilder, Pester, PSScriptAnalyzer,
ChangelogManagement) is resolved via `RequiredModules.psd1` and is not distributed as
part of the built module. See each project's own repository for license terms.

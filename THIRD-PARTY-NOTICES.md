# Third-Party Notices

TenantPulse depends on third-party software, and two of its Phase 1 checks adapt logic from
a third-party project. This file lists both and their licenses (post-review fix: an earlier
draft of this file claimed "no third-party content has been ported into this repository
yet", which contradicted TP.INT.0001 and TP.INT.0003 - both of which carry a
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

  Each descriptor's own `Origin` field (`Project`/`Id`/`License`) records this at the point
  of adaptation - `Get-PulseCheckCatalog` and every findings document surface it as
  provenance on the check itself, not only here.

Maester's MIT license and copyright notice:

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
| [GraphKit](https://github.com/AdamGell/GraphKit) | See GraphKit's own repository | The sole Graph-access layer TenantPulse calls through; declared in `source/TenantPulse.psd1` and pinned in `RequiredModules.psd1`. Not vendored - resolved from PSGallery at install time. |

## Build/test-only dependencies

Build and test tooling (Sampler, InvokeBuild, ModuleBuilder, Pester, PSScriptAnalyzer,
ChangelogManagement) is resolved via `RequiredModules.psd1` and is not distributed as
part of the built module. See each project's own repository for license terms.

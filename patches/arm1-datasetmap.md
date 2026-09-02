# ARM1 DatasetMap proposal

Do not apply this entry to `source/Data/DatasetMap.psd1` until the ARM provider live contract is proven. This file is the proposed shape only.

## Why this stays out of DatasetMap

`DatasetMap.psd1` is the Graph catalog pivot. Every released key is a `{Type, Operation, ApiVersion}` tuple resolved through GraphKit `Get-GraphOperation` and the static read-only gate. ARM diagnostic settings are not a Microsoft Graph operation. Putting them in that map would force a fake Graph descriptor or a Pending walk that the read-only gate would treat as Graph.

`TP.INT.0010` stays unshipped. There is no `source/Data/Checks/TP.INT.0010.psd1`.

## Proposed entry (not applied)

When a protected read-only diagnostic-settings proof exists, add a sibling ARM map rather than a Graph map key. Suggested shape:

```powershell
intuneDiagnosticSettings = @{
    Provider          = 'ARM'
    Cloud             = 'Global'
    Authority         = 'https://management.azure.com'
    Audience          = 'https://management.azure.com/.default'
    ResourceId        = '/providers/microsoft.intune'
    ChildProvider     = 'microsoft.insights'
    ChildType         = 'diagnosticSettings'
    Method            = 'GET'
    ApiVersion        = $null   # fill only after live proof; do not guess
    ApiVersionStatus  = 'Unproven'
    ReplayPolicy      = 'Safe'
    ThrottleClass     = 'Read'
    RbacActions       = @('Microsoft.Insights/diagnosticSettings/read')
    Disposition       = 'DeferredUntilLiveContract'
    MissingDependency = 'GraphKit.Auth'
    CheckId           = 'TP.INT.0010'
}
```

## Rules for any later apply

- Do not add `Type` or `Operation` Graph catalog fields.
- Do not send this entry through `Get-GraphOperation` or `Assert-PulseReadOnlyDescriptor`.
- Keep `Write-PulseDataset` Graph `v1.0`/`beta` validation off this path; ARM versions are dated.
- If the static read-only gate grows an ARM walker, assert Azure RBAC and ARM authority, not Graph permissions.
- Add the `TP.INT.0010` check descriptor only after the provider result and permission model are proven.

## Recheck trigger

Re-evaluate after `GraphKit.Auth` exists and a protected read-only diagnostic-settings read succeeds. Until then the adapter records `Skipped` / `DependencyUnavailable` / `arm-live-contract-deferred`.

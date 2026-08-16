# Check descriptors

This directory holds the check descriptor `.psd1` files that `Import-PulseCheckCatalog`
loads and validates at the start of every assessment run. It is empty except for
`.gitkeep` until Task 1.9 adds the ten seed checks - `Import-PulseCheckCatalog` treats an
empty (or missing) directory as a valid, empty catalog rather than an error.

## Schema

Every descriptor is a `.psd1` file containing a single hashtable with PascalCase keys,
matching this schema exactly:

```powershell
@{
  Id           = 'TP.ENT.0001'         # ^TP\.(INT|ENT)\.\d{4}$
  Title        = '...'
  Category     = 'Entra.ConditionalAccess'   # dotted area path
  Severity     = 'High'                # Critical|High|Medium|Low|Info
  Effort       = 'Low'                 # Low|Medium|High  (consulting axis, not scored)
  Impact       = 'High'                # Low|Medium|High  (consulting axis, not scored)
  Data         = @{ Datasets = @('conditionalAccessPolicies'); Gates = @('EntraP1') }
  Rule         = @{ Type = 'Function'; Function = 'Test-PulseLegacyAuthBlocked' }
                 # or Type='Expression'; Expression='<scriptblock text over $Datasets>'
  Consulting   = @{ WhatItMeans='...'; WhyItMatters='...'; Remediation=@('step...');
                    PortalLinks=@('https://entra.microsoft.com/...') }
  References   = @{ Research='docs/research/iha-v2/<file>#<anchor>'
                    Authorities=@('https://learn.microsoft.com/...','MS.AAD.1.1v1') }
  Origin       = $null                 # or @{ Project='Maester'; Id='MT.1105'; License='MIT' }
}
```

## Loading and validation

`Import-PulseCheckCatalog [-Path <dir>] [-DatasetMapPath <file>]` reads every `*.psd1`
file directly under `-Path` (default: this directory) with `Import-PowerShellDataFile`
(safe - no code execution) and returns a sorted-by-`Id` array of validated descriptor
objects with `PSTypeName 'TenantPulse.CheckDescriptor'`.

An empty or missing catalog directory returns an empty array - it is not an error.

A catalog with one or more invalid descriptors throws a single aggregated error: one line
per problem, across every descriptor in the directory (not just the first bad file), each
naming the offending descriptor's `Id` (or its filename, when `Id` itself is
missing/malformed) and the offending property. Validation failures include:

- duplicate `Id` across the catalog
- `Id`, `Severity`, `Effort`, or `Impact` not matching their allowed pattern/values
- `Rule.Type` not `Function` or `Expression`
- `Rule.Function` naming a command that does not resolve (via `Get-Command`) at import
  time - this is treated as a module-authoring bug and hard-fails catalog import; a
  runtime throw from a *resolvable* function is a different, later concern (the
  evaluator's per-check `Error` status, Task 1.6)
- empty `Data.Datasets`
- a dataset name in `Data.Datasets` not present in the shared dataset map (see below)
- missing/empty `References.Research`, or empty `References.Authorities`
- any missing `Consulting` field (`WhatItMeans`, `WhyItMatters`, `Remediation`,
  `PortalLinks`)

### Dataset map cross-check (Task 1.5 handshake)

`-DatasetMapPath` defaults to `source/Data/DatasetMap.psd1`, the shared map of dataset
names TenantPulse knows how to collect, added by Task 1.5. Until that file exists, the
`Data.Datasets` membership cross-check above is skipped (with a `Write-Verbose` note) -
descriptors are not rejected for referencing datasets the map does not know about yet.
Once Task 1.5 lands `DatasetMap.psd1`, every dataset name referenced by a descriptor's
`Data.Datasets` must be a top-level key in that map, or catalog import fails.

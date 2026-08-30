# Check descriptors

This directory holds the check descriptor `.psd1` files that `Import-PulseCheckCatalog`
loads and validates at the start of every assessment run. The shipped catalog contains 53
descriptors: 30 `TP.INT` checks and 23 `TP.ENT` checks, one file per check. A caller-supplied
empty (or missing) catalog directory remains valid and returns an empty catalog rather than an
error.

## Schema

Every descriptor is a `.psd1` file containing a single hashtable with PascalCase keys,
matching this schema exactly:

```powershell
@{
  Id           = 'TP.INT.0014'         # ^TP\.(INT|ENT)\.\d{4}$
  Title        = 'BitLocker full-disk encryption enforced via Endpoint Security policy'
  Category     = 'Intune.EndpointSecurity'   # dotted area path
  Severity     = 'Critical'            # Critical|High|Medium|Low|Info
  Effort       = 'Medium'               # Low|Medium|High  (consulting axis, not scored)
  Impact       = 'High'                # Low|Medium|High  (consulting axis, not scored)
  Data         = @{
                   Datasets        = @('endpointSecurityDiskEncryptionPolicies')
                   Expansions      = @() # optional; may replace Datasets for artifact-only checks
                   PartialDatasets = @('endpointSecurityDiskEncryptionPolicies') # optional Function opt-in
                   Gates           = @('Intune')
                 }
  Rule         = @{ Type = 'Function'; Function = 'Test-PulseBitLockerFullDiskEncryption' }
                 # or Type='Expression'; Expression='<scriptblock text over $Datasets>'
  Consulting   = @{ WhatItMeans='...'; WhyItMatters='...'; Remediation=@('step...');
                    PortalLinks=@('https://intune.microsoft.com/...') }
  References   = @{ Research='docs/research/iha-v2/<file>#<anchor>'
                    Authorities=@('https://learn.microsoft.com/...','MS.AAD.1.1v1')
                    Cis=@('CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 5.2.2.1 (E3 Level 1)') }
                 # Cis is OPTIONAL - omit the key entirely unless you have verified a real
                 # CIS Benchmark mapping for this check (see docs/licensing/cis-cite-only.md).
                 # ID-ONLY, always: "<benchmark name> v<version>, Rec. <id> (<profile level>)"
                 # and nothing else - never a recommendation's TITLE (titles ARE CIS's own
                 # copyrighted expression, exactly like its Description/Rationale/Audit/
                 # Remediation text) and never a claim that this check's result equals or
                 # implies CIS Benchmark compliance.
  Origin       = $null                 # or @{ Project='Maester'; Id='MT.1105'; License='MIT' }
}
```

## Loading and validation

`Import-PulseCheckCatalog [-Path <dir>] [-DatasetMapPath <file>]` reads every `*.psd1`
file directly under `-Path` (default: this directory) with `Import-PowerShellDataFile`
(safe - no code execution) and returns a sorted-by-`Id` array of validated descriptor
objects with `PSTypeName 'TenantPulse.CheckDescriptor'`.

An empty or missing catalog directory returns an empty array - it is not an error. A file
literally named `DatasetMap.psd1` inside this directory is excluded from descriptor
scanning (it is the shared dataset map, not a check - see below), not treated as an
invalid descriptor.

Ordering is ordinal, not culture-aware: `Id`s are sorted with `[string]::CompareOrdinal`
(the same index-sort approach `ConvertTo-PulseCanonicalJson` uses for JSON object keys),
so catalog order is identical regardless of the host's locale.

A catalog with one or more invalid descriptors throws a single aggregated error: one line
per problem, across every descriptor in the directory (not just the first bad file, and
not stopping at the first problem within a descriptor either). Every line is prefixed
with the **source filename** - the one unambiguous identifier, since two files can share
the same (possibly malformed) `Id` - followed by the descriptor's `Id`-or-filename label
and the offending property: `<filename>: <Id-or-filename>: <property>: <problem>`.
Validation failures include:

- duplicate `Id` across the catalog
- a field holding the wrong *type* - every field is explicitly type-checked before any
  pattern/enum/emptiness rule runs on it, so e.g. `Id = @('TP.ENT.0001')` (an array where
  a scalar string is required) is reported as `must be a string, got Object[].` rather
  than silently coercing through a pattern match and landing array-typed in the loaded
  descriptor. Scalar `[string]` is required for `Id`, `Title`, `Category`, `Severity`,
  `Effort`, `Impact`, `Rule.Type`, `Rule.Function`, `Rule.Expression`, and
  `References.Research`. A required, non-empty `[string[]]` (no blank elements) is
  required for `References.Authorities`, `Consulting.Remediation`, and
  `Consulting.PortalLinks`. `Data.Datasets` and `Data.Expansions` are individually
  optional arrays, but they may not both be absent or empty: an expansion-only check is
  valid and does not invent an unused dataset dependency. `Data.Gates` must also be a
  `[string[]]`, but may be empty.
- `Id`, `Severity`, `Effort`, or `Impact` not matching their allowed pattern/values
- `Rule.Type` not `Function` or `Expression`
- `Rule.Function` not resolving to exactly one ordinal-exact PowerShell Function at
  import time. Wildcard names, ambiguous matches, aliases, cmdlets, and native
  applications are not Function rules and are rejected as aggregated catalog errors. A
  runtime throw from one resolvable Function is a different, later concern (the
  evaluator's per-check `Error` status, Task 1.6).
- both `Data.Datasets` and `Data.Expansions` absent/empty, or empty
  `References.Authorities`
- a dataset name in `Data.Datasets` not present in the shared dataset map (see below)
- `Data.PartialDatasets`, when present, not being a non-empty `[string[]]` of unique
  canonical dataset names, containing a member outside `Data.Datasets`, being attached
  to an Expression rule, or naming a Function that has no `DatasetOutcomes` parameter
- missing/empty `References.Research`
- `References.Cis`, if the key is present at all (it is OPTIONAL and most checks omit it
  entirely), not being a non-empty `[string[]]` (no blank elements) - same "wrong type" and
  "empty array" rules as `References.Authorities`, just not required in the first place
- any missing `Consulting` field (`WhatItMeans`, `WhyItMatters`, `Remediation`,
  `PortalLinks`)
- the descriptor file itself failing to parse as a PowerShell data file

### Dataset map cross-check (Task 1.5 handshake)

`-DatasetMapPath` defaults to `source/Data/DatasetMap.psd1`, the shared map of dataset
names TenantPulse knows how to collect, added by Task 1.5. That file is parsed **exactly
once per catalog load** (not once per descriptor) and validated to be a hashtable. Until
the file exists, the `Data.Datasets` membership cross-check above is skipped (with a
`Write-Verbose` note) - legacy descriptors without `PartialDatasets` are not rejected for
referencing datasets the map does not know about yet. Partial awareness depends on
canonical dataset identity, so a descriptor containing `PartialDatasets` fails closed
when the map is missing or unavailable. Once Task 1.5 lands `DatasetMap.psd1`, every
dataset name referenced by a descriptor's `Data.Datasets` must be a top-level key in that
map, or catalog import fails. A present-but-malformed map file (parse failure, or a root
value that isn't a hashtable) is reported through the same aggregated-errors mechanism
as any other catalog problem, not as a raw, unrelated error.

### Partial-aware Function checks

`Data.PartialDatasets` is optional and changes evaluation only. It does not add a dataset
to `Data.Datasets`, the shared dataset map, the collection manifest, or collection
dependency ordering. Every member must already appear in `Data.Datasets`, must use the
exact canonical casing from both that array and `DatasetMap.psd1`, and must be unique
under `OrdinalIgnoreCase`. The field is legal only for a resolvable Function rule whose
command metadata declares a `DatasetOutcomes` parameter.

Opting in means the Function has been reviewed for a monotonic decision that remains
sound despite unresolved gaps:

- A universal check may **Fail** when a known row proves an offender, but it cannot Pass
  while gaps remain.
- An existential check may **Pass** when a known row proves a witness, but it cannot Fail
  while gaps remain.

If the usable rows do not prove that one safe direction, the check remains fail-closed;
the presence of `PartialDatasets` is never permission to treat incomplete scope as a
complete assessment.

The built-in catalog has exactly four partial-aware descriptors:

- `TP.INT.0013` / `intuneRbacGroupProtection` is universal: a known unprotected group may
  prove Fail; it cannot prove Pass with gaps.
- `TP.INT.0014` / `endpointSecurityDiskEncryptionPolicies` is existential: a known policy
  whose `isFullDiskEncryption` value is a native `[bool]` `$true` may prove Pass; it cannot
  prove Fail with gaps.
- `TP.INT.0015` / `endpointSecurityLapsPolicies` is existential: one known policy whose four
  criteria are native `[bool]` `$true` values may prove Pass; it cannot prove Fail with gaps.
- `TP.INT.0029` / `securityBaselinesAssignedAndCurrent` is universal: a known unassigned or
  obsolete baseline may prove Fail; it cannot prove Pass with gaps.

The other 49 checks remain `NotApplicable` when a required dataset is `Partial`. For these four
opt-ins, a structurally valid Partial dataset with no decisive proof is also `NotApplicable`.
Zero usable rows, invalid gaps/outcomes, or a malformed known row without decisive monotonic proof
is `Error`; a decisive witness/offender remains authoritative even when an unrelated row is
malformed, regardless of row order.

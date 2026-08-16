# TenantPulse

TenantPulse is a read-only PowerShell module that assesses a Microsoft Intune/Entra
tenant's health against a versioned set of checks, and produces a deterministic,
pseudonymized, scored findings report. It never writes to a tenant: every Graph read goes
through [GraphKit](https://github.com/AdamGell/GraphKit)'s read-class descriptors
(`ThrottleClass 'Read'`, `ReplayPolicy 'Safe'`) - TenantPulse never calls `Connect-MgGraph`,
never uses the Microsoft Graph PowerShell SDK, and never constructs a Graph URI of its own.

## Quick start

```powershell
# 1. Install TenantPulse (and its GraphKit dependency) from PSGallery
Install-PSResource -Name TenantPulse -Repository PSGallery

# 2. Register a GraphKit profile for the tenant you want to assess (one-time, per tenant)
#    - see GraphKit's own documentation for profile registration (app registration /
#      certificate or client secret setup). TenantPulse never touches credentials itself;
#      it only resolves an already-registered profile by name.
Register-GraphProfile -ProfileId 'contoso' -TenantId '<tenant-id>' -ClientId '<app-id>' ...

# 3. Run a full assessment
Invoke-PulseAssessment -ProfileId 'contoso' -OutputPath './out'
```

This collects a snapshot, evaluates every check in the catalog, scores the result, and
writes a canonical-JSON findings report to `./out/tenantpulse-findings.json` - along with the
raw snapshot store under `./out/snapshot/` (see **Where files are written**, below, before
you decide where `-OutputPath` should point).

## The five public commands

| Command | What it does |
|---|---|
| `Get-PulseTenantSnapshot` | Collects a read-only, pseudonymized snapshot of tenant data through GraphKit and writes it to a snapshot store on disk. The only command that ever talks to Graph. |
| `Get-PulseCheckCatalog` | Lists every check descriptor in the catalog (id, title, category, severity, authorities) as a lightweight, read-only view - useful for discovering what `-IncludeCategory`/`-IncludeCheck` values exist before running an assessment. |
| `Invoke-PulseAssessment` | The end-to-end entry point: collect (or reuse `-FromSnapshot`), evaluate every check, score, and render a findings report. Supports `-Redact` to pseudonymize evidence identities in the rendered report. |
| `Invoke-PulseCheck` | Runs a scoped subset of checks (by id or category) against a fresh or existing snapshot - the same pipeline as `Invoke-PulseAssessment`, narrowed to exactly the checks you name. |
| `Export-PulseReport` | Re-renders an already-scored findings JSON file, unchanged, to a new location. Render-only - no re-evaluation, no re-scoring, and (deliberately) no `-Redact`: see its own help for why. |

Run `Get-Help <command> -Full` for the complete parameter and example reference on any of
these; every one of them ships detailed comment-based help.

## Required Graph permissions

TenantPulse reads whichever datasets the checks you run declare - the checks shipped in
Phase 1 read Conditional Access policies, Intune device/compliance/configuration data,
authentication methods policy, Autopilot devices, domains, and (once released) security
defaults, directory role assignments, and Entra device data. Every one of those reads is a
**read-only, application-permission Graph call** resolved through GraphKit's own descriptor
catalog - TenantPulse does not declare its own separate permission list, it inherits
whichever `Microsoft Graph` application permissions the GraphKit profile's app registration
was granted, applied at the API's own least-privilege read scope for each resource (for
example `Policy.Read.All` for Conditional Access and authentication methods policy,
`DeviceManagementConfiguration.Read.All` / `DeviceManagementManagedDevices.Read.All` /
`DeviceManagementApps.Read.All` for the Intune datasets, `Directory.Read.All` /
`RoleManagement.Read.Directory` for directory role data, `Domain.Read.All` for domains).

A missing permission is never a hard failure: the collector attempts every dataset
independently and classifies a `403` as `Skipped` with reason
`permission-denied: <the exact permissions that operation needs>` - read straight out of
GraphKit's own descriptor, so you always get the precise, current scope name to grant next,
rather than a guess baked into this README going stale. Every check that needed a Skipped
dataset degrades honestly to `NotApplicable`, never a silently-wrong Pass or Fail.

## Snapshot data is sensitive at rest

A snapshot store (`Get-PulseTenantSnapshot`'s output, or the `snapshot/` subdirectory
`Invoke-PulseAssessment` writes alongside its findings report) contains **raw, unredacted
tenant data** - device names, policy definitions, configuration values, and more, exactly as
Graph returned them. The manifest's `tenant` field and every collection-failure reason are
pseudonymized (an HMAC of the tenant id under a local operator key - see
`about_TenantPulse` for the full pseudonymization contract), but the *dataset contents
themselves are not*. Treat a snapshot directory the same way you would treat a Graph API
export: store it somewhere access-controlled, do not commit it to source control, and clean
it up when you are done with it.

**Where files are written:** every command that writes output takes an explicit
`-OutputPath` (or, for `Get-PulseTenantSnapshot`, a required output directory) - TenantPulse
never picks a location on your behalf or writes outside that directory. A full
`Invoke-PulseAssessment -OutputPath './out'` run writes:

- `./out/snapshot/` - the raw snapshot store (manifest + collected datasets; see the
  sensitivity note above)
- `./out/tenantpulse-findings.json` - the scored, canonical-JSON findings report (evidence
  identities are pseudonymized only if you passed `-Redact`)

The operator key used for pseudonymization lives at `~/.tenantpulse/operator.key` by
default (overridable) - back it up if you need pseudonyms to stay stable across machines,
and protect it the same way you would protect any key material: the same key that produced
a pseudonym is required to reproduce it.

## CIS compliance disclaimer

TenantPulse's checks are informed by Microsoft's own official guidance and, for two checks
(`TP.INT.0001`, `TP.INT.0003`), adapted logic from the open-source
[Maester](https://github.com/maester365/maester) project (MIT-licensed - see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)). **TenantPulse does not claim, imply, or
certify CIS Benchmark compliance, alignment, or coverage of any kind**, for Intune, Entra,
or any other product. No check in this module's Phase 1 catalog is mapped to, scored
against, or claims correspondence with any CIS Benchmark control. If you need a CIS
Benchmark assessment, use a tool that specifically implements and maintains that mapping;
TenantPulse's findings should not be represented as one.

## Operator prerequisites

- PowerShell 7.4 or later
- [GraphKit](https://github.com/AdamGell/GraphKit) 0.1.1 or later, installed from PSGallery
  (TenantPulse declares this as a runtime dependency in its module manifest, so
  `Install-PSResource -Name TenantPulse` pulls it automatically)
- A GraphKit profile already registered for the tenant you want to assess (see GraphKit's
  own documentation - profile registration, credential setup, and Graph app-registration
  concerns are entirely GraphKit's responsibility, not TenantPulse's)
- The app registration behind that profile granted the read-only Graph application
  permissions the checks you intend to run actually need (see **Required Graph
  permissions** above) - most commonly `Policy.Read.All` for the Conditional-Access-backed
  checks (`TP.ENT.0003`-`0005`), plus whichever Intune/device permissions the datasets you
  collect require
- PSGallery access (or an internal mirror) to install TenantPulse and GraphKit

Of the three operator gates Phase 1 originally identified, two are now closed: GraphKit
0.1.1 is published to PSGallery (all ten seed checks' descriptors are live, none Pending),
and `Policy.Read.All` has been granted on the Ivy24 lab app registration (Conditional-Access
-backed checks assess for real). Only TenantPulse's own first publish to PSGallery remains
- see `docs/STATUS.md` for the current live-gate results and that gate's status.

## Phase 1 scope - what this is and isn't, honestly

TenantPulse's Phase 1 catalog ships **ten checks** across Entra Conditional Access
(`TP.ENT.0001`-`0005`) and Intune device management (`TP.INT.0001`-`0005`) - a deliberately
small, verified-against-a-real-tenant starting set, not a comprehensive tenant-health
product. What Phase 1 delivers:

- A deterministic, byte-reproducible evaluation engine: re-evaluating the same snapshot
  with the same catalog always produces the same findings document.
- Honest degradation everywhere a signal is missing - a permission gap, a not-yet-released
  GraphKit descriptor, or a malformed manifest field degrades the affected check to
  `NotApplicable` or `Error`, never a confident, silently-wrong verdict.
- Pseudonymization of the tenant identifier and (with `-Redact`) evidence identities -
  never full de-identification of a report; see `-Redact`'s own help for the honestly
  documented residual (rule-authored evidence `Detail` fields and free-text reason strings
  are not redacted).

What Phase 1 does **not** cover: group- or role-based Conditional Access exclusion
resolution (several checks are explicitly documented as fail-closed or limited on this
axis), assignment verification for Intune policies (existence is checked, not whether a
policy is actually assigned to any device), a CIS Benchmark mapping (see the disclaimer
above), or a rendering format other than JSON. These are documented, known limitations in
each affected check's own docstring - not silent gaps.

## Development

Dependencies and build tools are restored through the repository scripts. Run the test
suite through the build entry point rather than invoking Pester directly:

```powershell
./build.ps1 -ResolveDependency -Tasks noop
./build.ps1 -Tasks build
./build.ps1 -Tasks test
./build.ps1 -Tasks pack
```

The `pack` task produces the package from the tested build output. Generated artifacts are
written under `output/` and should not be edited directly. `./build.ps1 -Tasks test` also
enforces a whole-result `MinimumTests` gate (via `tests/QA/Assert-GateResult.ps1`) locally,
the same one CI enforces, and records a per-shipped-file SHA-256 digest manifest that
`scripts/Publish-TenantPulsePackage.ps1` later verifies the packaged `.nupkg` against.

`scripts/Publish-TenantPulsePackage.ps1` publishes an already-packed `.nupkg` to PSGallery.
It never builds and enforces pack-first-then-verify: it compares every shipped file inside
the package against the digest manifest recorded at test time, and refuses to publish on
any mismatch (packaging bytes nothing tested is exactly the failure this exists to
prevent). It defaults to a dry run - it prints what it would publish and does not call
PSGallery - and only publishes for real when given a resolved API key (via
`-NuGetApiKeySecure` or the `TENANTPULSE_NUGET_API_KEY` environment variable - there is no
plain-string API key parameter) and `-Confirm`.

GraphKit is declared as a runtime dependency in the module manifest
(`source/TenantPulse.psd1`) and pinned to the same version in `RequiredModules.psd1` (the
Sampler build-dependency file), so `./build.ps1 -ResolveDependency` resolves it from
PSGallery like every other build dependency - no manual `$env:PSModulePath` setup needed.

Unit tests never import real GraphKit: every GraphKit command TenantPulse calls
(`Get-GraphContext`, `Get-GraphObject`, `Invoke-GraphOperation`, `Get-GraphOperation`) is
stubbed inside the TenantPulse module scope in each test file's `BeforeAll`, with a default
mock that throws registered before any test-specific mock (GraphKit's own test
convention). GraphKit is still importable in the test environment (it is a
`RequiredModules` dependency of TenantPulse itself), but the module-scope stubs shadow it
for every call TenantPulse's own code makes - that shadowing, not the absence of GraphKit,
is what keeps the tests deterministic and independent of a live tenant.

## Project layout

- `source/` - module source (Sampler/ModuleBuilder layout)
- `source/Data/` - check descriptors and other non-code data assets
- `source/en-US/` - comment-based help and the `about_TenantPulse` conceptual help topic
- `tests/QA/` - module quality gates (manifest validity, clean-process import, secret scan,
  changelog format, whole-result test-count ratchet)
- `scripts/` - standalone operational scripts (PSGallery publish tooling)
- `docs/STATUS.md` - internal development status/task narrative (not needed to use the
  module - see that file only if you want the implementation history)

## License

MIT. See [LICENSE](LICENSE). Third-party attributions (Maester, MIT-licensed) are in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

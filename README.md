# TenantPulse

[![PSGallery Version](https://img.shields.io/powershellgallery/v/TenantPulse)](https://www.powershellgallery.com/packages/TenantPulse)
[![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/TenantPulse)](https://www.powershellgallery.com/packages/TenantPulse)
[![PowerShell 7.4+](https://img.shields.io/badge/PowerShell-7.4%2B-blue)](https://github.com/PowerShell/PowerShell)

> Read-only tenant health assessment for Microsoft Intune and Entra — a versioned check catalog, deterministic scoring, and pseudonymized findings reports, built on [GraphKit](https://github.com/AdamGell/GraphKit).

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

TenantPulse's checks are informed by Microsoft's own official guidance, CISA's SCuBA/ScubaGear
baselines, and (for the EIDSCA-ported and two Intune checks) adapted logic from the open-source
[Maester](https://github.com/maester365/maester) project (MIT-licensed - see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)). **TenantPulse does not claim, imply, or
certify CIS Benchmark compliance, alignment, or coverage of any kind**, for Intune, Entra,
or any other product.

As of Phase 4 (Task 4.5), the check-descriptor schema supports an *optional, cite-only*
`References.Cis` field - a bare "benchmark name + version, Rec. `<id>` (`<profile>`)" string,
never CIS recommendation text (title/description/rationale/audit/remediation), which would pull
this MIT-licensed catalog into CIS's incompatible CC BY-NC-SA license (see
`docs/research/iha-v2/2026-08-15-cis-benchmarks-licensing.md` for the full licensing analysis).
**No check in this module's 28-check catalog carries a `References.Cis` entry today** - the
Phase 4 research this catalog was authored from cites ScuBA/CISA, Maester/EIDSCA, and Microsoft
Learn exclusively, with zero verified CIS mappings. The wiring exists and is tested end to end
(a findings document's `notices.cisDisclaimer` field is `null` when no rendered finding carries a
CIS reference, and is populated with the disclaimer text below the moment even one does) so a
future task can add a verified mapping without a schema or renderer change - but today it fires
for nobody, because nobody qualifies. If you need a CIS Benchmark assessment, use a tool that
specifically implements and maintains that mapping; TenantPulse's findings should not be
represented as one.

When the disclaimer does fire, its text reads: *"CIS Benchmarks are (c) Center for Internet
Security, Inc. Recommendation references in this report are provided for cross-reference only.
This project is not affiliated with, endorsed by, or certified by CIS, and its results do not
constitute a claim of CIS Benchmark compliance."*

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

## Catalog scope - what this is and isn't, honestly

TenantPulse's catalog has grown across four phases to **28 checks**: Phase 1's ten-check seed
(Entra Conditional Access `TP.ENT.0001`-`0005`, Intune device management `TP.INT.0001`-`0005`),
Phase 3's Intune settings-catalog/typed-policy expansion work (feeding those same ten Intune/CA
checks richer data, not new check IDs), and Phase 4's Entra core catalog - the EIDSCA port
(`TP.ENT.0006`-`0011`), authorization/consent/password/guest-access clusters
(`TP.ENT.0012`/`0013`/`0015`/`0016`), and the ScuBA/CISA-cited Conditional Access, privileged-role,
and credential-hygiene checks (`TP.ENT.0017`-`0024`). Not a comprehensive tenant-health product -
a deliberately scoped, verified-against-a-real-tenant catalog.

| Id | Category | Severity | Dataset | Title |
|---|---|---|---|---|
| TP.ENT.0001 | Entra.Identity | High | Live | Security Defaults state is appropriate |
| TP.ENT.0002 | Entra.PrivilegedRoles | High | Live | Fewer than 5 Global Administrators |
| TP.ENT.0003 | Entra.ConditionalAccess | Critical | Live | Break-glass accounts exist and are excluded from Conditional Access |
| TP.ENT.0004 | Entra.ConditionalAccess | High | Live | Legacy authentication is blocked by an enforced Conditional Access policy |
| TP.ENT.0005 | Entra.ConditionalAccess | High | Live | MFA is required for admin roles by an enforced Conditional Access policy |
| TP.ENT.0006 | Entra.AuthenticationMethods | High | Live | FIDO2 security key authentication method is enabled with attestation and key restrictions enforced |
| TP.ENT.0007 | Entra.AuthenticationMethods | High | Live | Authentication methods policy general settings (migration state, suspicious-activity reporting) |
| TP.ENT.0008 | Entra.AuthenticationMethods | High | Live | Microsoft Authenticator is enabled with number matching and app-name display required tenant-wide |
| TP.ENT.0009 | Entra.AuthenticationMethods | High | Live | SMS is not usable as an authentication sign-in factor |
| TP.ENT.0010 | Entra.AuthenticationMethods | Medium | Live | Temporary Access Pass is enabled and configured for one-time use |
| TP.ENT.0011 | Entra.AuthenticationMethods | High | Live | Voice call is not enabled as an authentication method |
| TP.ENT.0012 | Entra.AuthorizationPolicy | High | Pending | Default authorization policy settings restrict SSPR-for-admins, guest self-service, and default app-registration rights |
| TP.ENT.0013 | Entra.Consent | High | Pending | Group/team owner and risk-based user consent restrictions |
| TP.ENT.0015 | Entra.PasswordProtection | High | Pending | Password Protection mode, on-prem enforcement, and Smart Lockout thresholds |
| TP.ENT.0016 | Entra.GuestAccess | Medium | Pending | Guest group ownership is restricted and guest group-content access is intact |
| TP.ENT.0017 | Entra.ConditionalAccess | Critical | Live | MFA is required for all users by an enforced Conditional Access policy |
| TP.ENT.0018 | Entra.ConditionalAccess | Critical | Live | Phishing-resistant authentication strength is required for privileged roles |
| TP.ENT.0019 | Entra.Identity | High | Live | Service principal credential hygiene (password/certificate lifetime) |
| TP.ENT.0020 | Entra.PrivilegedRoles | High | Live | Global Administrator count is within ScuBA's 2-8 SHALL range |
| TP.ENT.0021 | Entra.PrivilegedRoles | High | Live | Fewer than 10 total privileged role assignments |
| TP.ENT.0022 | Entra.PrivilegedRoles | High | Pending | Zero permanent-active assignments for privileged roles (PIM posture, Entra ID P2) |
| TP.ENT.0023 | Entra.Identity | Medium | Pending | Cross-tenant access default settings restrict inbound/outbound B2B collaboration |
| TP.ENT.0024 | Entra.ConditionalAccess | Info | Live | Conditional Access coverage for workload identities (awareness, non-scored) |
| TP.INT.0001 | Intune.Enrollment | Critical | Live | MDM authority is set to Intune |
| TP.INT.0002 | Intune.Compliance | High | Live | A compliance policy exists for every enrolled platform |
| TP.INT.0003 | Intune.Compliance | High | Live | Devices without an assigned compliance policy are marked noncompliant |
| TP.INT.0004 | Intune.Updates | Medium | Live | At least 2 Windows Update rings have deadlines configured |
| TP.INT.0005 | Intune.DeviceLifecycle | Medium | Live | Devices inactive for more than 90 days |

"Dataset: Pending" means the check's descriptor is written, tested (both PSObject- and
Hashtable-shaped fixtures), and cited, but degrades honestly to `NotApplicable` with reason
`descriptor-pending: awaiting GraphKit release` until a future GraphKit release ships the
underlying descriptor(s) it needs (`Entra.AuthorizationPolicy.Get`, `Entra.DirectorySettings.Values`,
`Entra.PIM.RoleAssignmentScheduleInstances/RoleEligibilityScheduleInstances.List`,
`Entra.CrossTenantAccessPolicy.Default.Get`) - never a silent gap, never a guessed result.
`TP.ENT.0022` additionally requires Entra ID P2 licensing once its descriptor lands; a 400/403 on
a non-P2 tenant is itself a rendered finding ("PIM posture unassessable - Entra ID P2 required"),
per its own research entry - not a collection failure hidden from the report.

What the catalog does **not** cover, honestly, as of Phase 4: group-**membership** expansion for
Conditional Access exclusions (only direct user/group/role references resolve today - a group
assigned to a CA exclusion is read as a group reference, not expanded to its members, because no
group-members dataset exists yet; several checks document this as a known limitation, not a
silent gap), assignment verification for Intune policies (existence is checked, not whether a
policy is actually assigned to any device), transitive/group-assigned role-assignment expansion
for `TP.ENT.0021`'s privileged-role count (direct assignments only - documented in that check's
own evidence text), `TP.ENT.0019`'s service-principal-only credential-hygiene note (application
objects and service principals are both read, but evidence is capped to the top 50 worst
offenders by design, not exhaustive), and a rendering format other than JSON.

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

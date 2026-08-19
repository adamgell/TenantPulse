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

## Sharing a findings artifact

`-Redact` pseudonymizes evidence *identities* only (the `evidence[].identity`/`sortKey`
values a finding is keyed on) - it does **not** touch `evidence[].detail`, where most of a
finding's real, free-text tenant data actually lives (device/policy display names, role
names, setting values, and similar). A `-Redact` render is safe to share with someone who
needs to see *which* checks passed or failed and roughly why, but is **not** on its own
safe to post somewhere public or hand to someone outside the tenant's own trust boundary -
`detail` can still carry real names.

For a findings JSON you actually intend to publish or share outside that boundary (e.g. a
committed `docs/gates/*.json` reference artifact), run it through
`scripts/Protect-PulseGateArtifact.ps1` first - an exhaustive scrub that replaces every
string leaf inside every finding's `evidence[].detail` with a stable pseudonym, no
per-field-name allowlist (see that script's own docstring for why a field-name allowlist is
exactly the failure mode it exists to avoid). That is the actual "safe to share" bar; a
`-Redact` render alone is not.

The raw **snapshot store** (`./out/snapshot/` - see **Snapshot data is sensitive at rest**
above) is local-only and never safe to share in any form - it is the raw, unredacted Graph
data itself, not a findings report. Neither `-Redact` nor `Protect-PulseGateArtifact.ps1`
touch it; there is no supported way to scrub a snapshot store for sharing, only to delete
it when you are done.

## CIS compliance disclaimer

TenantPulse's checks are informed by Microsoft's own official guidance, CISA's SCuBA/ScubaGear
baselines, and (for the EIDSCA-ported Entra checks and the 19 Maester-ported Intune checks)
adapted logic from the open-source
[Maester](https://github.com/maester365/maester) project (MIT-licensed - see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for the complete per-check attribution list,
which a QA gate keeps reconciled 1:1 with the check catalog's Origin declarations). **TenantPulse does not claim, imply, or
certify CIS Benchmark compliance, alignment, or coverage of any kind**, for Intune, Entra,
or any other product.

As of Phase 4 (Task 4.5), the check-descriptor schema supports an *optional, cite-only*
`References.Cis` field - a bare "benchmark name + version, Rec. `<id>` (`<profile>`)" string,
never a CIS recommendation's title or any of its description/rationale/audit/remediation text,
which would pull this MIT-licensed catalog into CIS's incompatible CC BY-NC-SA license (see
[docs/licensing/cis-cite-only.md](docs/licensing/cis-cite-only.md), this repo's own vendored
licensing summary, for the full rule and the reasoning behind it).
**No check in this module's 53-check catalog carries a `References.Cis` entry today** - the
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
- [GraphKit](https://github.com/AdamGell/GraphKit) 0.2.2 or later, installed from PSGallery
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
0.2.2 is published to PSGallery (TenantPulse 0.1.1 consumes it; the twelve GET/List
datasets that were Pending on GraphKit 0.1.1 are live), and `Policy.Read.All` has been
granted on the Ivy24 lab app registration (Conditional-Access-backed checks assess for
real). TenantPulse 0.1.0 is already published; this release is the 0.1.1 GraphKit 0.2.2
consume. See `docs/STATUS.md` for the current live-gate results.

## Catalog scope - what this is and isn't, honestly

TenantPulse's catalog has grown across four phases to **53 checks** (30 `TP.INT` + 23
`TP.ENT`; count source of truth: `source/Data/Checks/*.psd1`, one file per check, or
`(Import-PulseCheckCatalog).Count` against the built module). It did **not** stop at
Phase 1's ten-check seed plus Phase 4's Entra work, the way an earlier draft of this section
said: Phase 1 shipped the ten-check seed (Entra Conditional Access `TP.ENT.0001`-`0005`,
Intune device management `TP.INT.0001`-`0005`); Phase 3 then did two separate things, easy to
conflate but not the same - the settings-catalog/typed-policy expansion engine (feeding
richer data into checks that already existed, not new IDs) **and**, across Tasks 3.1-3.4, a
23-check Intune wave (`TP.INT.0006`-`0009`, `0011`-`0016`, `0019`-`0031` - `TP.INT.0010`
is DESCOPED until GraphKit ARM exists) that took `TP.INT` from 5 checks to 28, then
`TP.INT.0017`/`0018` (App Control enforce + Managed Installer pairing) shipped against
the live `applicationcontrolv2` schema and took `TP.INT` to 30; Phase
4 then added the 23-check Entra core catalog - the EIDSCA port (`TP.ENT.0006`-`0011`),
authorization/consent/password/guest-access clusters (`TP.ENT.0012`/`0013`/`0015`/`0016`), and
the ScuBA/CISA-cited Conditional Access, privileged-role, and credential-hygiene checks
(`TP.ENT.0017`-`0024`). Not a comprehensive tenant-health product - a deliberately scoped,
verified-against-a-real-tenant catalog.

"Live" below means the check's dataset(s) resolve against an already-released GraphKit
descriptor and assess for real against a live tenant today. "Pending" means the opposite -
degrades honestly to `NotApplicable` with reason `descriptor-pending: awaiting GraphKit
release` until a future GraphKit release ships the descriptor(s) it needs (source of truth:
the `Pending = $true` flag on each dataset entry in `source/Data/DatasetMap.psd1`) - never a
silent gap, never a guessed result. `TP.ENT.0022` additionally requires Entra ID P2 licensing
once collected; a 400/403 on a non-P2 tenant is itself a rendered finding ("PIM
posture unassessable - Entra ID P2 required"), per its own research entry - not a collection
failure hidden from the report.

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
| TP.ENT.0012 | Entra.AuthorizationPolicy | High | Live | Default authorization policy settings restrict SSPR-for-admins, guest self-service, and default app-registration rights |
| TP.ENT.0013 | Entra.Consent | High | Live | Group/team owner and risk-based user consent restrictions |
| TP.ENT.0015 | Entra.PasswordProtection | High | Live | Password Protection mode, on-prem enforcement, and Smart Lockout thresholds |
| TP.ENT.0016 | Entra.GuestAccess | Medium | Live | Guest group ownership is restricted and guest group-content access is intact |
| TP.ENT.0017 | Entra.ConditionalAccess | Critical | Live | MFA is required for all users by an enforced Conditional Access policy |
| TP.ENT.0018 | Entra.ConditionalAccess | Critical | Live | Phishing-resistant authentication strength is required for privileged roles |
| TP.ENT.0019 | Entra.Identity | High | Live | Service principal credential hygiene (password/certificate lifetime) |
| TP.ENT.0020 | Entra.PrivilegedRoles | High | Live | Global Administrator count is within ScuBA's 2-8 SHALL range |
| TP.ENT.0021 | Entra.PrivilegedRoles | High | Live | Fewer than 10 total privileged role assignments |
| TP.ENT.0022 | Entra.PrivilegedRoles | High | Live | Zero permanent-active assignments for privileged roles (PIM posture, Entra ID P2) |
| TP.ENT.0023 | Entra.Identity | Medium | Live | Cross-tenant access default settings restrict inbound/outbound B2B collaboration |
| TP.ENT.0024 | Entra.ConditionalAccess | Info | Live | Conditional Access coverage for workload identities (awareness, non-scored) |
| TP.INT.0001 | Intune.Enrollment | Critical | Live | MDM authority is set to Intune |
| TP.INT.0002 | Intune.Compliance | High | Live | A compliance policy exists for every enrolled platform |
| TP.INT.0003 | Intune.Compliance | High | Live | Devices without an assigned compliance policy are marked noncompliant |
| TP.INT.0004 | Intune.Updates | Medium | Live | At least 2 Windows Update rings have deadlines configured |
| TP.INT.0005 | Intune.DeviceLifecycle | Medium | Live | Devices inactive for more than 90 days |
| TP.INT.0006 | Intune.SettingsCatalog | Medium | Live | Conflicting security-setting values across policies |
| TP.INT.0007 | Intune.Governance | Low | Live | Intune device clean-up rule configured |
| TP.INT.0008 | Intune.Governance | Medium | Live | Intune Multi Admin Approval policy configured |
| TP.INT.0009 | Intune.Governance | Low | Pending | Windows diagnostic data processor configuration enabled |
| TP.INT.0011 | Intune.Governance | Low | Live | Default branding profile customized |
| TP.INT.0012 | Intune.Updates | High | Live | Windows Feature Update policy avoids end-of-support builds |
| TP.INT.0013 | Intune.Governance | High | Pending | Intune RBAC groups protected via RMAU or role-assignable groups |
| TP.INT.0014 | Intune.EndpointSecurity | Critical | Pending | BitLocker full-disk encryption enforced via Endpoint Security policy |
| TP.INT.0015 | Intune.EndpointSecurity | High | Pending | LAPS configuration policy meets minimum security bar |
| TP.INT.0016 | Intune.SettingsCatalog | High | Live | Attack Surface Reduction "Standard Protection" baseline rules configured |
| TP.INT.0017 | Intune.SettingsCatalog | High | Live | App Control for Business policy enforcing (not audit-only) |
| TP.INT.0018 | Intune.SettingsCatalog | High | Live | Managed Installer rules paired with an enforcing App Control policy |
| TP.INT.0019 | Intune.Connectors | Critical | Live | Apple MDM Push (APNs) certificate valid for more than 30 days |
| TP.INT.0020 | Intune.Connectors | High | Live | Apple Automated Device Enrollment tokens valid and syncing |
| TP.INT.0021 | Intune.Connectors | High | Live | Apple Volume Purchase Program tokens valid and syncing |
| TP.INT.0022 | Intune.Connectors | Critical | Live | Android Enterprise connection bound, validated, and syncing |
| TP.INT.0023 | Intune.Connectors | High | Live | Intune Certificate Connectors healthy and on a supported version |
| TP.INT.0024 | Intune.Connectors | High | Live | Mobile Threat Defense connectors enabled and syncing |
| TP.INT.0025 | Intune.Enrollment | Medium | Live | Personally-owned Windows device enrollment blocked |
| TP.INT.0026 | Intune.Enrollment | Medium | Live | Windows Autopilot deployment profile exists and is assigned |
| TP.INT.0027 | Intune.Enrollment | Low | Live | No orphaned Windows Autopilot device identities |
| TP.INT.0028 | Intune.Enrollment | Medium | Live | Enrollment Status Page configured with blocking failure behavior |
| TP.INT.0029 | Intune.SecurityBaselines | Medium | Pending | Security baselines assigned and not on a deprecated version |
| TP.INT.0030 | Intune.Compliance | Medium | Live | Fleet compliance rate below acceptable threshold |
| TP.INT.0031 | Intune.SettingsCatalog | Critical | Live | BitLocker CSP settings present and correct across all Settings Catalog policies |

Every `Pending` row above resolves against one of these not-yet-released GraphKit dataset
descriptors (`source/Data/DatasetMap.psd1`'s own `Pending = $true` entries are the source of
truth if this list ever drifts): `DataProcessorServiceForWindowsFeaturesOnboarding.Get`,
`IntuneRbacGroupProtectionWalk.Walk`, `EndpointSecurityDiskEncryptionPolicyWalk.Walk`,
`EndpointSecurityLapsPolicyWalk.Walk`, and `SecurityBaselineAssignedAndCurrentWalk.Walk`.
GraphKit 0.2.2 shipped official GET/List descriptors for the twelve datasets those five
do not cover; Walks were not invented for the remaining Types.

What the catalog does **not** cover, honestly, as of Phase 4: group-**membership** expansion for
Conditional Access exclusions (only direct user/group/role references resolve today - a group
assigned to a CA exclusion is read as a group reference, not expanded to its members, because no
group-members dataset exists yet; several checks document this as a known limitation, not a
silent gap), assignment verification for Intune policies (existence is checked, not whether a
policy is actually assigned to any device), transitive/group-assigned role-assignment expansion
for `TP.ENT.0021`'s privileged-role count (direct assignments only - documented in that check's
own evidence text), `TP.ENT.0019`'s scope (only `servicePrincipal` credentials are read - GraphKit
0.2.2 has no `Application` type yet, so app-**registration** client secrets/certificates are not
visible to this check at all until a future GraphKit release adds one; evidence is also capped to
the top 50 worst offenders by design, not exhaustive), and a rendering format other than JSON.

## Settings expansion (Phase 2)

`Get-PulseTenantSnapshot -ExpandSettings` (and `Invoke-PulseAssessment -ExpandSettings`,
which passes it straight through) decomposes every policy TenantPulse can currently
setting-expand into individual canonical setting rows, on top of the ordinary check-driven
collection Phase 1 already does:

- **Settings Catalog** (`configurationPolicies` + `ConfigurationPolicySetting.ListBeta`
  per policy) - the modern, definitionId-driven configuration model.
- **Compliance and legacy device configuration policies** (`deviceCompliancePolicies`,
  `deviceConfigurations`) - the older, polymorphic `@odata.type`-typed Graph resources,
  decomposed via a hand-maintained property map (`source/Data/TypedPolicyMaps.psd1`) rather
  than a Graph-side settings catalog, since none exists for these types.
- **Conflict detection** - a single pass over every row from the families above, grouping
  by `settingDefinitionId` to surface settings where two or more policies disagree, with a
  four-state assignment-overlap verdict (`proven`/`possible`/`none`/`unknown`).

Every artifact this produces is recorded in the snapshot manifest under
`manifest.expansions.<name>` and written to `expanded/<name>.<sha256>.jsonl` (or
`expanded/conflicts.<sha256>.json` for the conflicts document) - immutable,
content-addressed files, never a fixed name. See
`source/Private/Evaluate/FindingsSchema.md`'s own "Settings expansion artifacts" section
for the exact row/conflict-record schema.

**Known gap, by design, for this phase**: `ConfigurationPolicyAssignment.ListBeta` (the
descriptor that would resolve which devices/users a Settings Catalog policy is actually
assigned to) is not yet a released GraphKit descriptor as of this phase - every Settings
Catalog row carries `assignments: null`, and any conflict that involves at least one such
row reports `assignmentOverlap: 'unknown'` with an explicit `'assignments-deferred:
awaiting GraphKit release'` reason, rather than a silently wrong verdict. Compliance and
legacy device configuration policies do NOT have this gap (their assignment descriptors are
already released) - their rows carry real assignment data today. This is tracked as its own
follow-up slice ("Phase 2b" in the implementation plan), not a silent limitation.

**Scale note**: Settings Catalog expansion fans out one Graph read per policy, at the
measured rate documented in `docs/spike/` (mean ~300ms/policy on the Ivy24 lab tenant) -
budget your own run's wall time accordingly for a large policy count. See
`docs/spike/2026-08-16-t27-perf-container.md` for the dedicated performance/scale/memory
test container (`./build.ps1 -Tasks build,perftest`, not part of the default test run) and
its own recorded numbers, including three genuine, documented scale characteristics this
phase surfaced rather than hid:

1. Per-policy raw-dataset writes get slower as a snapshot's own manifest grows (an
   O(n)-per-write cost with no batching yet, confirmed against the real Ivy24 781-policy
   run).
2. Neither `Write-PulseDataset` nor `Read-PulseDataset` streams - both hold the full
   dataset in memory (measured ~5.6-16x the serialized file size), which matters most for
   a very large `managedDevices`-shaped dataset.
3. The Settings Catalog and typed-policy expansion drivers (`Invoke-PulseSettingsCatalog
   Expansion`/`Invoke-PulseTypedPolicyExpansion`) accumulate every row for every policy in
   an in-memory list before merging, sorting, and publishing the family's `.jsonl` file -
   a fragment-then-merge streaming path (writing and merging row fragments incrementally
   instead of holding the whole family in memory at once) has not been built yet. At the
   ~27 rows/policy the T2.7 perf container's own 5,000-policy synthetic corpus produces per
   `settingDefinitionId` cycling, a realistic 5,000-policy tenant's Settings Catalog family
   alone would hold on the order of 135,000 rows in memory at once during expansion -
   budget accordingly for very large tenants until this streams.

Separately, capturing the Settings Catalog definitions corpus (`Save-PulseSettingDefinition
Corpus`, the per-tenant reference index every Settings Catalog row's `settingName`/
`valueLabel` resolution depends on) has an honest measured peak of roughly **1.7 GB of
managed heap** for one capture call against a corpus the size of Ivy24's (18,227
definitions): ~1.2 GB is GraphKit's own response materialization, plus ~475 MB this
module's own canonical-JSON serialization step adds on top before its mitigations (write
canonical JSON to disk and release the string; hash the file's bytes on disk rather than a
second in-memory copy). This number previously lived only in that function's own source
comment - noted here because it is a real per-run memory floor an operator sizing a host for
`-ExpandSettings` should plan for, independent of policy count.

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

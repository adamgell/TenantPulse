# TenantPulse

[![PSGallery Version](https://img.shields.io/powershellgallery/v/TenantPulse)](https://www.powershellgallery.com/packages/TenantPulse)
[![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/TenantPulse)](https://www.powershellgallery.com/packages/TenantPulse)
[![PowerShell 7.4+](https://img.shields.io/badge/PowerShell-7.4%2B-blue)](https://github.com/PowerShell/PowerShell)

> Read-only tenant health assessment for Microsoft Intune and Entra — a versioned check catalog, deterministic scoring, and findings reports with opt-in identity pseudonymization, built on [GraphKit](https://github.com/AdamGell/GraphKit).

TenantPulse is a read-only PowerShell module that assesses a Microsoft Intune/Entra
tenant's health against a versioned set of checks, and produces a deterministic, scored
findings report with opt-in identity pseudonymization. It never writes to a tenant: every Graph read goes
through [GraphKit](https://github.com/AdamGell/GraphKit)'s read-class descriptors
(`ThrottleClass 'Read'`, `ReplayPolicy 'Safe'`) - TenantPulse never calls `Connect-MgGraph`,
never uses the Microsoft Graph PowerShell SDK, and never constructs a Graph URI of its own.

## Current release

[GraphKit `0.3.0`](https://www.powershellgallery.com/packages/GraphKit/0.3.0) and
[TenantPulse `0.2.0`](https://www.powershellgallery.com/packages/TenantPulse/0.2.0) are the
current immutable PSGallery pair. TenantPulse `0.2.0` is the current immutable release on PSGallery.
Its 411284-byte archive was published at `2026-08-30T14:07:39.587Z` with SHA-256
`a0d5ff793b92753ab3efb4db20cf5bcf8b953e3cf81bf1a776c96a3d992417bd`. The merged source is
`b2eb7a882cc1fcb7994c39a606c7b9ac22f5a114`; exact-main CI run `33295648250` executed 2,277
tests with zero failures, errors, skips, or NotRun results across all six OS/PowerShell jobs,
with gitleaks green.

Current source starts the unreleased TenantPulse `0.3.0` product-program line. It has a unique
successor identity and is not the public TenantPulse `0.2.0` archive. On this line, Endpoint
Security composite provenance uses the stable qualified primitives `ConfigurationPolicy.ListBeta`
and `ConfigurationPolicySetting.ListBeta`, independent of tenant policy count. Legacy schema
1.0.0/1.1.0 manifests remain fail-closed when they contain the later `Partial` state; reads reject
that unsupported state without rewriting the manifest.

The unreleased line also carries one canonical Graph failure mapping across direct, composite,
and expansion collectors. A request-time `403` is `Failed` / `PermissionDenied`, and only
`AuthenticationFailed` stops later network work; deadline expiration, cancellation, indeterminate
certainty, permission denial, and provider failure remain explicit and isolated. Partial evaluation
is an exact, reviewed opt-in for only `TP.INT.0013`, `TP.INT.0014`, `TP.INT.0015`, and
`TP.INT.0029`: the two universal checks may Fail on a known offender but cannot Pass with gaps,
while the two existential checks may Pass on a known native-Boolean witness but cannot Fail with
gaps. The other 49 checks remain `NotApplicable` on Partial. For the four opt-ins, malformed input
without decisive monotonic proof is `Error`, not `NotApplicable`. Findings schema `1.0`, snapshot
schema `2.0.0`, and scoring model `1.0` are unchanged. These are deterministic current-source and
package-test claims only; they are not new live-service, merged-release, or publication claims.

The current product-program boundary is narrower than a finished successor release:

- **The implemented R1a foundation is locally package-first proven; R1a acceptance and remote
  integration remain open.** Structured dataset outcomes are available to the evaluator but do not
  yet migrate into a versioned findings/renderer contract as the governing R1a text requires. That
  product contract still needs an explicit decision. No current verified evidence establishes a
  remote refresh/push, exact remote-head review, merge, or merged-main CI for the runtime tree.
  Nothing in this paragraph promotes it over the immutable public `0.2.0` package.
- **R1b is partial.** Settings Catalog assignments and typed include/exclude intent exist, but
  Administrative Template expansion, the governing program's expansion-summary dataset, protected
  live proof with populated assignment targets, and stale pre-implementation map/reason text remain
  open. A local Phase 2 task once descoped that summary; the later governing R1b contract supersedes
  that task-local decision.
- **R2 is partial.** Four real Read/Safe provider plans exist, but the static dataset map still
  publishes synthetic `Pending` / `Walk` tuples and the current composite outcomes do not preserve
  complete operation provenance. Known certainty defects remain in Endpoint Security template
  handling, unknown BitLocker/LAPS values, and the independent current-versus-legacy baseline paths.
  Protected-live proof of the BitLocker raw-value mapping and LAPS template identity is also still
  required before those Pending representations can close.
- **R3 is partial.** Runtime correctly performs no network request and returns
  `PlatformUnavailable`, but the static map and outcome provenance still describe a GraphKit `Get`
  operation that never occurs.
- **R4 is open.** Bounded group closure, application-registration credential coverage, complete
  Intune assignment awareness, exclusion-only assignment semantics, deterministic evidence caps,
  and a supported renderer beyond JSON remain to be implemented and proven. R5 privacy and R6 scale
  are separately open in `docs/STATUS.md`.
- **R9 has a split disposition.** Reusable GraphKit app-registration provisioning and actual-grant
  verification remain applicable. The owner-confirmed absence of installed users, legacy consumers,
  customer-tenant consumers, and repoint targets makes adopter migration, customer repointing,
  rollback-window operation, legacy-runtime retirement, and destructive directory cleanup
  `NotApplicable` rather than pending gates. They must not be performed to create completion evidence.

## Quick start

```powershell
# 1. Install TenantPulse (and its GraphKit dependency) from PSGallery
Install-PSResource -Name TenantPulse -Repository PSGallery

# 2. Register a GraphKit profile for the tenant you want to assess (one-time, per tenant)
#    - see GraphKit's own documentation for profile registration (app registration /
#      certificate or client secret setup). TenantPulse never touches credentials itself;
#      it only resolves an already-registered profile by name.
Register-GraphTenant -ProfileId 'contoso' -TenantId '<tenant-id>' -ClientId '<app-id>' ...

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
| `Get-PulseTenantSnapshot` | Collects a read-only, sensitive snapshot through GraphKit and writes it to a snapshot store on disk. Manifest identity/reasons and selected known-sensitive values are protected, but the store is not de-identified. The only command that ever talks to Graph. |
| `Get-PulseCheckCatalog` | Lists every check descriptor in the catalog (id, title, category, severity, authorities) as a lightweight, read-only view - useful for discovering what `-IncludeCategory`/`-IncludeCheck` values exist before running an assessment. |
| `Invoke-PulseAssessment` | The end-to-end entry point: collect (or reuse `-FromSnapshot`), evaluate every check, score, and render a findings report. Supports `-Redact` to pseudonymize evidence identities in the rendered report. |
| `Invoke-PulseCheck` | Runs a scoped subset of checks (by id or category) against a fresh or existing snapshot - the same pipeline as `Invoke-PulseAssessment`, narrowed to exactly the checks you name. |
| `Export-PulseReport` | Re-renders an already-scored findings JSON file, unchanged, to a new location. Render-only - no re-evaluation, no re-scoring, and (deliberately) no `-Redact`: see its own help for why. |

Run `Get-Help <command> -Full` for the complete parameter and example reference on any of
these; every one of them ships detailed comment-based help.

## Required Graph permissions

TenantPulse reads whichever datasets the checks you run declare - the checks shipped in
Phase 1 read Conditional Access policies, Intune device/compliance/configuration data,
authentication methods policy, Autopilot devices, domains, security defaults, directory role
assignments, and Entra device data. Every one of those reads is a
**read-only, application-permission Graph call** resolved through GraphKit's own descriptor
catalog - TenantPulse does not declare its own separate permission list, it inherits
whichever `Microsoft Graph` application permissions the GraphKit profile's app registration
was granted, applied at the API's own least-privilege read scope for each resource (for
example `Policy.Read.All` for Conditional Access and authentication methods policy,
`DeviceManagementConfiguration.Read.All` / `DeviceManagementManagedDevices.Read.All` /
`DeviceManagementApps.Read.All` for the Intune datasets, `Directory.Read.All` /
`RoleManagement.Read.Directory` for directory role data, `Domain.Read.All` for domains).

A missing permission is never a process-wide abort: the collector attempts every dataset
independently and records a request-time `403` as dataset status `Failed`, failure class
`PermissionDenied`, and reason code `permission-denied`. The bounded reason names the exact
permissions from GraphKit's own descriptor when available, so the scope guidance does not become a
second stale permission list in this README. Only `AuthenticationFailed` stops later network
collection. A check whose required dataset Failed degrades honestly to `NotApplicable`, never a
silently wrong Pass or Fail.

Every completeness-producing Graph read requests GraphKit's result envelope. TenantPulse records a
dataset as `Collected` only when exactly one genuine `GraphKit.OperationResult` carries the required
non-null `Data`, `Outcome`, `Certainty`, and native-Boolean `Truncated` members and reports
`Succeeded` / `Known` / not truncated. A complete envelope with an empty `Data` array is an
authoritative empty collection. Missing output, rows-only output, multiple results, type-spoofed
objects, and malformed envelopes are rejected rather than converted into empty success. A successful
but truncated or indeterminate envelope is `Partial` when it contains usable rows and
`Failed` / `Indeterminate` otherwise.

## Snapshot data is sensitive at rest

A snapshot store (`Get-PulseTenantSnapshot`'s output, or the `snapshot/` subdirectory
`Invoke-PulseAssessment` writes alongside its findings report) contains **sensitive
tenant-derived data** - device names, policy definitions, configuration values, and more.
It is not a byte-for-byte Graph response: GraphKit provenance is removed, the manifest's
`tenant` field and collection-failure reasons are pseudonymized, exact tenant-id matches are
redacted, and typed-policy fields explicitly marked `Sensitive` are replaced before
persistence. Those narrow protections do **not** make a snapshot de-identified or safe to
share. Most other collected values remain available to evaluation, while the typed-policy
and Settings Catalog classifiers also redact some unknown or complex value shapes
conservatively when they cannot prove the content safe. Treat a snapshot directory the same
way you would treat a raw Graph API export: store it somewhere access-controlled, do not
commit it to source control, and clean it up when you are done with it.

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

`-Redact` always pseudonymizes evidence identities. It replaces a sort key only when that
key is itself an exact entry in the redaction map (including the usual default where sort key
equals identity); a custom composite sort key can still retain an identity fragment. It also
pseudonymizes the small set of `evidence[].detail` keys that their producing rules explicitly
mark through `RedactDetailKeys`. It does **not** enforce a complete classification over every
Detail value, reason, error, label, sort key, or future renderer field. A `-Redact` render can
therefore still contain tenant-derived names or free text and is **not** on its own safe to post
publicly or hand outside the tenant's trust boundary.

For a findings JSON you actually intend to publish or share outside that boundary (e.g. a
committed `docs/gates/*.json` reference artifact), run it through
`scripts/Protect-PulseGateArtifact.ps1` first - a required gate-artifact scrub that replaces every
string leaf inside every finding's `evidence[].detail` with a stable pseudonym, no
per-field-name allowlist (see that script's own docstring for why a field-name allowlist is
exactly the failure mode it exists to avoid). Then review the resulting artifact under the
intended sharing boundary. The script is not a general PII classifier and does not prove the
later R5 privacy contract; a `-Redact` render alone is even narrower.

The **snapshot store** (`./out/snapshot/` - see **Snapshot data is sensitive at rest** above)
is local-only and never safe to share in any form. It is the sensitive collection/evaluation
source, not a findings report. Neither report-time `-Redact` nor
`Protect-PulseGateArtifact.ps1` transforms it into a shareable artifact; there is no
supported snapshot-sharing scrub, only controlled storage and cleanup when you are done.

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
- [GraphKit](https://www.powershellgallery.com/packages/GraphKit/0.3.0) exactly `0.3.0`.
  Published TenantPulse `0.2.0` and the unreleased `0.3.0` source line both declare this with
  `RequiredVersion`, so a different GraphKit version does not satisfy the runtime contract.
  Installing TenantPulse `0.2.0` from PSGallery resolves the exact published GraphKit `0.3.0`
  dependency.
- A GraphKit profile already registered for the tenant you want to assess (see GraphKit's
  own documentation - profile registration, credential setup, and Graph app-registration
  concerns are entirely GraphKit's responsibility, not TenantPulse's)
- The app registration behind that profile granted the read-only Graph application
  permissions the checks you intend to run actually need (see **Required Graph
  permissions** above) - most commonly `Policy.Read.All` for the Conditional-Access-backed
  checks (`TP.ENT.0003`-`0005`), plus whichever Intune/device permissions the datasets you
  collect require
- PSGallery access (or an internal mirror) to install TenantPulse and GraphKit

GraphKit `0.3.0` and TenantPulse `0.2.0` are the immutable current PSGallery releases.
The `0.2.0` release was greenfield, pre-adoption work: there was no installed TenantPulse user
base, customer estate, prior runtime, or migration/cutover task. It added the cleanup-rule
primitive, Settings Catalog assignments, expanded Intune
RBAC primitives, and default TenantPulse provider plans for RBAC, BitLocker, LAPS, and current
plus legacy security baselines. The Windows data-processor path is explicitly classified as
platform-unavailable because Microsoft has not published the GET/application-permission
contract needed for a releasable descriptor. See `docs/STATUS.md` for the exact local, live,
package, CI, and publication evidence boundaries. Current source is the separate unreleased
TenantPulse `0.3.0` product-program line.

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

"Live" below is historical evidence for the exact immutable TenantPulse `0.2.0` package only: its
dataset and evaluation path completed against a live tenant. It is separate from exact-SHA CI and
publication, and it does **not** prove current unreleased-source acceptance or closure of R1b-R6.
"Live (partial)" means the path completed but the service evidence contained explicit gaps, so
evaluation failed closed.
"Platform unavailable" means TenantPulse
returns an explicit non-collecting disposition because the service contract needed for a
supported read does not exist. A raw `Pending = $true` map placeholder is still never sent to
Graph directly; a built-in provider plan must resolve it first or it degrades honestly to
`NotApplicable`. `TP.ENT.0022` additionally requires Entra ID P2 licensing, but TenantPulse calls
that gate unavailable only when successfully collected `subscribedSkus` evidence proves P2 is
absent. A `400`/`403` from a PIM read is not proof that the tenant lacks P2; it remains an explicit
provider/permission outcome and the check fails closed rather than inventing a license finding.

| Id | Category | Severity | Evidence | Title |
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
| TP.INT.0009 | Intune.Governance | Low | Platform unavailable | Windows diagnostic data processor configuration enabled |
| TP.INT.0011 | Intune.Governance | Low | Live | Default branding profile customized |
| TP.INT.0012 | Intune.Updates | High | Live | Windows Feature Update policy avoids end-of-support builds |
| TP.INT.0013 | Intune.Governance | High | Live | Intune RBAC groups protected via RMAU or role-assignable groups |
| TP.INT.0014 | Intune.EndpointSecurity | Critical | Live (partial) | BitLocker full-disk encryption enforced via Endpoint Security policy |
| TP.INT.0015 | Intune.EndpointSecurity | High | Live | LAPS configuration policy meets minimum security bar |
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
| TP.INT.0029 | Intune.SecurityBaselines | Medium | Live | Security baselines assigned and not on a deprecated version |
| TP.INT.0030 | Intune.Compliance | Medium | Live | Fleet compliance rate below acceptable threshold |
| TP.INT.0031 | Intune.SettingsCatalog | Critical | Live | BitLocker CSP settings present and correct across all Settings Catalog policies |

The four composite rows still retain synthetic `Pending` / `Walk` map tuples because they do not
map to a single Graph operation. Current runtime dispatch is safe: TenantPulse's default provider
registry intercepts them and composes only GraphKit Read/Safe primitives. That safety does not make
the placeholder schema final; removing the invented production tuples and recording every actual
primitive in structured outcomes is open R2 work. The Windows data-processor runtime similarly
performs no network request and emits `PlatformUnavailable`, but its static map and outcome
provenance still claim a GraphKit `Get`; correcting that representation is open R3 work. The cleanup
rule is no longer Pending: GraphKit `0.3.0` ships its direct Read/Safe collection descriptor.

What the current catalog does **not** cover, honestly:

- **Entra relationship closure.** Conditional Access group references are not expanded with
  policy/root attribution, bounds, cycle handling, or partial certainty. This can affect
  `TP.ENT.0003` status and the evidence/certainty of `TP.ENT.0004`, `0005`, `0017`, and `0018`.
  `TP.ENT.0002`, `0020`, and `0021` count direct principals or a group object rather than unique
  effective members. `TP.ENT.0022` must continue to count one permanent group assignment as one
  violation; future expansion is bounded blast-radius evidence, not multiplication of that finding.
- **Application registrations.** `TP.ENT.0019` reads only `servicePrincipal` credentials because
  GraphKit `0.3.0` and the current successor tree have no `Application.List` operation. Ordinary app
  registration secrets/certificates are invisible. An all-unparseable credential population can
  also currently reach Pass; R4 must make that result `NotApplicable` unless a proven offender
  already establishes Fail.
- **Intune assignment awareness.** `TP.INT.0002`, `0004`, `0011`, `0012`, `0014`, `0015`, `0017`,
  and `0018` can still evaluate policy existence/configuration without authoritative positive
  assignment proof. `TP.INT.0028` has assignment-aware evaluator logic, but its producer does not
  yet collect the required authoritative full-object/assignment shape. The shared presence and
  conflict indexes also treat exclusion-only scope as assigned or possibly overlapping instead of
  effectively targeting nobody.
- **Bounded output and presentation.** Many affected findings still lack a deterministic evidence
  cap with emitted/omitted counts. The governing R4 design requires a supported renderer beyond
  JSON, but no specific non-JSON format/output contract has been selected and none has been
  implemented or proven.

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
  than a Graph-side settings catalog, since none exists for these types. Per-policy
  assignments preserve include/exclude intent and filter metadata; a malformed assignment
  target gaps that policy instead of publishing a false unassigned row.
- **Conflict detection** - a single pass over every row from the families above, grouping
  by `settingDefinitionId` to surface settings where two or more policies disagree, with a
  four-state assignment-overlap verdict (`proven`/`possible`/`none`/`unknown`).

Every artifact this produces is recorded in the snapshot manifest under
`manifest.expansions.<name>` and written to `expanded/<name>.<sha256>.jsonl` (or
`expanded/conflicts.<sha256>.json` for the conflicts document) - immutable,
content-addressed files, never a fixed name. See
`source/Private/Evaluate/FindingsSchema.md`'s own "Settings expansion artifacts" section
for the exact row/conflict-record schema.

Settings Catalog assignment collection uses GraphKit 0.3.0's
`ConfigurationPolicyAssignment.ListBeta` descriptor for each policy. TenantPulse persists
that raw payload and normalizes include/exclude intent, target type, group id, and assignment
filter fields onto every expanded setting row. An exactly-one, complete GraphKit envelope with an
empty `Data` array is authoritative and becomes `assignments: []`; missing or malformed output is
not an empty assignment response. An unavailable payload or an assignment with a missing, null, or
non-object target gaps that policy instead of publishing a false unassigned result.
Conflict overlap therefore consumes real Settings Catalog targets whenever those policy rows
are present.

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
   instead of holding the whole family in memory at once) has not been built yet. The T2.7
   5,000-policy synthetic fixture creates one setting per policy and therefore measures
   5,000 rows, not 135,000. Real tenants may carry many settings per policy, so that fixture
   is a regression/capacity baseline rather than an end-to-end peak-memory proof; budget
   accordingly for large tenants until collection and expansion stream.

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
./build.ps1 -Tasks pack
./build.ps1 -Tasks test
```

The `pack` task begins with `Clean`, so package before testing. The `test` task proves that package-producing build, enforces the whole-result gate, and records the per-shipped-file SHA-256 manifest that `scripts/Publish-TenantPulsePackage.ps1` compares with the `.nupkg`.

`scripts/Publish-TenantPulsePackage.ps1` publishes an already-packed `.nupkg` to PSGallery.
It never builds and enforces pack-first-then-verify: it compares every shipped file inside
the package against the digest manifest recorded at test time, and refuses to publish on
any mismatch (packaging bytes nothing tested is exactly the failure this exists to
prevent). It defaults to a dry run - it prints what it would publish and does not call
PSGallery - and only publishes for real when explicitly authorized with `-Publish`, given
a resolved API key (via `-NuGetApiKeySecure` or the `TENANTPULSE_NUGET_API_KEY`
environment variable - there is no plain-string API key parameter), and confirmed through
the normal `ShouldProcess` confirmation boundary.

`source/TenantPulse.psd1` declares GraphKit `0.3.0` with `RequiredVersion`, the exact runtime
contract. `RequiredModules.psd1` separately pins `GraphKit = '0.3.0'` for build-time staging.
These two files intentionally use different schemas but must resolve the same version. For the
unreleased TenantPulse `0.3.0` source line, validation stages the already-tested published
GraphKit `0.3.0` package locally; it must not silently fall back to any other GraphKit version.

Unit tests never import real GraphKit: every GraphKit command TenantPulse calls
(`Get-GraphContext`, `Get-GraphObject`, `Invoke-GraphOperation`, `Get-GraphOperation`) is
stubbed inside the TenantPulse module scope in each test file's `BeforeAll`, with a default
mock that throws registered before any test-specific mock (GraphKit's own test
convention). GraphKit is still importable in the test environment (it is a
`RequiredModules` dependency of TenantPulse itself), but the module-scope stubs shadow it
for every call TenantPulse's own code makes - that shadowing, not the absence of GraphKit,
is what keeps the tests deterministic and independent of a live tenant. A successful
`Get-GraphObject -PassThruResult` mock must return exactly one genuine-shaped
`GraphKit.OperationResult`, including non-null `Data`, `Outcome`, `Certainty`, and a native-Boolean
`Truncated`; returning rows or `@()` models an invalid provider result, not success.

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

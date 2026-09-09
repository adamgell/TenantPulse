# TenantPulse

[![PSGallery Version](https://img.shields.io/powershellgallery/v/TenantPulse)](https://www.powershellgallery.com/packages/TenantPulse)
[![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/TenantPulse)](https://www.powershellgallery.com/packages/TenantPulse)
[![PowerShell 7.4+](https://img.shields.io/badge/PowerShell-7.4%2B-blue)](https://github.com/PowerShell/PowerShell)

> Read-only tenant health assessment for Microsoft Intune and Entra — a versioned check catalog, deterministic scoring, and canonical JSON plus self-contained HTML findings reports, built on [GraphKit](https://github.com/AdamGell/GraphKit).

TenantPulse is a read-only PowerShell module that assesses a Microsoft Intune/Entra
tenant's health against a versioned set of checks, and produces a deterministic, scored
findings report with opt-in identity pseudonymization. It never writes to a tenant: every Graph read goes
through [GraphKit](https://github.com/AdamGell/GraphKit)'s read-class descriptors
(`ThrottleClass 'Read'`, `ReplayPolicy 'Safe'`) - TenantPulse never calls `Connect-MgGraph`,
never uses the Microsoft Graph PowerShell SDK, and never constructs a Graph URI of its own.

## Current release

TenantPulse `0.2.0` is the current immutable release on PSGallery. It depends on the separately
released [GraphKit `0.3.0`](https://www.powershellgallery.com/packages/GraphKit/0.3.0).
Its 411284-byte archive was published at `2026-08-30T14:07:39.587Z` with SHA-256
`a0d5ff793b92753ab3efb4db20cf5bcf8b953e3cf81bf1a776c96a3d992417bd`. The merged source is
`b2eb7a882cc1fcb7994c39a606c7b9ac22f5a114`; exact-main CI run `33295648250` executed 2,277
tests with zero failures, errors, skips, or NotRun results across all six OS/PowerShell jobs,
with gitleaks green.

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

# Also capture neutral inputs for a future customer workbook/document pipeline
Invoke-PulseAssessment -ProfileId 'contoso' -OutputPath './out' -ReportData All -ExpandSettings
```

This collects a snapshot, evaluates every check in the catalog, scores the result, and
writes a canonical-JSON findings report to `./out/tenantpulse-findings.json` - along with the
raw snapshot store under `./out/snapshot/` (see **Where files are written**, below, before
you decide where `-OutputPath` should point). Add `-Format Html` to also write the
self-contained `./out/tenantpulse-report.html` renderer.

## The five public commands

| Command | What it does |
|---|---|
| `Get-PulseTenantSnapshot` | Collects a read-only, sensitive snapshot through GraphKit and writes it to a snapshot store on disk. `-ReportData All` selects the neutral audit source set and every versioned report-data artifact for downstream builders; each source and artifact records its actual outcome, including unavailable or failed states. Manifest identity/reasons and selected known-sensitive values are protected, but the store is not de-identified. The only command that ever talks to Graph. |
| `Get-PulseCheckCatalog` | Lists every check descriptor in the catalog (id, title, category, severity, authorities) as a lightweight, read-only view - useful for discovering what `-IncludeCategory`/`-IncludeCheck` values exist before running an assessment. |
| `Invoke-PulseAssessment` | The end-to-end entry point: collect (or reuse `-FromSnapshot`), evaluate every check, score, and render canonical JSON. `-ReportData All` passes every neutral report profile to fresh collection; `-Format Html` also writes a self-contained HTML report; `-Redact` remains the local-only compatibility pseudonymization path. |
| `Invoke-PulseCheck` | Runs a scoped subset of checks (by id or category) against a fresh or existing snapshot - the same pipeline as `Invoke-PulseAssessment`, narrowed to exactly the checks you name. |
| `Export-PulseReport` | Re-renders an already-scored findings JSON file as canonical JSON or self-contained HTML. Render-only - no Graph, snapshot read, re-evaluation, or re-scoring, and (deliberately) no `-Redact`: see its own help for why. |

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
- `./out/tenantpulse-report.html` - additionally written when `-Format Html` is selected;
  a self-contained rendering of the canonical findings JSON

The operator key used for pseudonymization lives at `~/.tenantpulse/operator.key` by
default (overridable) - back it up if you need pseudonyms to stay stable across machines,
and protect it the same way you would protect any key material: the same key that produced
a pseudonym is required to reproduce it.

## Sharing a findings artifact

TenantPulse now has a versioned 1.0 privacy-classification framework. Classified construction
uses exactly five classes: `Identity`, `SecretSensitive`, `SafeTechnical`,
`SafeOperatorLabel`, and `BoundedReviewedText`. Identity values are HMAC-pseudonymized,
secret-sensitive values are irreversibly replaced, safe technical values and intentionally
retained operator labels remain useful, and reviewed text stays bounded and must be HTML-encoded.
Missing, unknown, or value-incompatible classifications fail closed.

Classification completeness is not the same as safe-share protection. `privacy.complete = true`
means all required fields have classification metadata, but an ordinary evaluation document may
still contain raw classified values and therefore remains `privacy.boundary = "local-only"`.
HTML rendering treats missing, malformed, incomplete, non-classified, or unstamped privacy
metadata as local-only and displays a prominent not-safe-to-share warning.

`ConvertTo-PulseSafeShareDocument`, reached by the private JSON exporter's
`-RequireClassification` path, is the fail-closed classified JSON boundary. It emits
`privacy.classification = "1.0"`, `privacy.complete = true`,
`privacy.boundary = "classified"`, `privacy.compatLayer = false`, and the exact
`privacy.protection = "safe-share-v1"` provenance marker only after every required field has
passed classification and protection. Older or hand-built classified/complete envelopes without
that marker remain warning-bearing when rendered.
The public safe-share workflow remains undecided under C0 D6, so TenantPulse does not currently
expose `-RequireClassification` as a public assessment/export switch. Catalog checks are not yet
fully migrated to classified construction; do not infer that an ordinary findings file is a
classified safe-share artifact.

`-Redact`, `RedactDetailKeys`, and `Protect-PulseReason` remain the compatibility path. They
pseudonymize known identities and bound selected text, but they do not establish complete field
classification. Treat their output as local-only (`privacy.complete = false`,
`privacy.boundary = "local-only"` in the compatibility envelope), not as safe to share outside
the tenant's trust boundary. `scripts/Protect-PulseGateArtifact.ps1` remains a purpose-built
legacy scrub for reviewed gate artifacts; it is not the classified safe-share contract.

There is no public operator-key rotate cmdlet. Back up the 32-byte `operator.key` offline with
owner-only permissions before replacement. A newly generated replacement intentionally breaks
identity joins with reports produced under the prior key; restoring that backed-up generation
restores those joins. Never store the key in snapshots, reports, logs, tickets, or source control.

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
- [GraphKit `0.3.0`](https://www.powershellgallery.com/packages/GraphKit/0.3.0), installed
  automatically as TenantPulse `0.2.0`'s required dependency
- A GraphKit profile already registered for the tenant you want to assess (see GraphKit's
  own documentation - profile registration, credential setup, and Graph app-registration
  concerns are entirely GraphKit's responsibility, not TenantPulse's)
- The app registration behind that profile granted the read-only Graph application
  permissions the checks you intend to run actually need (see **Required Graph
  permissions** above) - most commonly `Policy.Read.All` for the Conditional-Access-backed
  checks (`TP.ENT.0003`-`0005`), plus whichever Intune/device permissions the datasets you
  collect require
- PSGallery access for TenantPulse and its published dependencies

TenantPulse `0.2.0` is the immutable current PSGallery release and depends on the immutable
GraphKit `0.3.0` release. The `0.2.0` release was greenfield, pre-adoption work: there was no installed TenantPulse user
base, customer estate, prior runtime, or migration/cutover task. It added the cleanup-rule
primitive, Settings Catalog assignments, expanded Intune
RBAC primitives, and default TenantPulse provider plans for RBAC, BitLocker, LAPS, and current
plus legacy security baselines. The Windows data-processor path is explicitly classified as
platform-unavailable because Microsoft has not published the GET/application-permission
contract needed for a releasable descriptor. See `docs/STATUS.md` for the exact local, live,
package, CI, and publication evidence boundaries.

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
is DESCOPED until a separate ARM authentication and live-service contract is proven; the current
private injected adapter is deferred foundation code, not live collection) that took `TP.INT` from
5 checks to 28, then
`TP.INT.0017`/`0018` (App Control enforce + Managed Installer pairing) shipped against
the live `applicationcontrolv2` schema and took `TP.INT` to 30; Phase
4 then added the 23-check Entra core catalog - the EIDSCA port (`TP.ENT.0006`-`0011`),
authorization/consent/password/guest-access clusters (`TP.ENT.0012`/`0013`/`0015`/`0016`), and
the ScuBA/CISA-cited Conditional Access, privileged-role, and credential-hygiene checks
(`TP.ENT.0017`-`0024`). Not a comprehensive tenant-health product - a deliberately scoped,
verified-against-a-real-tenant catalog.

"Live" below is historical evidence for the exact immutable TenantPulse `0.2.0` package only: its
dataset and evaluation path completed against a live tenant. It is separate from exact-SHA CI and
publication.
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

Composite datasets are explicit TenantPulse `Plan` entries rather than synthetic GraphKit
`Pending` / `Walk` tuples. The default provider registry declares every GraphKit child primitive;
permission preflight and the static read-only gate validate that exact operation union before a plan
can dispatch. The Windows data-processor entry is also a TenantPulse plan, but intentionally has a
null API version and empty operation set because it performs no network request and emits
`PlatformUnavailable`. The cleanup rule is a direct entry because GraphKit `0.3.0` ships its
Read/Safe collection descriptor.

What the current catalog does **not** cover, honestly:

- **Entra relationship closure.** Conditional Access group references are not expanded with
  policy/root attribution, bounds, cycle handling, or partial certainty. This can affect
  `TP.ENT.0003` status and the evidence/certainty of `TP.ENT.0004`, `0005`, `0017`, and `0018`.
  `TP.ENT.0002`, `0020`, and `0021` count direct principals or a group object rather than unique
  effective members. `TP.ENT.0022` must continue to count one permanent group assignment as one
  violation; future expansion is bounded blast-radius evidence, not multiplication of that finding.
- **Application registrations.** `TP.ENT.0019` reads only `servicePrincipal` credentials because
  the released operation catalog has no `Application.List` operation. Ordinary app
  registration secrets/certificates are invisible. An all-unparseable credential population can
  also currently reach Pass; R4 must make that result `NotApplicable` unless a proven offender
  already establishes Fail.
- **Intune assignment awareness.** `TP.INT.0011`, `0012`, `0014`, `0015`, `0017`, and `0018` can
  still evaluate policy existence/configuration without authoritative positive assignment proof.
  `TP.INT.0028` has assignment-aware evaluator logic, but its producer does not yet collect the
  required authoritative full-object/assignment shape. The shared presence and conflict indexes
  also treat exclusion-only scope as assigned or possibly overlapping instead of effectively
  targeting nobody.
- **Bounded output and presentation.** Many affected findings still lack a deterministic evidence
  cap with emitted/omitted counts. Self-contained HTML is now the supported second renderer;
  JSON remains canonical, and neither renderer changes collection, evaluation, or scoring.

## HTML findings reports

`Export-PulseReport -Format Html` writes `tenantpulse-report.html` from an existing scored
findings JSON document. `Invoke-PulseAssessment -Format Html` always writes the canonical
`tenantpulse-findings.json` first, then writes `tenantpulse-report.html` beside it. HTML is a
second renderer, not a new artifact manifest or findings schema.

The HTML file is self-contained: CSS is inline, scripts are absent, and it contains no
network-loading URLs. It consumes findings JSON only and never calls Graph, opens a snapshot,
re-evaluates checks, or recalculates scores. Tenant-derived and reviewed text is HTML-encoded,
and the renderer preserves the findings document's existing notices rather than inventing or
recomputing them.

## Neutral application report data

`Get-PulseTenantSnapshot -ReportData Applications` and the equivalent
`Invoke-PulseAssessment ... -ReportData Applications` collect two report-oriented artifacts
independently of check selection:

- `application-assignments` inventories every mobile app, preserves apps with no assignments,
  resolves group names and bounded member counts, reserves optional group descriptions for a
  later verified GraphKit producer, and retains assignment intent,
  include/exclude target type, filters, settings, ids, and explicit resolution states.
- `app-install-errors` reads GraphKit's safe `AppInstallSummaryReport.Get` report action,
  request-body pages through the service's `TotalRowCount` with a hard 200-page cap and repeated-page
  detection, accepts both Graph's schema/values matrix and named-record shapes, preserves every
  source column, and provides stable normalized columns without inventing severity or a failure
  rate. Only an explicit valid zero-row report is authoritative empty; a missing payload remains
  unavailable.

Both are schema-v1 canonical JSONL files recorded under `manifest.expansions`, with content
hashes and `Expanded`, `Partial`, or `NotExpanded` truth. A partial page, per-app 403,
unresolved group, malformed report row, permission-preflight block, and authentication abort
remain visible rather than becoming an empty-success claim. Collection uses one permission
preflight and GraphKit's read/safe descriptors; the report POST is a non-mutating Graph report
operation, not a TenantPulse write. Tenant identifiers are recursively scrubbed from nested report
rows before persistence, and a report-originated authentication failure sets the snapshot-wide
collection failure and stops every later network read.

These artifacts are neutral local snapshot data. TenantPulse does not create DOCX/XLSX files,
does not carry CDW or customer branding, and does not interpret approval fields. A later
harness-independent Office builder can consume the versioned rows and preserve customer-owned
workbook/document regions. The exact row and failure contract is documented in
[`docs/contracts/application-report-data-v1.md`](docs/contracts/application-report-data-v1.md).

`-ReportData Devices` guarantees one ordinary `managedDevices` read, performs the documented beta
singleton detail read for each Windows device, and publishes one `managed-device-inventory`
artifact. It carries normalized identity, user, hardware, health-attestation, TPM, OS, encryption,
compliance, ownership, enrollment, and sync fields plus every original source column.
The artifact is intended for downstream reporting; presentation layers own worksheet filters and
record the stale-device UTC cutoff. TenantPulse does not claim TPM state
from encryption/compliance fields; `tpmVersion` is used only when the device detail actually returns
it. The exact schema and certainty rules are documented in
[`docs/contracts/device-report-data-v1.md`](docs/contracts/device-report-data-v1.md).

`-ReportData Inventory` guarantees the audit profile's 25 neutral source datasets even when no
selected check consumes them. It uses the ordinary deduplicated
snapshot collection path, so combining `Inventory`, `Applications`, and `Devices` does not fetch a
shared root twice. Add `-ExpandSettings` when the run also needs policy-conflict and setting
artifacts. The exact dataset set, GraphKit bindings, and sensitivity boundary are documented in
[`docs/contracts/audit-inventory-v1.md`](docs/contracts/audit-inventory-v1.md).

`-ReportData Reports` requests six additional schema-v1 artifacts for Apple enrollment profiles,
compliance policy assignments, Conditional Access policy overview, connectors and tokens, directory
roles, and groups. The Apple artifact uses one read-only GraphKit child collection per stored DEP
token; the other five are snapshot-only projections. Each artifact records its actual outcome, and
only successfully published artifacts carry a content hash. `-ReportData All` selects `Applications`,
`Devices`, `Inventory`, and `Reports` while deduplicating shared datasets. These artifacts preserve
structured ids, source columns, hashes,
and explicit gaps; they do not compute approval, severity, expiration status, or Office display
cells. The exact schemas and projection rules are documented in
[`docs/contracts/audit-report-data-v1.md`](docs/contracts/audit-report-data-v1.md).

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
  than a Graph-side settings catalog, since none exists for these types. Ordinary collection
  joins each policy to its authoritative per-policy assignment List response first; expansion
  reuses that embedded evidence with no duplicate Graph read and persists the per-policy raw
  payload for later snapshot-only re-expansion. A complete zero-row child is an empty array;
  unavailable child evidence is explicit null plus a scoped gap. Assignments preserve
  include/exclude intent and filter metadata, and a malformed target gaps that policy instead
  of publishing a false unassigned row.
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

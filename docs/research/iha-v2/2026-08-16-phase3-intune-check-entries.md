# Phase 3 Intune check entries - research backfill

This file is the research record `References.Research` in
`source/Data/Checks/TP.INT.00{06,07,08,09,11,12,13,14,15}.psd1` points at. It was
reconstructed on 2026-08-16 to backfill resolutions that, until now, lived only in
rule-function docstrings and commit messages - each item below is marked
`RESOLVED (2026-08-16):` and cites exactly where the resolution already shipped in code,
so this file matches what actually shipped rather than restating it from scratch. It was
further backfilled on 2026-08-16 by merging in the full original research record (claim,
authority, origin, data, severity rationale, and operational notes for each entry), so it
now stands as the authoritative combined record for TP.INT.0006-0015.

**TP.INT.0016-0030 import (2026-08-16, Task 3.3):** the entries below were imported
verbatim-in-substance from the original Phase 3 research record (sections A and B of that
record) to backfill coverage for the remainder of the Maester Intune port
(TP.INT.0016-0024) and the research-matrix checks with no Maester origin
(TP.INT.0025-0030). Per this task's standing rules, **every citation in these imported
entries is treated as unverified regardless of any flag present in the source record** -
the source record's own flags are known to undercount. Live-fetch verification happens at
per-check authoring time (see each check's own `Test-Pulse*.ps1` docstring for the
resolution, or a `RESOLVED (date):` callout appended below when a citation needed
correction). TP.INT.0016-0018 (ASR Standard Protection, App Control enforce-mode, Managed
Installer pairing) are imported here for record-completeness but were **not** implemented
in Task 3.3 - see the T3.3 report for the scoping rationale (they are a template-family
continuation of the TP.INT.0014/0015 Endpoint Security batch, not part of the
connector/token-expiry + research-matrix set T3.3 actually scoped).

## TP.INT.0006 — Conflicting security-setting values across policies

Conflicting Settings Catalog / configuration policy values across two or more policies.
Per Microsoft's own guidance, a proven/possible assignment-scope conflict means Intune
"generates an error and doesn't apply either setting" - an enforcement gap, not a
last-writer-wins outcome. Ported check: `Test-PulseConflictingPolicySettings.ps1`
(TP.INT.0006), reading Task 2.6's `expanded/conflicts.json` artifact rather than a raw
Graph dataset.

- Origin: none (practitioner judgment, built on Phase 2 T2.6 conflict index) - settings-
  conflict detection is not a named check in Maester, ScuBA, or the Microsoft guidance
  matrix; it is a first-party capability enabled by the settings-expansion layer.
- Data: consumes `expanded/conflicts.json` (derived artifact, not raw Graph) - built from
  `beta/deviceManagement/configurationPolicies(...)/settings` rows plus assignment sets;
  descriptor: `Expansion.ConflictIndex` (compact record, not raw jsonl per T2.6 interface).
- Severity rationale: Medium default (config drift, not a security control gap by itself)
  - escalate to High only for conflicts touching security-baseline setting definitions
  (BitLocker, ASR, LAPS CSPs), decided at evaluation time from the setting's definitionId,
  not statically.
- Notes: ID reserved since Phase 2 (`docs/superpowers/plans/2026-08-16-tenantpulse-phase2-settings-expansion.md`
  T2.6) - this is the first research entry written for it, not a renumbering. Evidence must
  report the four overlap states (`proven`/`possible`/`none`/`unknown`) verbatim, never
  collapse `possible`/`unknown` into a false positive. No pairwise policy comparison -
  index-based only.

**RESOLVED (2026-08-16):** the original research entry's own Authority URL,
`.../mem/intune/configuration/conflict-resolution`, returns 404 on Microsoft Learn. The
shipped descriptor (`source/Data/Checks/TP.INT.0006.psd1`) does not carry that URL at all
- its `References.Authorities` was already built against the live, verified citation
`https://learn.microsoft.com/en-us/intune/solutions/education/tutorial-school-deployment/policy-conflicts`
(also cited directly in `Test-PulseConflictingPolicySettings.ps1`'s own docstring), which
is the one this research entry should have always pointed to.

## TP.INT.0007 — Intune device clean-up rule configured

Whether `deviceInactivityBeforeRetirementInDays` is configured (non-zero) on the tenant's
managed-device clean-up settings.

- Authority: Maester https://maester.dev/docs/tests/MT.1053 ; https://learn.microsoft.com/en-us/intune/governance/configure-cleanup-rules
- Origin: Maester MT.1053 (`Test-MtManagedDeviceCleanupSettings`, MIT, port)
- Data: `beta/deviceManagement/managedDeviceCleanupRules`; descriptor:
  `DeviceManagement.CleanupRules.List` (beta)
- Severity rationale: Low - hygiene/reporting-accuracy issue, not a direct exposure; fails
  when `deviceInactivityBeforeRetirementInDays` is absent or `0`.
- Notes: beta-only endpoint, isolate behind degradation layer per roadmap G-note. Don't
  conflate with Entra stale-device cleanup (separate object, separate check).

**RESOLVED (2026-08-16):** an earlier draft of this research entry said clean-up rules
"delete managed-device records". Live-verified against
`https://learn.microsoft.com/en-us/intune/governance/configure-cleanup-rules` (fetched
for this check): clean-up rules only HIDE stale device records from the admin
center/reports and take no action on the device itself (no wipe, no retire) - a hidden
device reappears automatically if it checks back in before its device certificate
expires. This correction already shipped in
`Test-PulseDeviceCleanupRuleConfigured.ps1`'s own docstring ("CORRECTED CLAIM") and in
`TP.INT.0007.psd1`'s Consulting remediation text ("Remember this only hides devices...
not from Microsoft Entra ID") - every reference to this behavior in the shipped check
says "hides", never "deletes".

## TP.INT.0008 — Intune Multi Admin Approval policy configured

Whether Intune's Multi Admin Approval (Access Reviews-backed) governance control has at
least one active policy.

- Claim: At least one Multi Admin Approval (operation approval) policy exists, requiring a
  second admin to approve sensitive Intune operations (e.g., script/remediation deployment)
  before execution.
- Authority: Maester https://maester.dev/docs/tests/MT.1096 ; https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/multi-admin-approval
- Origin: Maester MT.1096 (`Test-MtOperationApprovalPolicies`, MIT, port)
- Data: `beta/deviceManagement/operationApprovalPolicies`; descriptor:
  `DeviceManagement.OperationApprovalPolicies.List` (beta)
- Severity rationale: Medium - reduces blast radius of a single compromised/careless admin
  account for high-impact operations; not Critical because it's a defense-in-depth control,
  not a primary access gate.
- Notes: pass = any policy returned (count > 0); the Maester check does not evaluate scope
  coverage (which operation types are actually gated) - flag that as a known depth gap if we
  don't extend it.

**RESOLVED (2026-08-16):** the Authority URL was updated to the canonical
`https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/role-based-access-control/multi-admin-approval`
path. The original `.../intune-service/fundamentals/multi-admin-approval` path (used
above and in the earlier draft) resolves only via redirect on Microsoft Learn, not as a
direct hit; the canonical path is what `TP.INT.0008.psd1`'s `References.Authorities`
should carry going forward.

## TP.INT.0009 — Windows diagnostic data processor configuration enabled

Whether both the "Enable features that require Windows diagnostic data in processor
configuration" toggle and the "I confirm that my tenant owns one of these licenses"
license-verification toggle are on (Tenant administration > Connectors and tokens >
Windows data, both default Off).

- Claim: The tenant has enabled Microsoft as the data processor for Windows diagnostic
  data, and holds a valid Windows license entitling it to that processor configuration.
- Origin: Maester MT.1099 (`Test-MtWindowsDataProcessor`, MIT, port)
- Data: `beta/deviceManagement/dataProcessorServiceForWindowsFeaturesOnboarding`;
  descriptor: `DeviceManagement.DataProcessorServiceForWindowsFeaturesOnboarding.Get`
  (beta)
- Severity rationale: Low - a compliance/data-governance posture item, not an
  attack-surface control; pass requires BOTH `hasValidWindowsLicense` and
  `areDataProcessorServiceForWindowsFeaturesEnabled` true.
- Notes: field-absence trap - tenants without qualifying Windows licensing get
  `hasValidWindowsLicense=false` and should render as a licensing finding, not a bare fail;
  surface the two booleans separately in evidence so the two failure reasons aren't
  conflated.

**RESOLVED (2026-08-16):** the original research entry's own Authority URL,
`windows/privacy/manage-windows-1809-endpoints`, was live-fetched and found to be an
unrelated page about Windows network endpoints, not the data-processor topic. It was
already dropped from the shipped descriptor - `TP.INT.0009.psd1`'s
`References.Authorities` carries only
`https://learn.microsoft.com/en-us/intune/privacy/enable-windows-diagnostic-data` and the
Graph resource doc, matching `Test-PulseWindowsDataProcessorEnabled.ps1`'s own docstring
note ("...was live-fetched and found to be an unrelated page... it was NOT used in this
descriptor's References.Authorities").

**RESOLVED (2026-08-16):** this research entry's own earlier framing asserted the cited
Authority page supports a GDPR-defined-CONTROLLER / EU-Data-Boundary reading of this
setting. Live re-fetched: the page never mentions GDPR, controller, or Data Boundary - it
describes two independent toggles, both default Off, gating overlapping-but-not-identical
feature sets (diagnostic-data enablement gates compatibility/expedite reports plus
driver/expedited/feature update failure alerts; license verification gates
compatibility/expedite reports plus Remediations). `TP.INT.0009.psd1`'s
Consulting.WhatItMeans/WhyItMatters text was corrected to match this on 2026-08-16 (see
that file's own git history) - any remaining GDPR mention there is explicitly the
author's own contextual note, not attributed to the cited Authority.

## TP.INT.0011 — Default branding profile customized

Whether the tenant's default Intune branding profile has a non-default displayName or
privacyUrl, or more than one branding profile exists.

- Claim: The default Intune company branding profile (shown in the Company Portal /
  enrollment UI) has been customized beyond Microsoft's blank defaults (organization name
  and/or privacy URL set), or more than one branding profile exists for role/scope-based
  branding.
- Authority: Maester https://maester.dev/docs/tests/MT.1101 ; https://learn.microsoft.com/en-us/intune/intune-service/apps/company-portal-app-branding
- Origin: Maester MT.1101 (`Test-MtTenantCustomization`, MIT, port)
- Data: `beta/deviceManagement/intuneBrandingProfiles`; descriptor:
  `DeviceManagement.BrandingProfiles.List` (beta)
- Severity rationale: Low - user-trust/anti-phishing hygiene (unbranded enrollment screens
  are harder for end users to distinguish from a spoofed prompt), not a technical control.
- Notes: pass condition is an OR: default profile has `displayName` or `privacyUrl` set, OR
  `count > 1`. A tenant with exactly one still-blank default profile fails even if it never
  matters operationally (e.g., fully kiosk/Autopilot-only fleet) - this is a low-confidence
  finding, so consulting text should soften accordingly.

## TP.INT.0012 — Windows Feature Update policy avoids end-of-support builds

Whether every configured Windows Feature Update deployment profile targets a build whose
`endOfSupportDate` is still in the future, as of the snapshot's own evaluation cutoff
(never wall-clock "now" - see `Test-PulseFeatureUpdatePolicyAvoidsEos.ps1`'s own
determinism note).

- Claim: No Windows Feature Update deployment profile targets a Windows version/build that
  has already reached Microsoft's end-of-support date, which would leave targeted devices
  without security updates.
- Authority: Maester https://maester.dev/docs/tests/MT.1102 ; https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education
- Origin: Maester MT.1102 (`Test-MtFeatureUpdatePolicy`, MIT, port)
- Data: `beta/deviceManagement/windowsFeatureUpdateProfiles`; descriptor:
  `DeviceManagement.WindowsFeatureUpdateProfiles.List` (beta)
- Severity rationale: High - devices pinned to an EOS build receive no further security
  patches; fails when any profile's `endOfSupportDate` is in the past.
- Notes: distinct object from the already-seeded `TP.INT.0004` (≥2 update rings, which
  reads `windowsUpdateForBusinessConfiguration` under `deviceConfigurations`) - do not
  merge; feature update profiles are a separate beta resource governing OS *version*
  targeting, rings govern deferral/deadline cadence. Skip-if-none-configured (not a fail)
  mirrors Maester's behavior.

## TP.INT.0013 — Intune RBAC groups protected via RMAU or role-assignable groups

Whether every group backing an Intune RBAC role assignment is either scoped to a
Restricted Management Administrative Unit or is an `isAssignableToRole` group - i.e.
cannot have members silently added by an administrator outside the intended
privileged-role governance path.

- Claim: Every Entra group used as a member target on an Intune RBAC role assignment is
  either a Restricted Management Administrative Unit (RMAU) scope or an
  `isAssignableToRole` group, so Global Admins/other broad roles can't silently add
  themselves to an Intune-privileged group.
- Authority: Maester https://maester.dev/docs/tests/MT.1103 ; https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept
- Origin: Maester MT.1103 (`Test-MtIntuneRbacGroupsProtected`, MIT, port)
- Data: `beta/deviceManagement/roleDefinitions` →
  `beta/deviceManagement/roleDefinitions/{id}/roleAssignments` →
  `beta/deviceManagement/roleAssignments/{id}` →
  `v1.0/groups/{id}?$select=displayName,isManagementRestricted,isAssignableToRole,id`;
  descriptor: `DeviceManagement.RbacGroupProtection.Walk` (composite, 4-call fan-out)
- Severity rationale: High - an unprotected group backing an Intune RBAC role is a
  privilege-escalation path (self-nomination via ordinary group-membership rights).
- Notes: requires Entra ID P1 AND Intune license (dual license gate) - fan-out call shape
  (N role definitions × M assignments × K groups) - budget/paginate carefully, this is the
  most expensive Maester Intune port call graph. Evidence must list every offending group
  by name.

## TP.INT.0014 — BitLocker full-disk encryption enforced via Endpoint Security policy

Whether at least one Endpoint Security Disk Encryption (`templateFamily
endpointSecurityDiskEncryption`) policy resolves the BitLocker CSP system-drive
encryption-type setting to Full encryption (not used-space-only, not unconfigured).

- Claim: At least one Endpoint Security Disk Encryption policy (Settings Catalog, endpoint
  security surface) sets the Windows OS drive encryption type to full encryption (not
  used-space-only, not unconfigured).
- Authority: Maester https://maester.dev/docs/tests/MT.1123 ; https://learn.microsoft.com/en-us/intune/intune-service/protect/endpoint-security-disk-encryption-profile-settings
- Origin: Maester MT.1123 (`Test-MtBitLockerFullDiskEncryption`, MIT, port)
- Data: `beta/deviceManagement/configurationPolicies?$filter=templateReference/templateFamily eq 'endpointSecurityDiskEncryption'&$select=id,name,description,templateReference`
  then `beta/deviceManagement/configurationPolicies('{id}')/settings?$expand=settingDefinitions&$top=1000`;
  descriptor: `DeviceManagement.EndpointSecurityPolicies.ByTemplateFamily` (beta,
  parameterized on templateFamily)
- Severity rationale: Critical - unencrypted disks on lost/stolen devices expose data at
  rest with no compensating control; CIS Intune Windows 11 benchmark and CIS M365 §4 both
  treat disk-encryption enforcement as baseline.
- Notes: matches only policies created through the "Endpoint security > Disk encryption"
  blade (templateReference route). Does **not** catch BitLocker CSP settings pushed
  through a generic Settings Catalog profile outside that blade - see `TP.INT.0031` for
  the settings-expansion complement that closes this gap. Suffix-matching on setting
  option values (`_1` = full encryption) is opaque-ID-dependent; verify against the live
  tenant's settings-catalog schema before shipping, not just against Maester's hardcoded
  suffix.

**PENDING VERIFICATION (carried through from the shipped rule's own hedge, not resolved
here):** `Test-PulseBitLockerFullDiskEncryption.ps1`'s own docstring documents that
Maester's own function reads the resolved choice value's opaque suffix (`_1` = Full
encryption) directly off the raw BitLocker CSP setting row
(`device_vendor_msft_bitlocker_systemdrivesencryptiontype` and its child dropdown), and
that this suffix mapping is schema-version-dependent and has NOT been independently
re-verified against a live tenant's actual Settings Catalog schema from inside this task
- it is carried through from Maester's own source as-is. Whoever builds the composite
`endpointSecurityDiskEncryptionPolicies` descriptor must re-confirm this suffix mapping
against Ivy24 before this check's Pending dataset flag is dropped. Separately: the
"Full vs Used-space-only" behavioral claim in `TP.INT.0014.psd1`'s Consulting text is
supported by the BitLocker CSP reference
(`https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp`), not by
the deprecated pre-June-2023 `ref-disk-encryption-settings` page also listed in that
descriptor's Authorities - see that descriptor's own git history for the Authorities
reorder/annotation that makes this explicit.

## TP.INT.0015 — LAPS configuration policy meets minimum security bar

Whether at least one Windows LAPS Endpoint Security policy (`templateFamily
endpointSecurityAccountProtection`, LAPS template) has ALL FOUR of: backs up to Entra ID,
sufficient password complexity, sufficient password length, and a recognized
post-authentication reset action, on the SAME policy (criteria are never OR'd across
separate policies).

- Claim: At least one Windows LAPS (Local Administrator Password Solution) Endpoint
  Security policy backs up to Entra ID, enforces 4-class-or-higher password complexity,
  ≥14-character passwords, and a recognized post-authentication action (rotate on
  unlock/expiry).
- Authority: Maester https://maester.dev/docs/tests/MT.1177 ; https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords
- Origin: Maester MT.1177 (`Test-MtIntuneLAPSConfiguration`, MIT, port)
- Data: same `configurationPolicies` template-family pattern as TP.INT.0014 with
  `templateFamily eq 'endpointSecurityAccountProtection'`, further filtered client-side on
  the fixed LAPS template id (see the "template ID trap" note below for the value and its
  provenance); descriptor: `DeviceManagement.EndpointSecurityPolicies.ByTemplateFamily`
  (shared with TP.INT.0014, filter applied post-fetch)
- Severity rationale: High - weak/missing LAPS config leaves local admin credentials
  static or shared across the fleet, a classic lateral-movement enabler.
- Notes: template ID trap - the LAPS template GUID is hardcoded in Maester's
  implementation; confirm it hasn't rotated for the current Settings Catalog schema before
  porting verbatim. All four criteria must hold on the *same* policy (not OR'd across
  separate policies) per Maester's logic - mirror that exactly, a check that OR's across
  policies would be a meaningfully looser (wrong) bar.

**PENDING VERIFICATION (carried through from the shipped rule's own hedge, not resolved
here):** `Test-PulseLapsConfigurationMeetsBar.ps1`'s own docstring documents the LAPS
templateId this check client-side-filters on, `adc46e5a-f4aa-4ff6-aeff-4f27bc525796`, as
carried through AS-IS from Maester's own hardcoded value - it could not be independently
re-verified against a live tenant from inside this task ("the research entry's own
'template ID trap' note"). Whoever builds the composite `endpointSecurityLapsPolicies`
descriptor must re-confirm this GUID against Ivy24 before this check's Pending dataset
flag is dropped.

## TP.INT.0016 — Attack Surface Reduction "Standard Protection" baseline rules configured

The union of all ASR-templated Endpoint Security policies sets Microsoft's three
"Standard Protection" ASR rules (block abuse of vulnerable signed drivers, block LSASS
credential theft, block WMI-event-subscription persistence) to Block or Audit, not
Warn/Disabled/unconfigured.

- Authority: Maester https://maester.dev/docs/tests/MT.1178 ; https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
- Origin: Maester MT.1178 (`Test-MtIntuneASRRules`, MIT, port)
- Data: same `configurationPolicies` pattern as TP.INT.0014/0015, `templateFamily eq 'endpointSecurityAttackSurfaceReduction'`; descriptor: `DeviceManagement.EndpointSecurityPolicies.ByTemplateFamily` (shared)
- Severity rationale: High - LSASS credential-theft and WMI persistence are top ransomware
  precursor techniques; "Standard Protection" is Microsoft's own minimum-recommended ASR
  set.
- Notes: evaluates as a union across every ASR policy in the tenant, not per-policy - a
  rule set entirely by policy A and another entirely by policy B still counts as a
  combined pass. Only 3 of Defender's ~19 ASR rules are checked (the "Standard
  Protection" subset); this is intentionally a floor, not full ASR coverage.
- Task 3.3 scoping note: **RESOLVED: implemented in T3.4** (`Test-PulseAsrStandardProtectionRulesConfigured.ps1`).
  Implemented via Part A's settingPresenceIndex (`Data.Expansions = @('settingPresenceIndex')`),
  not the template-family-filtered `configurationPolicies` fetch this entry originally
  proposed - the settings-expansion layer answers the SAME "union across every ASR policy
  in the tenant" question this entry's own Notes already call for, from data already
  collected, without a second Graph fetch. Live-fetched
  https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
  (2026-08-17, confirmed live) for the exact GUIDs of the three "Standard protection
  rules": `56a863a9-875e-4185-98a7-b882c64b5ce5` (Block abuse of exploited vulnerable
  signed drivers), `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` (Block credential stealing from
  LSASS), `e6db77e5-3df2-4cf1-b95a-636979351e5b` (Block persistence through WMI event
  subscription); and
  https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender
  (2026-08-17, confirmed live) for the Policy CSP node path,
  `./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules`. The Settings
  Catalog `settingDefinitionId` string this check's map derives from that CSP path
  (`device_vendor_msft_policy_config_defender_attacksurfacereductionrules`, one
  GroupSettingCollection keyed per rule GUID) is **PENDING VERIFICATION against a live
  tenant** - carried through from the documented CSP path using this module's own
  established naming convention (see TP.INT.0014's own identical hedge for
  `device_vendor_msft_bitlocker_systemdrivesencryptiontype`), not independently confirmed
  against Ivy24's actual Settings Catalog schema from inside this task. See
  `Test-PulseAsrStandardProtectionRulesConfigured.ps1`'s own docstring for the full
  accounting.

## TP.INT.0017 — App Control for Business policy enforcing (not audit-only)

At least one App Control for Business (WDAC) policy is in Enforce mode with either
built-in controls selected or a non-empty uploaded XML payload.

- Authority: Maester https://maester.dev/docs/tests/MT.1179 ; https://learn.microsoft.com/en-us/intune/intune-service/protect/endpoint-security-app-control-policy
- Origin: Maester MT.1179 (`Test-MtIntuneAppControl`, MIT, port)
- Data: same `configurationPolicies` pattern, `templateFamily eq 'endpointSecurityApplicationControl'`; descriptor: `DeviceManagement.EndpointSecurityPolicies.ByTemplateFamily` (shared)
- Severity rationale: High - application allowlisting is one of the strongest single
  controls against unknown/novel malware, but only when enforced, not audited.
- Notes: audit-vs-enforce trap - a tenant can have App Control policies and still fail
  this check correctly, because audit-only policies provide zero real-world blocking.
  Empty-XML-upload is a second silent-failure mode.
- Task 3.3 scoping note: imported for record-completeness, not implemented in T3.3.

## TP.INT.0018 — Managed Installer rules paired with an enforcing App Control policy

A Managed Installer configuration is enabled AND is backed by an App Control policy that
is itself in Enforce mode with an active control.

- Authority: Maester https://maester.dev/docs/tests/MT.1180 ; https://learn.microsoft.com/en-us/intune/intune-service/protect/endpoint-security-app-control-policy#managed-installer
- Origin: Maester MT.1180 (`Test-MtIntuneManagedInstallerRules`, MIT, port)
- Data: same `configurationPolicies` pattern (same fetch as TP.INT.0017, different
  evaluation); descriptor: `DeviceManagement.EndpointSecurityPolicies.ByTemplateFamily` (shared)
- Severity rationale: High - Managed Installer without an enforcing base policy is a false
  sense of protection.
- Notes: dependency trap - this check can only meaningfully pass if TP.INT.0017 also
  passes.
- Task 3.3 scoping note: imported for record-completeness, not implemented in T3.3.

## TP.INT.0019 — Apple MDM Push (APNs) certificate valid for more than 30 days

The tenant's Apple Push Notification service certificate (required for all
iOS/iPadOS/macOS MDM management) has more than 30 days remaining before expiration.

- Authority: Maester https://maester.dev/docs/tests/MT.1092 ; https://learn.microsoft.com/en-us/intune/intune-service/enrollment/apple-mdm-push-certificate-get
- Origin: Maester MT.1092 (`Test-MtApplePushNotificationCertificate`, MIT, port)
- Data: `beta/deviceManagement/applePushNotificationCertificate`; descriptor:
  `DeviceManagement.ApplePushNotificationCertificate.Get` (beta)
- Severity rationale: Critical - an expired APNs cert makes ALL Apple devices
  unmanageable instantly and irreversibly (renewal must use the same Apple ID, and a
  lapse can force full re-enrollment of the entire Apple fleet); 30-day threshold matches
  Microsoft's own 30-day grace-period framing.
- Notes: 404 on this endpoint means no cert configured at all (distinct from "expiring
  soon") - render as a separate finding, not folded into the expiry message. Threshold
  (30) is hardcoded in Maester; keep it configurable rather than baking it in.

**RESOLVED (2026-08-17):** the Authority URL above,
`.../intune-service/enrollment/apple-mdm-push-certificate-get`, was originally reported (in
`Test-PulseApplePushCertificateValid.ps1`'s own docstring and the T3.3 report) as returning
a hard 404. A dual-review re-fetch found this is inaccurate: the URL REDIRECTS to the live,
current page (`https://learn.microsoft.com/en-us/intune/device-enrollment/apple/create-mdm-push-certificate`,
the URL this check's own Authorities already cite) rather than hard-404ing. The shipped
descriptor's citation is unaffected either way (it already points at the live,
redirect-target URL, not the redirecting one), but the "404" characterization itself was
wrong and is corrected here to "superseded/redirects" - distinct from TP.INT.0020's,
TP.INT.0023's, and TP.INT.0024's own original Authority URLs, all three of which were
re-verified as genuine hard 404s and are left as originally reported.

## TP.INT.0020 — Apple Automated Device Enrollment tokens valid and syncing

Every configured Apple ADE (Automated Device Enrollment, formerly DEP) token has more
than 30 days remaining before expiration and completed a successful sync today.

- Authority: Maester https://maester.dev/docs/tests/MT.1093 ; https://learn.microsoft.com/en-us/intune/intune-service/enrollment/automated-device-enrollment
- Origin: Maester MT.1093 (`Test-MtAppleAutomatedDeviceEnrollmentToken`, MIT, port)
- Data: `beta/deviceManagement/depOnboardingSettings`; descriptor:
  `DeviceManagement.DepOnboardingSettings.List` (beta)
- Severity rationale: Critical - an expired ADE token stops new Apple devices from
  auto-enrolling via zero-touch, and drops previously-enrolled device visibility until
  renewed.
- Notes: two independent pass/fail conditions per token - expiry (>30 days) AND sync
  recency (last successful sync = today, stricter than the ADE cert's own rule
  elsewhere). Don't collapse the two reasons into one evidence line. Zero tokens found is
  a skip, not a fail.

## TP.INT.0021 — Apple Volume Purchase Program tokens valid and syncing

Every configured Apple VPP (Volume Purchase Program, app licensing) token has more than
30 days remaining before expiration and synced within the last day.

- Authority: Maester https://maester.dev/docs/tests/MT.1094 ; https://learn.microsoft.com/en-us/intune/intune-service/apps/vpp-apps-ios
- Origin: Maester MT.1094 (`Test-MtAppleVolumePurchaseProgramToken`, MIT, port)
- Data: `beta/deviceAppManagement/vppTokens`; descriptor: `DeviceAppManagement.VppTokens.List` (beta)
- Severity rationale: High - expired VPP tokens stop licensed-app deployment/revocation
  to Apple devices; one severity step below APNs/ADE because it affects app delivery, not
  device management enrollment itself.
- Notes: same two-condition shape as TP.INT.0020 but with a looser sync window (≤1 day,
  not same-day) - don't copy TP.INT.0020's stricter threshold by mistake. Zero tokens =
  skip, not a fail.

## TP.INT.0022 — Android Enterprise connection bound, validated, and syncing

The tenant's Android Enterprise (managed Google Play) connection is bound and validated
(`bindStatus == boundAndValidated`), and its last app catalog sync succeeded within the
last day.

- Authority: Maester https://maester.dev/docs/tests/MT.1095 ; https://learn.microsoft.com/en-us/intune/intune-service/enrollment/connect-intune-android-enterprise
- Origin: Maester MT.1095 (`Test-MtAndroidEnterpriseConnection`, MIT, port)
- Data: `beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings`; descriptor:
  `DeviceManagement.AndroidManagedStoreAccountEnterpriseSettings.Get` (beta)
- Severity rationale: Critical - an unbound or stale Android Enterprise connection blocks
  Android device management wholesale for the whole Android fleet.
- Notes: `notBound` status is treated by Maester as a skip (tenant not using Android
  Enterprise), not a fail - only a previously-bound-then-broken connection should fail.
  Three-way AND condition (bind status, sync status, sync recency) - surface which leg
  failed in evidence.

## TP.INT.0023 — Intune Certificate Connectors healthy and on a supported version

Every registered Intune Certificate Connector (NDES/SCEP/PKCS bridge) is in an `active`
state, running at least version `6.2406.0.1001`, and has connected within the last hour.

- Authority: Maester https://maester.dev/docs/tests/MT.1097 ; https://learn.microsoft.com/en-us/intune/intune-service/protect/certificate-connector-linux-installation
- Origin: Maester MT.1097 (`Test-MtCertificateConnectors`, MIT, port)
- Data: `beta/deviceManagement/ndesConnectors`; descriptor: `DeviceManagement.NdesConnectors.List` (beta)
- Severity rationale: High - a stale/unhealthy certificate connector silently breaks
  certificate-based Wi-Fi/VPN/authentication profile delivery to new and renewing
  devices.
- Notes: hardcoded version floor trap - `6.2406.0.1001` will go stale as Microsoft ships
  connector updates; treat it as a "known good as of this research date" floor to
  verify/refresh at implementation time. Zero connectors found is a skip, not a fail.

## TP.INT.0024 — Mobile Threat Defense connectors enabled and syncing

Every configured Mobile Threat Defense (MTD) connector (Defender for Endpoint or a
third-party MTD partner) has `partnerState == enabled` and a heartbeat within the last
day.

- Authority: Maester https://maester.dev/docs/tests/MT.1098 ; https://learn.microsoft.com/en-us/intune/intune-service/protect/mtd-connector-configure
- Origin: Maester MT.1098 (`Test-MtMobileThreatDefenseConnectors`, MIT, port)
- Data: `beta/deviceManagement/mobileThreatDefenseConnectors`; descriptor:
  `DeviceManagement.MobileThreatDefenseConnectors.List` (beta)
- Severity rationale: High - a broken MTD connector silently stops device-risk signals
  from reaching compliance policies that key off them, so noncompliant/compromised
  devices can pass compliance unnoticed.
- Notes: zero connectors = skip (MTD not in use) - do not fail tenants without MTD
  configured.

## TP.INT.0025 — Personally-owned Windows device enrollment blocked

The Windows platform restriction in device-enrollment configuration blocks
personally-owned device enrollment, limiting Windows enrollment to corporate-authorized
paths (Autopilot, co-management, bulk provisioning, DEM).

- Authority: https://learn.microsoft.com/en-us/intune/device-enrollment/restrictions
- Origin: none (practitioner judgment from Microsoft's own enrollment-restrictions
  guidance - not a named Maester/ScuBA check)
- Data: `v1.0/deviceManagement/deviceEnrollmentConfigurations` filtered to
  `#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration`, property
  `windowsRestriction.personalDeviceEnrollmentBlocked`; descriptor:
  `DeviceManagement.EnrollmentConfigurations.PlatformRestrictions` (v1.0)
- Severity rationale: Medium - personal-device enrollment without restriction expands the
  unmanaged-endpoint attack surface, but is a deliberate BYOD choice for some orgs.
- Notes: restriction applies to user-driven enrollment only - Autopilot/co-management/bulk
  paths bypass it by design; don't fail this if the tenant's actual strategy is
  corporate-owned-only via Autopilot (cross-reference TP.INT.0026).

## TP.INT.0026 — Windows Autopilot deployment profile exists and is assigned

At least one Windows Autopilot deployment profile exists and has a non-empty assignment
(targets a group), so registered Autopilot devices actually receive an out-of-box
experience.

- Authority: https://learn.microsoft.com/en-us/autopilot/ ; https://learn.microsoft.com/en-us/intune/fundamentals/platform-guide-windows
- Origin: none (practitioner judgment)
- Data: `beta/deviceManagement/windowsAutopilotDeploymentProfiles?$expand=assignments`;
  descriptor: `DeviceManagement.WindowsAutopilotDeploymentProfiles.List` (beta)
- Severity rationale: Medium - no assigned profile means registered Autopilot devices
  don't get the intended zero-touch provisioning experience.
- Notes: Microsoft is actively transitioning classic Autopilot toward "device
  preparation" policies - a tenant fully migrated to device-preparation could
  legitimately show zero classic profiles; check device-preparation policy presence as an
  alternate pass path before implementation ships.

## TP.INT.0027 — No orphaned Windows Autopilot device identities

Every registered Windows Autopilot device identity is covered by at least one assigned
deployment profile.

- Authority: https://learn.microsoft.com/en-us/graph/api/resources/intune-enrollment-windowsautopilotdeviceidentity?view=graph-rest-1.0
- Origin: none (practitioner judgment)
- Data: `v1.0/deviceManagement/windowsAutopilotDeviceIdentities` cross-referenced against
  assigned-profile coverage from TP.INT.0026's dataset; descriptor:
  `DeviceManagement.WindowsAutopilotDeviceIdentities.List` (v1.0)
- Severity rationale: Low - an operational/logistics gap rather than a security control
  failure; evidence value is high for deployment planning even at low severity.
- Notes: composite check - needs both datasets (device identities AND deployment-profile
  assignments) reconciled; make the descriptor pairing explicit in `Data.Datasets`.

## TP.INT.0028 — Enrollment Status Page configured with blocking failure behavior

A Windows Autopilot Enrollment Status Page (ESP) profile is configured and assigned with
blocking behavior enabled (`allowDeviceUseOnInstallFailure = false` or install-failure
blocking equivalent).

- Authority: https://learn.microsoft.com/en-us/autopilot/enrollment-status ; https://learn.microsoft.com/en-us/intune/fundamentals/platform-guide-windows
- Origin: none (practitioner judgment)
- Data: `beta/deviceManagement/deviceEnrollmentConfigurations` filtered to
  `#microsoft.graph.windows10EnrollmentCompletionPageConfiguration`; descriptor:
  `DeviceManagement.EnrollmentConfigurations.ESP` (beta - no v1.0 equivalent as of this
  research date)
- Severity rationale: Medium - without ESP blocking, users can bypass an
  incomplete/failed provisioning run and start working on an under-configured,
  potentially noncompliant device.
- Notes: beta-only endpoint, no v1.0 fallback exists today. ESP has multiple
  sub-timeouts and app/profile block-lists; this check asserts the top-level blocking
  toggle only, not full ESP depth-of-config assessment.

## TP.INT.0029 — Security baselines assigned and not on a deprecated version

For each Intune security baseline family in use (Windows, Defender for Endpoint,
Microsoft Edge, Windows 365), at least one instance exists, carries assignments, and its
`templateReference` points to a template that is not flagged deprecated.

- Authority: https://learn.microsoft.com/en-us/intune/device-security/security-baselines/overview ; deprecation context: https://techcommunity.microsoft.com/blog/intunecustomersuccess/updates-to-beta-apis-for-windows-endpoint-security-and-administrative-templates/4357002
- Origin: none (practitioner judgment, drawn directly from Microsoft's baseline-versioning
  guidance)
- Data: `beta/deviceManagement/configurationPolicies?$expand=assignments`, matched on
  `templateReference.templateFamily in (baseline, baselineDefenderForEndpoint,
  baselineMicrosoftEdge, baselineWindows365)`; descriptor:
  `DeviceManagement.SecurityBaselines.AssignedAndCurrent` (beta, composite)
- Severity rationale: Medium - a deprecated-version baseline still enforces its settings
  (not a hard failure) but misses newer hardening additions; unassigned baseline
  instances are the more urgent half of this check.
- Notes: API-transition trap - per the March 2025 deprecation, `deviceManagement/intents`
  / `deviceManagement/templates` no longer support creating/managing baselines; only
  `configurationPolicies` with `templateReference` is current for v1 of this check.
  Per-setting drift vs. baseline default is explicitly out of scope for v1
  (assigned-and-current only) - deferred to Phase 5 baseline-diffing.

## TP.INT.0030 — Fleet compliance rate below acceptable threshold

The proportion of managed devices in a noncompliant state exceeds a configurable
threshold (default staged-rollout guidance target: <5% noncompliant before layering CA
enforcement on top).

- Authority: https://learn.microsoft.com/en-us/intune/device-security/compliance/overview (staged-rollout <5% noncompliance target)
- Origin: none (practitioner judgment; the <5% figure is Microsoft's own staged-rollout
  recommendation, not a formal SHALL/SHOULD baseline)
- Data: `v1.0/deviceManagement/managedDevices?$select=complianceState` (paged fleet scan)
  or the pre-aggregated `v1.0/deviceManagement/deviceCompliancePolicyDeviceStateSummary`
  per policy; descriptor: `DeviceManagement.ComplianceRate.Summary` (v1.0; prefer the
  summary endpoint over paging the full device list for large fleets)
- Severity rationale: Medium - this is a telemetry/trend check, not a binary control gap;
  severity should scale with how far above threshold the tenant sits.
- Notes: for v1, expressed as strict pass/fail against the threshold (graduated/scored
  scale deferred to Phase 5 rule-type-3/thresholded rules per the evaluator's current
  Phase 1 rule-type contract) - confirm this framing holds at implementation time.

**RESOLVED (2026-08-17):** two corrections to the entry above, both superseded by what
actually shipped in `Test-PulseFleetComplianceRateAcceptable.ps1` (`TP.INT.0030.psd1`):

1. **Scoring scheme.** This Notes section's own "for v1, expressed as strict pass/fail"
   framing did NOT hold at implementation time - the shipped check is a real three-tier
   Pass/Warn/Fail using the evaluator's existing Warn status (no Phase 5 thresholded
   rule-type was needed; Warn is already first-class in the Rule.Type 'Function' contract).
   Deferring to Phase 5 was an unnecessary hedge.
2. **Bucket adjudication (post-review HIGH fix, dual-review fix round).** The FIRST
   shipped version of this check only counted `complianceState -eq 'noncompliant'` toward
   the numerator - every other state (`conflict`, `error`, `inGracePeriod`, `configManager`,
   `unknown`, and any future/unrecognized value) silently fell through uncounted, meaning a
   fleet with unverifiable devices could Pass identically to a perfectly compliant one. The
   check now classifies every device into exactly three buckets - verified COMPLIANT
   (`compliant`), verified NONCOMPLIANT (`noncompliant`), and UNVERIFIED-OR-UNHEALTHY
   (everything else, fail-closed) - and a MATERIAL unverified share (>= 5% of the fleet)
   escalates the finding to Warn even when the verified-noncompliant rate alone is
   comfortably under 5%. See `Test-PulseFleetComplianceRateAcceptable.ps1`'s own docstring
   for the full per-state bucket mapping and rationale.
3. **"Microsoft's own staged-rollout guidance target" attribution.** Also already corrected
   in the shipped rule's own docstring (T3.3's original authoring pass) - neither the
   Authority URL nor a live web search could locate an official Microsoft "<5% noncompliant"
   SHALL/SHOULD figure anywhere. The 5%/10% bands are this check's own practitioner-judgment
   default, not a Microsoft citation - this entry's own Authority/Origin bullets above are
   the SUPERSEDED original research claim, kept for record-completeness, not the shipped
   check's actual position.

**TP.INT.0031 import (2026-08-17, Task 3.4 Part B):** imported from section C ("Setting-
level checks on Phase 2 expansion rows") of the ORIGINAL Phase 3 research record
(`/Users/Adam.Gell/repo/GraphKit/.claude/worktrees/intune-health-automation-v2-867eda/docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md`,
read-only reference, not itself part of this repo) - the settings-expansion-index
complement TP.INT.0014's own Consulting text and research entry already named as planned
future work. Implemented via Part A's settingPresenceIndex artifact
(`Data.Expansions = @('settingPresenceIndex')`), consuming
`$Context.ArtifactReader.GetSettingPresenceIndex()` - never a raw Graph fetch, never the
`configurationPolicies`-template-family pattern TP.INT.0014 itself uses.

## TP.INT.0031 — BitLocker CSP settings present and correct across all Settings Catalog policies

Across every expanded Settings Catalog policy (any creation path, not just the Endpoint
Security blade), the BitLocker CSP `SystemDrivesEncryptionType` setting resolves to
full-disk encryption on at least one policy this module can confirm is assigned.

- Authority: https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp (live-fetched 2026-08-17, confirmed live) - complements Maester MT.1123 (TP.INT.0014)
- Origin: none (practitioner judgment - extends MT.1123's template-scoped coverage using the settings-expansion layer)
- Data: Part A's settingPresenceIndex artifact (`expanded/settingPresenceIndex.<sha256>.json`), filtered by definitionId `device_vendor_msft_bitlocker_systemdrivesencryptiontype` across every family (settingsCatalog/compliance/deviceConfiguration)
- Severity rationale: Critical - same underlying risk as TP.INT.0014 (unencrypted disk at rest); severity is not lower just because the setting arrived through a different profile type.
- Notes: **dedupe trap with TP.INT.0014** (carried through from the original research
  entry) - this check and TP.INT.0014 are deliberately independent, non-suppressing
  signals over the same underlying risk (TenantPulse's finding schema has no cross-check
  suppression mechanism, same YAGNI-bounded scope as TP.INT.0006's own severity-escalation
  note) - a tenant whose only qualifying policy went through the Endpoint Security blade
  Passes both checks identically, which is intentional corroboration, not disagreement.
  **SETTING IDENTITY PENDING VERIFICATION** (same hedge as TP.INT.0014's own): the
  definitionId and its `_1` = Full-encryption option-id suffix are carried through
  unchanged from TP.INT.0014's own composite descriptor, not independently re-derived or
  re-verified against a live tenant's actual Settings Catalog schema from inside this
  task - see `Test-PulseBitlockerCspSettingsPresentAndCorrect.ps1`'s own docstring.
  **ASSIGNMENT-AWARE, beyond the original entry's own claim scope**: unlike TP.INT.0014
  (which does not itself check assignment), this check additionally requires the
  qualifying policy be confirmed ASSIGNED (Part A's own per-value `assignedPolicyCount`) -
  a correct value on an unassigned policy Fails here, disclosed as such, since an
  unassigned policy protects zero devices in practice.

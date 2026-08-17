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

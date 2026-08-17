# Phase 3 Intune check entries - research backfill

This file is the research record `References.Research` in
`source/Data/Checks/TP.INT.00{06,07,08,09,11,12,13,14,15}.psd1` points at. It was
reconstructed on 2026-08-16 to backfill resolutions that, until now, lived only in
rule-function docstrings and commit messages - each item below is marked
`RESOLVED (2026-08-16):` and cites exactly where the resolution already shipped in code,
so this file matches what actually shipped rather than restating it from scratch.

## TP.INT.0006 — Conflicting security-setting values across policies

Conflicting Settings Catalog / configuration policy values across two or more policies.
Per Microsoft's own guidance, a proven/possible assignment-scope conflict means Intune
"generates an error and doesn't apply either setting" - an enforcement gap, not a
last-writer-wins outcome. Ported check: `Test-PulseConflictingPolicySettings.ps1`
(TP.INT.0006), reading Task 2.6's `expanded/conflicts.json` artifact rather than a raw
Graph dataset.

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

## TP.INT.0009 — Windows diagnostic data processor configuration enabled

Whether both the "Enable features that require Windows diagnostic data in processor
configuration" toggle and the "I confirm that my tenant owns one of these licenses"
license-verification toggle are on (Tenant administration > Connectors and tokens >
Windows data, both default Off).

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

## TP.INT.0012 — Windows Feature Update policy avoids end-of-support builds

Whether every configured Windows Feature Update deployment profile targets a build whose
`endOfSupportDate` is still in the future, as of the snapshot's own evaluation cutoff
(never wall-clock "now" - see `Test-PulseFeatureUpdatePolicyAvoidsEos.ps1`'s own
determinism note).

## TP.INT.0013 — Intune RBAC groups protected via RMAU or role-assignable groups

Whether every group backing an Intune RBAC role assignment is either scoped to a
Restricted Management Administrative Unit or is an `isAssignableToRole` group - i.e.
cannot have members silently added by an administrator outside the intended
privileged-role governance path.

## TP.INT.0014 — BitLocker full-disk encryption enforced via Endpoint Security policy

Whether at least one Endpoint Security Disk Encryption (`templateFamily
endpointSecurityDiskEncryption`) policy resolves the BitLocker CSP system-drive
encryption-type setting to Full encryption (not used-space-only, not unconfigured).

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

**PENDING VERIFICATION (carried through from the shipped rule's own hedge, not resolved
here):** `Test-PulseLapsConfigurationMeetsBar.ps1`'s own docstring documents the LAPS
templateId this check client-side-filters on, `adc46e5a-f4aa-4ff6-aeff-4f27bc525796`, as
carried through AS-IS from Maester's own hardcoded value - it could not be independently
re-verified against a live tenant from inside this task ("the research entry's own
'template ID trap' note"). Whoever builds the composite `endpointSecurityLapsPolicies`
descriptor must re-confirm this GUID against Ivy24 before this check's Pending dataset
flag is dropped.

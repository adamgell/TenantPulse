# Phase 4 — Entra catalog: per-check research entries

Research entries for TenantPulse Phase 4 (roadmap P0.2). Numbering continues from the seed
checks (`TP.ENT.0001`–`TP.ENT.0005`, Phase 1 T1.9) — new entries here start at `TP.ENT.0006`.

Sources: [Maester catalog](2026-08-15-maester-catalog.md), [Microsoft official guidance](2026-08-15-microsoft-official-guidance.md),
[ScuBA + community baselines](2026-08-15-scuba-and-community-baselines.md), [CIS benchmarks + licensing](2026-08-15-cis-benchmarks-licensing.md).
EIDSCA endpoint/property/expected-value details below were verified 2026-08-16 directly against
the individual `maester.dev/docs/tests/EIDSCA.*` pages (not just the catalog summary) — one page
per representative control in each cluster; siblings in the same cluster share the same Graph
object and were cross-checked against the maester.dev EIDSCA index page's category grouping.

**Grouping rule applied (per task scope):** one entry per control cluster where controls share
an endpoint/policy object (e.g. all `authenticationMethodConfigurations('X')` controls for one
method X) — every EIDSCA ID covered by a cluster is listed in that entry's Claim/Notes.

---

## A. EIDSCA port (44 controls, T4.2)

### TP.ENT.0006 — FIDO2 security key authentication method configuration (EIDSCA.AF01–AF06)
- Claim: FIDO2 security keys are enabled as an authentication method (AF01: `state=enabled`),
  with self-service registration policy set intentionally (AF02), attestation enforced for
  phishing-resistance guarantees (AF03), key-restriction policy configured (AF04), the
  restriction set to allowed/blocked as intended (AF05), and specific AAGUIDs enumerated where
  key restriction is in use (AF06).
- Authority: https://maester.dev/docs/tests/EIDSCA.AF01 (and sibling AF02–AF06 pages); ScuBA `MS.AAD.3.1v1` (SHALL, phishing-resistant MFA) provides the security rationale for enabling FIDO2 specifically
- Origin: EIDSCA AF01–AF06 (MIT, port; https://maester.dev/docs/tests/eidsca/)
- Data: `beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Fido2')`;
  descriptor needed: `Entra.AuthenticationMethodsPolicy.MethodConfig` (beta, parameterized on
  method name — shared shape across every cluster in this section)
- Severity rationale: High (per EIDSCA's own severity tag on AF01/AF03/AF04/AF05); FIDO2 is one
  of the two Microsoft-recognized phishing-resistant methods (with certificate-based auth) —
  absence undermines the entire phishing-resistant-MFA control area (`TP.ENT.0018`).
- Notes: beta-only object, no v1.0 equivalent for authentication method configurations as of
  this research date. `state=enabled` alone doesn't guarantee attestation/restriction are set
  correctly — AF03–AF06 are meaningful even when AF01 passes; don't collapse to a single
  boolean. Attestation enforcement (AF03) specifically requires enterprise-attestation-capable
  keys — flag as a hardware-dependent finding, not purely a policy toggle.

### TP.ENT.0007 — Authentication methods policy general settings (EIDSCA.AG01–AG03)
- Claim: The legacy MFA/SSPR-to-unified-policy migration is complete or was never started fresh
  (AG01: `policyMigrationState in (migrationComplete, '')`), and suspicious sign-in-attempt
  reporting from the Authenticator app is enabled (AG02: state) with a defined include-target
  scope (AG03).
- Authority: https://maester.dev/docs/tests/EIDSCA.AG01 ; Microsoft's Sept 2025 legacy-policy deprecation notice (cited on the AG01 page)
- Origin: EIDSCA AG01–AG03 (MIT, port)
- Data: `beta/policies/authenticationMethodsPolicy` (top-level properties: `policyMigrationState`,
  `reportSuspiciousActivitySettings`); descriptor needed:
  `Entra.AuthenticationMethodsPolicy.Get` (beta, whole-object read — distinct from the
  per-method `MethodConfig` descriptor used by the other clusters in this section)
- Severity rationale: High (AG01, per EIDSCA tag) — an incomplete migration means legacy
  per-user MFA / SSPR policy can still silently override the unified policy's settings,
  undermining every other authentication-method check in this file.
- Notes: **evaluate this cluster before trusting AF/AM/AS/AT/AV results** — if migration is
  incomplete, the unified policy checks may not reflect actual enforced behavior; surface AG01
  as a gating/prerequisite finding in the report, not just one row among many.

### TP.ENT.0008 — Microsoft Authenticator method configuration (EIDSCA.AM01–AM04, AM06, AM07, AM09, AM10)
- Claim: Microsoft Authenticator is enabled (AM01), OTP fallback use is deliberately allowed or
  disallowed (AM02), number matching is required for push approvals with a defined scope
  (AM03/AM04), and app-name/geographic-location display in notifications is configured with its
  own scope (AM06/AM07, AM09/AM10) to help users spot fraudulent approval requests.
- Authority: https://maester.dev/docs/tests/EIDSCA.AM01 (and sibling pages for AM02–AM10)
- Origin: EIDSCA AM01, AM02, AM03, AM04, AM06, AM07, AM09, AM10 (MIT, port) — **AM05 and AM08 do
  not exist** in the EIDSCA control set (confirmed gap in the numbering, not an omission on our
  part; do not invent entries for them)
- Data: `beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('MicrosoftAuthenticator')`;
  descriptor needed: `Entra.AuthenticationMethodsPolicy.MethodConfig` (shared, method=
  `MicrosoftAuthenticator`)
- Severity rationale: High (AM01, per EIDSCA tag) — Authenticator push is the tenant's most
  widely deployed MFA method in most estates; number-matching absence is the specific control
  that closes MFA-fatigue/push-bombing attacks, a live attack pattern.
- Notes: number matching (AM03) and its target scope (AM04) are two separate controls — a
  tenant can have number matching "enabled" tenant-default but scoped to an empty group,
  effectively off; check both, don't treat AM03 alone as sufficient. Same pattern for
  AM06/AM07 and AM09/AM10 (state + scope pairs) — report state and scope as one combined
  finding per feature, not four independent rows that could be misread as unrelated.

### TP.ENT.0009 — SMS sign-in authentication method disabled (EIDSCA.AS04)
- Claim: SMS is not usable as a sign-in factor
  (`authenticationMethodConfigurations('Sms').includeTargets.isUsableForSignIn == false`) —
  SMS may still exist for other purposes but must not be a viable primary/MFA sign-in path.
- Authority: https://maester.dev/docs/tests/EIDSCA.AS04 ; ScuBA `MS.AAD.3.5v2` (SHALL: SMS, Voice, and Email OTP disabled)
- Origin: EIDSCA AS04 (MIT, port)
- Data: `beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Sms')`;
  descriptor needed: `Entra.AuthenticationMethodsPolicy.MethodConfig` (shared, method=`Sms`)
- Severity rationale: High — SMS/voice OTP is vulnerable to SIM-swap and SS7 interception;
  ScuBA rates this SHALL (federal-mandatory under BOD 25-01), the strongest criticality tier.
- Notes: this is per-`includeTargets` entry, not a single tenant-wide boolean — a tenant can
  have SMS disabled for most groups but still usable for a forgotten pilot/exception group;
  evidence must enumerate targets with `isUsableForSignIn=true`, not just report an aggregate
  pass/fail. Voice call has its own cluster below (`TP.ENT.0011`) — don't conflate the two even
  though ScuBA's `MS.AAD.3.5v2` covers both plus Email OTP (which has no EIDSCA control at all —
  a genuine coverage gap to flag, not silently skip).

### TP.ENT.0010 — Temporary Access Pass method configuration (EIDSCA.AT01–AT02)
- Claim: Temporary Access Pass is enabled (AT01: `state=enabled`) and configured for one-time
  use rather than reusable passes where appropriate (AT02), supporting secure onboarding flows
  that avoid emailing/verbally sharing initial passwords.
- Authority: https://maester.dev/docs/tests/EIDSCA.AT01 (and AT02)
- Origin: EIDSCA AT01, AT02 (MIT, port)
- Data: `beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('TemporaryAccessPass')`;
  descriptor needed: `Entra.AuthenticationMethodsPolicy.MethodConfig` (shared, method=
  `TemporaryAccessPass`)
- Severity rationale: Medium — absence is an operational-hygiene gap (orgs likely fall back to
  weaker onboarding methods like emailed temp passwords) rather than a direct exploitable
  control failure; below the High severity of the disable-weak-methods clusters.
- Notes: this is a positive-enablement check (want `enabled`), opposite polarity from
  TP.ENT.0009/0011 (want `disabled`) — make sure the check-authoring convention doesn't
  accidentally invert one of these when porting from the generated EIDSCA test file.

### TP.ENT.0011 — Voice call authentication method disabled (EIDSCA.AV01)
- Claim: Voice call is not enabled as an authentication method
  (`authenticationMethodConfigurations('Voice').state == disabled`), matching the SMS
  cluster's rationale.
- Authority: https://maester.dev/docs/tests/EIDSCA.AV01 ; ScuBA `MS.AAD.3.5v2` (SHALL, shared with TP.ENT.0009)
- Origin: EIDSCA AV01 (MIT, port)
- Data: `beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Voice')`;
  descriptor needed: `Entra.AuthenticationMethodsPolicy.MethodConfig` (shared, method=`Voice`)
- Severity rationale: High — same rationale/ScuBA citation as TP.ENT.0009.
- Notes: unlike AS04, this control checks top-level `.state`, not a per-target
  `isUsableForSignIn` — a simpler tenant-wide toggle; don't apply TP.ENT.0009's per-target
  evidence shape here, it's a single value.

### TP.ENT.0012 — Default authorization policy settings cluster (EIDSCA.AP01, AP04–AP10, AP14)
- Claim: A cluster of tenant-wide authorization defaults on the single `authorizationPolicy`
  object: admins cannot use SSPR for recovery (AP01, want `false`); guest invite restrictions
  are set deliberately (AP04); email-based subscription self-signup is restricted (AP05);
  join-by-email-verification is restricted (AP06); guest user role is the most-restricted
  option (AP07); a user consent policy is assigned rather than left default-open (AP08);
  risk-based user consent is not auto-allowed (AP09); default users cannot register apps
  (AP10, want `false`); default users cannot read other users' full profile beyond defaults
  (AP14).
- Authority: https://maester.dev/docs/tests/EIDSCA.AP01 (and sibling pages); ScuBA `MS.AAD.5.1v1`
  (SHALL: only admins register apps — maps to AP10) and `MS.AAD.7.x`/`MS.AAD.8.1v1` guest-access
  family (maps to AP04/AP07)
- Origin: EIDSCA AP01, AP04, AP05, AP06, AP07, AP08, AP09, AP10, AP14 (MIT, port) — **AP02,
  AP03, AP11, AP12, AP13 do not appear in the current 44-control EIDSCA set** and must not be
  invented
- Data: `beta/policies/authorizationPolicy` (single object, 9 properties read from it);
  descriptor needed: `Entra.AuthorizationPolicy.Get` (beta)
- Severity rationale: High for AP01, AP07, AP10, AP14 (privilege/role-boundary properties, per
  EIDSCA tags); Medium for AP04, AP05, AP06, AP08, AP09 (self-service/consent-hygiene
  properties, per EIDSCA tags) — apply per-property severity, not one blanket rating for the
  cluster.
- Notes: **single-object, nine-property fan-in** — one Graph call backs nine distinct findings;
  make sure the check authoring pattern reports nine separate evidence rows (each citing its
  own EIDSCA ID and severity) rather than one pass/fail for the whole object, or nine
  interrelated-but-independent misconfigurations get flattened into a misleading single result.
  AP10 doubles as the "only admins can register apps" control also cited by ScuBA
  `MS.AAD.5.1v1` — cite both authorities on that one property's finding.

### TP.ENT.0013 — Group/team owner and risk-based user consent restrictions (EIDSCA.CP01, CP03, CP04)
- Claim: Group/team owners cannot grant third-party apps consent to read group data on members'
  behalf (CP01, want `false`); user consent is blocked for apps Microsoft flags as risky (CP03);
  and users can raise an admin-consent request rather than being fully blocked with no path
  forward (CP04).
- Authority: https://maester.dev/docs/tests/EIDSCA.CP01 (and CP03, CP04); ScuBA `MS.AAD.5.2v1`
  (SHALL: user consent to apps restricted — the CISA citation named explicitly on the CP01 page
  as "SCuBA 2.7")
- Origin: EIDSCA CP01, CP03, CP04 (MIT, port)
- Data: `beta/settings` (directorySetting resource) filtered to the values backing CP01/CP03/
  CP04 (directorySettingTemplate context, distinct template from the Password/Group.Unified
  templates used elsewhere in this file); descriptor needed: `Entra.DirectorySettings.Values`
  (beta, parameterized on settingName — **verify the exact directorySettingTemplate id and
  setting names for CP03/CP04 at implementation time**, the CP01 fetch confirmed the `settings`
  endpoint pattern but CP03/CP04's precise setting names were not independently re-verified in
  this research pass)
- Severity rationale: High (CP01, CP03 per EIDSCA tags); Medium (CP04); user/group consent
  sprawl is the most common real-world path to a malicious OAuth app gaining tenant data access.
- Notes: UNVERIFIED — CP03/CP04's exact `settings.values` key names were not independently
  fetched (only CP01 was); do not hardcode a `settingName` string into the descriptor without
  confirming it against the live maester.dev CP03/CP04 pages or the generated EIDSCA test file
  first. Flagging per the task's instruction to surface anything not directly verified.

### TP.ENT.0014 — Admin consent request workflow configuration (EIDSCA.CR01–CR04)
- Claim: The admin consent request feature is enabled (CR01, want `true`), so a user blocked
  from self-consenting can request review rather than being dead-ended; reviewers get
  notified on new requests (CR02) and again near expiration (CR03); and the request duration is
  a deliberately chosen value, not left at the default (CR04).
- Authority: https://maester.dev/docs/tests/EIDSCA.CR01 (and CR02–CR04); ScuBA `MS.AAD.5.3v1`
  (SHALL: admin consent workflow configured for applications)
- Origin: EIDSCA CR01, CR02, CR03, CR04 (MIT, port)
- Data: `beta/policies/adminConsentRequestPolicy`; descriptor needed:
  `Entra.AdminConsentRequestPolicy.Get` (beta)
- Severity rationale: High (CR01, CR04 per EIDSCA tags — the feature being off is the
  meaningful failure); Medium (CR02, CR03, notification hygiene once the workflow exists).
- Notes: this cluster is the operational complement to TP.ENT.0013's consent *restriction*
  checks — restricting user consent (CP01/CP03) without an admin-consent-request path (CR01)
  turns "restricted" into "users have no legitimate path to get an app approved," which tends
  to produce shadow-IT workarounds; consider surfacing CR01 alongside CP03 in consulting text as
  a paired recommendation, not two unrelated findings.

### TP.ENT.0015 — Password Protection mode and smart lockout settings (EIDSCA.PR01–PR03, PR05, PR06)
- Claim: Password Protection is set to Enforce (not Audit-only) mode (PR01); the on-premises AD
  password-protection proxy/agent is enabled where hybrid (PR02); a custom banned-password list
  is enforced (PR03); and Smart Lockout thresholds — lockout duration (PR05) and lockout
  threshold (PR06) — are set to reasonable, deliberately-chosen values rather than defaults left
  untouched.
- Authority: https://maester.dev/docs/tests/EIDSCA.PR01 (and PR02, PR03, PR05, PR06); NIST/MITRE
  mapping cited on the PR01 page (TA0006 Credential Access / T1110 Brute Force)
- Origin: EIDSCA PR01, PR02, PR03, PR05, PR06 (MIT, port) — **PR04 does not appear in the
  current 44-control set**
- Data: `beta/settings` (directorySetting resource, Password Rule Settings
  directorySettingTemplate — distinct template object from the CP01/ST08 settings clusters);
  descriptor needed: `Entra.DirectorySettings.Values` (shared descriptor shape with TP.ENT.0013,
  different template id — **verify the Password Rule Settings template id at implementation
  time**; PR01's `Enforce` value and endpoint pattern were independently confirmed, PR02/PR03/
  PR05/PR06's exact setting-name strings were not)
- Severity rationale: High (PR01, PR02 per EIDSCA tags — mode/on-prem-enforcement are the
  binary gate); Medium (PR03, PR05, PR06 — tuning parameters once enforcement is on).
- Notes: UNVERIFIED beyond PR01 — same caution as TP.ENT.0013 applies to PR02/PR03/PR05/PR06's
  precise setting names; confirm against maester.dev's individual PR0x pages before hardcoding.
  Audit-vs-Enforce is the same trap pattern as `TP.INT.0017` (App Control) — a tenant "has
  Password Protection configured" in Audit mode looks superficially fine but blocks nothing;
  make the mode explicit in evidence, don't just report "Password Protection: present."

### TP.ENT.0016 — Guest group ownership and content access restrictions (EIDSCA.ST08–ST09)
- Claim: Guests cannot become owners of Microsoft 365 groups (ST08, want `false`) and guest
  access to group content is limited rather than treated identically to member access (ST09).
- Authority: https://maester.dev/docs/tests/EIDSCA.ST08 (and ST09); ScuBA `MS.AAD.8.1v1`
  (SHOULD: guests should have limited/restricted access to directory objects — cited by name on
  the ST08 page as "CISA SCuBA 2.18")
- Origin: EIDSCA ST08, ST09 (MIT, port)
- Data: `beta/settings` (directorySetting resource, Group.Unified directorySettingTemplate);
  descriptor needed: `Entra.DirectorySettings.Values` (shared descriptor shape, Group.Unified
  template — ST08's fetch confirmed this endpoint/template pairing; ST09's precise setting name
  was not independently re-fetched but follows the same documented Group.Unified template
  structure as ST08 with high confidence)
- Severity rationale: Medium (per EIDSCA tag on both) — guest-in-groups exposure is real but
  bounded by whatever the group actually contains; this is one layer of a broader guest-access
  posture, not the whole picture (see `TP.ENT.0023` for tenant-level cross-tenant/B2B controls).
- Notes: narrower in scope than it sounds — ST08/ST09 govern M365 *group* ownership/content
  specifically, not general external-collaboration invite policy (that's AP04, already in
  `TP.ENT.0012`) or B2B cross-tenant defaults (`TP.ENT.0023`, new object entirely). Keep these
  three guest-related checks distinct in consulting text so a reader doesn't assume fixing one
  closes the whole guest-access story.

---

## B. CISA/ScuBA + role/CA checks beyond the seeds (T4.3–T4.4)

### TP.ENT.0017 — MFA required for all users by an enforced Conditional Access policy
- Claim: At least one CA policy with `state == enabled` (not `enabledForReportingButNotEnforced`)
  targets all users (or all users minus documented exclusions) and grants MFA (or a stronger
  authentication-strength requirement) — the all-users complement to the already-seeded
  admin-scoped `TP.ENT.0005`.
- Authority: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength ; ScuBA `MS.AAD.3.2v2` (SHALL: MFA enforced for all users)
- Origin: none directly (Maester/CISA implement this as `Test-MtCisa*`, but the specific
  all-users-MFA check's Maester test ID was not independently confirmed in this research pass —
  treat as UNVERIFIED origin, author as a fresh implementation citing ScuBA + Microsoft Learn
  rather than claiming a Maester port)
- Data: `v1.0/identity/conditionalAccess/policies` (shared dataset with `TP.ENT.0003`–`0005`);
  descriptor needed: none — reuses the existing `ConditionalAccessPolicies.List` descriptor from
  Phase 1 seed checks
- Severity rationale: Critical — ScuBA rates the all-users MFA requirement SHALL (BOD 25-01
  mandatory tier); this is the single highest-leverage CA control in the whole catalog.
- Notes: **report-only vs. enforced trap, same as seeded TP.ENT.0004/0005** — Microsoft
  auto-deploys several of these policies in report-only by default (`managed-policies` doc); a
  tenant showing the policy "exists" but never toggled to On must fail, not NA. Reuse the shared
  exclusion-context (break-glass/service-account) work from T4.1 so break-glass accounts
  excluded from this policy don't register as a coverage gap.

### TP.ENT.0018 — Phishing-resistant authentication strength required for privileged roles
- Claim: At least one enforced CA policy applies an `authenticationStrength` grant of a
  phishing-resistant combination (FIDO2, certificate-based auth, or Windows Hello for Business)
  — not merely generic MFA — scoped to the current minimum 14 Microsoft-named privileged roles.
- Authority: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa ; ScuBA `MS.AAD.3.1v1` (SHALL, all users) and `MS.AAD.3.6v1` (SHALL, highly privileged roles specifically)
- Origin: none (practitioner judgment / fresh implementation — distinct from the seeded
  `TP.ENT.0005`, which only checks for *any* MFA grant, not an authentication-strength grant
  restricted to phishing-resistant methods)
- Data: `v1.0/identity/conditionalAccess/policies` (same dataset), evaluating
  `grantControls.authenticationStrength.id` against the built-in phishing-resistant strength
  GUID, cross-referenced against role-condition coverage of the 14 named roles; descriptor
  needed: none new — reuses `ConditionalAccessPolicies.List`; may need
  `Entra.AuthenticationStrengths.List` (`v1.0/policies/authenticationStrengthPolicies`) to
  resolve custom strength IDs if the tenant defines its own beyond the built-in one
- Severity rationale: Critical — this is meaningfully stronger than TP.ENT.0005's generic MFA
  bar; ScuBA rates both the all-users and privileged-role phishing-resistant requirements SHALL.
- Notes: **do not merge with TP.ENT.0005** — a tenant can pass "MFA required for admins" while
  still allowing SMS/voice OTP as the second factor, which is exactly the gap ScuBA `MS.AAD.3.6v1`
  targets; keep these as two checks with different bars so consulting language can distinguish
  "you have MFA for admins" (lower bar, already true) from "you have phishing-resistant MFA for
  admins" (higher bar, the actual recommendation).

### TP.ENT.0019 — Application and service principal credential hygiene
- Claim: No application or service principal has a password credential (client secret) with a
  lifetime exceeding 180 days, or a certificate credential exceeding 365 days, and ideally no
  password-credential (client secret) additions occur where certificate-based credentials are
  viable — matching ScuBA's app-credential lifetime guidance.
- Authority: https://learn.microsoft.com/en-us/graph/api/resources/application (passwordCredentials/keyCredentials shape); ScuBA `MS.AAD.5.5v1` (SHOULD: app password addition blocked), `MS.AAD.5.6v1` (SHOULD: app password lifetime ≤180 days), `MS.AAD.5.7v1` (SHOULD: app cert lifetime ≤365 days)
- Origin: none (practitioner judgment; also directly mirrors the Entra Recommendations API's
  "renew expiring app credentials" finding class described in the Microsoft guidance report,
  §4)
- Data: `v1.0/applications?$select=id,displayName,passwordCredentials,keyCredentials` and
  `v1.0/servicePrincipals?$select=id,displayName,passwordCredentials,keyCredentials`; descriptor
  needed: `Entra.Applications.Credentials.List` + `Entra.ServicePrincipals.Credentials.List`
  (both v1.0, `Application.Read.All`)
- Severity rationale: High — long-lived app secrets are a durable, easily-forgotten credential
  class; a leaked long-lived secret grants standing access with none of the rotation hygiene
  interactive user credentials get, and app-only compromises are a common real-world breach
  vector distinct from user-account compromise.
- Notes: this dataset can be **large** on tenants with heavy app-registration sprawl — page
  carefully and consider capping evidence to top-N oldest/longest-lived rather than enumerating
  every app; ScuBA's three sub-controls (block addition, ≤180d password, ≤365d cert) are all
  SHOULD not SHALL — reflect that in severity/tone versus the SHALL-tier CA checks above.

### TP.ENT.0020 — Global Administrator count within ScuBA's 2–8 SHALL range
- Claim: The tenant provisions between 2 and 8 (inclusive) users with the Global Administrator
  role — enough for break-glass/succession resilience, few enough to bound blast radius —
  distinct from and complementary to the already-seeded `TP.ENT.0002` (Microsoft's own <5
  guidance, which has no explicit floor).
- Authority: ScuBA `MS.AAD.7.1v1` (SHALL: 2–8 users provisioned with Global Administrator)
- Origin: none (fresh implementation citing ScuBA specifically; the seeded `TP.ENT.0002` cites
  Microsoft's role best-practices doc instead — same underlying dataset, two different
  authorities with different pass criteria)
- Data: same dataset as `TP.ENT.0002` — `v1.0/roleManagement/directory/roleAssignments` filtered
  to the Global Administrator role template ID; descriptor needed: none new, reuses
  `DirectoryRoleAssignments.List`
- Severity rationale: High — ScuBA rates this SHALL; the *floor* half of this check (fewer than
  2, i.e. single-admin risk) is arguably the more urgent failure mode and one Microsoft's own
  <5-only guidance doesn't capture at all.
- Notes: **deliberately duplicate-looking, not a duplicate** — TP.ENT.0002 and TP.ENT.0020 read
  the same Graph data but apply different pass/fail bars from different authorities (Microsoft
  guidance vs. ScuBA SHALL); present them as two rows citing two different authorities rather
  than merging, since a tenant with exactly 1 Global Admin passes TP.ENT.0002 (<5) but fails
  TP.ENT.0020 (needs ≥2) — that divergence is the whole point of keeping both.

### TP.ENT.0021 — Fewer than 10 total privileged role assignments
- Claim: The count of active assignments across all Entra roles flagged `isPrivileged=true`
  (not just Global Administrator) is below 10, per Microsoft's own role-hygiene guidance (the
  portal itself warns above this threshold).
- Authority: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices ("fewer than 10 privileged role assignments")
- Origin: none (practitioner judgment, directly from Microsoft's numeric guidance, distinct from
  any ScuBA/Maester ID)
- Data: `v1.0/roleManagement/directory/roleDefinitions?$filter=isPrivileged eq true` to get the
  privileged role set, then `v1.0/roleManagement/directory/roleAssignments` filtered to those
  role definition IDs; descriptor needed: `Entra.PrivilegedRoleAssignments.Count` (v1.0,
  composite — role-definition filter then assignment count)
- Severity rationale: High — broad privileged-role sprawl (not just Global Admin) is the
  realistic picture of blast radius in most tenants, since many high-impact roles
  (Application Administrator, Privileged Role Administrator, Exchange Administrator) sit
  outside Global Admin but carry serious lateral-movement/escalation potential.
- Notes: **expand transitive/group-assigned membership for accuracy** per the Microsoft
  guidance report — a role assigned to a group with 50 members undercounts badly if only direct
  assignments are read; this is a known accuracy trap the research report calls out explicitly,
  carry it into the implementation, not just this entry.

### TP.ENT.0022 — Zero permanent-active assignments for privileged roles (PIM posture)
- Claim: Every privileged-role assignment is either eligible-with-activation (PIM) or, if
  active, time-bound rather than permanent — permanent standing access to a privileged role
  defeats the purpose of PIM even when PIM is technically licensed and configured.
- Authority: ScuBA `MS.AAD.7.4v1` (SHALL NOT: permanent active role assignments for privileged
  roles); https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-deployment-plan
- Origin: none (fresh implementation citing ScuBA; the underlying Graph shape is described in
  the Microsoft guidance report's role-hygiene section but not tied to a specific check there)
- Data: `v1.0/roleManagement/directory/roleAssignmentScheduleInstances` (active, check
  `assignmentType`/`endDateTime` for permanence) vs.
  `v1.0/roleManagement/directory/roleEligibilityScheduleInstances` (eligible); descriptor needed:
  `Entra.PIM.RoleAssignmentScheduleInstances.List` + `Entra.PIM.RoleEligibilityScheduleInstances.List`
  (both v1.0, **require Entra ID P2**)
- Severity rationale: High — ScuBA rates SHALL; standing privileged access is the single most
  common finding in real-world Entra assessments and the specific gap PIM exists to close.
- Notes: **license gate is a first-class outcome, not an error** — per the Microsoft guidance
  report, a 400/403 on these endpoints on a non-P2 tenant is itself a finding ("PIM posture
  unassessable — Entra ID P2 required"), not a collection failure to hide; render it as an NA
  with an explicit licensing reason, never as a silent pass. Break-glass accounts are the one
  legitimate case for permanent Global Admin — cross-reference the shared exclusion/break-glass
  context from T4.1 so break-glass doesn't register as a false positive here.

### TP.ENT.0023 — Cross-tenant access default settings restrict inbound/outbound B2B collaboration
- Claim: The tenant's default cross-tenant access policy does not allow unrestricted inbound
  B2B collaboration from every external tenant, and outbound collaboration is scoped
  deliberately rather than left at Microsoft's permissive defaults — the tenant-wide B2B
  posture, distinct from the per-group guest controls in `TP.ENT.0016` and the invite-approval
  setting already covered in `TP.ENT.0012` (AP04).
- Authority: https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview ; ScuBA `MS.AAD.8.1v1` (SHOULD: guests should have limited/restricted directory access — the closest ScuBA anchor, though ScuBA's own guest-access policies concentrate on directory-object visibility rather than the cross-tenant-access object specifically)
- Origin: none (practitioner judgment — no Maester or ScuBA check reads this specific Graph
  object as of this research pass; flagged accordingly rather than force-fit to an ID)
- Data: `v1.0/policies/crossTenantAccessPolicy/default` (`b2bCollaborationInbound`,
  `b2bCollaborationOutbound` blocks); descriptor needed:
  `Entra.CrossTenantAccessPolicy.Default.Get` (v1.0)
- Severity rationale: Medium — default cross-tenant access is permissive out of the box by
  design (Microsoft's default allows inbound/outbound B2B broadly to support ad hoc
  collaboration), so this is a "verify it was a deliberate choice" finding rather than a clear
  violation; severity should not read as Critical/High without evidence the org has no
  legitimate broad-collaboration need.
- Notes: **distinct object from every other guest/consent check in this file** — don't conflate
  with AP04 (invite restrictions, `TP.ENT.0012`) or ST08/ST09 (group-level guest permissions,
  `TP.ENT.0016`); this is the tenant's outer B2B perimeter. Partner-specific overrides live at
  `v1.0/policies/crossTenantAccessPolicy/partners` — out of scope for a v1 default-only check,
  note as a depth gap.

### TP.ENT.0024 — Conditional Access coverage for workload identities (practitioner note)
- Claim: Where the tenant has service principals with credentials/permissions sensitive enough
  to warrant it, at least one CA policy scopes `conditions.clientApplications.includeApplications`
  to apply MFA-equivalent controls (compliant network location, certificate-based auth) to
  workload identities, not just interactive user sign-ins — Conditional Access for workload
  identities requires Entra ID Workload ID Premium.
- Authority: https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity ; https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview (licensing)
- Origin: none (practitioner judgment — this is a narrative/awareness-tier item, not a clean
  automatable pass/fail; documented here so it isn't silently dropped from the catalog, per the
  "a check with no research entry doesn't ship" rule cutting both ways — an unshippable idea
  still needs a paper trail explaining why)
- Data: `v1.0/identity/conditionalAccess/policies` filtered to policies whose
  `conditions.clientApplications` block is non-empty; descriptor needed: none new (reuses
  `ConditionalAccessPolicies.List`) — but evaluation logic can only assert "a workload-identity-
  scoped CA policy exists," not "the right service principals are covered," since there's no
  general Graph signal for "this SP is sensitive enough to need CA"
- Severity rationale: Low/Info — this ships as an awareness finding (informational: "0
  workload-identity CA policies found, consider whether any of your N service principals with
  privileged Graph permissions warrant one") rather than a scored pass/fail, because the
  "should you have one" judgment call can't be automated from data alone.
- Notes: **candidate for Info severity / non-scored finding rather than a full check** — flag
  this to whoever owns the Phase 4 T4.1 CA-normalization work as a judgment call: either (a)
  ship it as Info-severity with count-only evidence (service principals with
  `Application.ReadWrite.All`-class permissions, cross-referenced against CA coverage), or (b)
  cut it from v1 and leave this entry as the paper trail for why it was considered and deferred.
  Requires Workload ID Premium to *act* on findings even once detected — note that gate in
  consulting text so it doesn't read as free to fix.

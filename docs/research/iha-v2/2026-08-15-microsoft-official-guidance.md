# Microsoft Official Guidance Research: Entra + Intune Tenant Health Assessment Tool

Research report for IHA v2. Gathered 2026-08-15 via background research agent from learn.microsoft.com and official Microsoft sources.

Cross-cutting note on app-only feasibility: everything below marked "checkable" works with application permissions — the read-only set is roughly `Policy.Read.All`, `RoleManagement.Read.Directory`, `Directory.Read.All`, `SecurityEvents.Read.All`, `DirectoryRecommendations.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementServiceConfig.Read.All`, `DeviceManagementManagedDevices.Read.All`, `AuditLog.Read.All`, `Reports.Read.All`. Graph Intune APIs require the tenant to hold an active Intune license regardless of permission.

---

## 1. Intune Security Baselines (Windows, Edge, Defender)

**Source: Learn about Intune security baselines for Windows devices**

- URL: https://learn.microsoft.com/en-us/intune/device-security/security-baselines/overview
- What it is: Overview of Microsoft's pre-built, versioned hardening policy templates. Current catalog: Windows security baseline, Microsoft Defender for Endpoint baseline, Microsoft Edge baseline, Windows 365 baseline, and a STIG *audit-only* baseline.
- Claims about tenant objects: each baseline is a versioned template; separate baselines can carry the *same setting with different defaults* (Windows MDM vs Defender), so orgs must reconcile; Defender for Endpoint baseline is not recommended for VMs/VDI.
- Settings references: https://learn.microsoft.com/en-us/intune/device-security/security-baselines/ref-v2-edge-settings and .../ref-defender-settings enumerate every setting + baseline default (e.g., "Prevent bypassing SmartScreen warnings: Enabled") — these lists are the raw material for per-setting drift checks.

**Versioning & Graph queryability**

- Historically baselines were `deviceManagement/intents` instantiated from `deviceManagement/templates` (beta only). Template metadata (`securityBaselineTemplate`: `versionInfo`, `isDeprecated`, `intentCount`) is at https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceintent-securitybaselinetemplate?view=graph-rest-beta
- **Important deprecation**: per the Intune Customer Success blog (https://techcommunity.microsoft.com/blog/intunecustomersuccess/updates-to-beta-apis-for-windows-endpoint-security-and-administrative-templates/4357002), since late March 2025 `deviceManagement/templates` and `deviceManagement/intents` no longer support creating/managing Windows endpoint security policies; the replacement surface is **`beta/deviceManagement/configurationPolicies`** (Settings Catalog unified API), where baseline instances carry a `templateReference` identifying baseline family + version.
- Checkable claims (app-only, beta, `DeviceManagementConfiguration.Read.All`):
  - "A security baseline (Windows / Defender / Edge) exists and is assigned" — enumerate `beta/deviceManagement/configurationPolicies?$expand=assignments` and match `templateReference.templateFamily` (values like `baseline`, `baselineDefenderForEndpoint`, `baselineMicrosoftEdge`); legacy tenants: `beta/deviceManagement/intents`.
  - "Baseline is not on a deprecated version" — compare instance template version against template catalog `isDeprecated`/latest version.
  - Per-setting drift vs. baseline default is possible but expensive (settings addressed by opaque definition IDs on the old API; settings-catalog IDs on the new one). Recommend check-at-profile-level first, per-setting as stretch.

---

## 2. Conditional Access Guidance

**Source: Conditional Access templates / common policies**

- URL: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-common
- What it is: Microsoft's catalog of ~16 recommended policy templates (Secure Foundation / Zero Trust / Remote work / Protect admins / Emerging threats categories). Created in report-only by default; JSON exportable.

**Per-policy how-to pages** (each one is effectively a spec for one automated check):

- Require MFA for admins: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-require-mfa-admin (now points to phishing-resistant variant)
- Require phishing-resistant MFA for admins: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa — names the current minimum 14 roles to cover (Global Admin, Application Admin, Authentication Admin, Billing Admin, Cloud App Admin, CA Admin, Exchange Admin, Helpdesk Admin, Password Admin, Privileged Authentication Admin, Privileged Role Admin, Security Admin, SharePoint Admin, User Admin)
- Block legacy authentication: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication
- Require MFA for all users: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength
- Require device compliance: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance
- Require security-info registration protections: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration
- Block-access example: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-example

**Source: Microsoft-managed CA policies**

- URL: https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies — Microsoft auto-deploys certain policies (MFA for admins, MFA for Azure management, block legacy auth) in report-only; guidance says exclude break-glass and turn On.

**Source: Plan a Conditional Access deployment**

- URL: https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access — naming conventions, report-only first, avoid all-users/all-apps blocks without exclusions, service-account exclusion (use workload-identity CA for SPs).

**Source: Manage emergency access accounts**

- URL: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access — ≥2 cloud-only (`.onmicrosoft.com`) accounts, permanent Global Admin, phishing-resistant credentials, excluded from CA, monitored sign-ins, not tied to an individual.

**Checkable claims (app-only, `Policy.Read.All`; v1.0):**

- Enumerate policies: `GET v1.0/identity/conditionalAccess/policies` (https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0). From the returned objects you can automate:
  - An enabled (`state == "enabled"`, not reportOnly) policy requires MFA (or authenticationStrength with phishing-resistant combos) for admin directory roles covering all 14 currently named role IDs.
  - An enabled policy with `conditions.clientAppTypes` including `exchangeActiveSync`/`other` and `grantControls.builtInControls == ["block"]` (block legacy auth).
  - MFA-for-all-users policy exists; device-compliance/hybrid-join grant exists; no enabled policy blocks all users + all apps without exclusions.
  - Break-glass hygiene (heuristic): at least one account/group excluded from every blocking policy; cross-reference with permanent Global Admins.
- Compare against Microsoft's own templates: `GET v1.0/identity/conditionalAccess/templates` (https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-templates?view=graph-rest-1.0) — lets the tool cite Microsoft's template JSON as the norm rather than hardcoding it.
- Legacy-auth *usage* (not just policy) via sign-in logs `clientAppUsed` filter: `v1.0/auditLogs/signIns` (`AuditLog.Read.All`, requires Entra ID P1).
- Licensing constraint: CA requires Entra ID P1; tenants without it should use security defaults (https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults — security defaults state is checkable at `v1.0/policies/identitySecurityDefaultsEnforcementPolicy`).

---

## 3. Microsoft Secure Score

**Source: Microsoft Secure Score (Defender XDR)**

- URL: https://learn.microsoft.com/en-us/defender-xdr/microsoft-secure-score
- What it is: tenant-wide posture score aggregating improvement actions across categories: Identity (Entra), Device (Intune/Defender for Endpoint), Apps, Data. Microsoft shows *all* possible recommendations regardless of license (unlicensed actions count toward max score but aren't actionable). No extra license for Secure Score itself — it comes with the underlying M365/Defender subscriptions.

**Source: Identity Secure Score**

- URL: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-identity-secure-score — identity subset; available to free and paid tenants, some recommendations need paid licenses to act on. Being consolidated into Microsoft Secure Score / Entra recommendations.

**Graph API — fully readable app-only, v1.0:**

- `GET v1.0/security/secureScores` — per-day tenant score, 90 days retained, includes `currentScore`, `maxScore`, `controlScores[]` (per-control state), `averageComparativeScores` (https://learn.microsoft.com/en-us/graph/api/security-list-securescores?view=graph-rest-1.0)
- `GET v1.0/security/secureScoreControlProfiles` — control metadata: `controlCategory` (Identity/Device/...), `actionType` (Config/Review/Behavior), `remediation`, `implementationCost`, `userImpact`, `rank`, `deprecated`, tenant tags (ignored/thirdParty/reviewed) (https://learn.microsoft.com/en-us/graph/api/resources/securescorecontrolprofiles?view=graph-rest-beta; v1.0 equivalent exists)
- Permission: `SecurityEvents.Read.All` (application) — app-only confirmed.
- API overview: https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0
- Known quirk: `scoreInPercentage` disappeared from responses at one point — compute percentage yourself from currentScore/maxScore.
- Checkable claims: ingest all controlScores with `controlCategory in (Identity, Device)` and re-surface Microsoft's own scored recommendations (MFA registration, block legacy auth, self-service password reset, Intune compliance policies, etc.) with Microsoft's remediation text as the citation. This is the cheapest way to get a large, Microsoft-maintained check catalog "for free" — position bespoke checks as additive to, and cross-referenced with, Secure Score.

---

## 4. Entra Recommendations API (directory recommendations)

**Sources:**

- Overview: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/overview-recommendations
- How-to: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-use-recommendations
- Graph API overview: https://learn.microsoft.com/en-us/graph/api/resources/recommendations-api-overview?view=graph-rest-beta
- What it surfaces: daily-evaluated best-practice findings with impacted-resource lists — examples: convert per-user MFA to CA, minimize MFA prompts from known locations, migrate off Azure AD Graph (`aadGraphDeprecationApplication`/`aadGraphDeprecationServicePrincipal`), renew expiring app credentials, remove unused apps, migrate ADAL to MSAL, protect all users with a sign-in risk policy, use least-privileged roles, etc.
- Graph: **beta only** — `GET beta/directory/recommendations` and `GET beta/directory/recommendations/{id}/impactedResources` (portal caps impacted resources at 50; API returns all). Permission: `DirectoryRecommendations.Read.All` (application supported). Status values: active/postponed/dismissed/completedBySystem/completedByUser.
- Licensing: varies per recommendation — most core ones are free; risk-based ones need Entra ID P2; preview recommendations' license requirements "subject to change". The overview page carries the per-recommendation license table.
- Checkable claim: simply mirror active recommendations + impactedResources into the report with Microsoft's own text. Flag beta-endpoint fragility in architecture notes.

---

## 5. Zero Trust / Privileged Access & Role Hygiene

**Source: Best practices for Microsoft Entra roles**

- URL: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices
- Concrete numeric claims (excellent for automation):
  - **Fewer than 5 Global Administrator assignments** (portal shows an alert card at ≥5).
  - **Fewer than 10 privileged role assignments** overall (roles carrying the PRIVILEGED label; portal warns above 10).
  - Use least-privileged role per task; use PIM for just-in-time; keep **zero permanently active assignments** except emergency access accounts.
- Checkable app-only (`RoleManagement.Read.Directory` or `Directory.Read.All`, v1.0):
  - Global Admin count: `GET v1.0/directoryRoles(roleTemplateId='62e90394-69f5-4237-9190-012177145e10')/members` or `v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '62e90394...'` (expand transitive/group-assigned membership for accuracy).
  - Privileged-role count: roleDefinitions have an `isPrivileged` flag (v1.0) — count assignments across privileged definitions.
  - PIM posture: `v1.0/roleManagement/directory/roleAssignmentScheduleInstances` (active) vs `roleEligibilityScheduleInstances` (eligible) — ratio of permanent-active to eligible admins. **Requires Entra ID P2**; a 400/403 here is itself a licensing finding.
  - Break-glass: heuristics — permanent GA accounts that are cloud-only, excluded from CA policies, with recent-credential checks; sign-in alerting is out of scope for read-only but "no sign-in activity monitoring configured" can be noted.

**Source: PIM deployment plan** — https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-deployment-plan (zero standing access, approval workflows, access reviews).
**Source: Emergency access accounts** — https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access (see section 2).
**Source: Zero Trust deployment / privileged access guidance** — https://learn.microsoft.com/en-us/security/zero-trust/ (identity and endpoints pillars) and https://learn.microsoft.com/en-us/security/privileged-access-workstations/ — largely architectural; use for narrative framing/citations rather than checks.

---

## 6. Intune Operational Guidance

**Device compliance**

- Overview: https://learn.microsoft.com/en-us/intune/device-security/compliance/overview; Windows settings ref: https://learn.microsoft.com/en-us/intune/device-security/compliance/ref-windows-settings
- Claims: compliance policies should exist per platform; pair with CA "require compliant device"; configure actions for noncompliance; recommended staged rollout targeting <5% noncompliance before CA enforcement. A key implicit check: the tenant-wide **"mark devices with no compliance policy as compliant"** default should be set to Not Compliant.
- Checkable (v1.0, `DeviceManagementConfiguration.Read.All`): `GET v1.0/deviceManagement/deviceCompliancePolicies?$expand=assignments` (exists per enrolled platform, has assignments, has scheduledActionsForRule); tenant default via `v1.0/deviceManagement/settings` (`deviceComplianceCheckinThresholdDays`, `secureByDefault`); fleet compliance rate via `v1.0/deviceManagement/managedDevices` `complianceState` or `deviceCompliancePolicyDeviceStateSummary`.

**Windows Update for Business rings**

- https://learn.microsoft.com/en-us/intune/device-updates/windows/ and https://learn.microsoft.com/en-us/intune/device-updates/windows/manage-update-rings, settings ref https://learn.microsoft.com/en-us/intune/device-updates/windows/ref-update-ring-settings
- Claims: use multiple deployment rings (pilot → broad); quality deferral 0–30 days, feature deferral 0–365; deadline/grace settings recommended.
- Checkable (v1.0): `GET v1.0/deviceManagement/deviceConfigurations` filtered to `#microsoft.graph.windowsUpdateForBusinessConfiguration` (https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windowsupdateforbusinessconfiguration?view=graph-rest-1.0) — check ≥2 assigned rings, sane deferrals, deadlines configured. Feature/quality/driver update profiles are beta (`windowsFeatureUpdateProfiles`, `windowsQualityUpdateProfiles`).

**Enrollment restrictions**

- https://learn.microsoft.com/en-us/intune/device-enrollment/restrictions
- Claims: restrict personally-owned Windows enrollment (corporate-authorized methods only: Autopilot, co-management, bulk provisioning, DEM); restrictions apply to user-driven enrollment only; device-limit restrictions.
- Checkable: `GET v1.0/deviceManagement/deviceEnrollmentConfigurations` (`deviceEnrollmentPlatformRestrictionsConfiguration` — check `personalDeviceEnrollmentBlocked` per platform; richer per-platform single-restriction objects on beta).

**Windows Autopilot**

- Platform deployment guide: https://learn.microsoft.com/en-us/intune/fundamentals/platform-guide-windows; Autopilot docs under learn.microsoft.com/en-us/autopilot/ (note: Microsoft is transitioning classic Autopilot toward "device preparation" policies).
- Checkable (beta): `GET beta/deviceManagement/windowsAutopilotDeploymentProfiles` (profile exists, assigned) — https://learn.microsoft.com/en-us/graph/api/resources/intune-enrollment-windowsautopilotdeploymentprofile?view=graph-rest-beta; unassigned Autopilot device identities via `v1.0/deviceManagement/windowsAutopilotDeviceIdentities` (devices with no profile assigned = finding); ESP config in deviceEnrollmentConfigurations (`windows10EnrollmentCompletionPageConfiguration`, beta).

**Stale device cleanup**

- Intune cleanup rules: https://learn.microsoft.com/en-us/intune/governance/configure-cleanup-rules — rules hide (not delete/wipe) devices not checked in for N days; one rule per platform; shorter rule wins; does not touch Entra objects.
- Entra stale devices: https://learn.microsoft.com/en-us/entra/identity/devices/manage-stale-devices — use `approximateLastSignInDateTime`; disable-then-delete grace period; never delete system-managed (Autopilot) devices; Entra has no native auto-cleanup.
- Checkable: cleanup rule configured — beta `deviceManagement/managedDeviceCleanupSettings` / `managedDeviceCleanupRules`; stale-device inventory — `v1.0/devices?$filter=approximateLastSignInDateTime le {date}` (`Device.Read.All`/`Directory.Read.All`) and `v1.0/deviceManagement/managedDevices` `lastSyncDateTime`; report counts of devices inactive >90/180 days and disabled-but-not-deleted backlog.

---

## 7. Existing Microsoft Assessment Tooling (positioning)

- **Microsoft Zero Trust Assessment / Workshop** — https://learn.microsoft.com/en-us/security/zero-trust/assessment/overview and https://microsoft.github.io/zerotrustassessment/ — the **closest competitor**: open-source PowerShell module (`Connect-ZtAssessment`), read-only Graph scan producing hundreds of checks across 7 pillars (Identity + Devices/Intune included), Excel/roadmap output, SFI/CISA SCuBA-aligned. Differentiators available to IHA v2: app-only unattended scheduled runs (ZT assessment is interactive delegated sign-in + app-consent flow), trend history, custom scoring/reporting, MSP multi-tenant. Its open-source check catalog is also a legitimate reference for check design.
- **Microsoft Secure Score** (section 3) — continuous posture scoring; ingest/cross-reference, not duplicate.
- **Entra recommendations** (section 4) — in-product; mirror via Graph.
- **Intune Advanced Analytics / Endpoint Analytics** — https://learn.microsoft.com/en-us/intune/advanced-analytics/ and https://learn.microsoft.com/en-us/intune/endpoint-analytics/ — device health/experience (anomaly detection, device query, battery/boot scores), not config posture; licensed via Intune Suite add-on / Intune Plan 2, and per Dec 2025 licensing changes now included in M365 E3. Position as complementary (they answer "are devices healthy," we answer "is the tenant configured per Microsoft guidance").
- **Entra workbooks** (https://learn.microsoft.com/en-us/entra/identity/monitoring-health/overview-workbooks) — require Log Analytics diagnostic-settings export; interactive, not automated posture assessment.
- **Security Compliance Toolkit** (download center) — offline GPO baseline references; useful as the canonical baseline-settings source for citations.

---

## Highest-value automated checks (summary matrix)

| Check | Microsoft claim source | Graph endpoint | Version | App-only |
|---|---|---|---|---|
| <5 Global Admins | Entra roles best practices | `/roleManagement/directory/roleAssignments` + roleDefinitions | v1.0 | Yes |
| <10 privileged role assignments | same | same (`isPrivileged`) | v1.0 | Yes |
| PIM eligible vs permanent | PIM deployment plan | `/roleManagement/directory/roleEligibilityScheduleInstances` | v1.0 | Yes (P2) |
| ≥2 break-glass accounts, CA-excluded | security-emergency-access | policies + role assignments (heuristic) | v1.0 | Yes |
| CA: MFA (phishing-resistant) for admins | how-to-policy-phish-resistant-admin-mfa | `/identity/conditionalAccess/policies` | v1.0 | Yes |
| CA: block legacy auth | policy-block-legacy-authentication | same | v1.0 | Yes |
| CA: MFA all users / require compliant device | policy pages above | same | v1.0 | Yes |
| Security defaults state (fallback) | security-defaults | `/policies/identitySecurityDefaultsEnforcementPolicy` | v1.0 | Yes |
| Secure Score + Identity/Device controls | defender-xdr/microsoft-secure-score | `/security/secureScores`, `/security/secureScoreControlProfiles` | v1.0 | Yes |
| Entra recommendations mirror | overview-recommendations | `/directory/recommendations` | **beta** | Yes |
| Security baselines assigned & current | security-baselines/overview | `/deviceManagement/configurationPolicies` (templateReference); legacy `/intents` | **beta** | Yes |
| Compliance policy per platform + noncompliance actions | compliance/overview | `/deviceManagement/deviceCompliancePolicies` | v1.0 | Yes |
| "No policy = noncompliant" default | compliance/overview | `/deviceManagement/settings` | v1.0 | Yes |
| ≥2 WUfB rings, deferrals/deadlines | device-updates/windows | `/deviceManagement/deviceConfigurations` (windowsUpdateForBusinessConfiguration) | v1.0 | Yes |
| Personal Windows enrollment blocked | device-enrollment/restrictions | `/deviceManagement/deviceEnrollmentConfigurations` | v1.0 (richer beta) | Yes |
| Autopilot profile assigned; no orphaned identities | autopilot docs | `/deviceManagement/windowsAutopilotDeploymentProfiles` (beta), `windowsAutopilotDeviceIdentities` (v1.0) | mixed | Yes |
| Intune cleanup rule configured | governance/configure-cleanup-rules | `managedDeviceCleanupSettings`/`Rules` | beta | Yes |
| Stale Entra/Intune devices >90d | manage-stale-devices | `/devices`, `/deviceManagement/managedDevices` | v1.0 | Yes |
| Legacy auth actually in use | block-legacy-auth doc | `/auditLogs/signIns` (clientAppUsed) | v1.0 | Yes (P1) |

Key architectural findings: (1) the entire check catalog is achievable app-only read-only; (2) the notable beta dependencies are Entra recommendations, security-baseline/configurationPolicies, Autopilot profiles, and cleanup rules — isolate them behind a degradation layer; (3) licensing gates to detect and report rather than fail on: Entra P1 (CA, sign-in logs), P2 (PIM, risk-based recommendations), Intune license (all deviceManagement APIs); (4) the Microsoft Zero Trust Assessment is the incumbent to position against — its gaps are unattended/scheduled app-only operation, trending, and multi-tenant reporting.

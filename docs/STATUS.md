# TenantPulse - internal status (Phase 1 through Phase 4)

This is internal development/task narrative, moved out of README.md (post-review fix -
README.md is meant to read as a PSGallery landing page, not an implementation log). Nothing
here is required to install or use TenantPulse; see README.md for that.

## Phase 1 engine: complete

Collection, evaluation, scoring, and the deterministic pseudonymized JSON report all work
end to end through `Invoke-PulseAssessment`, and the whole pipeline has been
**live-smoke verified against a real tenant** (the Ivy24 lab tenant, Task 1.11): a fresh
`Invoke-PulseAssessment -ProfileId ivy24` run collected real Intune data
(`deviceCompliancePolicies`, `deviceConfigurations`, `deviceManagementSettings`,
`managedDevices`), degraded a permission gap honestly (`conditionalAccessPolicies` Skipped
with reason `permission-denied: Policy.Read.All`, its dependent checks NotApplicable rather
than silently wrong), left every not-yet-released GraphKit descriptor Skipped with
`descriptor-pending`, produced real Pass findings from the data that did collect, and
re-evaluating the same snapshot via `-FromSnapshot` reproduced a byte-identical findings
JSON. The tenant identifier appeared nowhere in the output tree except as its `tp-...`
pseudonym.

The live run also surfaced a real GraphKit 0.1.0 error-shape gap (its `Get-GraphObject`
throw carries no structured status code or `403`/`forbidden` text on failure) that made a
genuine permission denial misclassify as a generic failure instead of the honest-degradation
path above; that gap was fixed in the collector (a supplemental, read-only
`Invoke-GraphOperation` call recovers the real status code) with a regression test pinning
the fix against the real shape.

## Final fix wave (this pass)

A merged fix list from two independent reviews was implemented in full - contract fixes
(pseudonym-input source moved from `-ProfileId` to the resolved tenant id; `-Path`
parameters renamed to explicit `-OutputPath`/`-CatalogPath` with a deprecated alias),
snapshot-store boundary hardening (clear-on-reuse, manifest type validation, atomic
writes extracted into a shared helper), determinism/redaction fixes (a datetime
round-trip byte-drift bug, a culture-sensitive sort reaching document bytes, an
under-redacted evidence field, a DateTime-Kind-Unspecified handling bug in the canonical
serializer), check-logic fixes (a break-glass exemption that could wrongly exempt a
group/role-reachable account, an admin-MFA check that did not count `includeUsers: 'All'`
coverage, a dataset-status gate that enumerated bad statuses instead of failing closed on
any non-`Collected` status, a stale-device check that could silently fall back to
wall-clock time on a malformed manifest timestamp, an auth-abort loop that could overwrite
a Pending dataset's real reason), publish-tooling hardening (a shipped-file digest manifest
recorded at test time and verified at publish time, a `[SecureString]`/environment-variable
-only API key parameter, enum-typed HTTP status code handling, a silent supplemental-recovery
failure upgraded to a visible warning plus an artifact-level marker), and the public-facing
skin (this README, THIRD-PARTY-NOTICES.md, the `about_TenantPulse` help topic, pinned build
tool versions, an extended offline secret scan, and this file).

See the repository's git history and commit messages for the itemized, per-fix detail.

## GraphKit 0.1.1 migration (Task 1.11, complete)

GraphKit 0.1.1 is published to PSGallery and both pins (`source/TenantPulse.psd1`,
`RequiredModules.psd1`) are bumped. The migration:

- Deleted the `Get-PulseGraphFailureStatusCode` supplemental-probe workaround entirely -
  GraphKit 0.1.1's `Get-GraphObject` now throws an `ErrorRecord` with structured signal
  (`CategoryInfo.Category`, `TargetObject.Telemetry[-1].StatusCode`) directly, so no
  extra read-only Graph call is needed to recover a status code. `Get-PulseFailureClass`
  was rewritten to consume that ErrorRecord's structured data first, falling back to the
  rendered message only when neither signal is present.
- Dropped `Pending = $true` from all six DatasetMap.psd1 entries that had it
  (`securityDefaultsPolicy`, `directoryRoleAssignments`, `directoryRoleDefinitions`,
  `organization`, `organizationMdmAuthority`, `entraDevices`) - the static read-only QA
  gate (`tests/QA/ReadOnly.tests.ps1`) auto-upgraded all six to live catalog verification
  against installed GraphKit 0.1.1 and they pass the real Read/Safe predicate. The
  Pending mechanism itself stays covered by a synthetic fixture for the next descriptor
  that ships Pending.
- `./build.ps1 -Tasks pack` now produces `output/TenantPulse.0.1.0.nupkg` cleanly
  (GraphKit's `ExternalModuleDependencies` fix resolved the prior pack-time blocker).
  `scripts/Publish-TenantPulsePackage.ps1`'s dry run passes end-to-end (digest-manifest
  verification, no key, no publish).

**Two live-gate surprises, both fixed with regression tests** (first real run of the six
newly-live descriptors against a real tenant):

1. Two of the six datasets (`organization`, `directoryRoleAssignments`) carry the raw
   tenant GUID as a genuine Graph response FIELD (`Organization.id`,
   `DirectoryRoleAssignment.principalOrganizationId`), not merely a GraphKit provenance
   stamp. Fixed with a new `Protect-PulseGraphRowTenantId` helper, wired into
   `Write-PulseDataset`, that walks every row's value tree and redacts an exact match of
   the raw tenant id to its pseudonym before the dataset file is written. +5 regression
   tests in `Snapshot.Tests.ps1`.
2. `Protect-PulseGraphRowTenantId`'s first cut walked Hashtable-valued properties (e.g. a
   real `ConditionalAccessPolicy`'s `conditions`/`grantControls`, which GraphKit returns
   as `OrderedHashtable`, not `PSCustomObject`) via `.PSObject.Properties` - which
   surfaces a Hashtable's own adapter members (`Keys`, `Values`, `SyncRoot`, ...) rather
   than its dictionary entries. A non-synchronized Hashtable's `SyncRoot` IS the same
   hashtable, so the walk recursed into itself and blew PowerShell's call depth on every
   policy row (reproduced live: ~4s burned per row before falling back to the unredacted
   original - TOTAL-by-construction meant it never crashed the run, but it silently
   defeated the redaction on any Hashtable-nested tenant id and made collection
   pathologically slow). Fixed by walking `IDictionary` via its own `Keys`/`this[key]`
   entries, checked before the generic PSObject branch. +1 regression test pinning a
   Hashtable-nested tenant GUID redacts correctly and fast (<2s).

**Live gate re-run against Ivy24 after both fixes, clean**: all 11 datasets Collected
(including `securityDefaultsPolicy` - no 403; the tenant's granted `Policy.Read.All`
covers it), all 10 seed checks resolved with real statuses (5 Pass, 3 Fail, 1
NotApplicable, 0 Error), coverage 9/10 (90%), `-FromSnapshot` reproduced a byte-identical
findings JSON, and the raw tenant GUID appears nowhere in the output tree (datasets,
manifest, or findings) - only its `tp-...` pseudonym.

## Phase 4: core Entra catalog (complete, Task 4.5 phase gate)

Phase 4 took the catalog from 20 checks (Phase 1 seed + Phase 3's EIDSCA wave-1 clusters) to
**28** across five tasks: T4.1 (CA-policy and auth-method normalization views + a real
BreakGlassAccounts/ServiceAccounts exclusion context), T4.2 (EIDSCA wave-1, verified clusters),
T4.3 (EIDSCA wave-2, resolving every UNVERIFIED research flag before its check shipped), T4.4
(the ScuBA/CISA-cited Conditional Access, privileged-role, and credential-hygiene checks,
`TP.ENT.0017`-`0024`), and T4.5 (this task: cite-only CIS cross-reference support, the phase
gate, README/STATUS).

### T4.5 - CIS cross-references

Added an optional, cite-only `References.Cis` field to the check-descriptor schema (validated
only when present) and wired it through `Invoke-PulseEvaluation` into a document-level
`notices.cisDisclaimer` that fires only when at least one rendered finding carries a CIS
reference. Both directions (silent when none, firing when >=1, firing regardless of finding
order, Hashtable- and PSCustomObject-shaped `References` both read correctly) are covered by
new tests in `Evaluator.Tests.ps1`. **Zero of the 28 shipped checks carry a `References.Cis`
entry** - the Phase 4 research entries (`docs/research/iha-v2/2026-08-16-phase4-entra-check-
entries.md`) cite ScuBA/CISA, Maester/EIDSCA, and Microsoft Learn exclusively, with no verified
CIS mapping for any check in this catalog. The wiring is real and tested against synthetic
fixture data; it has nothing to cite yet on the live catalog. See README.md's "CIS compliance
disclaimer" section for the full picture.

### T4.5 - full-catalog live gate vs Ivy24

`Invoke-PulseAssessment -ProfileId ivy24 -OutputPath ./output/live-ivy24-t45 -Redact`, run from
this branch (`phase4/t4.1-normalization`) against the already-registered `ivy24` GraphKit
profile (certificate auth, `~/.graphkit/profiles.json`).

**Coverage: 21/28 assessed (75%)**. The 7 not-assessed checks are all honest `NotApplicable`,
not errors: `TP.ENT.0012` (the `authorizationPolicy`-backed cluster), `TP.ENT.0013`/`0015`/`0016`
(the three `directorySettings`-backed clusters), and `TP.ENT.0022`/`0023` (PIM posture,
cross-tenant access) are `descriptor-pending: awaiting
GraphKit release` - written, tested, cited, just waiting on GraphKit descriptors this catalog's
research already scoped. `TP.ENT.0001` (Security Defaults) is a genuine, correct
`NotApplicable`: this tenant runs Conditional Access, not Security Defaults, so the check
declines to evaluate a control the tenant deliberately superseded.

**Scores: overall 65.0/127.0 (51.2%)**. Hand-verified against the weight table (Critical=10,
High=6, Medium=3, Low=1, Info=0; Pass=full weight, Warn=half, Fail=0-but-counts-toward-possible,
NotApplicable excluded from the denominator entirely - `Add-PulseScores.ps1`) for two
categories, arithmetic below matching the findings JSON exactly:

- **Entra.ConditionalAccess** (assessed 6/6): `TP.ENT.0003` Critical(10) Fail=0,
  `TP.ENT.0004` High(6) Pass=6, `TP.ENT.0005` High(6) Pass=6, `TP.ENT.0017` Critical(10)
  Pass=10, `TP.ENT.0018` Critical(10) Fail=0, `TP.ENT.0024` Info(0) Pass=0.
  Possible = 10+6+6+10+10+0 = **42**. Earned = 0+6+6+10+0+0 = **22**. 22/42 = **52.4%** -
  matches the reported `earned:22.0, possible:42.0, percent:52.4`.
- **Entra.PrivilegedRoles** (assessed 3/4, `TP.ENT.0022` excluded as `NotApplicable`):
  `TP.ENT.0002` High(6) Fail=0, `TP.ENT.0020` High(6) Pass=6, `TP.ENT.0021` High(6) Fail=0.
  Possible = 6+6+6 = **18**. Earned = 0+6+0 = **6**. 6/18 = **33.3%** - matches the reported
  `earned:6.0, possible:18.0, percent:33.3`.

**Per-check status, all 28** (`status` / `reason`, `-Redact`ed evidence, tenant field
`tp-5de2c5ec...` pseudonym, never the raw GUID):

| Id | Status | Reason (verbatim, truncated where long) |
|---|---|---|
| TP.ENT.0001 | NotApplicable | Conditional Access is in use (4 enabled policies); Security Defaults is not evaluated as a standalone control here. |
| TP.ENT.0002 | Fail | (no reason string; evidence-only) |
| TP.ENT.0003 | Fail | No break-glass accounts are declared in the assessment profile (BreakGlassAccounts). |
| TP.ENT.0004 | Pass | 2 enabled CA policies block legacy authentication. |
| TP.ENT.0005 | Pass | All 9 of Microsoft's minimum admin roles are covered by MFA-requiring, enabled CA policies. |
| TP.ENT.0006 | Fail | FIDO2 attestation (AF03) and key restrictions (AF04) are not enforced. |
| TP.ENT.0007 | Fail | Suspicious sign-in reporting is not enabled (AG02, `state='default'`). |
| TP.ENT.0008 | Pass | Authenticator enabled, OTP fallback off, number matching + app-name display required tenant-wide. |
| TP.ENT.0009 | Fail | SMS still usable as a sign-in factor for 1 target group (`all_users`, AS04). |
| TP.ENT.0010 | Fail | Temporary Access Pass is disabled (AT01). |
| TP.ENT.0011 | Pass | Voice call is disabled (AV01). |
| TP.ENT.0012/0013/0015/0016 | NotApplicable | `descriptor-pending: awaiting GraphKit release` |
| TP.ENT.0017 | Pass | An enabled, enforced CA policy requires MFA for all users. |
| TP.ENT.0018 | Fail | 9 of 9 minimum admin roles lack an enforced phishing-resistant-strength CA policy. |
| TP.ENT.0019 | Fail | 1 of 12 evaluated SP credentials exceed ScuBA's lifetime guidance. |
| TP.ENT.0020 | Pass | (no reason string; evidence-only) |
| TP.ENT.0021 | Fail | 11 active privileged-role assignments across 36 privileged roles (direct-assignment count; see the check's documented group-expansion gap). |
| TP.ENT.0022/0023 | NotApplicable | `descriptor-pending: awaiting GraphKit release` |
| TP.ENT.0024 | Pass | 0 workload-identity-scoped CA policies found (Info, awareness-only, non-scored). |
| TP.INT.0001 | Pass | (no reason string; evidence-only) |
| TP.INT.0002 | Pass | Every enrolled platform (Windows) has a compliance policy. |
| TP.INT.0003 | Pass | (no reason string; evidence-only) |
| TP.INT.0004 | Pass | 4 Windows Update rings have deadlines configured. |
| TP.INT.0005 | Fail | 0/13 Intune-managed devices and 67/95 Entra-registered devices inactive >90d; 82 Entra-registered devices are not Intune-managed at all (population gap noted in evidence). |

`notices.cisDisclaimer` is `null` on this run (no finding carries a CIS reference, as expected -
see the T4.5 CIS section above), and `Import-PulseCheckCatalog`'s own count still pins at
exactly 28 (`CheckCatalog.Tests.ps1`).

### Suite

`./build.ps1 -Tasks build,test`: **1375 tests, 0 failed, 0 errors** (was 1366 before this task's
+9 net new Its). All four `MinimumTests` ratchet locations (`.build/AssertGateResult.tasks.ps1`,
`.github/workflows/ci.yml`, `scripts/Publish-TenantPulsePackage.ps1`,
`tests/QA/PublishTenantPulsePackage.tests.ps1`) bumped together in the same commit.

### Retrospective - what review rounds caught this phase

- **T4.1 (normalization layer):** the shape-neutrality fix round - CA-policy and auth-method
  views both needed to accept Hashtable- and PSObject-shaped input identically, a recurring
  theme every later task's fixtures had to keep honoring.
- **T4.2 (ci.yml ratchet miss):** the MinimumTests ratchet was bumped in
  `.build/AssertGateResult.tasks.ps1` but missed in `.github/workflows/ci.yml`, letting CI
  silently enforce a stale floor - the exact failure mode the "four locations, same commit"
  rule now exists to prevent, and this task re-verified all four before committing.
  **Lesson:** a ratchet with N tracking locations needs an explicit checklist step, not
  memory, every time the count changes - this task grepped for all occurrences of the old
  value before editing, specifically because of this history.
- **T4.3 (UNVERIFIED-flag resolution):** a genuine zero-fix review round - every flagged
  EIDSCA setting name had already been correctly re-verified against the live config source
  before review, nothing to fix. **Lesson:** the "five stages or defer with a ledger note"
  discipline from the task's own Definition of Done paid for itself here; nothing shipped on
  inference.
- **T4.4 (ScuBA/CISA checks):** the most consequential round - a fabricated authentication-
  strength GUID had been invented rather than sourced from a real Graph read (fixed by
  dropping the fabricated ID and reading the tenant's actual built-in strength), and
  `excludeRoles` exclusions were not being subtracted from `TP.ENT.0018`'s privileged-role
  coverage count, silently understating a real gap as smaller than it was (fixed to subtract
  documented exclusions and note them in evidence). **Lesson, carried into T4.5:** never
  invent an identifier a live Graph read can supply - this task's live-gate run was executed
  for real, against the real Ivy24 tenant, specifically because fabricating "what a live run
  would show" is the same failure class as T4.4's fabricated GUID, just at the report layer
  instead of the check-logic layer. Every number in the live-gate section above came out of
  the real `tenantpulse-findings.json` this run produced, not estimation.
- **T4.5 (this task):** the CIS cross-reference research entries turned out to carry zero
  actual CIS mappings - initially read as a possible gap in scope, confirmed correct by
  re-reading both the per-check research file and the licensing methodology doc: the research
  was written cite-only and deliberately conservative, and "add mappings where the research
  carries them" is correctly zero for this catalog. **Lesson:** a plan step reading as "should
  produce something" does not obligate inventing that something when the honest answer,
  checked directly against source, is "there is nothing here yet" - the same anti-fabrication
  discipline T4.4's fix round established.

## Not yet done - one thing, an operator action, not code

1. **First publish to PSGallery**, which needs a PSGallery API key. Publish tooling is
   ready (`scripts/Publish-TenantPulsePackage.ps1`) but defaults to a dry run and refuses
   to publish without a resolved API key and `-Confirm`; Adam runs it.

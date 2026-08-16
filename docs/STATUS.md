# TenantPulse Phase 1 - internal status

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

## Not yet done - three things, all operator actions, none of them code

1. **GraphKit 0.1.1 release.** TenantPulse's module manifest (`source/TenantPulse.psd1`)
   and `RequiredModules.psd1` both currently pin GraphKit 0.1.0, the version the live gate
   ran clean against. A separate, already-fixed-upstream GraphKit dependency-resolution bug
   is slated to ship in an unreleased GraphKit 0.1.1 - once it is published, bumping both
   pins is a version-bump/republish step, not a blocking defect for Phase 1 as shipped.
2. **`Policy.Read.All` grant on the Ivy24 lab app registration.** Without it,
   Conditional-Access-backed checks (`TP.ENT.0003`-`0005`) stay honestly NotApplicable
   rather than assessed - the pipeline proved it degrades correctly here, but coverage on
   that category stays at 0% until the grant lands.
3. **First publish to PSGallery**, which needs a PSGallery API key. Publish tooling is
   ready (`scripts/Publish-TenantPulsePackage.ps1`) but defaults to a dry run and refuses
   to publish without a resolved API key and `-Confirm`; Adam runs it.

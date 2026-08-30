# TenantPulse R1a Outcome Fidelity and Partial-Aware Evaluation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development` task by task, with a fresh implementation agent and an independent review for each task. Keep this checklist current as evidence lands.

**Goal:** Preserve GraphKit's outcome and certainty semantics through every TenantPulse collection path, then allow only explicitly reviewed Function checks to evaluate usable rows from a `Partial` dataset without turning unresolved scope into false reassurance.

**Architecture:** One total, provider-neutral mapper converts a caught GraphKit `ErrorRecord` into a bounded failure DTO. Every direct, composite, and expansion collector consumes that DTO instead of reinterpreting errors. The check catalog gains an opt-in `Data.PartialDatasets` contract; the evaluator passes deep-cloned rows plus an allowlisted `DatasetOutcomes` projection only to validated Function rules. Existing checks remain fail-closed. Four monotonic checks opt in: two universal checks may prove a known failure, and two existential checks may prove a known pass; all other partial cases remain `NotApplicable`.

**Tech stack:** PowerShell 7.4/7.6, Pester 6.1.0, Sampler 0.120.1, ModuleBuilder 3.2.18, GraphKit 0.3.0.

**Spec:** GraphKit repository `docs/superpowers/specs/2026-08-19-graphkit-tenantpulse-product-program-design.md`, R1a.

## Fixed constraints

- Start from exact merged TenantPulse main `4b00f4991cdc254dce4e82aab0cda73a73cd58d1`, verified by main CI run `33322546604`: six OS/PowerShell jobs plus gitleaks green, 2,288 tests in each matrix job.
- Keep TenantPulse source at the unique unreleased `0.3.0` identity. Public TenantPulse 0.2.0 and its archive SHA-256 `a0d5ff793b92753ab3efb4db20cf5bcf8b953e3cf81bf1a776c96a3d992417bd` remain immutable.
- Keep exact GraphKit `RequiredVersion = '0.3.0'` in the runtime manifest and restore pin. This tranche consumes the public GraphKit contract; it does not rebuild or relabel GraphKit.
- Work only in `.worktrees/program-completion` on `codex/r1a-outcomes-partial`; do not touch the dirty primary checkout.
- Pack before test. Never publish from this tranche. Publication remains a later exact-artifact gate.
- Snapshot schema remains 2.0 and findings schema remains 1.0. These changes expose no new serialized schema field.
- A live tenant is not required to prove deterministic error mapping or evaluator branching. Do not manufacture a live timeout, cancellation, permission failure, or ambiguous response merely for evidence.
- Reasons and findings may state aggregate gap counts, operation names, and bounded failure classes. They must not surface raw gap scopes, raw provider detail, tenant identifiers, tokens, or PII.

---

### Task 0: Freeze the exact merged baseline

**Files:**
- Create: this plan
- Verify only: `source/TenantPulse.psd1`
- Verify only: `RequiredModules.psd1`
- Verify only: `.build/AssertGateResult.tasks.ps1`

**Interfaces:**
- Consumes: merged-main SHA and CI evidence above.
- Produces: a clean local package/test baseline before runtime changes.

- [x] Confirm `HEAD` is `4b00f4991cdc254dce4e82aab0cda73a73cd58d1`, the branch is `codex/r1a-outcomes-partial`, and tracked status contains only this plan.
- [x] Confirm the manifest still declares TenantPulse 0.3.0 and exact GraphKit 0.3.0.
- [x] Run `./build.ps1 -Tasks pack`, then `./build.ps1 -Tasks test`.
- [x] Measured 2,290 tests: the 2,288 merged baseline plus the plan's two discovery-time Secret/PII and control-byte cases; zero failures/errors/skips/NotRun. Keep the synchronized floor at 2,288 until implementation's final measured ratchet.
- [ ] Commit the plan and baseline record as `docs: plan R1a outcome fidelity`.

### Task 1: Add the canonical total Graph failure mapper

**Files:**
- Create: `source/Private/Collect/Resolve-PulseGraphFailure.ps1`
- Create: `tests/Unit/Collect/GraphFailureResolution.Tests.ps1`
- Modify or remove after migration: `source/Private/Collect/Get-PulseFailureClass.ps1`
- Modify or remove after migration: `source/Private/Collect/Test-PulseErrorRecordHasStructuredSignal.ps1`
- Modify: `tests/Unit/Get-PulseTenantSnapshot.Tests.ps1`

**Interfaces:**
- Input: nullable/malformed `System.Management.Automation.ErrorRecord` whose `TargetObject` may be a GraphKit operation envelope.
- Output: exactly one `TenantPulse.GraphFailureResolution` object with `FailureClass`, `ReasonCode`, `AbortCollection`, `HasStructuredSignal`, and nullable `StatusCode`.
- Precedence: `Outcome = DeadlineExpired`; `Outcome = Cancelled`; otherwise `Certainty = Indeterminate`; then explicit 403/permission; then 401/authentication; then provider failure.

- [ ] Write parameterized failing tests for real-shaped GraphKit envelopes: `DeadlineExpired/Indeterminate`, `Cancelled/Indeterminate`, `Failed/Indeterminate`, HTTP 403, HTTP 401, HTTP 404/429/5xx, and a structure-free provider error.
- [ ] Prove envelope outcome/certainty wins over lossy status or message fallback: a deadline carrying status 403 remains `DeadlineExpired`; a cancelled envelope carrying auth-shaped text remains `Cancelled`; a non-special indeterminate envelope remains `Indeterminate`.
- [ ] Test enum and integer status codes, CategoryInfo fallback, message-only AADSTS/unauthorized/forbidden fallback, missing telemetry, null input, hostile property getters, malformed collections, and values whose string conversion throws. The mapper must never throw.
- [ ] Implement one exception-contained mapper. Use safe property access and `TryParse`; never bare-cast untrusted values. Map:
  - `DeadlineExpired` -> `FailureClass = DeadlineExpired`, `ReasonCode = deadline-expired`, `AbortCollection = false`.
  - `Cancelled` -> `Cancelled`, `cancelled`, `false`.
  - remaining `Certainty = Indeterminate` -> `Indeterminate`, `indeterminate`, `false`.
  - 403/permission -> `PermissionDenied`, `permission-denied`, `false`.
  - 401/AADSTS/token acquisition/unauthorized -> `AuthenticationFailed`, `authentication-failed`, `true`.
  - everything else -> `ProviderFailed`, `provider-failed`, `false`.
- [ ] `HasStructuredSignal` is true for a readable envelope `Outcome`/`Certainty`, a known GraphKit category, or readable last-attempt status. Message matching alone does not make it structured.
- [ ] Keep old private helpers only as logic-free transition wrappers if a same-task caller still needs them. By Task 2 completion there must be no production caller outside the canonical mapper; remove dead wrappers and migrate their tests if safe.
- [ ] Run the new mapper container and the migrated failure-classifier tests green.
- [ ] Commit as `feat: preserve Graph failure outcomes`.

### Task 2: Migrate every collection adapter atomically

**Files:**
- Modify: `source/Private/Collect/Invoke-PulseCollection.ps1`
- Modify: `source/Private/Collect/Invoke-PulseIntuneRbacGroupProtectionPlan.ps1`
- Modify: `source/Private/Collect/Invoke-PulseEndpointSecurityPolicyPlan.ps1`
- Modify: `source/Private/Collect/Invoke-PulseSecurityBaselinePlan.ps1`
- Modify: `source/Private/Collect/Invoke-PulseSubscribedSkuLicensePlan.ps1`
- Modify: `source/Private/Expand/Invoke-PulseSettingsCatalogPolicy.ps1`
- Modify: `source/Private/Expand/Invoke-PulseTypedPolicyExpansion.ps1`
- Modify: `tests/Unit/Get-PulseTenantSnapshot.Tests.ps1`
- Modify: `tests/Unit/Collect/ProviderPlanCollection.Tests.ps1`
- Modify: `tests/Unit/Collect/IntuneRbacGroupProtectionPlan.Tests.ps1`
- Modify: `tests/Unit/Collect/EndpointSecurityPolicyPlan.Tests.ps1`
- Modify: `tests/Unit/Collect/SecurityBaselinePlan.Tests.ps1`
- Modify: `tests/Unit/Collect/SubscribedSkuLicensePlan.Tests.ps1`
- Modify: `tests/Unit/Expand/SettingsCatalogExpansion.Tests.ps1`
- Modify: `tests/Unit/Expand/TypedPolicyExpansion.Tests.ps1`

**Interfaces:**
- Consumes: `Resolve-PulseGraphFailure` DTO.
- Produces: identical structured failure classes/reason codes in top-level outcomes and child gaps across all Graph-backed collection paths.

- [ ] Add focused red tests at every adapter boundary. Mock or inject real-shaped errors and assert `DeadlineExpired`, `Cancelled`, `Indeterminate`, `PermissionDenied`, `AuthenticationFailed`, and `ProviderFailed` survive into the persisted outcome or gap.
- [ ] Replace each `Get-PulseFailureClass` call and every local switch that re-collapses it with one mapper call. Use the DTO fields directly; no adapter may invent a second translation table.
- [ ] In `Invoke-PulseCollection`, persist a caught request failure as dataset `Status = Failed` for permission denied, deadline, cancellation, indeterminate certainty, and ordinary provider failure. A service-returned 403 is an attempted request and is not `Skipped`.
- [ ] Only `AuthenticationFailed` sets the run-wide network abort flag. Deadline, cancellation, permission, indeterminate certainty, and provider failures remain isolated to their dataset; later independent network work is still attempted.
- [ ] Preserve explicit no-request states outside this mapper: descriptor pending, platform unavailable, license/gate failures, and dependency unavailable may remain `Skipped` or their existing status because no service request was attempted.
- [ ] Preserve child operation identity, API version, row ordering, gap ordering, and provider name. Do not change the stable Endpoint Security operation set fixed in the prior train.
- [ ] Preserve existing expansion artifact category spellings for the three old cases: Settings Catalog settings/assignment failures remain `PermissionDenied`/`AssignmentPermissionDenied`, `AuthFailure`/`AssignmentAuthFailure`, and `FetchFailed`/`AssignmentFetchFailed`. Add distinct `DeadlineExpired`, `Cancelled`, and `Indeterminate` categories with the same `Assignment` prefix on the assignment side; do not silently break existing artifact consumers.
- [ ] Where a composite promotes child gaps to a top-level failure, preserve any uniform canonical `(FailureClass, ReasonCode)` tuple across all six classes and fall back to `ProviderFailed/provider-failed` only for mixed tuples. Do not special-case only permission and authentication.
- [ ] Add a collection dependency regression proving a `Partial` provider-plan result is persisted but is not inserted into `$collectedRows`; a later `IdFromDataset` child remains `DependencyUnavailable`. Only `Collected` satisfies collection dependencies.
- [ ] Add a source-contract assertion that production source outside `Resolve-PulseGraphFailure.ps1` contains no `Get-PulseFailureClass` or duplicate status/message classifier.
- [ ] Run all touched collector/expansion containers green, then run `pack` + the full suite before committing.
- [ ] Commit as `refactor: unify Graph failure mapping`.

### Task 3: Add the strict partial-awareness descriptor contract

**Files:**
- Modify: `source/Private/Checks/Test-PulseCheckDescriptor.ps1`
- Modify: `source/Private/Checks/Import-PulseCheckCatalog.ps1` only if object projection needs an explicit field
- Modify: `source/Data/Checks/README.md`
- Modify: `tests/Unit/CheckCatalog.Tests.ps1`

**Interfaces:**
- New optional descriptor field: `Data.PartialDatasets = [string[]]`.
- The field is an evaluator opt-in, never a collection dependency declaration.

- [ ] Write failing catalog tests for a scalar value, null/empty array, blank member, duplicate member, unknown dataset, dataset not listed in `Data.Datasets`, Expression rule use, and Function rule whose command lacks a `DatasetOutcomes` parameter.
- [ ] Write a passing test for a Function rule with one or more unique `PartialDatasets`, each a member of `Data.Datasets`, whose command declares `DatasetOutcomes`.
- [ ] Validate `PartialDatasets` only when present. It must be a non-empty string array, contain no ordinal duplicate, be a subset of `Data.Datasets`, and be legal only for `Rule.Type = Function`.
- [ ] Resolve `Rule.Function` first, then require its command metadata to declare a `DatasetOutcomes` parameter whenever `PartialDatasets` is present. A descriptor cannot claim partial awareness without an implementation able to receive the outcome projection.
- [ ] Do not add `PartialDatasets` to `Data.Datasets`, the dataset map, the collection manifest, or dependency ordering. It changes evaluation only.
- [ ] Document the field and monotonic safety rule in `source/Data/Checks/README.md`: universal checks may fail on a known offender but cannot pass with gaps; existential checks may pass on a known witness but cannot fail with gaps.
- [ ] Run catalog tests green and commit as `feat: validate partial-aware checks`.

### Task 4: Add fail-closed partial evaluation and an isolated outcome projection

**Files:**
- Modify: `source/Private/Evaluate/Invoke-PulseEvaluation.ps1`
- Modify: `source/Private/Evaluate/FindingsSchema.md`
- Modify: `tests/Unit/Evaluate/CollectionOutcomeEvaluation.Tests.ps1`
- Modify: `tests/Unit/Evaluator.Tests.ps1`

**Interfaces:**
- Function invocation for an opted-in check: `& <Rule.Function> -Datasets <deep clone> -DatasetOutcomes <deep-cloned allowlist> [-Context <clone>]`.
- `DatasetOutcomes[<name>]` exposes only `Status`, `FailureClass`, `ReasonCode`, `Detail`, `Provider`, `ApiVersion`, `Operations`, and `Gaps`.

- [ ] Add red evaluator tests proving every non-opted-in check still returns `NotApplicable` for `Partial`; Expression rules can never receive partial rows; missing/Failed/Skipped/unknown statuses remain fail-closed.
- [ ] For non-aware `Partial`, synthesize a bounded reason containing dataset name and gap count only. Do not quote manifest reason, scope, gap detail, or provider detail.
- [ ] For an opted-in Function check, read the usable rows from a valid Partial dataset, deep-clone them through the existing canonical JSON path, construct an allowlisted outcome projection for all declared datasets, deep-clone that projection independently, and pass it as `DatasetOutcomes`.
- [ ] Prove both inputs are isolated: a malicious test rule mutating rows, nested gap detail, operations, or the projection itself cannot change the dataset cache, manifest object, or what a later check sees.
- [ ] Fail closed if an opted-in partial entry has no usable rows, has no structured gaps, or cannot be projected safely. The check returns `NotApplicable` or `Error` as appropriate; it never silently executes as complete.
- [ ] Keep existing Function rules byte-for-byte compatible: pass `DatasetOutcomes` only when `Data.PartialDatasets` is present and validated. Existing `Context` opt-in remains independent.
- [ ] Do not serialize `DatasetOutcomes` into findings. Findings schema stays 1.0; snapshot schema stays 2.0.
- [ ] Run evaluator and collection-outcome tests green and commit as `feat: evaluate approved partial datasets`.

### Task 5: Opt in the four monotonic Intune checks

**Files:**
- Modify: `source/Data/Checks/TP.INT.0013.psd1`
- Modify: `source/Data/Checks/TP.INT.0014.psd1`
- Modify: `source/Data/Checks/TP.INT.0015.psd1`
- Modify: `source/Data/Checks/TP.INT.0029.psd1`
- Modify: `source/Private/Checks/Test-PulseRbacGroupsProtected.ps1`
- Modify: `source/Private/Checks/Test-PulseBitLockerFullDiskEncryption.ps1`
- Modify: `source/Private/Checks/Test-PulseLapsConfigurationMeetsBar.ps1`
- Modify: `source/Private/Checks/Test-PulseSecurityBaselinesAssignedAndCurrent.ps1`
- Modify: `tests/Unit/Checks/TP.INT.0013.Tests.ps1`
- Modify: `tests/Unit/Checks/TP.INT.0014.Tests.ps1`
- Modify: `tests/Unit/Checks/TP.INT.0015.Tests.ps1`
- Modify: `tests/Unit/Checks/TP.INT.0029.Tests.ps1`

**Interfaces:**
- Each descriptor opts in only its existing single dataset.
- Each Function adds a `DatasetOutcomes` parameter and preserves all complete-dataset behavior.

- [ ] TP.INT.0013 (universal RBAC protection): under Partial, any known unprotected group -> `Fail`; otherwise -> `NotApplicable`. It can never `Pass` while gaps remain.
- [ ] TP.INT.0014 (existential BitLocker policy): under Partial, any known qualifying full-disk policy -> `Pass`; otherwise -> `NotApplicable`. It can never `Fail` while gaps remain.
- [ ] TP.INT.0015 (existential LAPS policy): under Partial, any known policy meeting all four criteria -> `Pass`; otherwise -> `NotApplicable`. It can never `Fail` while gaps remain.
- [ ] TP.INT.0029 (universal baseline posture): under Partial, any known unassigned or deprecated baseline -> `Fail`; otherwise -> `NotApplicable`. It can never `Pass` while gaps remain.
- [ ] Partial result reasons state only the unresolved gap count and the monotonic decision. Evidence may describe known rows through the existing redaction path; it may not copy gap scope/detail into findings.
- [ ] Add hostile fixtures: zero usable rows, multiple gaps, mixed good/bad known rows, missing required row fields, malformed outcome projection, and mutation attempts. Preserve every existing complete, pending, gate-degraded, and field-absence assertion.
- [ ] Run the four check containers together, then evaluator/catalog containers, then `pack` + full suite.
- [ ] Commit as `feat: make four Intune checks partial aware`.

### Task 6: Reconcile compatibility and current-source documentation

**Files:**
- Modify: `source/TenantPulse.psd1`
- Modify: `tests/QA/ModuleManifest.tests.ps1`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/STATUS.md`
- Modify: `source/Data/Checks/README.md`
- Modify: `source/Private/Evaluate/FindingsSchema.md`

**Interfaces:**
- Current source remains unreleased TenantPulse 0.3.0 with exact GraphKit 0.3.0.
- Public TenantPulse 0.2.0 evidence remains historical and immutable.

- [ ] Add release notes for canonical Graph outcome mapping and reviewed partial-aware evaluation; do not claim the unreleased source is published.
- [ ] Document that request-time 403 is `Failed/PermissionDenied`, only authentication aborts subsequent network collection, and deadlines/cancellations/indeterminate certainty remain explicit.
- [ ] Document the exact four opted-in checks and their asymmetric monotonic semantics. State that all other checks remain `NotApplicable` on Partial.
- [ ] State explicitly that schemas did not change and no new live-service claim was made in this deterministic tranche.
- [ ] Preserve all current release hashes, merged SHAs, CI run IDs, test evidence, no-user/no-legacy premise, and exact dependency pins.
- [ ] Run focused manifest/release-truth QA green and commit as `docs: record R1a outcome contracts`.

### Task 7: Measure, ratchet, review, and merge the exact train

**Files:**
- Modify after measurement: `.build/AssertGateResult.tasks.ps1`
- Modify after measurement: `.github/workflows/ci.yml`
- Modify after measurement: `scripts/Publish-TenantPulsePackage.ps1`
- Modify after measurement: `tests/QA/TestProofGate.tests.ps1`
- Modify after measurement: `tests/QA/PublishTenantPulsePackage.tests.ps1`
- Modify after measurement: `docs/STATUS.md`

**Interfaces:**
- Produces one exact reviewed source head, one exact tested package artifact, six-job CI plus gitleaks, and a merged-main verification run.

- [ ] Run `./build.ps1 -Tasks pack`, then `./build.ps1 -Tasks test`. Record exact total, failures, errors, skipped, NotRun, package SHA-256, built manifest SHA-256, and built module SHA-256.
- [ ] Ratchet every synchronized minimum to the measured total only after the authoritative result exists. Update the floor history comment with an honest breakdown; set the negative floor fixture to measured minus one.
- [ ] Re-run `pack` then full `test` after the floor change. Confirm zero failures/errors/skips/NotRun and exact GraphKit 0.3.0 dependency in source, built module, package, and clean child-process import.
- [ ] Run the repo-local Secret/PII/control-byte scan and gitleaks. Inspect the diff for raw tenant IDs, client IDs, secrets, tokens, PII, gap scopes, or provider detail.
- [ ] Obtain independent task reviews and a final whole-branch review. Resolve every actionable finding; rerun the affected focused tests and authoritative full gate after fixes.
- [ ] Push `codex/r1a-outcomes-partial`, open one PR, run CodeRabbit, independently validate its findings, and resolve all threads.
- [ ] Require exact-head CI: PowerShell 7.4 and 7.6 on Windows, Ubuntu, and macOS, plus gitleaks, all green for the reviewed SHA.
- [ ] Merge only that reviewed SHA. Require the same merged-main matrix plus gitleaks green for the merge commit before starting R1b.
- [ ] Do not publish TenantPulse 0.3.0 from this train. Publication waits for the applicable R0-R11 program set and final package/live gates.

## Completion evidence for R1a

R1a is complete only when all of the following are true:

- One canonical mapper is the sole production interpreter of GraphKit error envelope outcome/certainty/status/message signals.
- Every direct, composite, and expansion path preserves the same failure class and reason code.
- A request-time 403 is Failed/PermissionDenied; only AuthenticationFailed aborts later network collection.
- Partial never satisfies a collection dependency.
- `Data.PartialDatasets` is strictly validated, Function-only, and requires `DatasetOutcomes`.
- Non-aware checks remain fail-closed; only TP.INT.0013, .0014, .0015, and .0029 opt in with the documented monotonic rules.
- Dataset rows and outcome projections are independently deep-cloned and do not leak into findings.
- Source, package, clean-process, exact-head CI, review, and merged-main gates are green, with documentation and floor synchronized to measured evidence.

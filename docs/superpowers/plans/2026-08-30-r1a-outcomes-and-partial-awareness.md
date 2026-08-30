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
- Function rules are trusted, reviewed code: the evaluator provides the structured `Gaps` projection but cannot prevent an arbitrary rule from copying raw projected values into a finding. The four built-in opt-ins must therefore prove with canaries that they emit only aggregate gap counts and reviewed row evidence.

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
- [x] Commit the plan and baseline record as `docs: plan R1a outcome fidelity` (`5664935`).

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

- [x] Write parameterized failing tests for real-shaped GraphKit envelopes: `DeadlineExpired/Indeterminate`, `Cancelled/Indeterminate`, `Failed/Indeterminate`, HTTP 403, HTTP 401, HTTP 404/429/5xx, and a structure-free provider error.
- [x] Prove envelope outcome/certainty wins over lossy status or message fallback: a deadline carrying status 403 remains `DeadlineExpired`; a cancelled envelope carrying auth-shaped text remains `Cancelled`; a non-special indeterminate envelope remains `Indeterminate`.
- [x] Test enum and integer status codes, CategoryInfo fallback, message-only AADSTS/unauthorized/forbidden fallback, missing telemetry, null input, hostile property getters, malformed collections, and values whose string conversion throws. The mapper must never throw.
- [x] Implement one exception-contained mapper. Use safe property access and `TryParse`; never bare-cast untrusted values. Map:
  - `DeadlineExpired` -> `FailureClass = DeadlineExpired`, `ReasonCode = deadline-expired`, `AbortCollection = false`.
  - `Cancelled` -> `Cancelled`, `cancelled`, `false`.
  - remaining `Certainty = Indeterminate` -> `Indeterminate`, `indeterminate`, `false`.
  - 403/permission -> `PermissionDenied`, `permission-denied`, `false`.
  - 401/AADSTS/token acquisition/unauthorized -> `AuthenticationFailed`, `authentication-failed`, `true`.
  - everything else -> `ProviderFailed`, `provider-failed`, `false`.
- [x] `HasStructuredSignal` is true for a readable envelope `Outcome`/`Certainty`, a known GraphKit category, or readable last-attempt status. Message matching alone does not make it structured.
- [x] Keep old private helpers only as logic-free transition wrappers if a same-task caller still needs them. By Task 2 completion there must be no production caller outside the canonical mapper; remove dead wrappers and migrate their tests if safe.
- [x] Run the new mapper container and the migrated failure-classifier tests green.
- [x] Commit as `feat: preserve Graph failure outcomes`.

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

- [x] Add focused red tests at every adapter boundary. Mock or inject real-shaped errors and assert `DeadlineExpired`, `Cancelled`, `Indeterminate`, `PermissionDenied`, `AuthenticationFailed`, and `ProviderFailed` survive into the persisted outcome or gap.
- [x] Replace each `Get-PulseFailureClass` call and every local switch that re-collapses it with one mapper call. Use the DTO fields directly; no adapter may invent a second translation table.
- [x] In `Invoke-PulseCollection`, persist a caught request failure as dataset `Status = Failed` for permission denied, deadline, cancellation, indeterminate certainty, and ordinary provider failure. A service-returned 403 is an attempted request and is not `Skipped`.
- [x] Only `AuthenticationFailed` sets the run-wide network abort flag. Deadline, cancellation, permission, indeterminate certainty, and provider failures remain isolated to their dataset; later independent network work is still attempted.
- [x] Preserve explicit no-request states outside this mapper: descriptor pending, platform unavailable, license/gate failures, and dependency unavailable may remain `Skipped` or their existing status because no service request was attempted.
- [x] Preserve child operation identity, API version, row ordering, gap ordering, and provider name. Do not change the stable Endpoint Security operation set fixed in the prior train.
- [x] Preserve existing expansion artifact category spellings for the three old cases: Settings Catalog settings/assignment failures remain `PermissionDenied`/`AssignmentPermissionDenied`, `AuthFailure`/`AssignmentAuthFailure`, and `FetchFailed`/`AssignmentFetchFailed`. Add distinct `DeadlineExpired`, `Cancelled`, and `Indeterminate` categories with the same `Assignment` prefix on the assignment side; do not silently break existing artifact consumers.
- [x] Where a composite promotes child gaps to a top-level failure, preserve any uniform canonical `(FailureClass, ReasonCode)` tuple across all six classes and fall back to `ProviderFailed/provider-failed` only for mixed tuples. Do not special-case only permission and authentication.
- [x] Add a collection dependency regression proving a `Partial` provider-plan result is persisted but is not inserted into `$collectedRows`; a later `IdFromDataset` child remains `DependencyUnavailable`. Only `Collected` satisfies collection dependencies.
- [x] Add a source-contract assertion that production source outside `Resolve-PulseGraphFailure.ps1` contains no `Get-PulseFailureClass` or duplicate status/message classifier.
- [x] Run all touched collector/expansion containers green, then run `pack` + the full suite before committing.
- [x] Commit as `refactor: unify Graph failure mapping`.

**Tasks 1-2 evidence (2026-08-30):**

- Task 1 red: 21 focused examples failed because `Resolve-PulseGraphFailure` did not exist. Task 1 green: 21/21 passed. Implementation commit: `8228993` (`feat: preserve Graph failure outcomes`).
- Task 2 red: 38 of 68 adapter-contract examples failed against the prior adapter behavior. Task 2 green: 68/68 passed. Implementation commit: `e623440` (`refactor: unify Graph failure mapping`).
- Independent review corrections landed in `1593724` (`fix: propagate authentication abort across adapters`): top-level and Partial-gap plan authentication now share the direct collector's run-wide abort state; later network expansion is suppressed; the root Settings Catalog and setting-definition reads use the canonical mapper; and no caught provider/plan message is persisted.
- Review-fix red evidence: the focused set reproduced direct provider-text persistence, provider-plan text persistence, a plan-returned authentication failure that allowed the next plan to run, a Partial authentication gap that allowed the next plan to run, six root Settings Catalog tuple collapses, and expansion work continuing after authentication failure. The paired non-authentication plan and Partial-gap cases remained isolated.
- Second review-correction red evidence: the unchanged implementation produced 183 passes and 8 focused failures. The failures proved that first/middle Settings Catalog and typed-assignment authentication errors did not expose a shared abort signal, the pre-request `Get-GraphContext` catch persisted planted provider text/UPN/client id, and a renamed interpreter using `Exception.Response.StatusCode` plus numeric 401/403 comparisons escaped the prior source contract.
- Second review correction threads one network-abort state through every built-in composite and expansion fan-out. Exact first/middle authentication and non-authentication control call counts cover RBAC groups, Endpoint Security settings, security-baseline assignments, Settings Catalog settings/assignments, and typed assignments. Authentication stops only later network work, records `collectionFailure`, and leaves already-available no-network derivation safe; non-authentication failures remain isolated. Pre-request context failure now persists only the fixed `authentication-failed: context unavailable before request` tuple.
- Focused collector/expansion gate: 555 tests across the mapper, direct collection, all built-in provider plans, root/fan-out expansion adapters, definition capture, snapshot orchestration, privacy, and the whole-production-source interpreter contract; 555 passed, 0 failed, 0 skipped, 0 NotRun.
- Package-first authoritative gate: `pack` succeeded with 10 tasks, 0 errors, 0 warnings; subsequent `test` succeeded with 2,408 tests, 0 failures, 0 errors, 0 skipped, 0 NotRun, and 11 build tasks with 0 errors/warnings.
- Tested TenantPulse 0.3.0 package SHA-256: `433a2083c0423fe888077dbce9eda2d195d873facd487bee36e9056f8d1429c5`; built manifest SHA-256: `4693f670b62e1c84aa83effa967f0692a252681a897c2e730e73586803f38f06`; built module SHA-256: `8e9d524d4e1ab043e94b4e67793ac65dbecbae23a9ca198d60186b2a01661844`.
- Exact test/package binding was recorded to `output/testResults/tested-release-proof.json`. The source contract now scans the whole production tree and is mutation-proven against renamed message, structured outcome/certainty, raw `Response.StatusCode`, and numeric 401/403 interpreters while allowing ordinary canonical DTO consumption; production source contains no legacy helper or second Graph failure interpreter outside `Resolve-PulseGraphFailure`.

### Task 3: Add the strict partial-awareness descriptor contract

**Files:**
- Modify: `source/Private/Checks/Test-PulseCheckDescriptor.ps1`
- Modify: `source/Private/Checks/Import-PulseCheckCatalog.ps1` only if object projection needs an explicit field
- Modify: `source/Data/Checks/README.md`
- Modify: `tests/Unit/CheckCatalog.Tests.ps1`

**Interfaces:**
- New optional descriptor field: `Data.PartialDatasets = [string[]]`.
- The field is an evaluator opt-in, never a collection dependency declaration.

- [x] Write failing catalog tests for a scalar value, null/empty array, blank member, exact duplicate, case-only duplicate, case-only alias of a canonical dataset, unknown dataset, dataset not listed in `Data.Datasets`, Expression rule use, and Function rule whose command lacks a `DatasetOutcomes` parameter.
- [x] Write a passing test for a Function rule with one or more unique `PartialDatasets`, each a member of `Data.Datasets`, whose command declares `DatasetOutcomes`.
- [x] Validate `PartialDatasets` only when present. It must be a non-empty string array, be unique under `OrdinalIgnoreCase`, use the exact canonical casing from `Data.Datasets` and the dataset map, be a subset of `Data.Datasets`, and be legal only for `Rule.Type = Function`.
- [x] Resolve `Rule.Function` first, then require its command metadata to declare a `DatasetOutcomes` parameter whenever `PartialDatasets` is present. A descriptor cannot claim partial awareness without an implementation able to receive the outcome projection.
- [x] Do not add `PartialDatasets` to `Data.Datasets`, the dataset map, the collection manifest, or dependency ordering. It changes evaluation only.
- [x] Prove `Import-PulseCheckCatalog` retains `Data.PartialDatasets` exactly and `Get-PulseCollectionManifest` remains driven only by `Data.Datasets`.
- [x] Document the field and monotonic safety rule in `source/Data/Checks/README.md`: universal checks may fail on a known offender but cannot pass with gaps; existential checks may pass on a known witness but cannot fail with gaps. Correct the stale claim that `Data.Datasets` is always required/non-empty, because expansion-only descriptors are valid.
- [x] Run catalog tests green and commit as `feat: validate partial-aware checks`.

**Task 3 evidence (2026-08-30):**

- Focused red gate: 60 catalog/manifest examples discovered; 48 passed and the 12 new rejection cases failed against the pre-contract validator, which ignored `Data.PartialDatasets`.
- Focused green gate: 60/60 passed. The cases pin scalar/null/empty/blank rejection, ordinal-ignore-case uniqueness, exact dataset/map casing, subset membership, Function-only use, command-resolution precedence, required `DatasetOutcomes` metadata, exact catalog projection, expansion-only compatibility, and collection-manifest isolation.
- Independent review correction red gate: 65 examples discovered; 61 passed and four failed. The failures reproduced a wildcard Rule.Function that ambiguously matched several functions without error, a native application whose null parameter metadata threw out of validation, a null DatasetMap that admitted a partial-aware descriptor, and the same missing-map bypass with a case-aliased dataset spelling. The unresolved literal still surfaced through the catalog's aggregated validation path.
- Independent review correction green gate: 65/65 passed. Function rules now require one ordinal-exact PowerShell Function before null-safe parameter inspection, while every partial-aware descriptor requires an available canonical dataset map. Legacy mapless descriptors without `PartialDatasets` retain their prior behavior.
- Package-first authoritative gate: `pack` succeeded with 10 tasks, 0 errors, and 0 warnings; subsequent `test` succeeded with 2,429 tests, 0 failures, 0 errors, 0 skipped, 0 NotRun, and 11 build tasks with 0 errors/warnings.
- Tested TenantPulse 0.3.0 package SHA-256: `b97ab79b204407f35266a8d5c853e503c12b657bd5ada6efc223bbb3285d1bdb`; built manifest SHA-256: `4693f670b62e1c84aa83effa967f0692a252681a897c2e730e73586803f38f06`; built module SHA-256: `487745ffe476a8839dffeafef62bb49ea6c1b34713fc6b055a030f7b0bbcdc3d`.

### Task 4: Add fail-closed partial evaluation and an isolated outcome projection

**Files:**
- Modify: `source/Private/Evaluate/Invoke-PulseEvaluation.ps1`
- Modify: `source/Private/Evaluate/FindingsSchema.md`
- Modify: `tests/Unit/Evaluate/CollectionOutcomeEvaluation.Tests.ps1`
- Modify: `tests/Unit/Evaluator.Tests.ps1`

**Interfaces:**
- Function invocation for an opted-in check: `& <Rule.Function> -Datasets <deep clone> -DatasetOutcomes <deep-cloned allowlist> [-Context <clone>]`.
- `DatasetOutcomes[<name>]` exposes only `Status`, `FailureClass`, `ReasonCode`, `Detail`, `Provider`, `ApiVersion`, `Operations`, and `Gaps`.
- Append optional `DatasetOutcomes = @{}` after the existing optional `Context` parameter in each opted-in Function to preserve positional compatibility.

- [x] Add red evaluator tests proving every non-opted-in check still returns `NotApplicable` for `Partial`; Expression rules can never receive partial rows; missing/Failed/Skipped/unknown statuses remain fail-closed.
- [x] For non-aware `Partial`, synthesize a bounded reason containing dataset name and gap count only. Do not quote manifest reason, scope, gap detail, or provider detail.
- [x] For an opted-in Function check, read the usable rows from a valid Partial dataset, deep-clone them through the existing canonical JSON path, construct an allowlisted outcome projection for every declared dataset, deep-clone that projection independently, and pass it as `DatasetOutcomes`. Pin the exact projection keys/casing and prove manifest-only `reason`, `sha256`, `itemCount`, and `collectedUtc` are absent.
- [x] Prove both inputs are isolated: a malicious test rule mutating dataset rows, `Gaps[].Detail`, `Operations`, projection keys, or the projection root cannot change the dataset cache, manifest object, or what a later check sees.
- [x] Fail closed with `Error` if an opted-in Partial entry has zero usable rows, absent/empty/null-containing/structurally invalid `Gaps`, or cannot be projected or cloned safely. Reuse the complete `New-PulseCollectionOutcome` gap structure contract, not merely `Gaps.Count`. Reserve `NotApplicable` for a structurally valid Partial dataset whose usable rows do not prove the monotonic decision.
- [x] Exercise all four Function invocation combinations: legacy `Datasets` only; `Datasets + Context`; `Datasets + DatasetOutcomes`; and all three. Pass `DatasetOutcomes` only when `Data.PartialDatasets` is present and validated; existing `Context` opt-in remains independent.
- [x] Prove the non-aware Partial reason contains only dataset name and gap count, with canary manifest/gap text absent. Do not serialize `DatasetOutcomes` into findings or scoring documents. Findings schema stays 1.0; snapshot schema stays 2.0.
- [x] Run evaluator and collection-outcome tests green and commit as `feat: evaluate approved partial datasets`.

**Task 4 evidence (2026-08-30):**

- Focused red gate against the pre-evaluator implementation: 104 examples discovered; 89 passed and 15 failed. The failures pinned bounded non-aware Partial reasons, partial-aware invocation, invalid-gap/zero-row errors, clone failures, mutation isolation, and canary-free serialization.
- Focused green gate under Pester 6.1.0: 105/105 passed across `CollectionOutcomeEvaluation.Tests.ps1` and `Evaluator.Tests.ps1`; zero failures, skips, NotRun, or failed containers.
- `DatasetOutcomes` is built only for validated Function opt-ins, independently canonical-JSON-cloned, and contains exactly `Status`, `FailureClass`, `ReasonCode`, `Detail`, `Provider`, `ApiVersion`, `Operations`, and `Gaps` for every declared dataset. Dataset rows use a separate canonical clone. Expression and non-aware rules never receive Partial rows.
- Structural validation reuses `New-PulseCollectionOutcome` and fails closed for zero rows, absent/empty/null/invalid gaps, unsafe projection, and either clone failure. Privacy fixtures prove manifest reason/detail, gap scope/detail, provider, and operation canaries do not enter non-aware reasons, findings, or score documents.
- Package-first authoritative gate: `pack` succeeded with 10 tasks, 0 errors, and 0 warnings; subsequent `test` succeeded with 2,452 tests, 0 failures, 0 errors, 0 skipped, 0 NotRun, and 11 build tasks with 0 errors/warnings.
- Tested TenantPulse 0.3.0 package SHA-256: `9ce0a35f98e2c30dd44dc911e4250c755f8ee261b353d7c502b7e8266933d2ce`; built manifest SHA-256: `4693f670b62e1c84aa83effa967f0692a252681a897c2e730e73586803f38f06`; built module SHA-256: `e635f83aa132f5aef8a76fb68a57563bd3a8eef7587f797b2a139ef95b0610ac`. Exact package/test binding is recorded in `output/testResults/tested-release-proof.json`.

**Task 4 independent-review correction evidence (2026-08-30):**

- The historical green evidence above is preserved, but it was not final approval: independent review found that the evaluator validated a Partial outcome and then projected the unnormalized raw manifest values, and that a one-element null row array was counted as usable evidence.
- Correction red gate against commit `929e08950fa38ad3f7dd97f1afa8a8afef5cdbf9`: 30 focused examples discovered; 22 passed and eight failed. The failures reproduced scalar `Gaps`, integer `Scope`, `ReasonCode`, `Operation`, and `ApiVersion` values reaching a rule, a null-only Partial row reaching a rule, null leakage in a mixed row set, and an extra raw gap key crossing the projection boundary.
- Fix commit `4e9031dabfce693a13bd91c5f3c6367d8e834291` projects only a canonical outcome returned by the shared constructors. It requires the persisted gap collection to retain array shape, requires every mandatory gap string to already be a nonblank string, rebuilds accepted gaps through `New-PulseCollectionGap`, and excludes null rows only from the check-local dataset copy.
- Regression coverage proves malformed input cannot invoke the rule; mixed null and valid rows deliver only the valid row while leaving the shared cache unchanged; extra gap properties are stripped; and a mixed declared set containing both Partial and writer-shaped Collected outcomes remains accepted with exact canonical projection keys.
- Final focused correction gate: 918/918 passed across the collection-outcome, evaluator, and privacy containers; zero failures, errors, skips, NotRun, or failed containers.
- Package-first authoritative correction gate: `pack` succeeded with 10 tasks, 0 errors, and 0 warnings; subsequent `test` succeeded with 2,460 tests, 0 failures, 0 errors, 0 skipped, 0 NotRun, and 11 build tasks with 0 errors/warnings.
- The authoritative correction run rechecked the complete deterministic suite after both bypasses were closed, including manifest generation, dependency ordering, mixed outcome projection, row and projection mutation isolation, serialization privacy, package integrity, and the existing evaluator compatibility surface. No production descriptor or check function from the following task was changed.
- Proof run identifier: `73f802ca-3e04-4115-b4e6-12f550044530`.
- The proof-bound candidate was produced from the corrected source and exercised through the full package-first gate. The null filter operates on a newly allocated check-local row list, so the shared dataset cache retains its original members for later checks; canonical outcome construction similarly prevents raw manifest members or hostile extra keys from reaching a rule.
- Corrected TenantPulse 0.3.0 package SHA-256: `6df3e676387c86d908963e1ca3e16afeffcb753a1c96d8e38fe934b1dfa8ad05`; built manifest SHA-256: `4693f670b62e1c84aa83effa967f0692a252681a897c2e730e73586803f38f06`; built module SHA-256: `1d81027c8bf4cb2d55f4f5f555de02cc7b107c136c2a16c22da666cacedba47d`.

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
- Each Function appends a `DatasetOutcomes` parameter after `Context` and preserves all valid complete-dataset behavior. Invalid boolean-like values that currently compare equal to `$true` must become `Error`, not accidental `Pass`.

- [x] TP.INT.0013 (universal RBAC protection): under Partial, any known unprotected group -> `Fail`; otherwise -> `NotApplicable`. It can never `Pass` while gaps remain.
- [x] TP.INT.0014 (existential BitLocker policy): under Partial, any known qualifying full-disk policy -> `Pass`; otherwise -> `NotApplicable`. It can never `Fail` while gaps remain.
- [x] TP.INT.0015 (existential LAPS policy): under Partial, any known policy meeting all four criteria -> `Pass`; otherwise -> `NotApplicable`. It can never `Fail` while gaps remain.
- [x] TP.INT.0029 (universal baseline posture): under Partial, any known unassigned or deprecated baseline -> `Fail`; otherwise -> `NotApplicable`. It can never `Pass` while gaps remain.
- [x] Partial result reasons state only the unresolved gap count and the monotonic decision. Evidence may describe known rows through the existing redaction path; it may not copy gap scope/detail into findings.
- [x] Require native `[bool]` values before TP.INT.0014 `isFullDiskEncryption` or TP.INT.0015's four criteria can be a qualifying witness. Add Collected and Partial fixtures for string `'true'`, integer `1`, and other non-boolean values; these must not earn a Pass.
- [x] Pin monotonic precedence and row-order independence: Partial + valid offender/witness + malformed unrelated row returns the monotonic `Fail`/`Pass`; Partial + no proof + all known rows valid returns `NotApplicable`; Partial + no proof + malformed known row returns `Error`; Complete + any malformed row returns `Error`. Test both row orders.
- [x] Update all four check fixture helpers to forward the full real outcome surface: `Status`, `FailureClass`, `ReasonCode`, `Detail`, `Provider`, `ApiVersion`, `Operations`, and structurally valid `Gaps`.
- [x] Add hostile fixtures: zero usable rows, multiple gaps, mixed good/bad known rows, missing required row fields, malformed outcome projection, and mutation attempts. Add GUID, UPN, secret-like, raw scope, and provider-detail canaries and prove none reaches reasons, evidence, serialized findings, or score documents. Preserve every existing complete, pending, gate-degraded, and field-absence assertion.
- [x] Prove scoring consequences: Partial Pass for TP.INT.0014/.0015 contributes earned, possible, and assessed weight; Partial Fail for TP.INT.0013/.0029 contributes possible and assessed but no earned weight; non-decisive Partial is excluded and increases not-assessed coverage. Findings schema remains 1.0, snapshot schema 2.0, and scoring model 1.0.
- [x] Run the four check containers together, then evaluator/catalog containers, then `pack` + full suite.
- [x] Commit as `feat: make four Intune checks partial aware`.

**Task 5 evidence (2026-08-30):**

- Focused red gate against the pre-Task-5 implementation: 76 examples discovered; 43 passed and 33 failed, with zero skipped/NotRun and four failed containers. The failures pinned missing `PartialDatasets` declarations and `DatasetOutcomes` parameters, non-decisive Partial behavior, the four asymmetric monotonic decisions, strict native-boolean witnesses, outcome projection handling, privacy, mutation isolation, scoring, and schema compatibility.
- The first post-implementation focused run reached 72/76. Its four remaining failures were test expectations using the plan's `2.0` shorthand instead of the unchanged concrete snapshot manifest schema value `2.0.0`; correcting those assertions required no production change. The focused green gate then passed 76/76 with zero failures, skips, NotRun, or failed containers.
- Evaluator/catalog compatibility gate: 178/178 passed across `Evaluator.Tests.ps1`, `CollectionOutcomeEvaluation.Tests.ps1`, and `CheckCatalog.Tests.ps1`. The privacy-plus-four-check regression set passed 881/881 after fixture canaries were constructed at runtime so the repository scanner could exercise serialized-output privacy without planting literal secret/PII-shaped pairs in source.
- Each descriptor opts in only its existing single dataset. All four functions append optional `DatasetOutcomes` after `Context`; Partial classification is two-phase and row-order independent, so decisive monotonic proof outranks an unrelated malformed row while non-decisive malformed input and every malformed Collected input fail closed. Partial evidence is limited to qualifying witnesses or offenders, and reasons disclose only aggregate gap count plus the reviewed monotonic conclusion.
- Scoring fixtures pin TP.INT.0014 Partial Pass at 10/10 with assessed/applicable 1/1, TP.INT.0015 Partial Pass at 6/6 with 1/1, TP.INT.0013 Partial Fail at 0/6 with 1/1, and TP.INT.0029 Partial Fail at 0/3 with 1/1. Non-decisive Partial contributes 0/0 with assessed/applicable 0/1. Findings schema remains `1.0`, the concrete snapshot manifest schema remains `2.0.0`, and scoring model remains `1.0`.
- An intermediate full run correctly failed four repository privacy-scan examples because its test fixtures contained literal canary pairs. That pre-test candidate capture was discarded and is not release proof. After the fixture-only correction, `pack` succeeded with 10 tasks, 0 errors, and 0 warnings; the authoritative subsequent `test` run passed 2,491/2,491 with 0 failures, 0 errors, 0 skipped, and 0 NotRun.
- Authoritative proof run identifier: `76653a5a-994c-495d-bed1-d5eb2e1c1c71`. Tested TenantPulse 0.3.0 package SHA-256: `fb9adc26d43280ef6ca191081e08bf1c4a4a96da680a4d72a3a47673015413ce`; built manifest SHA-256: `4693f670b62e1c84aa83effa967f0692a252681a897c2e730e73586803f38f06`; built module SHA-256: `98712d1a165f79283bf608875bf97bf763c07e8ab7214efdca644e207993ece2`.
- Implementation commit: `f21469272a4d103d6443ba11f56a51116df92786` (`feat: make four Intune checks partial aware`).

**Task 5 independent-review correction evidence (2026-08-30):**

- Independent review reproduced three actionable gaps: identity was validated only after a row became decisive evidence, unsupported persisted status/reason values could be copied into a finding, and TP.INT.0013's source commentary still claimed Function rules could not observe Partial outcomes.
- Focused correction red gate against the implementation above: 121 examples discovered; 110 passed and 11 failed, with zero skipped, NotRun, or failed containers. Four failures reproduced Complete and non-decisive Partial rows without usable identities returning Pass/Fail/NotApplicable instead of Error; four reproduced raw or interpolated direct-call outcome errors; one reproduced the persisted-engine status/reason leak; and two reproduced the evaluator leak for scalar and non-scalar unsupported statuses. The four decisive Partial plus malformed-identity row-order cases already passed, pinning the monotonic proof precedence that the fix had to preserve.
- A shared strict outcome-state helper now rejects null roots, null/non-dictionary entries, missing/unsupported/non-scalar status, and malformed Partial gap arrays with one fixed caller-specific error that contains no raw value. The evaluator emits one fixed bounded reason for truly unsupported persisted statuses while preserving the established Pending/Failed/Skipped reasons. TP.INT.0013's source contract now documents the actual Partial projection and zero-usable-row boundary.
- Each check validates every row's minimal identity before classification: nonblank `groupId` for TP.INT.0013, nonblank `policyId` for TP.INT.0014/.0015, and a usable `id` or `name` for TP.INT.0029. Complete and non-decisive Partial malformed rows Error; decisive Partial proof still outranks an unrelated malformed row in both orders.
- The first correction rerun passed 116/121 and exposed five compatibility regressions from treating known Pending/Failed/Skipped states as unknown. Narrowing the fixed unsupported-status reason to genuinely unknown states restored those historical reasons. Final focused correction gate: 121/121 passed with zero failures, skips, NotRun, or failed containers.
- Package-first authoritative correction gate: `pack` succeeded with 10 tasks, 0 errors, and 0 warnings; subsequent `test` passed 2,508/2,508 with 0 failures, 0 errors, 0 skipped, 0 NotRun, and 11 build tasks with 0 errors/warnings.
- Authoritative correction proof run identifier: `9a09a160-aa90-4b92-b05f-78c1aa9189e0`. Tested TenantPulse 0.3.0 package SHA-256: `0c5b4520a0bd0d5a9df11f8d1ad7b6f2e4c3a123c2b086200f822c075444d00a`; built manifest SHA-256: `4693f670b62e1c84aa83effa967f0692a252681a897c2e730e73586803f38f06`; built module SHA-256: `382583ecfa3edc99bbf75a30498168e431b86ffb37b018365b48d3b6c868e87e`.
- Review-fix commit: `71f81b5bb3719505a56e7a8c09974fe46c8b8389` (`fix: fail closed on malformed partial-aware rows`).

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

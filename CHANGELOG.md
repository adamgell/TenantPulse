# Changelog for TenantPulse

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Repository scaffold: Sampler build pipeline, module manifest, QA gates, and CI workflow.
- Snapshot store: `New-PulseSnapshotStore`, `Write-PulseDataset`, `Read-PulseDataset`,
  `Get-PulseSnapshotManifest`, `Set-PulseManifestEntry`, and the canonical serialization
  primitive `ConvertTo-PulseCanonicalJson`, with a hashed, reason-carrying manifest that
  every later collector/evaluator/renderer component builds on.
- Operator key + pseudonymization: `Get-PulseOperatorKey` auto-creates a 32-byte key
  (0600-equivalent permissions on non-Windows) at `~/.tenantpulse/operator.key` on first
  call and refuses to create or read one inside a snapshot root; `Get-PulsePseudonym`
  turns any value into a stable `tp-`-prefixed HMAC-SHA256 pseudonym under that key, so
  raw tenant IDs never need to appear in snapshots or reports.
- Check descriptor schema + loader: `Import-PulseCheckCatalog` reads and validates every
  `.psd1` check descriptor under a directory (default `source/Data/Checks`) with
  `Import-PowerShellDataFile`, returning an ordinally-sorted-by-`Id` array of
  `TenantPulse.CheckDescriptor` objects; an empty/missing catalog returns an empty array
  rather than throwing. `Test-PulseCheckDescriptor` validates one descriptor's schema
  with explicit per-field type enforcement (scalar `[string]` vs. required/allowed-empty
  `[string[]]`, reported as `must be a <type>, got <actual type>` rather than silently
  coercing), Id/Severity/Effort/Impact/Rule.Type patterns and enums, Rule.Function
  resolving via `Get-Command` at import time, required Consulting fields,
  References.Research/Authorities and, once Task 1.5 lands `DatasetMap.psd1`,
  cross-checks Data.Datasets membership against a map parsed exactly once per catalog
  load. All validation errors across a catalog are aggregated into a single thrown
  error, each line prefixed with its source filename and naming the offending
  descriptor and property, rather than failing on the first bad file. Schema documented
  verbatim in `source/Data/Checks/README.md`.
- Evaluator: `Invoke-PulseEvaluation` runs a check catalog against a snapshot store and
  produces the canonical findings document (`source/Private/Evaluate/FindingsSchema.md`),
  plus an in-memory-only `RedactionMap` covering every evidence identity seen (built at
  evaluate, applied at render). `New-PulseFinding` is the rule-result contract every
  Function rule (`Test-Pulse* -Datasets <hashtable>`) returns to produce `Pass`/`Warn`/
  `Fail` with evidence; Expression rules resolve straight to `[bool]` with no evidence.
  `NotApplicable` and `Error` are engine-assigned only: a missing/`Failed`/`Skipped`
  dataset degrades a check to `NotApplicable` quoting the manifest's own (already
  redacted) reason verbatim, and a throwing or malformed-output rule becomes `Error`
  without aborting the rest of the run. `Get-PulseGateStatus` is a Phase 1 gate stub -
  every gate resolves `Unknown`, which never degrades a check. Findings are sorted
  ordinally by check Id, each finding's evidence ordinally by sortKey then identity, and
  `generatedUtc` is pinned to the snapshot manifest's own `createdUtc` (never wall
  clock), so re-evaluating the same snapshot is byte-identical through
  `ConvertTo-PulseCanonicalJson`.

### Changed

- Check descriptor loader hardening (post-review): closed PowerShell-coercion type holes
  that let array-typed `Id`/`Severity`/`Rule.Type`/etc. silently pass their
  pattern/enum checks and land wrong-typed in the loaded descriptor (also closing the
  matching duplicate-Id-detection bypass); prefixed every aggregated error line with its
  source filename so two files sharing a bad Id are distinguishable; hoisted
  `DatasetMap.psd1` parsing to once per catalog load with its own aggregated-error
  handling for a malformed map instead of a raw exception, and excluded a
  `DatasetMap.psd1` living inside the catalog directory from descriptor scanning;
  switched catalog ordering from culture-aware `Sort-Object` to an ordinal
  `[string]::CompareOrdinal` index-sort, matching `ConvertTo-PulseCanonicalJson`'s
  established pattern for deterministic ordering.
- **Final fix-wave, contract:** `Get-PulseTenantSnapshot`'s snapshot manifest `tenant`
  pseudonym is now derived from the resolved GraphKit tenant id (`$Context.TenantId`),
  never from `-ProfileId` - the same tenant under two differently-named profiles now
  pseudonymizes identically, and renaming a profile no longer changes the pseudonym.
  `Get-GraphContext` is now called before the snapshot store is created so the tenant id
  is available before anything is written. `Get-PulseTenantSnapshot -Path` and
  `Get-PulseCheckCatalog -Path` are renamed to `-OutputPath`/`-CatalogPath` respectively
  (`-Path` kept as a deprecated alias for one release). `Export-PulseReport`'s return
  object now carries `FindingsPath`, matching `Invoke-PulseAssessment`'s return shape.
- **Final fix-wave, snapshot-store boundary:** `New-PulseSnapshotStore` now clears
  `datasets/`, `reference/` and `expanded/` before reuse (unconditionally, not behind a
  `-Force` flag), so a prior run's or a foreign file left in an existing store path can
  no longer silently survive into a new run. `Get-PulseSnapshotStore` now type-validates
  `datasets` (non-null object), `createdUtc` (a parseable timestamp) and `producer`
  (non-null object) when opening a store, throwing a specific path+field error instead of
  producing a confident-but-wrong evaluation or a mid-run crash. `Write-PulseDataset` and
  `New-PulseSnapshotStore`'s manifest write now share `Set-PulseAtomicFileContent`, the
  same tmp+rename pattern `Set-PulseManifestEntry` already used, instead of duplicating
  it.
- **Final fix-wave, publish tooling and local gates:** a new `Record_Tested_Module_Digest`
  build task (`.build/AssertGateResult.tasks.ps1`) records a SHA-256 manifest of every
  shipped file right after `./build.ps1 -Tasks test` passes; a new `Assert_Gate_Result`
  task in the same file wires the whole-result `MinimumTests` gate
  (`tests/QA/Assert-GateResult.ps1`) into the local `test` workflow, so a local
  `./build.ps1 -Tasks test` run enforces the same discovery-regression protection CI
  already had. `producer.graphKit` in the snapshot manifest is now populated from
  `(Get-Module GraphKit).Version` at collect time (previously always `null`). The offline
  secret/PII scan (`tests/QA/SecretScan.tests.ps1`) now also covers `scripts/`,
  `build.ps1`, `build.yaml`, `README.md`, `CHANGELOG.md` and `.github/workflows/ci.yml`,
  not just `source/` and `tests/`.
- **Final fix-wave, public-facing skin:** README.md rewritten to PSGallery-landing
  quality (quick start, the five public commands, required Graph permissions, a snapshot
  sensitive-at-rest warning, a CIS no-compliance-claim disclaimer, operator
  prerequisites, an honest Phase 1 scope statement); internal status/task narrative moved
  to `docs/STATUS.md`. `THIRD-PARTY-NOTICES.md` now documents Maester's MIT license and
  the two checks (`TP.INT.0001`, `TP.INT.0003`) that adapt its logic, resolving the
  contradiction with those checks' own `Origin` fields. `about_TenantPulse.help.txt`
  rewritten with real content and real examples (previously a `{{ add examples here }}`
  placeholder). Build-tool versions in `RequiredModules.psd1` (`InvokeBuild`,
  `PSScriptAnalyzer`, `ModuleBuilder`, `ChangelogManagement`) pinned to exact versions
  instead of `'latest'`.
- **GraphKit 0.1.1 migration (Task 1.11).** Pin bumped to GraphKit 0.1.1 in both
  `source/TenantPulse.psd1` and `RequiredModules.psd1`. Deleted the
  `Get-PulseGraphFailureStatusCode` supplemental-probe workaround (function, call site,
  and its unit tests) - GraphKit 0.1.1's `Get-GraphObject` now throws an `ErrorRecord`
  carrying structured failure signal directly (`CategoryInfo.Category`,
  `TargetObject.Telemetry[-1].StatusCode`), so no extra read-only Graph call is needed to
  recover a status code. `Get-PulseFailureClass` rewritten to consume that structured
  data first, falling back to the rendered exception message only when neither signal is
  present; still TOTAL by construction. Dropped `Pending = $true` from all six
  `DatasetMap.psd1` entries whose descriptors shipped in 0.1.1 (`securityDefaultsPolicy`,
  `directoryRoleAssignments`, `directoryRoleDefinitions`, `organization`,
  `organizationMdmAuthority`, `entraDevices`) - the static read-only QA gate now
  live-verifies all six against the installed catalog instead of asserting a declared
  expectation.

### Deprecated

- `Get-PulseTenantSnapshot -Path` and `Get-PulseCheckCatalog -Path`: renamed to
  `-OutputPath` and `-CatalogPath` respectively. `-Path` still works as an alias for one
  release; migrate to the new names before it is removed.

### Fixed

- **GraphKit 0.1.1 migration, live-gate surprises (Task 1.11, Ivy24 lab tenant):** the
  first real run of the six newly-live descriptors surfaced two genuine bugs.
  (1) Two datasets (`organization`, `directoryRoleAssignments`) carry the raw tenant GUID
  as an actual Graph response field (`Organization.id`,
  `DirectoryRoleAssignment.principalOrganizationId`), not merely a GraphKit provenance
  stamp - unredacted in `datasets/*.json`. Fixed with a new
  `Protect-PulseGraphRowTenantId` helper wired into `Write-PulseDataset` that walks every
  collected row's value tree and redacts an exact, case-insensitive match of the raw
  tenant id to its pseudonym. (2) That helper's first cut walked Hashtable-valued
  properties (GraphKit returns several nested Graph properties, e.g. a real
  `ConditionalAccessPolicy`'s `conditions`/`grantControls`, as `OrderedHashtable`, not
  `PSCustomObject`) via `.PSObject.Properties`, which surfaces a Hashtable's own adapter
  members (`Keys`, `Values`, `SyncRoot`, ...) rather than its dictionary entries - a
  non-synchronized Hashtable's `SyncRoot` IS the same hashtable, so the walk recursed into
  itself and blew PowerShell's call depth on every policy row (reproduced live: ~4s
  burned per row before falling back, TOTAL-by-construction, to the unredacted original -
  never crashed the run, but silently defeated redaction on any Hashtable-nested tenant id
  and made collection pathologically slow). Fixed by walking `IDictionary` via its own
  `Keys`/`this[key]` entries, checked and handled before the generic PSObject branch.
- **Final fix-wave, determinism/redaction:** `Export-PulseReport` and
  `Export-PulseJsonReport` now parse JSON with `-DateKind String`, so a findings
  document's timestamp fields round-trip byte-identical through re-rendering (previously
  a 7-digit-fraction timestamp lost precision when re-serialized at millisecond
  granularity, causing `-Redact` and unredacted reports of the same run to diverge on
  timestamp fields that should have matched). `Test-PulseCompliancePolicyPerPlatform` and
  `Import-PulseCheckCatalog`'s file-listing sort now use an explicit ordinal comparer
  instead of culture-aware `Sort-Object`, matching this codebase's established
  deterministic-ordering pattern. `TP.INT.0005`'s stale-device-population-gap evidence no
  longer carries a `deviceId` field in `Detail` that duplicated the already-redacted
  `Identity`. `ConvertTo-PulseCanonicalJson` now treats a `Kind=Unspecified` `DateTime` as
  already-UTC (`[DateTime]::SpecifyKind(...,'Utc')`) instead of calling
  `.ToUniversalTime()` on it, which silently assumed local time.

- `ConvertTo-PulseCanonicalJson` now sorts object/dictionary keys ordinally instead of via
  case-insensitive culture collation, which previously let case-distinct keys (`apple` vs
  `Apple`) keep their insertion order and produce non-deterministic bytes; it also now
  formats `DateTimeOffset` values with an explicit invariant offset instead of falling
  through to a lossy generic-string branch, and throws on non-finite `NaN`/`Infinity`
  doubles instead of silently emitting invalid JSON tokens.
- `Set-PulseManifestEntry` now guards its read-modify-write cycle with a per-store named
  Mutex and publishes `manifest.json` via a temp-file-then-atomic-rename, so a crash
  mid-write can no longer truncate the manifest and concurrent writers no longer silently
  drop one another's updates.
- `Write-PulseDataset`, `Read-PulseDataset` and `Set-PulseManifestEntry` now validate
  dataset `-Name` against a safe-character pattern before using it to build a file path,
  closing a path-traversal gap that could overwrite arbitrary files (including
  `manifest.json` itself) via a name like `..\manifest`.
- `Get-PulseOperatorKey` now creates its key file exclusively (`FileMode.CreateNew`), so
  two concurrent first callers on a machine with no key yet can no longer each write and
  silently diverge on their own key - the loser now reads the winner's key instead. On
  non-Windows the file is chmod'd to owner-only before any key bytes are written (not
  after), and the parent directory it creates is chmod'd `0700`. Reading a key file now
  requires it to be exactly 32 bytes, throwing a clear "corrupt key file" error naming the
  actual byte count and the path to delete, instead of silently returning a truncated key
  or an opaque `$null`-related error.
- **Final fix-wave, check logic:** `Test-PulseBreakGlassExcluded` (`TP.ENT.0003`) no
  longer exempts a Conditional Access policy from a break-glass account's evidence just
  because its `includeUsers` doesn't name the account - a non-empty `includeGroups` or
  `includeRoles` can still reach the account, so the check now fails closed (treats the
  policy as reachable) instead of exempting in that case. `Test-PulseAdminMfaEnforced`
  (`TP.ENT.0005`) now counts an MFA-requiring policy scoped via `includeUsers: 'All'`
  toward admin role coverage - it covers every admin role by definition and previously
  was not counted at all. `Invoke-PulseEvaluation`'s dataset-status gate now degrades a
  check to `NotApplicable` on any status `-ne 'Collected'` instead of enumerating
  `Failed`/`Skipped` - a novel/unrecognized status string now fails closed instead of
  silently reading as collected. `Test-PulseStaleDevices` (`TP.INT.0005`) now throws
  (surfacing as `Error`) instead of silently falling back to wall-clock time when a
  supplied cutoff-base timestamp cannot be parsed. `Invoke-PulseCollection`'s auth-abort
  loop no longer overwrites a remaining `Pending` dataset's `descriptor-pending` reason
  with `auth-failure: collection aborted`.
- **Final fix-wave, publish tooling:** `Get-PulseFailureClass` and
  `Get-PulseGraphFailureStatusCode` now handle enum-typed status code values (e.g.
  `[System.Net.HttpStatusCode]::Forbidden`) by casting to `[int]` directly, instead of
  stringifying (which rendered the enum's *name*, not its numeric value, and silently
  lost the signal). A supplemental status-recovery failure in
  `Get-PulseGraphFailureStatusCode` now `Write-Warning`s (previously `Write-Verbose`
  only, silent by default) and `Invoke-PulseCollection` appends `(status unknown)` to the
  affected dataset's own Failed reason, so the weaker signal is visible in the artifact
  itself, not only an easily-missed console message.
- `scripts/Publish-TenantPulsePackage.ps1`'s digest verification now compares every
  shipped file (`.psm1`, `.psd1`, `Data/**`, `en-US/**`) against a manifest of hashes
  recorded at test time (`output/testResults/tested-module-digest.txt`, written by the
  new `Record_Tested_Module_Digest` build task), not just `TenantPulse.psm1` re-hashed
  from whatever happens to be on disk at publish time - closing a gap where a built-module
  file could be silently edited (not rebuilt) between a passing test run and a later
  publish with nothing catching the drift.

### Security

- `scripts/Publish-TenantPulsePackage.ps1`'s `-NuGetApiKey` plain-`[string]` parameter is
  removed entirely (final fix-wave). The API key is now resolved ONLY from a
  `-NuGetApiKeySecure [SecureString]` parameter or the `TENANTPULSE_NUGET_API_KEY`
  environment variable, closing the plain-string-on-the-command-line exposure (shell
  history, process listings, CI job logs).
- `Invoke-PulseEvaluation`: Expression-type check rules now execute in
  `Invoke-PulseSandboxedExpression`'s own fresh, isolated PowerShell runspace
  (`ConstrainedLanguage`, no ambient variables, no scope chain to the caller, only a
  deep-cloned `$Datasets`) instead of in-process via `ScriptBlock.InvokeWithContext`.
  The prior implementation was proven able to read `$operatorKey` (the raw HMAC
  pseudonymization key) and other caller-scope variables, write parent/global scope,
  mutate the shared dataset cache by reference, and reach TenantPulse's own private
  functions from within a check descriptor's Rule.Expression text. A malformed or
  duck-typed rule result whose evidence entry lacked an `Identity` previously threw
  outside the per-check `try`/`catch`, at the redaction-map build step, aborting the
  entire evaluation run instead of degrading only that one check to `Error` - evidence
  is now normalized and validated inside `Invoke-PulseCheckEvaluation`'s own
  containment boundary via a shared `ConvertTo-PulseNormalizedEvidence` helper.
  Datasets are now deep-cloned per check for both rule types, closing a related
  isolation gap where one check's in-place mutation could change what a later check
  (sharing the same cached dataset) observed.
- `Invoke-PulseSandboxedExpression` (round 2): the sandbox's `InitialSessionState` is
  now built from an empty `::Create()` with an explicit five-cmdlet allowlist
  (`Where-Object`/`ForEach-Object`/`Select-Object`/`Measure-Object`/`Sort-Object`, added
  via `SessionStateCmdletEntry` against their real implementing types), replacing
  `CreateDefault2()`. `CreateDefault2()` was proven to load
  `Microsoft.PowerShell.Management` and `Microsoft.PowerShell.Utility`, not "Core
  cmdlets only" as first documented - `New-Item`, `Get-Content`, `Set-Content`,
  `Remove-Item`, `Invoke-WebRequest` and `Invoke-RestMethod` all executed successfully
  from inside an Expression rule under that configuration, meaning a check descriptor
  could read/write the host filesystem or make outbound network calls.
  `ConstrainedLanguage` restricts .NET types, not which cmdlets are loaded - the fix
  had to address the cmdlet surface directly.
- **Raw dataset writes now redact Sensitive typed-policy values (Task 2.3 review, C1).**
  `Invoke-PulseCollection` previously wrote every Graph row for `deviceCompliancePolicies`/
  `deviceConfigurations` to `datasets/<name>.json` verbatim - `TypedPolicyMaps.psd1`'s own
  `Sensitive` classifications (e.g. `windows10CustomConfiguration`'s `omaSettings[].value`
  - a WiFi pre-shared key/VPN secret/certificate push channel) only ever drove redaction in
  the setting-expansion walk, never the raw dataset write, so a Sensitive value sat in
  cleartext in the raw snapshot for the life of every collection run, independent of
  whether `-ExpandSettings` was ever used. Fixed by a new redaction pass
  (`Protect-PulseTypedPolicySensitivePayload`) called before the first byte of a
  map-covered dataset ever touches disk. This redaction is scoped to the two datasets
  `TypedPolicyMaps.psd1` maps (`deviceCompliancePolicies`/`deviceConfigurations`) -
  every other collected dataset has no Sensitive-redaction concept applied to its raw
  write at all, a boundary that (as of this note) lives only in that function's own
  private docstring, not anywhere an operator would see it without reading the source.
  **OPERATOR ACTION REQUIRED: any local TenantPulse snapshot created BEFORE this fix that
  ever collected `deviceConfigurations` may contain Sensitive-flagged values (e.g. WiFi
  PSKs pushed via `windows10CustomConfiguration`'s `omaSettings`) in cleartext in its
  `datasets/deviceConfigurations.json` file. Delete any such pre-existing local snapshot
  directories - do not assume they are safe to keep around or share.**

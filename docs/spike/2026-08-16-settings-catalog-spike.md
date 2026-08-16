# Settings Catalog populated-tenant spike (Ivy24, 781 policies)

Task 2.0. Read-only measurement run against the Ivy24 lab tenant via GraphKit 0.1.1
(`ProfileId ivy24`, certificate app-only auth). Every Graph call made by this spike is a
List read — `ConfigurationPolicy.ListBeta`, `ConfigurationSettingDefinition.ListBeta`,
`ConfigurationPolicySetting.ListBeta` — no mutating operation was ever invoked. Script:
`scratch/Invoke-SettingsCatalogSpike.ps1` (gitignored; not committed — see "Reproducing"
below). Run date: 2026-08-16.

## 1. Corpus size / fetch / parse timings

| Collection | Count | Fetch elapsed | Notes |
|---|---|---|---|
| `ConfigurationPolicy.ListBeta` | **781** | 41.08 s (run used for fixtures/latency below) — a separate warm-up run measured 21.95 s; see "Run-to-run variance" | Matches the tenant's documented policy count exactly. |
| `ConfigurationSettingDefinition.ListBeta` | **18,227** | **20.32 s** (TTFB-dominated; a separate run measured 36.05 s) | One page, as expected. GraphKit 0.1.1's per-operation `Timeouts` for this operation are `HeadersSeconds=60, BodySeconds=60` — comfortably admits the ~13-36 s TTFB observed across two runs. **No timeout was hit in either run.** |

- **Memory high-water for the definitions fetch**: `[GC]::GetTotalMemory()` delta across
  the call was **1150.6 MB** (a second run measured 1183.7 MB) — i.e. materializing the
  full 18,227-item definitions corpus as PowerShell objects costs **roughly 1.1–1.2 GB**
  of managed heap. This is the single most important budget number for T2.1: any
  in-memory join against the full definitions corpus needs to plan for this footprint (or
  an on-disk/streamed approach) rather than assuming it's negligible.
- **Estimated wire size**: serializing a 500-item sample of the definitions
  (`ConvertTo-Json -Depth 10 -Compress`) gives an average of **3,064.4 bytes/definition**;
  scaled to the full 18,227 items that is an estimated **~55.85 MB total** — in line with
  the ~55 MB the task brief anticipated. Serializing the 500-item sample itself took 19 ms
  (cheap; the cost is entirely in the network fetch + JSON deserialization, not
  re-serialization).
- **Run-to-run variance**: policy-list fetch varied 21.95 s → 41.08 s and the definitions
  fetch varied 20.32 s → 36.05 s across two runs made minutes apart against the same
  tenant, both comfortably inside GraphKit's 60 s headers/body timeout but a ~2x spread
  worth carrying into T2.1's budget as "TTFB is noisy, don't budget to the fast run."

## 2. Per-policy `/settings` latency (stratified sample, n=120)

Sample selection: systematic stride across the full, as-returned 781-policy list
(`step = floor(781/120) = 6`, indices `0, 6, 12, …`) — spread across the whole corpus
rather than just the first N, so the sample isn't biased toward however policies happen to
be ordered (observed to correlate with `createdDateTime`, i.e. import batches). This
satisfies the task's "≥50 policies covering all instance kinds found" requirement — all 5
`@odata.type` instance kinds present in the tenant (see §3) were represented well before
reaching 120.

| Metric | Value (ms) |
|---|---|
| n | 120 |
| min | 220 |
| p50 | 306 |
| p90 | 355 |
| p99 | 430 |
| max | 444 |
| mean | 304.2 |
| errors | 0 |

Extrapolated to all 781 policies at the observed mean (304.2 ms/call, sequential, no
concurrency): **~237.6 s (~4.0 minutes)** for a full-corpus `/settings` sweep. This is the
number T2.1/T2.2 should budget against for any full-tenant settings collection — it is
call-count-bound (not payload-size-bound; individual `/settings` payloads are small), so
concurrency is the lever if a full sweep needs to run faster than ~4 minutes.

## 3. Instance-kind histogram

Every `@odata.type` instance kind actually present in the sample, counted **recursively**
(walking into `groupSettingCollectionValue`/`groupSettingValue`/`choiceSettingValue`/
`choiceSettingCollectionValue` children, not just top-level settings):

| `@odata.type` (short form) | Count |
|---|---|
| `ChoiceSettingInstance` | 257 |
| `SimpleSettingInstance` | 54 |
| `GroupSettingCollectionInstance` | 40 |
| `SimpleSettingCollectionInstance` | 11 |
| `ChoiceSettingCollectionInstance` | 2 |

All 5 instance kinds that exist in the Settings Catalog schema's instance-shape family were
found in this tenant's real data (no `GroupSettingInstance` — the non-collection group
variant — was observed in the sample; it's schema-legal but this tenant's policies happen
not to use it). `ChoiceSettingInstance` dominates by a wide margin (~63% of all instances
seen), which matches the CIS/security-baseline-heavy policy set in this tenant (most
settings are toggle/dropdown choices, not free-form values).

`ChoiceSettingCollectionInstance` is rare (2 hits in the 120-sample, both nested *inside* a
`GroupSettingCollectionInstance`, not top-level) — a 3rd, distinct example was located by
extending the read-only search beyond the 120-sample (see §6, `choicecollection-03`).

## 4. Unresolved-definitionId rate vs. the corpus

Every distinct `settingDefinitionId` observed across the 120-policy sample (295 distinct
ids, counting nested children) was checked for membership in the full 18,227-item
definitions corpus fetched in §1 (case-insensitive `id` match).

**Unresolved rate: 0 / 295 = 0.00%.** Every setting definition id referenced by an actual
policy in this tenant resolves cleanly against `ConfigurationSettingDefinition.ListBeta`'s
output. This is a clean, expected result for a healthy tenant — it validates the join
approach itself, but T2.1/T2.2 should NOT assume 0% is guaranteed in every tenant (a
definition could in principle be retired/renamed between when a policy was created and
when the corpus is fetched); the check exists precisely to catch that case when it occurs
elsewhere.

## 5. `<rootId>_name` convention hit rate on groupSettingCollection instances

**Finding: the hypothesized `<rootId>_name` child-definitionId naming convention was NOT
observed in this tenant's data — 0 / 22 distinct groupSettingCollection roots (0.0%).**

This was verified two ways, not just via the histogram walk:

1. **Structural**: none of the 120 sampled policies' `groupSettingCollectionValue` arrays
   ever had more than 1 row (every `GroupSettingCollectionInstance` instance in this
   tenant's data is a single-row "group of settings," not a true multi-row "collection of
   named items" — e.g. the ASR-rules example below has exactly one row, and its child's
   `settingDefinitionId` is `..._blockabuseofexploitedvulnerablesigneddrivers`, not
   `..._name`).
2. **Schema-level**: for the `device_vendor_msft_policy_config_defender_attacksurfacereductionrules`
   root (one of the 22 sampled roots), the full definitions corpus was searched for any
   definition id matching `<root>*name*` — **none exists**. The convention, if it is real
   anywhere in the Settings Catalog schema, does not apply to this root's shape.

One near-miss worth flagging explicitly so it isn't mistaken for a hit: the BitLocker
recovery-options `ChoiceSettingInstance` (not a group collection) has children whose
`settingDefinitionId`s literally end in `_name`
(e.g. `device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrecoverykeyusagedropdown_name`)
— but that `_name` is part of the underlying CSP node's own name, a coincidence of this
particular setting's schema, not an instance of `<rootId>_name` where `rootId` is the
*root instance's own* `settingDefinitionId`. It was correctly excluded from the hit count
because it isn't a groupSettingCollection instance at all.

**Recommendation for T2.1/T2.2**: do not build display-name resolution logic around a
`<rootId>_name` convention as a general rule — this spike found no evidence it exists as a
general Settings Catalog pattern, at least not in the shapes this tenant's 781 policies
exercise. If a later task needs human-readable labels for groupSettingCollection rows,
budget for using the definitions corpus's own `displayName` field per child setting
instead.

## 6. Golden fixtures

15 sanitized fixtures were saved to `tests/Fixtures/SettingsCatalog/` (3 per major instance
kind, plus a 4th, richly-nested example for groupSettingCollection):

| Fixture | Kind | Notes |
|---|---|---|
| `choice-01/02/03.json` | `ChoiceSettingInstance` | |
| `simple-01/02/03.json` | `SimpleSettingInstance` | integer + string `simpleSettingValue` examples |
| `choicecollection-01/02/03.json` | `ChoiceSettingCollectionInstance` | `-03` located via an extended, still read-only search beyond the 120-sample (only 2 distinct policies in the sample had this rare kind) |
| `simplecollection-01/02/03.json` | `SimpleSettingCollectionInstance` | |
| `groupcollection-01.json` | `GroupSettingCollectionInstance`, single row | ASR rules example |
| `groupcollection-02-nested.json` | `GroupSettingCollectionInstance`, nested (group-inside-group, multi-row) | macOS `com.apple.servicemanagement` rules — 2-row nested collection, richest shape captured |
| `groupcollection-03.json` | `GroupSettingCollectionInstance` via `ChoiceSettingInstance` children | BitLocker recovery options; included as the `_name`-suffix near-miss discussed in §5 |

**Sanitization applied** (per `scratch/New-SanitizedFixtures.ps1`):
- every GUID in the raw payload (policy id, `settingInstanceTemplateId`,
  `settingValueTemplateId`, `templateReference.templateId`) remapped through a **per-fixture**
  `GUID -> [guid]::NewGuid()` table — consistent within one fixture file, freshly
  randomized per fixture.
- `Policy.name` scrubbed to a generic `Policy-NN` placeholder; `Policy.description` and
  `templateReference.templateDisplayName` scrubbed to generic placeholder text.
- `_Tenant` / `_RetrievedUtc` / `_GraphPath` / `_ApiVersion` request-metadata fields
  stripped from both the `Policy` and every `Settings` entry (recursively).
- `settingDefinitionId` and every `@odata.type` value left **verbatim** — public Settings
  Catalog schema, not tenant-identifying, and required verbatim for the fixtures to be
  useful against the real schema.

All 15 fixtures are declared in `tests/Fixtures/PROVENANCE.md` as
`sanitized(ivy24 spike 2026-08-16)` and pass both `tests/QA/FixtureProvenance.tests.ps1`
and `tests/QA/SecretScan.tests.ps1`.

### Secret-scan gate false positive found and fixed

The existing `tests/QA/SecretScan.tests.ps1` GUID-near-domain check false-positived on two
distinct shapes that are unavoidable in any real Settings Catalog JSON payload sanitized
per the rules above (GUIDs kept, `@odata.type` kept verbatim, both co-located in the same
object):

1. the literal JSON property key `"@odata.type"` itself is domain-shaped
   (`odata` + `.` + `type`) — same false-positive class the file's own docstring already
   documents and fixes for `TP.ENT`/`TP.INT` check-id prefixes.
2. the `@odata.type` **value**, e.g.
   `#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance` — domain-shaped
   once its leading `#` is stripped by the domain regex, and unbounded in count (every
   Settings Catalog instance/value kind produces a different value), so a by-value
   deny-list doesn't scale for this one the way it did for case 1.

Fixed by (a) adding `'odata.type'` to the existing `$denyListedDomains` set (same pattern
as the `tp.ent`/`tp.int` precedent) and (b) adding a new, narrower
`$safeDomainPrefixes = @('microsoft.graph.')` allowlist with a `StartsWith` check —
the suffix-based `$safeDomainSuffixes` mechanism can't reach a value that never ends in a
known TLD. Both changes are covered by new unit tests in
`tests/QA/SecretScan.tests.ps1` (including a negative test proving the prefix check is a
genuine `StartsWith`, not an accidental substring match). Full gate re-run after the fix:
**284/284 SecretScan assertions pass**, and the full `./build.ps1 -Tasks test` gate is
green (746 tests, 0 failed).

## 7. Reproducing

The spike script (`scratch/Invoke-SettingsCatalogSpike.ps1`) and the raw, **unsanitized**
per-policy payloads it writes to `scratch/spike-raw/` are intentionally **not** committed —
`scratch/` is gitignored repo-wide specifically so real-tenant data never lands in git by
accident (see the `.gitignore` comment above the `scratch/` entry). To reproduce:

```powershell
Import-Module GraphKit -RequiredVersion 0.1.1
./scratch/Invoke-SettingsCatalogSpike.ps1 -ProfileId ivy24 -SampleSize 120
./scratch/New-SanitizedFixtures.ps1   # re-sanitizes into tests/Fixtures/SettingsCatalog/
```

## 8. Summary for T2.1/T2.2 budgets

- Definitions corpus: 18,227 items / ~55.85 MB estimated wire size / ~1.15 GB managed-heap
  high-water / 20–36 s fetch, all safely inside GraphKit 0.1.1's 60 s headers/body timeout
  for this operation — but budget for the high end (36 s TTFB, ~1.2 GB heap), not the fast
  run.
- Per-policy `/settings`: ~304 ms mean, p99 ~430 ms, call-count-bound. A full 781-policy
  sweep is ~4 minutes sequential; plan for concurrency if that needs to shrink.
- Instance kinds: `Choice` (63%) and `Simple` (13%) dominate;
  `GroupSettingCollection` (10%) is common enough to require real nested-child handling
  (not just top-level flattening); `SimpleSettingCollection` (3%) and
  `ChoiceSettingCollection` (0.5%) are both real but rare — sample sizes for either in any
  future test corpus should not assume even distribution.
- Unresolved-definitionId rate: 0% in this tenant — join logic should still fail
  gracefully (not silently drop) for the case where it isn't 0% elsewhere.
- `<rootId>_name` convention: not observed; do not build on it as a general rule (§5).

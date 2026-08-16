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

## 2. Per-policy `/settings` latency (stratified sample + tail supplement, n=132)

**Correction (post-review):** the original stride-6 systematic sample
(`step = floor(781/120) = 6`, indices `0, 6, 12, …, 714`) never reaches indices 715–780 —
the newest 66-policy import batch (781 total, but `0 + 6×119 = 714` is the last index the
stride touches) was never sampled at all. This was caught in review, not by this spike run
itself. Fixed by adding a **12-policy supplementary sample** spread evenly across that
715–780 tail (`scratch/Invoke-TailSupplement.ps1`, indices `715, 720, 725, …, 770`) and
recombining both samples' raw payloads (`scratch/Merge-SpikeMeasurements.ps1`) for every
number in this document. Corrected sample selection description:

> Systematic stride-6 sample across indices `0`–`714` (120 policies) **plus** a
> supplementary stride-5 sample across indices `715`–`780` (12 policies) — combined
> stratified sample, n=132, covering the full 781-policy list end to end with no untested
> range. (Indices 771–780, the last 10 policies, remain outside both strides; see
> "Residual gap" below.)

| Metric | Value (ms) |
|---|---|
| n | 132 |
| min | 213 |
| p50 | 298 |
| p90 | 345 |
| p99 | 430 |
| max | 444 |
| mean | 298.4 |
| errors | 0 |

The tail supplement's own latencies (213–274 ms, mean well within the main sample's range)
did not shift the combined picture materially — the original stride-6 sample's numbers
(mean 304.2 ms) were already representative of the full corpus, but that was not knowable
without actually sampling the tail, which is why the gap needed closing rather than
assumed away.

Extrapolated to all 781 policies at the observed mean (298.4 ms/call, sequential, no
concurrency): **~233.1 s (~3.9 minutes)** for a full-corpus `/settings` sweep. This is the
number T2.1/T2.2 should budget against for any full-tenant settings collection — it is
call-count-bound (not payload-size-bound; individual `/settings` payloads are small), so
concurrency is the lever if a full sweep needs to run faster than ~4 minutes.

**Residual gap**: indices 771–780 (the last 10 policies) still fall outside both strides
(`floor(66/12) = 5`, so `715 + 5×11 = 770` is the tail stride's last index). This is a much
smaller, lower-risk gap than the original 66-policy miss — T2.1/T2.2 should not assume it's
zero-risk, but closing it further was judged not worth a third read-only sweep for this
spike's purposes.

## 3. Instance-kind histogram

Every `@odata.type` instance kind actually present in the **combined 132-policy sample**
(§2), counted **recursively** (walking into
`groupSettingCollectionValue`/`groupSettingValue`/`choiceSettingValue`/
`choiceSettingCollectionValue` children, not just top-level settings) —
recomputed from the raw payloads on disk after the tail supplement was added, not summed
from the two runs' separate summaries (to avoid any double-counting of overlapping ids):

| `@odata.type` (short form) | Count | % |
|---|---|---|
| `ChoiceSettingInstance` | 550 | 77.6% |
| `SimpleSettingInstance` | 79 | 11.1% |
| `GroupSettingCollectionInstance` | 42 | 5.9% |
| `SimpleSettingCollectionInstance` | 36 | 5.1% |
| `ChoiceSettingCollectionInstance` | 2 | 0.3% |

(The tail supplement shifted `ChoiceSettingInstance`'s share up from 63% to 77.6% and
`SimpleSettingCollectionInstance`'s count up from 11 to 36 — the newest import batch skews
more choice-heavy and has more collection-typed settings than the rest of the corpus. This
is itself evidence the original 66-policy gap mattered, not just a formality.)

All 5 instance kinds that exist in the Settings Catalog schema's instance-shape family were
found in this tenant's real data (no `GroupSettingInstance` — the non-collection group
variant — was observed in the sample; it's schema-legal but this tenant's policies happen
not to use it). `ChoiceSettingInstance` dominates by a wide margin, which matches the
CIS/security-baseline-heavy policy set in this tenant (most settings are toggle/dropdown
choices, not free-form values).

`ChoiceSettingCollectionInstance` is rare (2 hits in the combined 132-sample, both nested
*inside* a `GroupSettingCollectionInstance`, not top-level) — a 3rd, distinct example was
located by extending the read-only search beyond the sample (see §6, `choicecollection-03`;
that extra policy is excluded from all counts in this document so the sample numbers stay
a clean, well-defined 132).

## 4. Unresolved-definitionId rate vs. the corpus

Every distinct `settingDefinitionId` observed across the combined 132-policy sample (596
distinct ids, counting nested children — up from 295 in the pre-tail-supplement sample) was
checked for membership in the full 18,227-item definitions corpus fetched in §1
(case-insensitive `id` match).

**Unresolved rate: 0 / 596 = 0.00%.** Every setting definition id referenced by an actual
policy in this tenant resolves cleanly against `ConfigurationSettingDefinition.ListBeta`'s
output. This is a clean, expected result for a healthy tenant — it validates the join
approach itself, but T2.1/T2.2 should NOT assume 0% is guaranteed in every tenant (a
definition could in principle be retired/renamed between when a policy was created and
when the corpus is fetched); the check exists precisely to catch that case when it occurs
elsewhere.

## 5. `<rootId>_name` convention hit rate on groupSettingCollection instances

**Finding: the `<rootId>_name` child-definitionId naming convention is structurally absent
across all 24 distinct groupSettingCollection roots in the combined 132-policy sample
(0/24, 0.0%), and corpus-verified absent for all 24 of those same roots** (up from 22
roots / 1 corpus-checked root in the pre-review draft of this finding — see "Correction"
below).

1. **Structural** (all 24 sampled roots): none of the sampled policies'
   `groupSettingCollectionValue` arrays ever had more than 1 row (every
   `GroupSettingCollectionInstance` instance in this tenant's data is a single-row "group of
   settings," not a true multi-row "collection of named items" — e.g. the ASR-rules example
   below has exactly one row, and its child's `settingDefinitionId` is
   `..._blockabuseofexploitedvulnerablesigneddrivers`, not `..._name`).
2. **Corpus-level** (all 24 sampled roots, not a single spot-check): for every one of the
   24 distinct groupSettingCollection root `settingDefinitionId`s seen in the sample, the
   full 18,227-item definitions corpus was checked for a definition whose `id` is exactly
   `<root>_name` — **zero matches across all 24 roots**
   (`scratch/Merge-SpikeMeasurements.ps1`, `CorpusNameHits` in
   `_combined-measurements.json`). The convention, if it is real anywhere in the Settings
   Catalog schema, does not apply to any of the shapes this tenant's 781 policies exercise.

**Correction (post-review)**: the original draft of this finding checked the corpus for
only **1 of 22** sampled roots (`device_vendor_msft_policy_config_defender_attacksurfacereductionrules`)
and stated the convention was "verified two ways" as if that were representative of all 22
— an overclaim. The corpus-level check is cheap (it's a single `HashSet.Contains` per root
against the corpus already held in memory), so rather than soften the wording further it
was extended to check every one of the 24 roots in the corrected, combined sample instead
of just one.

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

### Value-level sanitization rule (added post-review — read this before making more fixtures)

**The original sanitization pass covered `Policy.name`/`description`/`templateDisplayName`
and every GUID, but NOT the actual setting VALUES carried inside `simpleSettingValue` /
`simpleSettingCollectionValue` string content — free text an org chooses, not schema.**
Code review caught one real leak this missed: `choicecollection-01.json` (the
LocalUsersAndGroups "add to Administrators" example) carried `"value": "REDACTED-ADMIN-NAME"` —
**this tenant's actual local-administrator account name**, not a placeholder. Fixed to
`"LapsAdmin-Example"`.

**The rule going forward, for T2.1/T2.2 and any future fixture-making from a real tenant**:
after GUID remapping and `Policy.*` scrubbing, walk every `simpleSettingValue.value` and
every `simpleSettingCollectionValue[].value` in the tree (`@odata.type` =
`StringSettingValue`; integer/boolean values need no scrubbing — they can't carry identity)
and scrub any value that is **org-chosen free text**, not a schema/public constant:
account names, group names, URLs/hostnames with org content, filesystem paths with org
content, certificate subjects that identify the *tenant's own* PKI (not a vendor's public,
tenant-invariant identifier), and any other string a human at the org typed in. Do **not**
scrub: well-known SID constants (e.g. `*S-1-5-32-544`, the built-in Administrators group —
identical on every Windows machine everywhere), Microsoft's own published,
tenant-invariant identifiers (e.g. app bundle IDs like `com.microsoft.OneDrive`, or
Microsoft's own Apple code-signing Team ID, which is the same for every tenant that
deploys a Microsoft macOS app and does not identify this tenant), default OS paths (e.g.
`%systemroot%\system32\LogFiles\Firewall\pfirewall.log`), or literal template placeholder
tokens a baseline's own authors left in (e.g. `<YOURACT>`, `<YOUROBJECT>`). When a value
sits behind a `settingDefinitionId` whose own name says it's a free-text/organization field
(e.g. `..._organization`, `..._userdefinedname`, `..._comment`), scrub it even if the
observed value happens to look generic or vendor-related — the field being editable by the
org is what matters, not whether this particular tenant's value happens to look safe.

**Re-pass results, corrected (honest history):** the first re-pass, done in response to
round 1 of review, claimed to have walked "every fixture, every `simpleSettingValue`/
`simpleSettingCollectionValue` string" and reported 4 values across 3 fixtures scrubbed.
That claim was **not actually true** — round 2 of review caught 2 more values that pass
missed: `simple-02.json`'s two `com.apple.servicemanagement_rules_item_comment` values,
`"REDACTED-FIXTURE-VALUE-03"` and `"REDACTED-FIXTURE-VALUE-04"`. These are exactly the shape the rule
above already called out (a `_comment` field is free-text/org-editable by definitionId
name, "scrub it even if the observed value happens to look generic") — the rule was
correct, the sweep that was supposed to apply it simply missed these two instances despite
claiming completeness. Fixed to `"Sanitized rule comment 1"` / `"Sanitized rule comment 2"`
in round 2. **6 values across 4 fixtures** needed scrubbing in total, across both rounds:

| Fixture | Value found | `settingDefinitionId` | Scrubbed to | Caught in |
|---|---|---|---|---|
| `choicecollection-01.json` | `REDACTED-ADMIN-NAME` (real tenant local-admin account name) | `..._accessgroup_users` | `LapsAdmin-Example` | round 1 |
| `groupcollection-02-nested.json` | `REDACTED-FIXTURE-VALUE-01` (free-text `_organization` field) | `com.apple.webcontent-filter_organization` | `Sanitized Organization Name` | round 1 |
| `groupcollection-02-nested.json` | `REDACTED-FIXTURE-VALUE-02` (free-text `_userdefinedname` field) | `com.apple.webcontent-filter_userdefinedname` | `Sanitized Content Filter Name` | round 1 |
| `groupcollection-02-nested.json` (×6) + `simple-02.json` (×2) | `UBF8T346G9` (Apple code-signing Team ID, appearing both standalone and inside cert-requirement strings) | various `com.apple.servicemanagement_rules_item_rulevalue` | `EXAMPLETEAMID9` (scrubbed out of caution per the review's explicit "certificate subjects" category, even though this specific value is Microsoft's own public, tenant-invariant Apple Team ID — see judgment call below) | round 1 |
| `simple-02.json` (×2) | `"REDACTED-FIXTURE-VALUE-03"` / `"REDACTED-FIXTURE-VALUE-04"` (free-text `_comment` field) | `com.apple.servicemanagement_rules_item_comment` | `"Sanitized rule comment 1"` / `"Sanitized rule comment 2"` | **round 2** — missed by round 1's re-pass despite that pass's "every value walked" claim |

**Lesson for T2.1/T2.2**: a manual grep-and-eyeball sweep, even one done carefully against
a written rule, is not a reliable substitute for a scripted, exhaustive walk of every
`simpleSettingValue`/`simpleSettingCollectionValue` node against the `settingDefinitionId`
free-text-field heuristic. If more fixtures are sanitized from a real tenant later, prefer
automating this check (flag every string value whose `settingDefinitionId` matches
`_comment|_organization|_userdefinedname|_name$` or similar, and require each one to be
either on an explicit "known safe" allowlist or scrubbed) over a one-off manual pass that
can silently claim completeness it didn't have.

**Judgment call on `UBF8T346G9`**: this is Microsoft's own published Apple Developer Team
ID, documented in Microsoft's own Defender-for-Mac deployment guides and identical for
every tenant that deploys a Microsoft macOS app — it does not identify Ivy24 specifically.
It was scrubbed anyway because the review named "certificate subjects" as a scrub category
without carving out vendor-public exceptions, and treating it as safe would have required
a judgment call embedded in the fixture rather than stated explicitly in this doc.
Documented here so T2.1/T2.2 can make an informed call if they hit the same tradeoff again
(overwhelmingly Microsoft's own app bundle IDs like `com.microsoft.OneDrive`,
`com.microsoft.wdav`, etc. were judged safe and left verbatim, for the same
tenant-invariant reasoning — see the "do not scrub" list above).

All 15 fixtures were re-validated as well-formed JSON after these edits and re-passed
through both QA gates (see below).

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
`$safeDomainExactPatterns = @('^microsoft\.graph\.[A-Za-z0-9]+$')` allowlist matched with a
full-token regex.

**Correction (post-review)**: the first version of fix (b) used a plain
`StartsWith('microsoft.graph.')` check, which admits any domain that merely *begins* with
that text — including an attacker-controlled domain like
`microsoft.graph.attacker-exfil.io`, registered specifically to slip past a naive prefix
check. Fixed by anchoring the *whole* matched token to
`^microsoft\.graph\.[A-Za-z0-9]+$` (no further dots permitted): every real `@odata.type`
value is exactly `microsoft.graph.<PascalCaseIdentifier>` with no additional dotted labels,
so legitimate values still match while `microsoft.graph.attacker-exfil.io` (which has three
more labels after `graph`) does not. The exact mutation from review is now a named
regression test (`'still flags a GUID near "microsoft.graph.attacker-exfil.io" - the exact
StartsWith-bypass mutation from code review'`), alongside the original "does not match"
negative test.

Both changes are covered by unit tests in `tests/QA/SecretScan.tests.ps1`. Full gate
re-run after all fixes: **285/285 SecretScan assertions pass**, and the full
`./build.ps1 -Tasks test` gate is green.

## 7. Reproducing

The spike script (`scratch/Invoke-SettingsCatalogSpike.ps1`) and the raw, **unsanitized**
per-policy payloads it writes to `scratch/spike-raw/` are intentionally **not** committed —
`scratch/` is gitignored repo-wide specifically so real-tenant data never lands in git by
accident (see the `.gitignore` comment above the `scratch/` entry). To reproduce:

```powershell
Import-Module GraphKit -RequiredVersion 0.1.1
./scratch/Invoke-SettingsCatalogSpike.ps1 -ProfileId ivy24 -SampleSize 120
./scratch/Invoke-TailSupplement.ps1 -ProfileId ivy24 -TailStart 715 -TailSampleSize 12
./scratch/Merge-SpikeMeasurements.ps1 -ProfileId ivy24   # recomputes histogram/unresolved/rootId_name over the combined sample
./scratch/New-SanitizedFixtures.ps1   # re-sanitizes into tests/Fixtures/SettingsCatalog/
```

## 8. Summary for T2.1/T2.2 budgets

- Definitions corpus: 18,227 items / ~55.85 MB estimated wire size / ~1.15 GB managed-heap
  high-water / 20–36 s fetch, all safely inside GraphKit 0.1.1's 60 s headers/body timeout
  for this operation — but budget for the high end (36 s TTFB, ~1.2 GB heap), not the fast
  run.
- Per-policy `/settings`: ~298 ms mean (n=132, full corpus coverage incl. tail), p99 ~430
  ms, call-count-bound. A full 781-policy sweep is ~3.9 minutes sequential; plan for
  concurrency if that needs to shrink.
- Instance kinds (n=132, full-corpus-coverage sample): `Choice` (77.6%) dominates even more
  than the pre-correction number suggested; `Simple` (11.1%),
  `GroupSettingCollection` (5.9%, common enough to require real nested-child handling, not
  just top-level flattening), `SimpleSettingCollection` (5.1%) and
  `ChoiceSettingCollection` (0.3%) are all real but rare — sample sizes for any of these in
  a future test corpus should not assume even distribution, and should not assume the
  newest import batch looks like the rest of the corpus (it doesn't, see §3).
- Unresolved-definitionId rate: 0% in this tenant (0/596, full-corpus-coverage sample) —
  join logic should still fail gracefully (not silently drop) for the case where it isn't
  0% elsewhere.
- `<rootId>_name` convention: structurally and corpus-verified absent across all 24
  sampled roots; do not build on it as a general rule (§5).
- **Value-level sanitization**: setting VALUES (not just policy names/GUIDs) can carry real
  tenant identity — see the value-scrub rule added to §6 after review caught a real leak
  (`REDACTED-ADMIN-NAME`, this tenant's actual local-admin account name). Any future fixture-making
  from a real tenant must walk `simpleSettingValue`/`simpleSettingCollectionValue` strings,
  not just `Policy.*` fields and GUIDs.

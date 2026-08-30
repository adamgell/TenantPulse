# TenantPulse findings document schema

Produced by `Invoke-PulseEvaluation -Store <store> -Checks <descriptors>` (Task 1.6). This
is the canonical shape every renderer (T1.8's `Export-PulseReport`) and the scoring layer
(T1.7) consume - it does not change shape after this task except for `coverage`/`scores`
being filled in by T1.7 (they are already keyed here as `null` placeholders).

`Invoke-PulseEvaluation` itself returns a `[pscustomobject]` with two top-level properties,
only one of which is ever serialized:

```
{
    Document     = <the findings document below>
    RedactionMap = @{ '<raw evidence identity>' = 'tp-<hmac-hex>' , ... }
}
```

`Document` is what gets passed to `ConvertTo-PulseCanonicalJson`. `RedactionMap` is an
in-memory-only lookup, one entry per distinct evidence `identity` seen across every finding,
built under the local operator key (`Get-PulseOperatorKey` / `Get-PulsePseudonym`). It is
**never** written into `Document` and must never be serialized to disk directly - it exists
so a later render step (`-Redact` on `Invoke-PulseAssessment`, T1.8) can substitute
pseudonyms for raw identities without re-running evaluation. A render-only path that only has
a `Document` (no fresh `RedactionMap`) cannot redact.

## Document shape

```jsonc
{
  "schemaVersion": "1.0",
  "generatedUtc": "2026-08-15T21:30:41.123Z",   // the SNAPSHOT MANIFEST's createdUtc, never
                                                  // wall clock - re-evaluating the same
                                                  // snapshot with the same catalog is
                                                  // byte-identical through
                                                  // ConvertTo-PulseCanonicalJson every time
  "tenant": "tp-<hmac-hex>",                     // pass-through of the manifest's own
                                                  // `tenant` field - already a pseudonym at
                                                  // snapshot-write time (New-PulseSnapshotStore
                                                  // -Tenant), never the raw tenant id
  "producer": {
    "tenantPulse": "0.1.0",                      // this module's own version
    "graphKit": null,                             // pass-through of manifest.producer.graphKit
    "scoringModelVersion": "1.0"                  // fixed for Phase 1 - T1.7 owns the model
  },
  "coverage": null,                               // placeholder - filled in by T1.7
  "scores": null,                                 // placeholder - filled in by T1.7
  "findings": [
    {
      "id": "TP.ENT.0001",                        // check descriptor Id
      "title": "Legacy authentication is blocked by Conditional Access",
      "category": "Entra.ConditionalAccess",
      "severity": "High",                         // Critical|High|Medium|Low|Info
      "status": "Pass",                            // Pass|Warn|Fail|NotApplicable|Error
      "evidence": [                                // sorted ordinally by sortKey then
        {                                           // identity; [] for Pass/Fail from an
          "identity": "<raw identity, e.g. an object id>",  // Expression rule, and for
          "detail": { /* arbitrary, rule-defined shape, or null */ },  // NotApplicable/Error
          "sortKey": "<defaults to identity when the rule didn't set one>"
        }
      ],
      "reason": null,                              // see "Reason semantics" below
      "effort": "Low",                              // Low|Medium|High
      "impact": "High",                             // Low|Medium|High
      "consulting": {
        "whatItMeans": "...",
        "whyItMatters": "...",
        "remediation": ["..."],
        "portalLinks": ["https://..."]
      },
      "references": {
        "research": "docs/research/...",
        "authorities": ["https://learn.microsoft.com/...", "MS.AAD.1.1v1"]
      },
      "origin": null                                // or { "project", "id", "license" }
    }
    // ... one entry per check, sorted ordinally by id
  ]
}
```

Every object in this document - `Document` itself, each finding, each evidence entry,
`consulting`/`references`/`origin` - is built without a `PSTypeName` key. `[pscustomobject]@{
PSTypeName = 'X'; ... }` leaves `PSTypeName` as a real, visible property in addition to
setting the object's type name (see `Import-PulseCheckCatalog`'s descriptor objects, which do
this deliberately); the findings document must never do that, since it would appear as a
`"PSTypeName"` key in the serialized JSON. The `TenantPulse.RuleResult` objects a Function
rule returns (`New-PulseFinding`'s output) DO carry `PSTypeName` - that is fine, because they
are an internal engine intermediate the evaluator consumes and never passes through to the
document as-is.

## Status semantics

| Status         | Who assigns it | Meaning |
|----------------|-----------------|---------|
| `Pass`         | rule            | The check's condition holds. |
| `Warn`         | rule (Function only) | The check needs attention but isn't a hard failure. Only a Function rule can produce this - an Expression rule can only resolve to Pass/Fail. |
| `Fail`         | rule            | The check's condition does not hold. |
| `NotApplicable`| engine, OR rule (Function only, with mandatory `Reason`) | Engine-assigned: a declared dataset is missing, `Failed`, `Skipped`, unknown, or `Partial` without an explicit reviewed Function opt-in; or a declared gate is unsatisfied - the rule is never invoked. A non-aware `Partial` reason contains only the canonical dataset name and aggregate gap count. Rule-assigned (post-review, adjudicated): a Function rule may itself return `NotApplicable` when its own condition genuinely does not apply given what it observed in `$Datasets` (including a structurally valid opted-in `Partial` dataset whose usable rows do not prove a monotonic decision) - `New-PulseFinding -Status NotApplicable` REQUIRES `-Reason` (throws without it). Both paths land in the identical `status: "NotApplicable"` string, so `Add-PulseScores` excludes both from its scoring denominator identically. |
| `Error`        | engine          | The rule threw, returned a shape the engine could not interpret, declared an unrecognized `Rule.Type`, or an opted-in `Partial` entry had zero usable rows, invalid structured gaps, or an input that could not be safely projected/deep-cloned. Evaluation of every OTHER check still continues - one bad rule never hides the rest of the run ("no silent gaps"). |

`Error` is **engine-assigned only** - no rule function or expression can ever produce it
directly. `NotApplicable` may be engine- or rule-assigned (see above). `New-PulseFinding`
(the only way a rule builds a result through the documented path) enforces `Status` to be
one of `Pass`/`Warn`/`Fail`/`NotApplicable` via `[ValidateSet]`, with a mandatory,
non-empty `Reason` whenever `Status` is `NotApplicable`.

## Reason semantics

- `Pass`/`Fail`: `reason` is whatever the rule set (`New-PulseFinding -Reason`, or `null` for
  an Expression rule, which never carries a reason).
- `Warn`: `reason` should explain what needs attention (Function rules only).
- `NotApplicable`: for an ENGINE-assigned NotApplicable, `reason` **quotes the snapshot
  manifest's own dataset reason verbatim** (already redacted upstream by Task 1.5's
  `Protect-PulseReason` - the evaluator does not redact it again) when the dataset was
  recorded `Failed`/`Skipped` with a reason. A dataset entirely missing from the manifest,
  or recorded `Failed`/`Skipped` with no reason on file, gets an engine-synthesized reason
  naming the dataset and its status instead. A non-aware `Partial` entry is different by
  design: its synthesized reason contains only the canonical dataset name and aggregate
  gap count, never manifest reason/detail, gap scope/detail, provider, or operation text.
  For a RULE-assigned NotApplicable, `reason` is
  whatever the rule passed to `New-PulseFinding -Reason` (mandatory for this status) -
  likewise quoted verbatim, never re-capped by `Protect-PulseReason` (the evaluator's
  redaction step is skipped for every NotApplicable finding regardless of who assigned it).
- `Error`: `reason` is the caught exception's message (for a throw), or an engine-authored
  sentence naming what was wrong with the rule's output shape.

## Dataset and gate resolution order

For each check, in order:

1. **Gates** (`Data.Gates`): each declared gate name is resolved via `Get-PulseGateStatus
   -Gate <name> -Manifest <manifest>`. Available permits collection. A proven
   `Unavailable` gate degrades the check to `NotApplicable` with `FailureClass =
   LicenseRequired`; an `Unknown` gate degrades it to `NotApplicable` with
   `FailureClass = GateUnknown`. No unknown gate may evaluate its rule as `Pass`.
   Gate resolution is deliberately fail-closed: a missing dataset is not proof of license
   absence, and permission-denied license evidence remains `PermissionDenied`.
2. **Datasets** (`Data.Datasets`): each declared dataset name must have a manifest entry.
   `Collected` is usable. Missing, `Failed`, `Skipped`, unknown, and non-opted `Partial`
   degrade to `NotApplicable`, and the rule is never invoked. Only a catalog-validated
   Function descriptor may name a dataset in `Data.PartialDatasets`; that opted-in
   `Partial` entry is usable only when it has one or more rows and its gaps satisfy the full
   `New-PulseCollectionOutcome` structure contract. Invalid opted-in Partial input is
   `Error`, not an inapplicable decision.
3. Once every declared dataset is usable, rows are read (`Read-PulseDataset`, cached once
   per dataset name across the whole evaluation run) and handed to the rule as an
   independently deep-cloned `$Datasets` hashtable. A partial-aware Function also receives
   an independently deep-cloned `-DatasetOutcomes` hashtable for **every** declared dataset.
   Each outcome exposes exactly `Status`, `FailureClass`, `ReasonCode`, `Detail`, `Provider`,
   `ApiVersion`, `Operations`, and `Gaps`; manifest-only `reason`, `sha256`, `itemCount`, and
   `collectedUtc` are absent. `DatasetOutcomes` is an in-memory evaluation input only. It is
   never copied into a finding, scoring document, snapshot, or report, so findings schema
   remains 1.0 and snapshot schema remains 2.0.

`$Context` (optional, threaded from `Invoke-PulseEvaluation -Context`) always carries two
engine-populated keys, unconditionally, regardless of whether the caller supplied its own
`-Context` at all: `SnapshotCreatedUtc` and `EvaluationCutoffBase` (both the same value -
the snapshot manifest's own `createdUtc`). A rule that needs "how long ago was this"
(e.g. a staleness threshold) MUST derive its cutoff from one of these, never from
`[datetime]::UtcNow` - the manifest's `createdUtc` is what makes re-evaluating the same
snapshot twice byte-identical regardless of when evaluation actually runs; wall-clock time
inside a rule breaks that guarantee.

## Ordering guarantees

- `findings` is sorted ordinally by `id` (`[string]::CompareOrdinal`), regardless of the
  order `-Checks` was supplied in.
- Each finding's `evidence` is sorted ordinally by `sortKey`, then by `identity` as a
  tie-breaker.
- Both use the same index-sort-then-project pattern `ConvertTo-PulseCanonicalJson` and
  `Import-PulseCheckCatalog` use for their own ordinal sorts (never `Sort-Object` without
  `-Culture`-independent comparers, and never the two-array `[Array]::Sort(keys, items)`
  overload - see those functions' own docstrings for why).

Combined with `generatedUtc` being pinned to the manifest's `createdUtc` (never wall clock),
re-evaluating the same snapshot against the same catalog produces a `Document` that
serializes byte-identically through `ConvertTo-PulseCanonicalJson` every time.

## Settings expansion artifacts (Phase 2, `-ExpandSettings`)

These are **not** part of the findings `Document` above - Phase 2's checks still read
`deviceCompliancePolicies`/`deviceConfigurations`/`configurationPolicies` the same way
Phase 1 checks read any other dataset (`Data.Datasets` + `$Datasets`, see "Dataset and gate
resolution order"). The expansion/conflict artifacts documented here are a **separate**,
lower-level derived-data layer under the snapshot store's own `expanded/` directory,
recorded in `manifest.expansions.<name>` (schema 1.1.0, Task 2.1) - they exist for tooling
that wants the per-setting decomposition directly (a future check family, an external
report), not for the findings document itself.

### `manifest.expansions.<name>` (per-family status entry)

```
manifest.expansions.<name> = {
  status: 'Expanded' | 'Partial' | 'NotExpanded' | 'Failed';
  path; format: 'jsonl' | 'json'; schemaVersion; sha256;
  policyCount;              # 'family count' for the conflicts entry (see Publish-
                             # PulseConflictArtifact's own docstring)
  rowCount; unresolvedNameCount; redactedSecretCount;
  gaps: [ { policyId; reason } , ... ];  # sorted ordinally on (policyId, reason)
  reason;                   # required for NotExpanded/Failed
}
```

`<name>` is one of `settingsCatalog`, `compliance`, `deviceConfiguration` (the three row
producers), or `conflicts` (see below). `path` points at an IMMUTABLE, content-addressed
generation file - `expanded/<name>.<sha256>.jsonl` for the three row producers,
`expanded/conflicts.<sha256>.json` for the conflicts artifact - never a fixed filename;
always resolve the real path from the manifest, never assume it.

### Row schema v1 (`settingsCatalog`/`compliance`/`deviceConfiguration` - one JSON object
per line in the family's own `.jsonl`)

```jsonc
{
  "schemaVersion": "1",
  "policyId": "...", "policyType": "settingsCatalog"|"compliance"|"deviceConfiguration",
  "policyName": "..."|null, "templateFamily": "..."|null, "isBaseline": true|false,
  "settingPath": "...",          // '/'-joined settingDefinitionId chain root->leaf, '/'
                                   // inside an id escaped as '~s'
  "settingDefinitionId": "...", "settingName": "..."|null, "nameResolved": true|false,
  "instanceId": "...",           // native id, or synthetic '<parentInstanceId>/<defId>#<n>'
  "value": <typed scalar|array>|null,   // null when redacted
  "valueLabel": "..."|[...]|null, "labelResolved": true|false,
  "redacted": true|false, "valueState": "..."|null,
  "applicability": { "platform"; "technologies" }|null,
  "assignments": [
    { "intent": "include"|"exclude"|null, "targetType": "..."|null,
      "groupId": "..."|null, "filterId": "..."|null, "filterType": "..."|null }
  ]                              // empty means authoritatively unassigned; a failed
                                   // assignment fetch gaps the policy instead of emitting rows
}
```

Rows within a family's `.jsonl` are sorted ordinally (`[string]::CompareOrdinal`) on
`(policyId, settingPath, instanceId)` - deterministic regardless of worker completion
order (see `Invoke-PulseSettingsCatalogExpansion`'s own docstring). Every line is one
compact JSON object (`ConvertTo-PulseCanonicalJsonLine`), ordinal-sorted properties, no
embedded raw newlines, exactly one trailing LF per line including the last.

### `conflicts` artifact (`expanded/conflicts.<sha256>.json`, one JSON document, not jsonl)

```jsonc
{
  "schemaVersion": "1",
  "conflicts": [
    {
      "settingDefinitionId": "...",
      "settingName": "..."|null,        // ordinal-minimum of every distinct resolved
                                          // settingName seen for this defId; null only
                                          // when no contributing row had a resolved name
      "nameVariants": [ "..." , ... ]|null,  // every OTHER distinct resolved name seen for
                                          // this defId (ordinal-sorted), when policies
                                          // disagree on display name; null when there was
                                          // zero or exactly one distinct name
      "values": [
        { "canonicalValue": <typed value>|null, "redacted": true|false,
          "policies": [ { "policyId": "..."; "policyName": "..."|null }, ... ] }
        // >= 2 value records per conflict entry, by construction (see below)
      ],
      "assignmentOverlap": "proven" | "possible" | "none" | "unknown",
      "assignmentOverlapReason": "..."|null   // populated at least for 'unknown'
    }
    // sorted ordinally by settingDefinitionId; each entry's values sorted by their own
    // canonical-value text; each value record's policies sorted by policyId
  ]
}
```

A `settingDefinitionId` becomes a conflict entry only when it has >= 2 distinct
canonical-value records collectively naming >= 2 distinct policy ids (one policy
disagreeing only with itself is not a conflict - see `ConvertTo-PulseConflictRecords`'s own
docstring). **Zero conflicts found is a valid, `Expanded` outcome** - it means detection ran
over every available family and found none, not that detection did not run; do not treat an
empty `conflicts` array as suspicious on its own. `redacted: true` on a value record means
every row that contributed to it carried a secret value - that record's `canonicalValue` is
always `null` in that case and the true value is never present anywhere in this document
(see the module-wide SECRET CONTRACT). `assignmentOverlap` is the plan's four-state result:
`'proven'` (every contributing policy's real assignment targets provably overlap),
`'possible'` (cannot rule overlap out, but not proven either - e.g. a filter or an
All-devices/All-users target is involved), `'none'` (every pair of contributing policies'
assignment targets is provably disjoint), or `'unknown'` (at least one contributing row
lacks authoritative assignment data). Settings Catalog rows always carry a normalized
assignment array: `[]` means authoritatively unassigned, while an unavailable or invalid
assignment payload gaps that policy before row publication.

### `settingPresenceIndex` artifact (`expanded/settingPresenceIndex.<sha256>.json`)

One JSON document, not jsonl. `families.<policyType>.<settingDefinitionId>.values[]`
carries `policyCount` / `assignedPolicyCount` (original) plus `policyIds` /
`assignedPolicyIds` (additive, ordinal-sorted distinct ids). Counts stay; the
id arrays let a same-policy AND (TP.INT.0017/0018) intersect without streaming
the underlying jsonl. A redacted value group still has `canonicalValue: null`
and never carries the secret; its `policyIds` are presence-only.

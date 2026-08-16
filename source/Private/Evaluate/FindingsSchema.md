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
| `NotApplicable`| engine, OR rule (Function only, with mandatory `Reason`) | Engine-assigned: a declared dataset is missing from the manifest, or recorded `Failed`/`Skipped`; or a declared gate is unsatisfied - the rule is never invoked. Rule-assigned (post-review, adjudicated): a Function rule may itself return `NotApplicable` when its own condition genuinely does not apply given what it observed in `$Datasets` (e.g. TP.ENT.0001 once Conditional Access supersedes Security Defaults) - `New-PulseFinding -Status NotApplicable` REQUIRES `-Reason` (throws without it), because unlike the engine's case there is no manifest reason to fall back on. Both paths land in the identical `status: "NotApplicable"` string, so `Add-PulseScores` (which keys off that string alone) excludes both from its scoring denominator identically - "who assigned it" is not a distinction the rest of the pipeline ever needs to make. |
| `Error`        | engine          | The rule threw, returned a shape the engine could not interpret (a Function rule not returning a `TenantPulse.RuleResult`-shaped object with a valid `Status`, or an Expression rule not resolving to `[bool]`), a Function rule returning `NotApplicable` with no `Reason`, or declared an unrecognized `Rule.Type`. Evaluation of every OTHER check still continues - one bad rule never hides the rest of the run ("no silent gaps"). |

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
  naming the dataset and its status instead. For a RULE-assigned NotApplicable, `reason` is
  whatever the rule passed to `New-PulseFinding -Reason` (mandatory for this status) -
  likewise quoted verbatim, never re-capped by `Protect-PulseReason` (the evaluator's
  redaction step is skipped for every NotApplicable finding regardless of who assigned it).
- `Error`: `reason` is the caught exception's message (for a throw), or an engine-authored
  sentence naming what was wrong with the rule's output shape.

## Dataset and gate resolution order

For each check, in order:

1. **Gates** (`Data.Gates`): each declared gate name is resolved via `Get-PulseGateStatus
   -Gate <name> -Manifest <manifest>`. Phase 1: this is a stub registry that always answers
   `'Unknown'` - no live license/feature detection exists yet. **`Unknown` never degrades a
   check** - the check still runs. This is deliberate staging: a later task teaching real
   gate detection only has to change `Get-PulseGateStatus` itself: the evaluator already
   calls it per declared gate and is ready to react to a real `Unavailable`/`Available`
   status.
2. **Datasets** (`Data.Datasets`): each declared dataset name must have a manifest entry with
   `status: 'Collected'`. Missing, `Failed`, or `Skipped` degrades the check to
   `NotApplicable` (see Reason semantics above) and the rule is never invoked.
3. Only once every declared dataset is confirmed `Collected` are the datasets read
   (`Read-PulseDataset`, cached once per dataset name across the whole evaluation run - many
   checks commonly share a dataset) and handed to the rule as `$Datasets` (a
   `dataset-name -> object[]` hashtable) - a `Function` rule receives it via
   `-Datasets <hashtable>`; an `Expression` rule sees it bound as the `$Datasets` variable.

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
  reason;                   # required for NotExpanded/Failed; also carries the
                             # 'assignments-deferred: awaiting GraphKit release' note on
                             # every successful settingsCatalog entry (G-gate core slice)
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
  "assignments": null            // ALWAYS null in the core slice - see the G-gate
                                   // sequencing amendment; a non-null shape is Phase 2b
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
      "groups": [
        { "canonicalValue": <typed value>|null, "redacted": true|false,
          "policies": [ { "policyId": "..."; "policyName": "..."|null }, ... ] }
        // >= 2 groups per conflict entry, by construction (see below)
      ],
      "assignmentOverlap": "proven" | "possible" | "none" | "unknown",
      "assignmentOverlapReason": "..."|null   // populated at least for 'unknown' -
                                                // 'assignments-deferred: awaiting GraphKit
                                                // release' for every core-slice
                                                // settingsCatalog-involving conflict
    }
    // sorted ordinally by settingDefinitionId; each entry's groups sorted by their own
    // canonical-value text; each group's policies sorted by policyId
  ]
}
```

A `settingDefinitionId` becomes a conflict entry only when it has >= 2 distinct
canonical-value groups collectively naming >= 2 distinct policy ids (one policy
disagreeing only with itself is not a conflict - see `ConvertTo-PulseConflictRecords`'s own
docstring). **Zero conflicts found is a valid, `Expanded` outcome** - it means detection ran
over every available family and found none, not that detection did not run; do not treat an
empty `conflicts` array as suspicious on its own. `redacted: true` on a group means every
row that contributed to it carried a secret value - the group's `canonicalValue` is always
`null` in that case and the true value is never present anywhere in this document (see the
module-wide SECRET CONTRACT). `assignmentOverlap` is the plan's four-state result:
`'proven'` (every contributing policy's real assignment targets provably overlap),
`'possible'` (cannot rule overlap out, but not proven either - e.g. a filter or an
All-devices/All-users target is involved), `'none'` (every pair of contributing policies'
assignment targets is provably disjoint), or `'unknown'` (at least one contributing row
carries `assignments: null` - the deferred-assignments state every `settingsCatalog` row
carries in the core slice, so overlap cannot be evaluated at all for any conflict that
includes one).

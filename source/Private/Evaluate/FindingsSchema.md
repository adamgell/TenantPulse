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
| `NotApplicable`| engine          | A declared dataset is missing from the manifest, or recorded `Failed`/`Skipped`; or a declared gate is unsatisfied. The rule is never invoked. |
| `Error`        | engine          | The rule threw, returned a shape the engine could not interpret (a Function rule not returning a `TenantPulse.RuleResult`-shaped object with a valid `Status`, or an Expression rule not resolving to `[bool]`), or declared an unrecognized `Rule.Type`. Evaluation of every OTHER check still continues - one bad rule never hides the rest of the run ("no silent gaps"). |

`NotApplicable` and `Error` are **engine-assigned only** - no rule function or expression can
ever produce them directly. `New-PulseFinding` (the only way a rule builds a result) enforces
`Status` to be `Pass`/`Warn`/`Fail` via `[ValidateSet]`.

## Reason semantics

- `Pass`/`Fail`: `reason` is whatever the rule set (`New-PulseFinding -Reason`, or `null` for
  an Expression rule, which never carries a reason).
- `Warn`: `reason` should explain what needs attention (Function rules only).
- `NotApplicable`: `reason` **quotes the snapshot manifest's own dataset reason verbatim**
  (already redacted upstream by Task 1.5's `Protect-PulseReason` - the evaluator does not
  redact it again) when the dataset was recorded `Failed`/`Skipped` with a reason. A dataset
  entirely missing from the manifest, or recorded `Failed`/`Skipped` with no reason on file,
  gets an engine-synthesized reason naming the dataset and its status instead.
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

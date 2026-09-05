# Application report data contract v1

## Purpose and boundary

TenantPulse can collect neutral application-report inputs with:

```powershell
Get-PulseTenantSnapshot -ProfileId 'contoso' -OutputPath './snapshot' -ReportData Applications
```

`Invoke-PulseAssessment` accepts the same `-ReportData Applications` profile on its fresh
collection parameter set. Report data is independent of selected health checks: an empty check
selection can still request it, and a check does not have to consume either artifact.

This contract ends at versioned JSONL. TenantPulse does not render DOCX/XLSX, apply CDW or
customer branding, decide whether a finding is approved, or overwrite customer-maintained Office
fields. Snapshot report data is sensitive, local-only audit material unless a later delivery
process applies its own complete classification and sharing policy.

## GraphKit operation contract

One permission preflight includes the exact operation union before any report target request:

| Type | Operation | API | Purpose |
|---|---|---|---|
| `MobileApp` | `ListBeta` | `beta` | Application inventory |
| `MobileAppAssignment` | `List` | `v1.0` | Per-application assignments |
| `Group` | `Get` | `v1.0` | Group identity and display name; optional description when producer-selected |
| `GroupMember` | `List` | `v1.0` | Bounded member evidence/count |
| `AppInstallSummaryReport` | `Get` | `beta` | Non-mutating install-summary report action |

Every call requires exactly one genuine, complete or explicitly partial
`GraphKit.OperationResult`. Raw rows, a lookalike object, multiple envelopes, or null `Data` is
invalid provider data. A successful `PagingStrategy=NextLink` envelope additionally requires
native-Boolean `Truncated` and positive-integer `PageCount` completeness signals. GraphKit's
terminal paged failure envelopes and `PagingStrategy=None` envelopes may omit both, while any
supplied values remain type-checked and a contradictory `Truncated=true` on a non-paged result
remains invalid. Authentication failure aborts later network report work and sets the snapshot's
top-level `collectionFailure`; other failures remain isolated to their artifact or row scope.

`AppInstallSummaryReport.Get` is request-body paged rather than `@odata.nextLink` paged. TenantPulse
sends `skip`, `top = 200`, `filter`, `orderBy = ["ApplicationId asc"]`, and `select`, then
continues until the accumulated matrix-row count equals `TotalRowCount`, subject to a hard
200-page limit. `skip` advances by the number of rows actually returned, so a short non-terminal
page cannot cause omitted rows. Application identity is checked across pages even with the stable
sort request: an overlapping/reordered page is discarded and recorded as a bounded gap rather
than counted toward false completeness. A continuation that lacks a unique application-identity
witness stops Partial. A missing, changing, exceeded, unreachable, or repeated page is likewise a
bounded gap; a repeated payload is not counted twice toward completeness. Rows from completed
pages remain available as `Partial`; they are never upgraded to complete merely because the
GraphKit request envelope itself succeeded. A complete direct named-record response is already
the complete row set and does not enter matrix paging. An empty first GraphKit `Data` array is
missing provider data, not an authoritative empty report.

## Artifact manifest

The snapshot manifest records:

- `manifest.expansions.application-assignments`
- `manifest.expansions.app-install-errors`

Each usable artifact has `format = jsonl`, `schemaVersion = 1`, a SHA-256 digest, row count, source
count, and a content-addressed file under `expanded/`. Status is:

- `Expanded`: the requested scope is complete, including a valid zero-row result.
- `Partial`: usable rows exist and one or more bounded gaps identify omitted or uncertain scope.
- `NotExpanded`: no usable artifact could be produced, with a bounded reason.
- `Failed`: collection produced candidate rows, but local redaction, serialization, or atomic
  publication could not safely publish this artifact. The sibling report remains independent and
  is still attempted unless a Graph authentication failure set the run-wide network abort.

Readers must resolve the file through the manifest and verify its hash. They must not guess a
filename or treat a missing/`NotExpanded` artifact as an authoritative empty result.

Before either artifact is staged, TenantPulse recursively replaces every case-insensitive
occurrence of the current tenant ID in every string value—including nested assignment settings,
group descriptions, application names, and forward-compatible `sourceColumns`. The scrub is
fail-closed: a row tree that cannot be safely traversed is not persisted.

`policyCount` is retained by the existing expansion-manifest schema. For these non-policy
artifacts it means root source count (mobile applications for assignments; Graph report payload
objects for install errors); `rowCount` remains the authoritative normalized-row count.

## `application-assignments` row schema

Every row carries `schemaVersion = "1"` and these stable fields:

| Field group | Fields |
|---|---|
| Application | `appId`, `appName`, `publisher`, `appType`, `isFeatured`, `isBuiltIn`, `isBuiltInDerived`, `createdDateTime`, `lastModifiedDateTime` |
| Assignment | `assignmentCount`, `assignmentId`, `intent`, `settings`, `assignmentResolutionState` |
| Target | `targetType`, `targetDisplayName`, `isExclusion`, `filterId`, `filterType` |
| Group | `groupId`, `groupName`, `groupDescription`, `groupMemberCount`, `groupResolutionState`, `memberResolutionState` |

TenantPulse `0.3.0` keeps its reproducible exact dependency on immutable GraphKit `0.3.0`.
That producer's `Group.Get` descriptor selects group identity and display name but not
`description`, so `groupDescription` is normally `null` under the stable dependency. The schema
reserves and safely preserves the field when a later verified GraphKit release selects it; this
unreleased source does not claim that a local GraphKit `0.4.0-r8` prerelease is a customer-installable
dependency.

An application with no assignments still produces one row with
`assignmentResolutionState = NoAssignments`; it is never silently discarded. Supported target
types are group, exclusion group, all devices, all licensed users, and device/app-management
filter targets. Unknown or malformed target types preserve the source application/assignment
identity and add a gap. A returned assignment without `assignmentId` is malformed. `Group.Get`
metadata is accepted only when its returned `id` matches the requested group; mismatched identity
is discarded while independently collected membership evidence can remain usable.

Groups are cached per collection run. Repeated include/exclude assignments to one group cause at
most one `Group.Get` and one `GroupMember.List`. Group metadata and membership certainty are
independent: a missing group can retain a known member count, and a truncated member walk retains
the observed count with `memberResolutionState = Partial` rather than calling it complete.
If child group/member authentication fails after an application's assignment list was fetched,
those assignment rows keep their independently proven `assignmentResolutionState`; only the
failed child and later suppressed child resolutions are marked `Failed`/`NotEvaluated`.

## `app-install-errors` row schema

Every row carries `schemaVersion = "1"` and stable normalized fields:

`appName`, `appVersion`, `platform`, `installStatus`, `errorCode`, `errorMessage`, `deviceCount`,
`userCount`, `lastUpdated`, `appId`, `publisher`, and `installationType`.

`sourceColumns` preserves the complete source row with its original column names and values. The
collector accepts both a Graph report `Schema`/`Values` matrix and direct named records. A valid
schema with zero values and `TotalRowCount = 0` is authoritative empty data. A malformed matrix row
becomes an explicit gap; valid sibling rows remain usable. Duplicate normalized column names are
rejected for both matrix schemas and direct named records, so punctuation/case aliases cannot
overwrite one another by enumeration order. A populated row is usable only when it contains a non-empty application identity value
(`ApplicationId`, `DisplayName`, or a documented alias) plus at least one non-null report signal
value such as failed device/user count, install status, or error code. Numeric zero is a meaningful
count, not a missing value. The current Intune summary's `ApplicationId`, `DisplayName`,
`FailedDeviceCount`, and `FailedUserCount` normalize to `appId`, `appName`, `deviceCount`, and
`userCount` while all sibling summary columns remain unchanged in `sourceColumns`.

TenantPulse deliberately does not copy IHA's computed `Failure Rate` or hard-coded `Severity`.
Those were interpretations rather than Graph facts. A downstream Office builder may derive and
label such presentation fields, but the source contract retains Graph's raw counts and error code
without presenting a derived judgment as collected evidence.

## Determinism and future Office builds

Rows and gaps are sorted ordinally before canonical serialization. Compact artifact-specific keys
sort first; the complete canonical serialized row is the final tie-breaker, so duplicate primary
keys cannot retain page or worker order. Equivalent input in a different Graph/page/worker order
therefore produces the same artifact bytes and digest. This makes a future Office builder able to
compare a new collection with a prior accepted document, update only its machine-owned tables, and
preserve customer-owned response, owner, target-date, prerequisite, and approval fields without
depending on TenantPulse implementation order.

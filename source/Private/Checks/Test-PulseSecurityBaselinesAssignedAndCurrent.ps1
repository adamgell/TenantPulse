<#
    Private: TP.INT.0029 rule function - security baselines assigned and not on a
    deprecated version (Task 3.3, research-matrix - no Maester origin, practitioner
    judgment).

    PENDING DATASET (honest NA): `securityBaselinesAssignedAndCurrent` is a COMPOSITE walk
    (templateFamily-filtered configurationPolicies + assignments + a deprecated-template
    catalog lookup) with no released GraphKit 0.1.1 descriptor for any of its three
    ingredients as a combined shape - confirmed via a live Get-GraphOperation -List
    enumeration (the raw `configurationPolicies` list itself IS released, but neither
    `$expand=assignments` on it nor a `deviceManagement/templates` deprecated-catalog
    lookup are). DatasetMap.psd1 marks it Pending=$true. On a live tenant this resolves
    NotApplicable until GraphKit ships the composite descriptor.

    COMPACT ROW SHAPE this rule expects (defined here, matching the precedent set by
    TP.INT.0013's own IntuneRbacGroupProtectionWalk compact-record contract, not raw
    Graph): one row per security-baseline-templateFamily configurationPolicy instance -
    {id, name, templateFamily, hasAssignment (bool), isDeprecated (bool)}. Building this
    shape from raw Graph (configurationPolicies filtered by templateFamily in
    baseline/baselineDefenderForEndpoint/baselineMicrosoftEdge/baselineWindows365, cross-
    checked against a deprecated-template catalog) is deferred to whichever composite
    descriptor eventually ships, same pattern TP.INT.0014/0015's own Endpoint Security
    walks already established.

    CLAIM (live-verified against
    https://learn.microsoft.com/en-us/intune/device-security/security-baselines/overview,
    fetched for this check): confirms baseline VERSIONING is real and current Microsoft
    behavior - "profiles based on the older versions become read-only... you can also edit
    the profile names, description, and assignments, but they don't support a change to
    their settings configuration" once a newer version exists. The SPECIFIC March-2025
    `deviceManagement/intents`/`deviceManagement/templates` API-deprecation claim from the
    original research entry's Authority URL (a techcommunity.microsoft.com blog post) could
    NOT be independently re-confirmed from inside this task - the page returned only a
    title with no retrievable body text via automated fetch. That specific claim is
    therefore NOT asserted verbatim in this check's Consulting text; only the
    Microsoft-Learn-confirmed "versions become read-only, migrate to get new settings"
    behavior above is asserted as fact. The techcommunity URL is kept in Authorities as
    supporting context, not as the sole basis for a specific claim.

    FIELD-ABSENCE LENS: hasAssignment/isDeprecated absent on a row is undecidable - throws
    (this composite shape is defined by this codebase, not raw Graph, so there is no
    narrow-exception case the way TP.INT.0026/0028's raw `assignments` relationship has).

    STRICT TYPING, NOT [bool]-COERCION (post-review fix, MEDIUM finding): the FIRST version
    of this rule read `[bool] $row.hasAssignment` directly - PowerShell's `[bool]` cast on a
    non-empty STRING (e.g. the string `'false'`, which is exactly what a JSON/JSON-ish
    composite descriptor could plausibly emit for a boolean-looking field before this
    check's own composite descriptor ships) coerces to `$true` regardless of the string's
    apparent meaning, because `[bool]` only treats an EMPTY string as falsy. That silently
    inverted an unassigned baseline (`hasAssignment = 'false'`) into a Pass - latent while
    the dataset is Pending (no live data can reach this path today), but a real, live bug
    the day GraphKit ships the composite descriptor if it (or an intermediate hop) ever
    emits a string rather than a native boolean. This rule now requires `hasAssignment` and
    `isDeprecated` to actually BE `[bool]` (PowerShell's own `-is [bool]` type check, which
    a string - even `'true'`/`'false'` - never satisfies) - any other type, including a
    boolean-LOOKING string, throws rather than being silently coerced one way or the other,
    the same field-absence-lens philosophy this codebase applies to outright-missing
    fields extended to wrongly-typed-but-present ones.

    RULE: zero rows = NotApplicable (no security baseline of any tracked family is in use -
    a legitimate, if security-notable, tenant state this check does not itself flag; that
    absence is better caught by a future "no baseline deployed at all" check, out of scope
    here). Otherwise Fail if any row has hasAssignment=$false OR isDeprecated=$true
    (unassigned is the more urgent half per the research entry's own severity rationale,
    but both conditions fail together rather than being split into separate severities);
    Pass otherwise.

    ZERO-BASELINES NA DEFERS TO A NONEXISTENT CHECK (Phase 3 whole-phase review,
    catalog-coherence finding M2, documentation-only): the "future 'no baseline deployed
    at all' check" referenced above does not exist anywhere in this catalog today - a
    tenant with zero security baselines configured currently gets a quiet NotApplicable
    and no other check ever flags that absence as a gap. This is a real, currently-open
    coverage hole, not a completed hand-off; tracked as a backlog candidate in this
    check's own research entry (docs/research/iha-v2/2026-08-16-phase3-intune-check-
    entries.md, TP.INT.0029 section) rather than fixed here, since authoring a new check
    is out of this fix round's scope.
#>

function Test-PulseSecurityBaselinesAssignedAndCurrent {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $rows = @($Datasets.securityBaselinesAssignedAndCurrent)
    if ($rows.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No Intune security baseline (Windows, Defender for Endpoint, Microsoft Edge, or Windows 365) instance was found for this tenant - there is nothing for this check to evaluate.'
    }

    $offending = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $rows) {
        foreach ($prop in @('hasAssignment', 'isDeprecated')) {
            if (-not (Test-PulseRowPropertyPresent -Row $row -PropertyName $prop) -or $null -eq $row.$prop) {
                throw "Test-PulseSecurityBaselinesAssignedAndCurrent: a securityBaselinesAssignedAndCurrent row is missing '$prop'."
            }
            if ($row.$prop -isnot [bool]) {
                throw "Test-PulseSecurityBaselinesAssignedAndCurrent: a securityBaselinesAssignedAndCurrent row's '$prop' is present but not a native boolean (got '$($row.$prop.GetType().Name)') - refusing to [bool]-coerce a non-boolean value (e.g. the STRING 'false' coerces to `$true under PowerShell's own [bool] cast, which would silently invert the meaning)."
            }
        }

        $hasAssignment = [bool] $row.hasAssignment
        $isDeprecated = [bool] $row.isDeprecated

        if (-not $hasAssignment -or $isDeprecated) {
            $identity = if (Test-PulseRowPropertyPresent -Row $row -PropertyName 'id') { [string] $row.id } else { [string] $row.name }
            $offending.Add(@{
                Identity = $identity
                Detail   = @{ name = $row.name; templateFamily = $row.templateFamily; hasAssignment = $hasAssignment; isDeprecated = $isDeprecated }
                SortKey  = $identity
            })
        }
    }

    if ($offending.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason "All $($rows.Count) security baseline instance(s) in use are assigned and on a current (non-deprecated) template version."
    }

    $reason = "$($offending.Count) of $($rows.Count) security baseline instance(s) are unassigned (zero enforcement) or on a deprecated template version (missing newer hardening additions and eventually losing support) - see evidence for which instance(s) and which condition applies to each."
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $offending.ToArray()
}

<#
    Private: TP.INT.0030 rule function - fleet compliance rate below acceptable threshold
    (Task 3.3, research-matrix - no Maester origin, practitioner judgment).

    LIVE DATASET: reuses the already-released, already-live `managedDevices` dataset
    (`ManagedDevice`/`List`, v1.0 - the same dataset TP.INT.0002/TP.INT.0005 already
    consume) - no new GraphKit descriptor needed, per the research entry's own Data note
    preferring the pre-aggregated summary endpoint "for large fleets" where available; that
    summary endpoint (`deviceCompliancePolicyDeviceStateSummary`) has no released GraphKit
    0.1.1 descriptor, so this v1 reads the same per-device `complianceState` field the
    seeded checks already use rather than adding a new Pending dependency for what would
    only be a performance optimization, not a correctness difference.

    THRESHOLD IS PRACTITIONER JUDGMENT, NOT A VERBATIM MICROSOFT FIGURE (live-verified
    against https://learn.microsoft.com/en-us/intune/device-security/compliance/overview,
    fetched for this check, AND a live web search for the specific "<5% noncompliant"
    staged-rollout figure the original research entry's own Notes attributed to Microsoft):
    NEITHER source publishes an official "<5% noncompliant" numeric SLA or SHALL/SHOULD
    baseline anywhere findable - the compliance overview page documents compliance policy
    mechanics generally but states no percentage target, and no other Microsoft-published
    guidance with that specific figure could be located. The research entry's own
    "Microsoft's own staged-rollout guidance target" attribution is therefore CORRECTED
    here: the 5%/10% bands below are this check's own practitioner-judgment default
    (informed by common staged-rollout practice, e.g. "start with an OS version 95% of the
    fleet already meets"), not a citation to a specific Microsoft SHALL/SHOULD document -
    the Consulting text says so explicitly rather than overclaiming Microsoft attribution.

    THREE-BUCKET ADJUDICATION (post-review fix, HIGH finding): the FIRST version of this
    rule only counted `complianceState -eq 'noncompliant'` toward the numerator - every
    OTHER state (`unknown`, `inGracePeriod`, `conflict`, `error`, `configManager`, and any
    future/unrecognized value) silently fell through uncounted, which means a device this
    check cannot actually verify as compliant was treated exactly like a genuinely
    compliant one (a fleet with 1/20 devices stuck in `unknown` Passed identically to a
    perfectly compliant fleet - reviewer-probed, confirmed real). Every managedDevices row
    is now classified into exactly one of three buckets, per Microsoft's own documented
    Graph `complianceState` enum values:
        - COMPLIANT bucket: `compliant` only - the one state that actually means "verified
          compliant".
        - NONCOMPLIANT bucket: `noncompliant` only - the one state that actually means
          "verified noncompliant" (this is what the Fail/Warn rate below is computed
          against, i.e. "rate computed against verified-compliant/verified-noncompliant",
          never against a bucket this check cannot actually confirm).
        - UNVERIFIED-OR-UNHEALTHY bucket: everything else - `conflict` (a policy conflict
          prevented evaluation), `error` (evaluation itself failed), `inGracePeriod`
          (device is mid-remediation, not yet definitively either state),
          `configManager` (Configuration Manager co-management owns compliance for this
          device, Intune's own complianceState is not authoritative for it), `unknown`,
          AND any value this rule does not recognize at all (a genuinely future/undocumented
          state) - fail-closed by construction: an unrecognized state is NEVER silently
          folded into "compliant", it always lands in the bucket this check flags as
          needing attention.
    The unverified-or-unhealthy bucket's count/percentage is ALWAYS disclosed in the
    Reason text regardless of Status, and a MATERIAL unverified share (>= 5% of the fleet,
    the same threshold the noncompliant rate itself uses) escalates the finding to at least
    Warn even when the verified-noncompliant rate alone is comfortably below 5% - a fleet
    cannot bare-Pass on the strength of a bucket this check cannot actually verify.

    GRADUATED FINDING (per the research entry's own Notes): expressed as a Warn/Fail band
    rather than strict binary pass/fail, consistent with the evaluator's existing Rule-type
    contract (Warn is a real, first-class Status here, not deferred to a future thresholded
    rule-type) - see the RULE section below for the exact band logic, now with two
    independent escalation paths (verified-noncompliant rate, and material-unverified
    share) rather than one.

    FIELD-ABSENCE LENS: complianceState absent (or present-$null) on an individual
    managedDevices row is undecidable and throws - a large fleet scan is only as
    trustworthy as its per-row data, and this check does not guess a fleet-wide rate from a
    dataset with unexplained gaps. This is distinct from a PRESENT-but-unrecognized state
    string, which is decidable (it lands in the unverified-or-unhealthy bucket, per the
    fail-closed classification above) - only true absence throws.

    DETERMINISM: purely a ratio over the dataset already handed in - no wall-clock
    dependency of any kind.
#>

function Test-PulseFleetComplianceRateAcceptable {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $devices = @($Datasets.managedDevices)
    if ($devices.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No managed devices were returned for this tenant - there is no fleet for this check to evaluate a compliance rate over.'
    }

    $compliantCount = 0
    $noncompliantCount = 0
    $unverifiedCount = 0
    $unverifiedStateCounts = @{}

    foreach ($device in $devices) {
        if (-not (Test-PulseRowPropertyPresent -Row $device -PropertyName 'complianceState') -or $null -eq $device.complianceState) {
            throw 'Test-PulseFleetComplianceRateAcceptable: a managedDevices row is missing complianceState.'
        }

        $state = [string] $device.complianceState

        if ($state -eq 'compliant') {
            $compliantCount++
        } elseif ($state -eq 'noncompliant') {
            $noncompliantCount++
        } else {
            # UNVERIFIED-OR-UNHEALTHY (fail-closed): conflict/error/inGracePeriod/
            # configManager/unknown, AND any state this rule does not recognize at all -
            # never silently folded into "compliant".
            $unverifiedCount++
            if ($unverifiedStateCounts.ContainsKey($state)) { $unverifiedStateCounts[$state]++ } else { $unverifiedStateCounts[$state] = 1 }
        }
    }

    $total = $devices.Count
    $noncompliantRate = [double] $noncompliantCount / [double] $total
    $unverifiedRate = [double] $unverifiedCount / [double] $total
    $noncompliantRatePercent = [System.Math]::Round($noncompliantRate * 100, 1)
    $unverifiedRatePercent = [System.Math]::Round($unverifiedRate * 100, 1)

    $unverifiedBreakdown = ($unverifiedStateCounts.Keys | Sort-Object | ForEach-Object { "$_=$($unverifiedStateCounts[$_])" }) -join ', '
    $unverifiedClause = if ($unverifiedCount -gt 0) {
        " $unverifiedCount of $total device(s) ($unverifiedRatePercent%) are in an unverified-or-unhealthy compliance state that cannot be confirmed as compliant ($unverifiedBreakdown)."
    } else {
        ''
    }

    # NESTED-vs-FLATTENED DETAIL (Task 3.5 fold-in decision): unverifiedStateBreakdown is
    # kept as a NESTED hashtable (state -> count), not flattened into sibling
    # unverified.<state> keys on Detail. Rationale (one line, per the fold-in): the
    # canonical JSON serializer (ConvertTo-PulseCanonicalJson) already key-sorts
    # recursively at every object depth, so nesting costs nothing on the determinism this
    # codebase requires everywhere - the only real trade-off is readability, and a reader
    # (operator or renderer) scans "which unverified states, and how many of each" far more
    # naturally as one grouped sub-object than as a flat bag of dynamically-named top-level
    # keys mixed in with the other five fixed Detail fields above.
    $evidence = @(
        @{
            Identity = 'fleet-compliance-rate'
            Detail   = @{
                totalDevices             = $total
                compliantDevices         = $compliantCount
                noncompliantDevices      = $noncompliantCount
                noncompliantRatePercent  = $noncompliantRatePercent
                unverifiedDevices        = $unverifiedCount
                unverifiedRatePercent    = $unverifiedRatePercent
                unverifiedStateBreakdown = $unverifiedStateCounts
            }
            SortKey  = 'fleet-compliance-rate'
        }
    )

    if ($noncompliantRate -gt 0.10) {
        return New-PulseFinding -Status Fail -Reason "$noncompliantCount of $total managed device(s) ($noncompliantRatePercent%) are verified noncompliant, above the 10% threshold this check treats as an unacceptable fleet-health signal - review compliance policy configuration and top noncompliance reasons before layering additional Conditional Access enforcement on top.$unverifiedClause" -Evidence $evidence
    }

    if ($noncompliantRate -ge 0.05) {
        return New-PulseFinding -Status Warn -Reason "$noncompliantCount of $total managed device(s) ($noncompliantRatePercent%) are verified noncompliant, within this check's 5-10% approaching-threshold band - worth investigating before it grows further.$unverifiedClause" -Evidence $evidence
    }

    if ($unverifiedRate -ge 0.05) {
        return New-PulseFinding -Status Warn -Reason "Verified-noncompliant devices are below this check's 5% threshold ($noncompliantCount of $total, $noncompliantRatePercent%), but a material share of the fleet cannot be verified either way:$unverifiedClause A fleet cannot be called healthy on the strength of a bucket this check cannot confirm - investigate the unverified state(s) before treating this as a clean Pass." -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason "$noncompliantCount of $total managed device(s) ($noncompliantRatePercent%) are verified noncompliant, below this check's 5% threshold.$unverifiedClause" -Evidence $evidence
}

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

    GRADUATED FINDING (per the research entry's own Notes): expressed as a Warn/Fail band
    rather than strict binary pass/fail, consistent with the evaluator's existing Rule-type
    contract (Warn is a real, first-class Status here, not deferred to a future
    thresholded rule-type) - Pass below 5% noncompliant, Warn 5%-10%, Fail above 10%.

    FIELD-ABSENCE LENS: complianceState absent on an individual managedDevices row is
    undecidable and throws - a large fleet scan is only as trustworthy as its per-row data,
    and this check does not guess a fleet-wide rate from a dataset with unexplained gaps.

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

    $reasonCounts = @{}
    $noncompliantCount = 0

    foreach ($device in $devices) {
        if (-not (Test-PulseRowPropertyPresent -Row $device -PropertyName 'complianceState') -or $null -eq $device.complianceState) {
            throw 'Test-PulseFleetComplianceRateAcceptable: a managedDevices row is missing complianceState.'
        }

        $state = [string] $device.complianceState
        if ($state -eq 'noncompliant') {
            $noncompliantCount++
            if ($reasonCounts.ContainsKey($state)) { $reasonCounts[$state]++ } else { $reasonCounts[$state] = 1 }
        }
    }

    $total = $devices.Count
    $rate = [double] $noncompliantCount / [double] $total
    $ratePercent = [System.Math]::Round($rate * 100, 1)

    $evidence = @(
        @{
            Identity = 'fleet-compliance-rate'
            Detail   = @{ totalDevices = $total; noncompliantDevices = $noncompliantCount; noncompliantRatePercent = $ratePercent }
            SortKey  = 'fleet-compliance-rate'
        }
    )

    if ($rate -gt 0.10) {
        return New-PulseFinding -Status Fail -Reason "$noncompliantCount of $total managed device(s) ($ratePercent%) are noncompliant, above the 10% threshold this check treats as an unacceptable fleet-health signal - review compliance policy configuration and top noncompliance reasons before layering additional Conditional Access enforcement on top." -Evidence $evidence
    }

    if ($rate -ge 0.05) {
        return New-PulseFinding -Status Warn -Reason "$noncompliantCount of $total managed device(s) ($ratePercent%) are noncompliant, within this check's 5-10% approaching-threshold band - worth investigating before it grows further." -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason "$noncompliantCount of $total managed device(s) ($ratePercent%) are noncompliant, below this check's 5% threshold." -Evidence $evidence
}

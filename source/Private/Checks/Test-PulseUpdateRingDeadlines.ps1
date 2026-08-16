<#
    Private: TP.INT.0004 rule function - at least 2 Windows Update rings exist with
    deadlines configured.

    Windows Update ring profiles are deviceConfigurations rows whose '@odata.type' is
    '#microsoft.graph.windowsUpdateForBusinessConfiguration' (v1.0). A "deadline" is
    considered configured when EITHER deadlineForFeatureUpdatesInDays or
    deadlineForQualityUpdatesInDays carries a value greater than zero - Microsoft's own
    default for both is null/unset (deadlines opt-in, not opt-out), so a non-null, positive
    value is a genuine authoring signal, not noise.

    The title's own number is the assertion: at least 2 rings (Microsoft's staged-rollout
    guidance - pilot then broad, minimum) must EACH have a deadline configured, not merely
    that 2 rings exist somewhere and 1 of them has a deadline.

    HONEST LIMITATION: this checks ring PROFILE existence and deadline configuration only,
    not assignment - deviceConfigurations (v1.0 List, no $expand) does not carry assignment
    data in this dataset's shape, the same limitation TP.INT.0002 documents for compliance
    policies.
#>

function Test-PulseUpdateRingDeadlines {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $configurations = @($Datasets.deviceConfigurations)
    $updateRings = @($configurations | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.windowsUpdateForBusinessConfiguration' })

    $hasDeadline = {
        param($ring)
        $feature = $ring.deadlineForFeatureUpdatesInDays
        $quality = $ring.deadlineForQualityUpdatesInDays
        return (($null -ne $feature) -and ($feature -gt 0)) -or (($null -ne $quality) -and ($quality -gt 0))
    }

    $ringsWithDeadlines = @($updateRings | Where-Object { & $hasDeadline $_ })

    if ($ringsWithDeadlines.Count -ge 2) {
        $evidence = @($ringsWithDeadlines | ForEach-Object { @{ Identity = [string] $_.id; Detail = @{ displayName = $_.displayName } } })
        return New-PulseFinding -Status Pass -Reason "$($ringsWithDeadlines.Count) Windows Update rings have deadlines configured." -Evidence $evidence
    }

    $ringsWithoutDeadlines = @($updateRings | Where-Object { -not (& $hasDeadline $_) })
    $evidence = @($ringsWithoutDeadlines | ForEach-Object { @{ Identity = [string] $_.id; Detail = @{ displayName = $_.displayName; hasDeadline = $false } } })

    return New-PulseFinding -Status Fail -Reason "Only $($ringsWithDeadlines.Count) of $($updateRings.Count) Windows Update ring(s) have deadlines configured; Microsoft's staged-rollout guidance recommends at least 2 rings (pilot + broad), each with a deadline, so updates cannot be deferred indefinitely." -Evidence $evidence
}

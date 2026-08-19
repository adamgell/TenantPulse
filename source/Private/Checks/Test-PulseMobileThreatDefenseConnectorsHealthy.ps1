<#
    Private: TP.INT.0024 rule function - Mobile Threat Defense connectors enabled and
    syncing (Task 3.3, Maester port MT.1098 - Test-MtMobileThreatDefenseConnectors, MIT).

    DATASET (live): GraphKit 0.2.2 shipped the official descriptor and DatasetMap now treats
    this dataset as live. Type `MobileThreatDefenseConnector`, Operation `List`,
    ApiVersion `v1.0`; this check evaluates live tenant data.

    CLAIM (live-verified against
    https://learn.microsoft.com/en-us/intune/device-security/mobile-threat-defense/enable-connector,
    fetched for this check): confirms Intune "can integrate data from a Mobile Threat
    Defense (MTD) partner for use by device compliance policies and device Conditional
    Access rules" and that the admin center shows a per-connector "Connection status" and
    "Last synchronized" time - the general shape the research entry's own
    partnerState/heartbeat claim describes, though the page does not publish an official
    numeric heartbeat SLA; this check's 1-day threshold is therefore practitioner judgment
    (matching the research entry's own framing), not a verbatim Microsoft-published number,
    and is documented as such rather than attributed to Microsoft.

    DETERMINISM: compares lastHeartbeatDateTime against $Context.EvaluationCutoffBase
    (falling back to SnapshotCreatedUtc) - never Get-Date/::Now/::UtcNow.

    FIELD-ABSENCE LENS: partnerState or lastHeartbeatDateTime absent on an existing
    connector row is undecidable - throws.

    RULE: zero connectors = NotApplicable (skip - MTD not in use, mirrors Maester's own
    behavior; common for tenants relying on Defender for Endpoint compliance signals
    differently, or not at all). Otherwise a connector is "offending" if partnerState is
    not `enabled`, OR its last heartbeat was more than a day before the cutoff. Fail if any
    connector is offending, Pass otherwise (now carrying a corroborating evidence row per
    connector on the Pass path too, post-review MINOR fix, consistent with
    Test-PulseStaleDevices.ps1's own precedent of never leaving a Pass evidence-empty when
    there is real per-row data to corroborate it with).

    IDENTITY FALLBACK (post-review MINOR fix): the FIRST version of this rule fell back to
    `partnerState` itself as the evidence Identity when `id` was absent - two id-less
    connectors sharing the same partnerState (a real possibility if a future GraphKit
    descriptor ever omits `id`) would collide on the SAME Identity/SortKey pair, which
    Assert-PulseEvidenceNoDuplicates (Invoke-PulseEvaluation.ps1) degrades to an engine
    Error. The fallback is now an ordinal, per-row `mtd-connector-<index>` (0-based
    position in the dataset) - guaranteed unique within a single evaluation regardless of
    how many rows share every other property.
#>

function Test-PulseMobileThreatDefenseConnectorsHealthy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $connectors = @($Datasets.mobileThreatDefenseConnectors)
    if ($connectors.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No Mobile Threat Defense (MTD) connectors are configured for this tenant - MTD-based device risk signal (Defender for Endpoint or a third-party MTD partner) is not in use, so there is nothing for this check to evaluate.'
    }

    $cutoffBaseText = $null
    if ($Context -and $Context.ContainsKey('EvaluationCutoffBase') -and $Context.EvaluationCutoffBase) {
        $cutoffBaseText = [string] $Context.EvaluationCutoffBase
    } elseif ($Context -and $Context.ContainsKey('SnapshotCreatedUtc') -and $Context.SnapshotCreatedUtc) {
        $cutoffBaseText = [string] $Context.SnapshotCreatedUtc
    }
    if ([string]::IsNullOrWhiteSpace($cutoffBaseText)) {
        throw 'Test-PulseMobileThreatDefenseConnectorsHealthy: no $Context.EvaluationCutoffBase/SnapshotCreatedUtc was supplied.'
    }
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $cutoff = [datetime]::Parse($cutoffBaseText, $culture, $styles)
    $heartbeatThreshold = $cutoff.AddDays(-1)

    $offending = [System.Collections.Generic.List[object]]::new()
    $allRows = [System.Collections.Generic.List[object]]::new()

    for ($index = 0; $index -lt $connectors.Count; $index++) {
        $connector = $connectors[$index]

        if (-not (Test-PulseRowPropertyPresent -Row $connector -PropertyName 'partnerState') -or $null -eq $connector.partnerState) {
            throw 'Test-PulseMobileThreatDefenseConnectorsHealthy: a mobileThreatDefenseConnectors row is missing partnerState.'
        }
        if (-not (Test-PulseRowPropertyPresent -Row $connector -PropertyName 'lastHeartbeatDateTime') -or $null -eq $connector.lastHeartbeatDateTime) {
            throw 'Test-PulseMobileThreatDefenseConnectorsHealthy: a mobileThreatDefenseConnectors row is missing lastHeartbeatDateTime.'
        }

        $state = [string] $connector.partnerState
        $lastHeartbeat = [datetime]::Parse([string] $connector.lastHeartbeatDateTime, $culture, $styles)

        $isDisabled = $state -ne 'enabled'
        $isStale = $lastHeartbeat -lt $heartbeatThreshold

        $identity = if (Test-PulseRowPropertyPresent -Row $connector -PropertyName 'id') { [string] $connector.id } else { "mtd-connector-$index" }
        $row = @{
            Identity = $identity
            Detail   = @{
                partnerState          = $state
                lastHeartbeatDateTime = $connector.lastHeartbeatDateTime
                disabled              = $isDisabled
                staleHeartbeat        = $isStale
            }
            SortKey  = $identity
        }
        $allRows.Add($row)

        if ($isDisabled -or $isStale) {
            $offending.Add($row)
        }
    }

    if ($offending.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason "All $($connectors.Count) Mobile Threat Defense connector(s) are enabled and reported a heartbeat within the last day." -Evidence $allRows.ToArray()
    }

    $reason = "$($offending.Count) of $($connectors.Count) Mobile Threat Defense connector(s) are disabled or have not reported a heartbeat within the last day - compliance policies that key off device threat level ($($offending.Count) affected) can silently stop receiving fresh risk signal, letting noncompliant/compromised devices pass compliance unnoticed."
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $offending.ToArray()
}

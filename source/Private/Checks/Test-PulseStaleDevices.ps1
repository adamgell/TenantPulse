<#
    Private: TP.INT.0005 rule function - devices with no activity in over 90 days.

    LIVE-TENANT VERIFICATION NOTE (Task 1.9): managedDevices (Intune-managed, lastSyncDateTime)
    and entraDevices (Entra-registered, approximateLastSignInDateTime) are genuinely DIFFERENT
    populations - a real tenant this task was verified against had 95 Entra devices and only
    13 Intune-managed devices. This check reads BOTH datasets and reports them as two
    DISTINCT sets in its evidence (never merged into one undifferentiated "stale devices"
    list), and separately surfaces the population gap itself - how many Entra-registered
    devices are not Intune-managed at all (joined via managedDevices.azureADDeviceId against
    entraDevices.deviceId) - in the finding's Reason, because that gap is itself a
    management-coverage finding, not just context.

    A device with NO recorded sync/sign-in timestamp at all (null/unparsable) is treated as
    stale, not silently skipped - "never checked in" is at least as concerning as "checked in
    91 days ago", and skipping it would hide the worst cases.

    Evidence identities are prefixed by source ('managed:'/'entra:') so the two id spaces -
    which are NOT the same identifier system - can never collide inside one finding's
    evidence set.
#>

function Test-PulseStaleDevices {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $staleThresholdDays = 90
    $cutoffUtc = [datetime]::UtcNow.AddDays(-$staleThresholdDays)

    function ConvertTo-PulseNullableUtcDateTime {
        param($Value)
        $text = [string] $Value
        if ([string]::IsNullOrWhiteSpace($text)) {
            return $null
        }
        try {
            return [datetime]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
        } catch {
            return $null
        }
    }

    $managedDevices = @($Datasets.managedDevices)
    $entraDevices = @($Datasets.entraDevices)

    $staleManaged = @($managedDevices | Where-Object {
        $lastSync = ConvertTo-PulseNullableUtcDateTime $_.lastSyncDateTime
        ($null -eq $lastSync) -or ($lastSync -lt $cutoffUtc)
    })

    $staleEntra = @($entraDevices | Where-Object {
        $lastSignIn = ConvertTo-PulseNullableUtcDateTime $_.approximateLastSignInDateTime
        ($null -eq $lastSignIn) -or ($lastSignIn -lt $cutoffUtc)
    })

    $managedAzureAdDeviceIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($device in $managedDevices) {
        if ($device.azureADDeviceId) {
            $managedAzureAdDeviceIds.Add([string] $device.azureADDeviceId) | Out-Null
        }
    }
    $entraOnlyCount = @($entraDevices | Where-Object { $_.deviceId -and -not $managedAzureAdDeviceIds.Contains([string] $_.deviceId) }).Count

    if ($staleManaged.Count -eq 0 -and $staleEntra.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason "No Intune-managed devices ($($managedDevices.Count) total) or Entra-registered devices ($($entraDevices.Count) total) have been inactive for more than $staleThresholdDays days."
    }

    $evidence = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($device in $staleManaged) {
        $evidence.Add(@{ Identity = "managed:$($device.id)"; Detail = @{ source = 'managedDevices'; deviceName = $device.deviceName; lastSyncDateTime = $device.lastSyncDateTime } })
    }
    foreach ($device in $staleEntra) {
        $evidence.Add(@{ Identity = "entra:$($device.id)"; Detail = @{ source = 'entraDevices'; displayName = $device.displayName; approximateLastSignInDateTime = $device.approximateLastSignInDateTime } })
    }

    $reason = "$($staleManaged.Count) of $($managedDevices.Count) Intune-managed device(s) and $($staleEntra.Count) of $($entraDevices.Count) Entra-registered device(s) have had no activity in over $staleThresholdDays days. $entraOnlyCount Entra-registered device(s) are not Intune-managed at all (population gap between the two datasets)."

    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence.ToArray()
}

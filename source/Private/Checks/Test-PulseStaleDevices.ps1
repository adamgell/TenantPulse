<#
    Private: TP.INT.0005 rule function - devices with no activity in over 90 days.

    LIVE-TENANT VERIFICATION NOTE (Task 1.9): managedDevices (Intune-managed, lastSyncDateTime)
    and entraDevices (Entra-registered, approximateLastSignInDateTime) are genuinely DIFFERENT
    populations - a real tenant this task was verified against had 95 Entra devices and only
    13 Intune-managed devices. This check reads BOTH datasets and reports them as two
    DISTINCT sets in its evidence (never merged into one undifferentiated "stale devices"
    list). The population gap itself - how many Entra-registered devices are not
    Intune-managed at all (joined via managedDevices.azureADDeviceId against
    entraDevices.deviceId) - is now (post-review, Important) surfaced as EVIDENCE ENTRIES
    (a summary entry carrying the count, plus one entry per Entra-registered-unmanaged
    device), not merely Reason text - a reader parsing evidence programmatically must be
    able to see the gap without string-parsing the Reason.

    WALL-CLOCK DETERMINISM (post-review, H2 adjudicated): the 90-day cutoff is computed
    from $Context.EvaluationCutoffBase (falls back to SnapshotCreatedUtc, both populated
    unconditionally by Invoke-PulseEvaluation from the snapshot manifest's own createdUtc -
    see that function's own docstring) - NEVER from [datetime]::UtcNow. Re-evaluating the
    same snapshot a week from now must produce the exact same verdict it produced today; a
    wall-clock cutoff would silently make yesterday's Pass tip into today's Fail with no
    change to the underlying snapshot at all. A direct/legacy call that supplies no
    -Context at all falls back to [datetime]::UtcNow as a last resort (documented, not the
    normal path - every real evaluation run supplies it).

    NEWLY-ENROLLED, NEVER-SYNCED DEVICES (post-review, L5): a managed device with no
    lastSyncDateTime at all is normally treated as stale (a device that has NEVER checked in
    is at least as concerning as one that checked in 91 days ago) - EXCEPT when its own
    enrolledDateTime is recent (< 30 days before the cutoff base): a device enrolled 3 days
    ago that has not synced yet is not a stale-device problem, it is normal onboarding lag.
    That device gets its own DISTINCT evidence Detail ('newly enrolled, never synced')
    instead of being folded into the stale count, and does not drive the Fail verdict by
    itself. A device with no enrolledDateTime EITHER, or an enrolledDateTime older than 30
    days, keeps the original fail-closed behavior - "no signal at all, and not recently
    onboarded" is exactly the case skipping it would hide.

    Evidence identities are prefixed by source ('managed:'/'entra:'/'gap:') so the
    different id spaces - which are NOT the same identifier system - can never collide
    inside one finding's evidence set.
#>

function Test-PulseStaleDevices {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $staleThresholdDays = 90
    $newlyEnrolledGraceDays = 30

    $cutoffBaseText = $null
    if ($Context -and $Context.ContainsKey('EvaluationCutoffBase') -and $Context.EvaluationCutoffBase) {
        $cutoffBaseText = [string] $Context.EvaluationCutoffBase
    } elseif ($Context -and $Context.ContainsKey('SnapshotCreatedUtc') -and $Context.SnapshotCreatedUtc) {
        $cutoffBaseText = [string] $Context.SnapshotCreatedUtc
    }

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

    # Wall-clock fallback only when no -Context was supplied at all (documented above as a
    # legacy/direct-call path - every real Invoke-PulseEvaluation run supplies one of the
    # two keys unconditionally).
    $cutoffBase = ConvertTo-PulseNullableUtcDateTime $cutoffBaseText
    if ($null -eq $cutoffBase) {
        $cutoffBase = [datetime]::UtcNow
    }

    $cutoffUtc = $cutoffBase.AddDays(-$staleThresholdDays)
    $newlyEnrolledCutoffUtc = $cutoffBase.AddDays(-$newlyEnrolledGraceDays)

    $managedDevices = @($Datasets.managedDevices)
    $entraDevices = @($Datasets.entraDevices)

    $staleManaged = [System.Collections.Generic.List[object]]::new()
    $newlyEnrolledNeverSynced = [System.Collections.Generic.List[object]]::new()

    foreach ($device in $managedDevices) {
        $lastSync = ConvertTo-PulseNullableUtcDateTime $device.lastSyncDateTime
        if ($null -ne $lastSync -and $lastSync -ge $cutoffUtc) {
            continue
        }

        if ($null -eq $lastSync) {
            $enrolledDate = ConvertTo-PulseNullableUtcDateTime $device.enrolledDateTime
            if ($null -ne $enrolledDate -and $enrolledDate -ge $newlyEnrolledCutoffUtc) {
                $newlyEnrolledNeverSynced.Add($device)
                continue
            }
        }

        $staleManaged.Add($device)
    }

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
    $entraOnlyDevices = @($entraDevices | Where-Object { $_.deviceId -and -not $managedAzureAdDeviceIds.Contains([string] $_.deviceId) })

    $evidence = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($device in $newlyEnrolledNeverSynced) {
        $evidence.Add(@{ Identity = "managed:$($device.id)"; Detail = @{ source = 'managedDevices'; deviceName = $device.deviceName; status = 'newly enrolled, never synced'; enrolledDateTime = $device.enrolledDateTime } })
    }
    foreach ($device in $staleManaged) {
        $evidence.Add(@{ Identity = "managed:$($device.id)"; Detail = @{ source = 'managedDevices'; deviceName = $device.deviceName; lastSyncDateTime = $device.lastSyncDateTime } })
    }
    foreach ($device in $staleEntra) {
        $evidence.Add(@{ Identity = "entra:$($device.id)"; Detail = @{ source = 'entraDevices'; displayName = $device.displayName; approximateLastSignInDateTime = $device.approximateLastSignInDateTime } })
    }
    if ($entraOnlyDevices.Count -gt 0) {
        $evidence.Add(@{ Identity = 'gap:summary'; Detail = @{ source = 'population-gap'; entraRegisteredNotIntuneManagedCount = $entraOnlyDevices.Count } })
        foreach ($device in $entraOnlyDevices) {
            $evidence.Add(@{ Identity = "gap:$($device.id)"; Detail = @{ source = 'population-gap'; displayName = $device.displayName; deviceId = $device.deviceId } })
        }
    }

    if ($staleManaged.Count -eq 0 -and $staleEntra.Count -eq 0) {
        $reason = "No Intune-managed devices ($($managedDevices.Count) total) or Entra-registered devices ($($entraDevices.Count) total) have been inactive for more than $staleThresholdDays days."
        if ($newlyEnrolledNeverSynced.Count -gt 0) {
            $reason += " $($newlyEnrolledNeverSynced.Count) device(s) are newly enrolled and have not synced yet (within the $newlyEnrolledGraceDays-day onboarding grace period)."
        }
        return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence.ToArray()
    }

    $reason = "$($staleManaged.Count) of $($managedDevices.Count) Intune-managed device(s) and $($staleEntra.Count) of $($entraDevices.Count) Entra-registered device(s) have had no activity in over $staleThresholdDays days. $($entraOnlyDevices.Count) Entra-registered device(s) are not Intune-managed at all (population gap between the two datasets - see the gap: evidence entries)."
    if ($newlyEnrolledNeverSynced.Count -gt 0) {
        $reason += " $($newlyEnrolledNeverSynced.Count) additional device(s) are newly enrolled and excluded from the stale count."
    }

    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence.ToArray()
}

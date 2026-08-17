<#
    Private: TP.INT.0022 rule function - Android Enterprise connection bound, validated,
    and syncing (Task 3.3, Maester port MT.1095 - Test-MtAndroidEnterpriseConnection, MIT).

    PENDING DATASET (honest NA): androidManagedStoreAccountEnterpriseSettings has no
    released GraphKit 0.1.1 descriptor (confirmed via a live Get-GraphOperation -List
    enumeration) - DatasetMap.psd1 marks it Pending=$true. On a live tenant this resolves
    NotApplicable until GraphKit ships the descriptor.

    CLAIM (live-verified against
    https://learn.microsoft.com/en-us/intune/device-enrollment/android/connect-managed-google-play,
    fetched for this check - the tenant must connect to managed Google Play before any
    Android Enterprise management option (work profile, fully managed, dedicated,
    corporate-owned work profile) functions at all): confirms the connection is a
    tenant-wide prerequisite, not a per-feature toggle.

    THREE-WAY AND CONDITION (per the research entry's own Notes, mirrored exactly): bind
    status must be `boundAndValidated`, AND the last app-catalog sync status must indicate
    success, AND that sync must have happened within the last day. `notBound` is treated as
    a legitimate skip (tenant not using Android Enterprise at all), NOT a fail - only a
    previously-bound-then-broken connection fails.

    DETERMINISM: compares lastAppSyncDateTime against $Context.EvaluationCutoffBase
    (falling back to SnapshotCreatedUtc) - never Get-Date/::Now/::UtcNow.

    FIELD-ABSENCE LENS: bindStatus absent on an existing settings row is undecidable -
    throws. lastAppSyncStatus/lastAppSyncDateTime absent when bindStatus IS
    boundAndValidated is likewise undecidable and throws (a genuinely bound connection with
    no sync record at all cannot honestly be called healthy OR broken without guessing).
#>

function Test-PulseAndroidEnterpriseConnectionHealthy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $rows = @($Datasets.androidManagedStoreAccountEnterpriseSettings)
    if ($rows.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No Android Enterprise (managed Google Play) connection settings were returned for this tenant - Android Enterprise device management has never been set up, so there is nothing for this check to evaluate.'
    }

    $settings = $rows[0]
    if (-not (Test-PulseRowPropertyPresent -Row $settings -PropertyName 'bindStatus') -or $null -eq $settings.bindStatus) {
        throw 'Test-PulseAndroidEnterpriseConnectionHealthy: the androidManagedStoreAccountEnterpriseSettings row is missing bindStatus.'
    }

    $bindStatus = [string] $settings.bindStatus

    if ($bindStatus -eq 'notBound') {
        return New-PulseFinding -Status NotApplicable -Reason 'The Android Enterprise (managed Google Play) connection is not bound - Android Enterprise device management is not in use for this tenant, so there is nothing for this check to evaluate.'
    }

    $evidence = @(
        @{
            Identity = if (Test-PulseRowPropertyPresent -Row $settings -PropertyName 'id') { [string] $settings.id } else { 'androidManagedStoreAccountEnterpriseSettings' }
            Detail   = @{ bindStatus = $settings.bindStatus; lastAppSyncStatus = $settings.lastAppSyncStatus; lastAppSyncDateTime = $settings.lastAppSyncDateTime }
            SortKey  = 'androidManagedStoreAccountEnterpriseSettings'
        }
    )

    if ($bindStatus -ne 'boundAndValidated') {
        return New-PulseFinding -Status Fail -Reason "The Android Enterprise connection is bound but not validated (bindStatus '$bindStatus') - Android device management (work profile, fully managed, dedicated, corporate-owned work profile) is impaired or non-functional for the whole Android fleet until the connection is repaired." -Evidence $evidence
    }

    if (-not (Test-PulseRowPropertyPresent -Row $settings -PropertyName 'lastAppSyncStatus') -or $null -eq $settings.lastAppSyncStatus) {
        throw 'Test-PulseAndroidEnterpriseConnectionHealthy: the connection is boundAndValidated but lastAppSyncStatus is absent - cannot determine sync health.'
    }
    if (-not (Test-PulseRowPropertyPresent -Row $settings -PropertyName 'lastAppSyncDateTime') -or $null -eq $settings.lastAppSyncDateTime) {
        throw 'Test-PulseAndroidEnterpriseConnectionHealthy: the connection is boundAndValidated but lastAppSyncDateTime is absent - cannot determine sync recency.'
    }

    $cutoffBaseText = $null
    if ($Context -and $Context.ContainsKey('EvaluationCutoffBase') -and $Context.EvaluationCutoffBase) {
        $cutoffBaseText = [string] $Context.EvaluationCutoffBase
    } elseif ($Context -and $Context.ContainsKey('SnapshotCreatedUtc') -and $Context.SnapshotCreatedUtc) {
        $cutoffBaseText = [string] $Context.SnapshotCreatedUtc
    }
    if ([string]::IsNullOrWhiteSpace($cutoffBaseText)) {
        throw 'Test-PulseAndroidEnterpriseConnectionHealthy: no $Context.EvaluationCutoffBase/SnapshotCreatedUtc was supplied.'
    }
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $cutoff = [datetime]::Parse($cutoffBaseText, $culture, $styles)
    $syncThreshold = $cutoff.AddDays(-1)

    $syncStatus = [string] $settings.lastAppSyncStatus
    $lastSync = [datetime]::Parse([string] $settings.lastAppSyncDateTime, $culture, $styles)

    if ($syncStatus -ne 'success') {
        return New-PulseFinding -Status Fail -Reason "The Android Enterprise connection is bound and validated, but its last app catalog sync did not succeed (lastAppSyncStatus '$syncStatus') - the managed Google Play app catalog can silently fall out of date until sync is restored." -Evidence $evidence
    }

    if ($lastSync -lt $syncThreshold) {
        return New-PulseFinding -Status Fail -Reason 'The Android Enterprise connection is bound and validated, but its last successful app catalog sync was more than a day ago - the managed Google Play app catalog can silently fall out of date.' -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason 'The Android Enterprise (managed Google Play) connection is bound, validated, and its app catalog synced successfully within the last day.' -Evidence $evidence
}

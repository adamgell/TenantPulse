<#
    Private: TP.INT.0020 rule function - Apple Automated Device Enrollment (ADE, formerly
    DEP) tokens valid and syncing (Task 3.3, Maester port MT.1093 -
    Test-MtAppleAutomatedDeviceEnrollmentToken, MIT).

    LIVE DATASET: `depOnboardingSettings` maps to GraphKit 0.1.1's released
    `AppleEnrollmentProgramToken`/`List` (beta) descriptor, PathTemplate
    `/deviceManagement/depOnboardingSettings` - confirmed via a live
    Get-GraphOperation -List enumeration of the installed 0.1.1 catalog, NOT Pending
    (contrary to this task's own briefing note, which assumed the whole connector/token
    family needed the Pending mechanism).

    FIELD NAMES (live-verified against the depOnboardingSetting resource's own documented
    property set - Get depOnboardingSetting / List depOnboardingSettings, Graph beta):
    `tokenExpirationDateTime` (token expiry) and `lastSuccessfulSyncDateTime` (most recent
    successful sync) - NOT `expirationDateTime`/`lastSyncDateTime`, which is the vppToken
    shape TP.INT.0021 reads instead; the two Apple token resources use different property
    names for the same concepts, a real trap when porting both checks side by side.

    CLAIM (live-verified against
    https://learn.microsoft.com/en-us/intune/device-enrollment/apple/setup-apple-token,
    fetched for this check - the original research entry's own Authority URL
    (.../intune-service/enrollment/automated-device-enrollment) 404s; this is the correct,
    canonical URL): "Renew your enrollment program token yearly" - the token has roughly a
    1-year lifetime, matching Maester's 30-day warning threshold framing.

    TWO INDEPENDENT CONDITIONS (per the research entry's own Notes, mirrored exactly):
    expiry (>30 days remaining) AND sync recency (last successful sync = the same calendar
    date as the snapshot cutoff, i.e. TotalDays == 0 - Maester's own stricter same-day rule
    for ADE, distinct from VPP's looser <=1-day rule in TP.INT.0021). Each token's evidence
    records BOTH legs separately so a caller can tell which one failed.

    DETERMINISM: compares against $Context.EvaluationCutoffBase (falling back to
    SnapshotCreatedUtc) - never Get-Date/::Now/::UtcNow.

    FIELD-ABSENCE LENS: tokenExpirationDateTime or lastSuccessfulSyncDateTime absent on an
    existing token row is undecidable - throws, per the standing "absent expiry/sync field
    -> throw" rule.

    RULE: zero tokens = NotApplicable (skip - tenant not using Apple ADE, mirrors Maester's
    own ItemNotFoundException -> Skipped behavior). Otherwise: a token is "offending" if it
    is expired, OR expires within 30 days, OR its last successful sync was not today (per
    the cutoff date) - Fail if any token is expired or sync-broken, Warn if the only issue
    across every offending token is approaching (not yet expired) expiry, Pass otherwise.

    PASS EVIDENCE (Phase 3 whole-phase review, catalog-coherence finding M1): the Pass
    path now attaches a corroborating per-row evidence summary too, matching
    Test-PulseStaleDevices.ps1's own precedent of never leaving a Pass evidence-empty when
    real per-row data already exists to corroborate it with.
#>

function Test-PulseAppleAdeTokensValid {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $tokens = @($Datasets.depOnboardingSettings)
    if ($tokens.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No Apple Automated Device Enrollment (ADE) tokens are configured for this tenant - Apple ADE/zero-touch enrollment is not in use, so there is nothing for this check to evaluate.'
    }

    $cutoffBaseText = $null
    if ($Context -and $Context.ContainsKey('EvaluationCutoffBase') -and $Context.EvaluationCutoffBase) {
        $cutoffBaseText = [string] $Context.EvaluationCutoffBase
    } elseif ($Context -and $Context.ContainsKey('SnapshotCreatedUtc') -and $Context.SnapshotCreatedUtc) {
        $cutoffBaseText = [string] $Context.SnapshotCreatedUtc
    }
    if ([string]::IsNullOrWhiteSpace($cutoffBaseText)) {
        throw 'Test-PulseAppleAdeTokensValid: no $Context.EvaluationCutoffBase/SnapshotCreatedUtc was supplied.'
    }
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $cutoff = [datetime]::Parse($cutoffBaseText, $culture, $styles)
    $warnThreshold = $cutoff.AddDays(30)
    $cutoffDate = $cutoff.Date

    $expiredOrStale = [System.Collections.Generic.List[object]]::new()
    $approachingOnly = [System.Collections.Generic.List[object]]::new()
    $allRows = [System.Collections.Generic.List[object]]::new()

    for ($index = 0; $index -lt $tokens.Count; $index++) {
        $token = $tokens[$index]

        if (-not (Test-PulseRowPropertyPresent -Row $token -PropertyName 'tokenExpirationDateTime') -or $null -eq $token.tokenExpirationDateTime) {
            throw 'Test-PulseAppleAdeTokensValid: a depOnboardingSettings row is missing tokenExpirationDateTime.'
        }
        if (-not (Test-PulseRowPropertyPresent -Row $token -PropertyName 'lastSuccessfulSyncDateTime') -or $null -eq $token.lastSuccessfulSyncDateTime) {
            throw 'Test-PulseAppleAdeTokensValid: a depOnboardingSettings row is missing lastSuccessfulSyncDateTime.'
        }

        $expiry = [datetime]::Parse([string] $token.tokenExpirationDateTime, $culture, $styles)
        $lastSync = [datetime]::Parse([string] $token.lastSuccessfulSyncDateTime, $culture, $styles)

        $isExpired = $expiry -le $cutoff
        $isApproaching = (-not $isExpired) -and ($expiry -le $warnThreshold)
        $isSyncStale = $lastSync.Date -ne $cutoffDate

        # ORDINAL FALLBACK (Phase 3 whole-phase review, catalog-coherence finding I2): the
        # id-less fallback used to be appleIdentifier itself - the SAME Apple ID can
        # legitimately own multiple tokens, so two id-less rows sharing an appleIdentifier
        # would collide on the same evidence Identity/SortKey pair and degrade the whole
        # evaluation to Error via Assert-PulseEvidenceNoDuplicates. Per-row ordinal
        # ('ade-token-<index>', 0-based) is guaranteed unique within one evaluation.
        $identity = if (Test-PulseRowPropertyPresent -Row $token -PropertyName 'id') { [string] $token.id } else { "ade-token-$index" }
        $row = @{
            Identity = $identity
            Detail   = @{
                appleIdentifier             = $token.appleIdentifier
                tokenName                   = $token.tokenName
                tokenExpirationDateTime     = $token.tokenExpirationDateTime
                lastSuccessfulSyncDateTime  = $token.lastSuccessfulSyncDateTime
                expired                     = $isExpired
                approachingExpiry           = $isApproaching
                syncStale                   = $isSyncStale
            }
            SortKey  = $identity
        }
        $allRows.Add($row)

        if ($isExpired -or $isSyncStale) {
            $expiredOrStale.Add($row)
        } elseif ($isApproaching) {
            $approachingOnly.Add($row)
        }
    }

    if ($expiredOrStale.Count -gt 0) {
        $evidence = @($expiredOrStale.ToArray() + $approachingOnly.ToArray())
        return New-PulseFinding -Status Fail -Reason "$($expiredOrStale.Count) of $($tokens.Count) Apple ADE token(s) are expired or have not completed a successful sync today - new Apple devices cannot auto-enroll via zero-touch and device visibility can silently stop updating until the token is renewed or sync is restored." -Evidence $evidence
    }

    if ($approachingOnly.Count -gt 0) {
        return New-PulseFinding -Status Warn -Reason "$($approachingOnly.Count) of $($tokens.Count) Apple ADE token(s) expire within 30 days - renew now to avoid an unplanned zero-touch enrollment outage." -Evidence $approachingOnly.ToArray()
    }

    # M1 (Phase 3 whole-phase review): Pass now carries a corroborating per-token evidence
    # row too, consistent with Test-PulseStaleDevices.ps1's own precedent of never leaving
    # a Pass evidence-empty when real per-row data already exists to corroborate it with.
    return New-PulseFinding -Status Pass -Reason "All $($tokens.Count) Apple ADE token(s) have more than 30 days remaining before expiration and completed a successful sync today." -Evidence $allRows.ToArray()
}

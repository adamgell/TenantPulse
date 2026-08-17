<#
    Private: TP.INT.0021 rule function - Apple Volume Purchase Program (VPP) tokens valid
    and syncing (Task 3.3, Maester port MT.1094 -
    Test-MtAppleVolumePurchaseProgramToken, MIT).

    LIVE DATASET: `vppTokens` maps to GraphKit 0.1.1's released `AppleVppToken`/`List`
    (beta) descriptor, PathTemplate `/deviceAppManagement/vppTokens` - confirmed via a live
    Get-GraphOperation -List enumeration, NOT Pending.

    FIELD NAMES (live-verified against the vppToken resource's own documented property
    set, Graph beta): `expirationDateTime` and `lastSyncDateTime` - NOT
    `tokenExpirationDateTime`/`lastSuccessfulSyncDateTime`, which is the depOnboardingSetting
    (ADE) shape TP.INT.0020 reads instead.

    CLAIM (live-verified against
    https://learn.microsoft.com/en-us/intune/app-management/deployment/manage-vpp-apple,
    fetched for this check): "Each token is valid for one year" and "Intune synchronizes
    the location tokens with Apple once a day, by default" - a token showing "invalid" in
    Intune if the Managed Apple ID account changes/expires, or if the token itself expires.

    ONE-DAY SYNC WINDOW (per the research entry's own Notes, deliberately looser than
    TP.INT.0020's same-day ADE rule - do not copy that stricter threshold here by mistake):
    "synced within the last day" is evaluated as <= 1.0 elapsed day between lastSyncDateTime
    and the cutoff, not "same calendar date".

    DETERMINISM: compares against $Context.EvaluationCutoffBase (falling back to
    SnapshotCreatedUtc) - never Get-Date/::Now/::UtcNow.

    FIELD-ABSENCE LENS: expirationDateTime or lastSyncDateTime absent on an existing token
    row is undecidable - throws.

    RULE: zero tokens = NotApplicable (skip - VPP not in use). Otherwise: a token is
    "offending" if expired, OR expires within 30 days, OR its last sync was more than 1 day
    before the cutoff. Fail if any token is expired or sync-stale, Warn if the only issue
    is approaching (not yet expired) expiry, Pass otherwise.

    PASS EVIDENCE (Phase 3 whole-phase review, catalog-coherence finding M1): the Pass
    path now attaches a corroborating per-row evidence summary too, matching
    Test-PulseStaleDevices.ps1's own precedent of never leaving a Pass evidence-empty when
    real per-row data already exists to corroborate it with.

    REDACTION (Phase 3 closing fix series, item 4, live surprise 2 - audit judgment call):
    organizationName can legitimately be a corporate/business name (not
    person-identifying) OR the actual Managed Apple ID account holder's name for a
    smaller/individually-administered tenant (person-identifying) - this check cannot
    distinguish the two shapes from the field alone, and the live proof this fix closes
    (a real Apple ID UPN surfacing raw in rendered evidence Detail under -Redact,
    2026-08-17, TP.INT.0020/0021) treats both this field and TP.INT.0020's appleIdentifier
    as the same risk class. Marked via every evidence row's
    RedactDetailKeys = @('organizationName') - redacting a benign corporate name under
    -Redact is a false positive with no real cost; leaving a person's name raw is not an
    acceptable trade the other way.
#>

function Test-PulseAppleVppTokensValid {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $tokens = @($Datasets.vppTokens)
    if ($tokens.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No Apple Volume Purchase Program (VPP) tokens are configured for this tenant - Apple app licensing via VPP is not in use, so there is nothing for this check to evaluate.'
    }

    $cutoffBaseText = $null
    if ($Context -and $Context.ContainsKey('EvaluationCutoffBase') -and $Context.EvaluationCutoffBase) {
        $cutoffBaseText = [string] $Context.EvaluationCutoffBase
    } elseif ($Context -and $Context.ContainsKey('SnapshotCreatedUtc') -and $Context.SnapshotCreatedUtc) {
        $cutoffBaseText = [string] $Context.SnapshotCreatedUtc
    }
    if ([string]::IsNullOrWhiteSpace($cutoffBaseText)) {
        throw 'Test-PulseAppleVppTokensValid: no $Context.EvaluationCutoffBase/SnapshotCreatedUtc was supplied.'
    }
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $cutoff = [datetime]::Parse($cutoffBaseText, $culture, $styles)
    $warnThreshold = $cutoff.AddDays(30)
    $syncThreshold = $cutoff.AddDays(-1)

    $expiredOrStale = [System.Collections.Generic.List[object]]::new()
    $approachingOnly = [System.Collections.Generic.List[object]]::new()
    $allRows = [System.Collections.Generic.List[object]]::new()

    for ($index = 0; $index -lt $tokens.Count; $index++) {
        $token = $tokens[$index]

        if (-not (Test-PulseRowPropertyPresent -Row $token -PropertyName 'expirationDateTime') -or $null -eq $token.expirationDateTime) {
            throw 'Test-PulseAppleVppTokensValid: a vppTokens row is missing expirationDateTime.'
        }
        if (-not (Test-PulseRowPropertyPresent -Row $token -PropertyName 'lastSyncDateTime') -or $null -eq $token.lastSyncDateTime) {
            throw 'Test-PulseAppleVppTokensValid: a vppTokens row is missing lastSyncDateTime.'
        }

        $expiry = [datetime]::Parse([string] $token.expirationDateTime, $culture, $styles)
        $lastSync = [datetime]::Parse([string] $token.lastSyncDateTime, $culture, $styles)

        $isExpired = $expiry -le $cutoff
        $isApproaching = (-not $isExpired) -and ($expiry -le $warnThreshold)
        $isSyncStale = $lastSync -lt $syncThreshold

        # ORDINAL FALLBACK (Phase 3 whole-phase review, catalog-coherence finding I2): the
        # id-less fallback used to be organizationName itself - the SAME organization can
        # legitimately hold multiple VPP tokens, so two id-less rows sharing an
        # organizationName would collide on the same evidence Identity/SortKey pair and
        # degrade the whole evaluation to Error via Assert-PulseEvidenceNoDuplicates.
        # Per-row ordinal ('vpp-token-<index>', 0-based) is guaranteed unique within one
        # evaluation.
        $identity = if (Test-PulseRowPropertyPresent -Row $token -PropertyName 'id') { [string] $token.id } else { "vpp-token-$index" }
        $row = @{
            Identity         = $identity
            Detail           = @{
                organizationName  = $token.organizationName
                expirationDateTime = $token.expirationDateTime
                lastSyncDateTime   = $token.lastSyncDateTime
                expired            = $isExpired
                approachingExpiry  = $isApproaching
                syncStale          = $isSyncStale
            }
            SortKey          = $identity
            # REDACT-DETAIL-KEYS (Phase 3 closing fix series, item 4, live surprise 2) -
            # see this file's own docstring for the "person-shaped or not" judgment call.
            RedactDetailKeys = @('organizationName')
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
        return New-PulseFinding -Status Fail -Reason "$($expiredOrStale.Count) of $($tokens.Count) Apple VPP token(s) are expired or have not synced within the last day - licensed-app deployment and revocation to Apple devices silently fails for apps assigned through the affected token(s) until it is renewed or sync is restored." -Evidence $evidence
    }

    if ($approachingOnly.Count -gt 0) {
        return New-PulseFinding -Status Warn -Reason "$($approachingOnly.Count) of $($tokens.Count) Apple VPP token(s) expire within 30 days - renew now to avoid an unplanned app-licensing outage." -Evidence $approachingOnly.ToArray()
    }

    # M1 (Phase 3 whole-phase review): Pass now carries a corroborating per-token evidence
    # row too, consistent with Test-PulseStaleDevices.ps1's own precedent of never leaving
    # a Pass evidence-empty when real per-row data already exists to corroborate it with.
    return New-PulseFinding -Status Pass -Reason "All $($tokens.Count) Apple VPP token(s) have more than 30 days remaining before expiration and synced within the last day." -Evidence $allRows.ToArray()
}

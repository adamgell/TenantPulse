<#
    Private: TP.INT.0019 rule function - Apple MDM Push (APNs) certificate valid for more
    than 30 days (Task 3.3, Maester port MT.1092 - Test-MtApplePushNotificationCertificate,
    MIT).

    DATASET (live): GraphKit 0.2.2 shipped the official descriptor and DatasetMap now treats
    this dataset as live. Type `ApplePushNotificationCertificate`, Operation `Get`,
    ApiVersion `v1.0`; this check evaluates live tenant data.

    CLAIM (live-verified against
    https://learn.microsoft.com/en-us/intune/device-enrollment/apple/create-mdm-push-certificate,
    fetched for this check - the original research entry's own Authority URL
    (.../intune-service/enrollment/apple-mdm-push-certificate-get) is SUPERSEDED and
    redirects here rather than hard-404ing (corrected post-review, dual-review fix round -
    an earlier draft of this note overstated it as a 404; see the research entry's own
    RESOLVED (2026-08-17) note); this is the correct, canonical redirect-target URL): "The
    Apple MDM push certificate is valid for 365 days... Once
    the certificate expires, there is a 30-day grace period to renew it" and it "must" be
    renewed "with the same Apple account you used to create it." A lapsed renewal forces
    devices through re-enrollment. 30-day threshold matches Maester's own hardcoded warning
    window.

    DETERMINISM: compares expirationDateTime against $Context.EvaluationCutoffBase (falling
    back to SnapshotCreatedUtc), exactly like Test-PulseFeatureUpdatePolicyAvoidsEos.ps1's
    own established pattern - never Get-Date/::Now/::UtcNow.

    FIELD-ABSENCE LENS: expirationDateTime absent on an existing certificate row is
    genuinely undecidable (the row exists but this rule cannot tell if it is fine, expiring,
    or expired) - throws, per the standing "absent expiry field -> throw" rule, rather than
    silently treating it as Pass or Fail.

    RULE: zero rows returned = NotApplicable ("no APNs certificate configured at all" - this
    is Microsoft's own documented 404-when-unconfigured shape, distinct from "expiring
    soon" - see the research entry's own Notes). One row: Fail if expirationDateTime is on
    or before the cutoff (already expired); Warn if it is after the cutoff but within 30
    days of it (approaching-expiry threshold, matching Maester's own 30-day framing); Pass
    otherwise.

    REDACTION (Phase 3 closing fix series, item 4 audit finding): appleIdentifier is the
    Apple ID (an email address, person-identifying) used to create/renew this
    certificate - the SAME risk class as TP.INT.0020/0021's own appleIdentifier/
    organizationName fields (the live proof that fix round closes: a real Apple ID UPN
    surfacing raw in rendered evidence Detail under -Redact, 2026-08-17). Marked via the
    evidence row's RedactDetailKeys = @('appleIdentifier') so Invoke-PulseAssessment
    -Redact pseudonymizes it in rendered output.
#>

function Test-PulseApplePushCertificateValid {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $rows = @($Datasets.applePushNotificationCertificate)
    if ($rows.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No Apple Push Notification Service (APNs) certificate is configured for this tenant - Apple device (iOS/iPadOS/macOS) management has never been set up, so there is nothing for this check to evaluate.'
    }

    $cutoffBaseText = $null
    if ($Context -and $Context.ContainsKey('EvaluationCutoffBase') -and $Context.EvaluationCutoffBase) {
        $cutoffBaseText = [string] $Context.EvaluationCutoffBase
    } elseif ($Context -and $Context.ContainsKey('SnapshotCreatedUtc') -and $Context.SnapshotCreatedUtc) {
        $cutoffBaseText = [string] $Context.SnapshotCreatedUtc
    }

    if ([string]::IsNullOrWhiteSpace($cutoffBaseText)) {
        throw 'Test-PulseApplePushCertificateValid: no $Context.EvaluationCutoffBase/SnapshotCreatedUtc was supplied - this rule cannot determine "as of when" to compare expirationDateTime without it.'
    }

    $cutoff = [datetime]::Parse($cutoffBaseText, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
    $warnThreshold = $cutoff.AddDays(30)

    $cert = $rows[0]
    if (-not (Test-PulseRowPropertyPresent -Row $cert -PropertyName 'expirationDateTime') -or $null -eq $cert.expirationDateTime) {
        throw 'Test-PulseApplePushCertificateValid: the applePushNotificationCertificate row is missing expirationDateTime - cannot determine expiry status for a certificate that otherwise exists.'
    }

    $expiry = [datetime]::Parse([string] $cert.expirationDateTime, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)

    $evidence = @(
        @{
            Identity         = if (Test-PulseRowPropertyPresent -Row $cert -PropertyName 'id') { [string] $cert.id } else { 'applePushNotificationCertificate' }
            Detail           = @{ appleIdentifier = $cert.appleIdentifier; expirationDateTime = $cert.expirationDateTime }
            SortKey          = 'applePushNotificationCertificate'
            RedactDetailKeys = @('appleIdentifier')
        }
    )

    if ($expiry -le $cutoff) {
        return New-PulseFinding -Status Fail -Reason 'The Apple Push Notification Service (APNs) certificate has already expired - ALL Apple (iOS/iPadOS/macOS) device management is broken until it is renewed, and a lapse can force affected devices through full re-enrollment.' -Evidence $evidence
    }

    if ($expiry -le $warnThreshold) {
        return New-PulseFinding -Status Warn -Reason 'The Apple Push Notification Service (APNs) certificate expires within 30 days - renew it now, using the SAME Apple ID that created it, to avoid an unplanned management outage across every Apple device in the tenant.' -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason 'The Apple Push Notification Service (APNs) certificate has more than 30 days remaining before expiration.' -Evidence $evidence
}

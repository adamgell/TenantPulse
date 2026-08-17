<#
    Private: TP.INT.0011 rule function - default Intune branding profile customized
    (Task 3.2, Maester port MT.1101 - Test-MtTenantCustomization, MIT).

    PENDING DATASET (honest NA): intuneBrandingProfiles has no released GraphKit 0.1.1
    descriptor - DatasetMap.psd1 marks it Pending=$true. On a live tenant this resolves
    NotApplicable until GraphKit ships the descriptor.

    RULE (ported verbatim from Maester's own OR condition - live-verified against
    https://learn.microsoft.com/en-us/intune/app-management/configuration/configure-company-portal,
    fetched for this check; the research entry's own Authority URL,
    intune-service/apps/company-portal-app-branding, was live-fetched and returned 404 -
    NOT used in this descriptor's References.Authorities): Pass when EITHER the default
    profile (isDefaultProfile = $true) has a non-empty displayName OR privacyUrl, OR more
    than one branding profile exists at all. Fail only when exactly one (still-default,
    still-blank) profile exists.

    LOW-CONFIDENCE FINDING (research entry's own Notes, honored in Consulting text): a
    fully kiosk/Autopilot-only fleet with a still-blank default profile can legitimately
    never need this, so Consulting softens the framing to "hygiene" rather than a hard
    security control - never escalated to a Fail-implies-incident tone.
#>

function Test-PulseBrandingProfileCustomized {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $profiles = @($Datasets.intuneBrandingProfiles)

    if ($profiles.Count -eq 0) {
        throw 'Test-PulseBrandingProfileCustomized: intuneBrandingProfiles dataset returned no rows - every tenant has at least a default branding profile; zero rows means the service returned nothing to evaluate, not a legitimately empty result.'
    }

    $defaultProfile = @($profiles | Where-Object { $_.isDefaultProfile -eq $true }) | Select-Object -First 1

    $defaultDisplayName = if ($defaultProfile) { [string] $defaultProfile.displayName } else { $null }
    $defaultPrivacyUrl = if ($defaultProfile) { [string] $defaultProfile.privacyUrl } else { $null }
    $defaultIsCustomized = -not ([string]::IsNullOrEmpty($defaultDisplayName)) -or -not ([string]::IsNullOrEmpty($defaultPrivacyUrl))

    $evidence = ConvertTo-PulseMaesterEvidence -Rows $profiles -IdentityProperty 'id' -SortKeyProperty 'displayName' -DetailProperties @('displayName', 'privacyUrl', 'isDefaultProfile')

    if ($defaultIsCustomized -or $profiles.Count -gt 1) {
        $reason = if ($defaultIsCustomized) {
            'The default Intune branding profile is customized (organization name and/or privacy URL is set) - enrollment and Company Portal screens are distinguishable from a generic/spoofed prompt.'
        } else {
            "The default branding profile is still blank, but $($profiles.Count) branding profiles exist in total - at least one custom, non-default profile is in use for some population."
        }
        return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence
    }

    $reason = 'The default Intune branding profile is unmodified (no organization name or privacy URL set) and no additional branding profiles exist - enrollment and Company Portal screens show Microsoft''s generic blank defaults, which are harder for end users to distinguish from a spoofed enrollment prompt. This is a hygiene/anti-phishing signal, not a technical control - a fleet that is entirely kiosk/Autopilot-provisioned with no interactive Company Portal use may reasonably accept this.'
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence
}
